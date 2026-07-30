#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define MANIFEST_PATH "/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256"
#define LAUNCHER_ROOT "/opt/bitcoinpir/publisher-netns-launcher"
#define LAUNCHER_NAME "payment-v1-publisher-netns-launcher"
#define NODE_PATH "/usr/bin/node"
#define EXECUTOR_PATH "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs"
#define INTEGRATED_GATE_PATH "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs"
#define PUBLISHER_GATE_PATH "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs"
#define MAX_MANIFEST_BYTES 4096
#define MAX_INPUT_BYTES (16 * 1024 * 1024)
#define MAX_NODE_BYTES (256 * 1024 * 1024)

extern char **environ;

struct input {
  const char *path;
  mode_t mode_a;
  mode_t mode_b;
  unsigned char expected[32];
  int fd;
  struct stat initial;
};

static struct input inputs[] = {
  { NODE_PATH, 0555, 0755, {0}, -1, {0} },
  { INTEGRATED_GATE_PATH, 0555, 0555, {0}, -1, {0} },
  { EXECUTOR_PATH, 0555, 0555, {0}, -1, {0} },
  { PUBLISHER_GATE_PATH, 0555, 0555, {0}, -1, {0} },
};

static void die(const char *message) {
  fprintf(stderr, "publisher-netns-launcher: %s\n", message);
  _exit(111);
}

static void die_errno(const char *message) {
  fprintf(stderr, "publisher-netns-launcher: %s: %s\n", message, strerror(errno));
  _exit(111);
}

static bool same_stat(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
    left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
    left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
    left->st_size == right->st_size &&
    left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
    left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
    left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
    left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static void validate_path_identity(const char *path, const struct stat *expected) {
  char resolved[PATH_MAX];
  struct stat current;
  if (realpath(path, resolved) == NULL) die_errno("realpath failed");
  if (strcmp(resolved, path) != 0) die("an input path resolves through a symlink");
  if (lstat(path, &current) != 0) die_errno("lstat failed");
  if (!same_stat(&current, expected)) die("an input pathname changed after it was opened");
}

static int open_pinned(const char *path, mode_t mode_a, mode_t mode_b,
                       size_t maximum, struct stat *snapshot) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) die_errno("open pinned input failed");
  if (fstat(fd, snapshot) != 0) die_errno("fstat pinned input failed");
  mode_t permissions = snapshot->st_mode & 07777;
  if (!S_ISREG(snapshot->st_mode) || snapshot->st_uid != 0 ||
      snapshot->st_gid != 0 || snapshot->st_nlink != 1 ||
      (permissions != mode_a && permissions != mode_b) ||
      snapshot->st_size < 1 || (uintmax_t)snapshot->st_size > maximum) {
    die("pinned input type, owner, mode, link count, or size drifted");
  }
  validate_path_identity(path, snapshot);
  return fd;
}

static void sha256_fd(int fd, off_t size, unsigned char output[32]) {
  struct sockaddr_alg address;
  memset(&address, 0, sizeof(address));
  address.salg_family = AF_ALG;
  memcpy(address.salg_type, "hash", 5);
  memcpy(address.salg_name, "sha256", 7);
  int transform = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (transform < 0) die_errno("AF_ALG SHA-256 socket failed");
  if (bind(transform, (struct sockaddr *)&address, sizeof(address)) != 0) {
    die_errno("AF_ALG SHA-256 bind failed");
  }
  int operation = accept4(transform, NULL, NULL, SOCK_CLOEXEC);
  if (operation < 0) die_errno("AF_ALG SHA-256 accept failed");
  unsigned char buffer[32768];
  off_t offset = 0;
  while (offset < size) {
    size_t wanted = (size - offset) > (off_t)sizeof(buffer)
      ? sizeof(buffer) : (size_t)(size - offset);
    ssize_t count = pread(fd, buffer, wanted, offset);
    if (count <= 0) die_errno("pinned input read failed");
    int flags = offset + count < size ? MSG_MORE : 0;
    ssize_t sent = send(operation, buffer, (size_t)count, flags);
    if (sent != count) die_errno("AF_ALG SHA-256 update failed");
    offset += count;
  }
  ssize_t received = read(operation, output, 32);
  if (received != 32) die_errno("AF_ALG SHA-256 digest failed");
  close(operation);
  close(transform);
}

static int hex_nibble(unsigned char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

static void parse_digest(const unsigned char *text, unsigned char output[32]) {
  for (size_t index = 0; index < 32; index++) {
    int high = hex_nibble(text[index * 2]);
    int low = hex_nibble(text[index * 2 + 1]);
    if (high < 0 || low < 0) die("manifest digest is not lowercase hexadecimal");
    output[index] = (unsigned char)((high << 4) | low);
  }
}

static void parse_manifest(const unsigned char *bytes, size_t size) {
  size_t offset = 0;
  for (size_t index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
    size_t path_size = strlen(inputs[index].path);
    size_t line_size = 64 + 2 + path_size + 1;
    if (offset + line_size > size || bytes[offset + 64] != ' ' ||
        bytes[offset + 65] != ' ' ||
        memcmp(bytes + offset + 66, inputs[index].path, path_size) != 0 ||
        bytes[offset + line_size - 1] != '\n') {
      die("launcher manifest is not the exact canonical four-entry manifest");
    }
    parse_digest(bytes + offset, inputs[index].expected);
    offset += line_size;
  }
  if (offset != size) die("launcher manifest contains trailing or missing data");
}

static void reject_influential_environment(void) {
  static const char *exact[] = {
    "BASH_ENV", "ENV", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD",
    "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "NODE_PATH",
  };
  for (char **entry = environ; entry != NULL && *entry != NULL; entry++) {
    const char *equals = strchr(*entry, '=');
    if (equals == NULL) die("environment contains a malformed entry");
    size_t name_size = (size_t)(equals - *entry);
    if ((name_size >= 3 && strncmp(*entry, "LD_", 3) == 0) ||
        (name_size >= 5 && strncmp(*entry, "DYLD_", 5) == 0)) {
      die("dynamic-loader or Node environment is forbidden");
    }
    for (size_t index = 0; index < sizeof(exact) / sizeof(exact[0]); index++) {
      if (strlen(exact[index]) == name_size &&
          memcmp(*entry, exact[index], name_size) == 0) {
        die("shell, dynamic-loader, or Node environment is forbidden");
      }
    }
  }
}

static void verify_self(const char *approved_text,
                        const unsigned char approved_sha256[32]) {
  int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (fd < 0) die_errno("open launcher executable failed");
  struct stat snapshot;
  if (fstat(fd, &snapshot) != 0) die_errno("fstat launcher executable failed");
  if (!S_ISREG(snapshot.st_mode) || snapshot.st_uid != 0 ||
      snapshot.st_gid != 0 || snapshot.st_nlink != 1 ||
      (snapshot.st_mode & 07777) != 0555 || snapshot.st_size < 1 ||
      (uintmax_t)snapshot.st_size > MAX_INPUT_BYTES) {
    die("launcher executable type, owner, mode, link count, or size drifted");
  }
  unsigned char observed[32];
  sha256_fd(fd, snapshot.st_size, observed);
  if (memcmp(observed, approved_sha256, 32) != 0) {
    die("launcher executable SHA-256 differs from the externally approved digest");
  }
  char expected[PATH_MAX];
  int count = snprintf(expected, sizeof(expected), "%s/%s/%s",
                       LAUNCHER_ROOT, approved_text, LAUNCHER_NAME);
  if (count <= 0 || (size_t)count >= sizeof(expected)) {
    die("approved launcher path is too long");
  }
  char resolved[PATH_MAX];
  if (realpath("/proc/self/exe", resolved) == NULL) {
    die_errno("realpath launcher executable failed");
  }
  if (strcmp(resolved, expected) != 0) {
    die("launcher executable is outside its approved content-addressed path");
  }
  struct stat final;
  if (fstat(fd, &final) != 0 || !same_stat(&snapshot, &final)) {
    die("launcher executable changed during self-verification");
  }
  close(fd);
}

int main(int argc, char **argv) {
  if (argc < 7 || strcmp(argv[1], "--approved-launcher-sha256") != 0 ||
      strlen(argv[2]) != 64 ||
      strcmp(argv[3], "--approved-manifest-sha256") != 0 ||
      strlen(argv[4]) != 64 || strcmp(argv[5], "--") != 0) {
    die("usage: payment-v1-publisher-netns-launcher --approved-launcher-sha256 HEX --approved-manifest-sha256 HEX -- COMMAND [ARG ...]");
  }
  reject_influential_environment();

  unsigned char approved_launcher_sha256[32];
  parse_digest((const unsigned char *)argv[2], approved_launcher_sha256);
  verify_self(argv[2], approved_launcher_sha256);

  unsigned char approved_manifest_sha256[32];
  parse_digest((const unsigned char *)argv[4], approved_manifest_sha256);

  struct stat manifest_stat;
  int manifest_fd = open_pinned(MANIFEST_PATH, 0444, 0444,
                                MAX_MANIFEST_BYTES, &manifest_stat);
  size_t manifest_size = (size_t)manifest_stat.st_size;
  unsigned char manifest[MAX_MANIFEST_BYTES];
  ssize_t manifest_read = pread(manifest_fd, manifest, manifest_size, 0);
  if (manifest_read != (ssize_t)manifest_size) die_errno("manifest read failed");
  unsigned char observed_manifest_sha256[32];
  sha256_fd(manifest_fd, manifest_stat.st_size, observed_manifest_sha256);
  if (memcmp(observed_manifest_sha256, approved_manifest_sha256, 32) != 0) {
    die("launcher manifest SHA-256 differs from the externally approved digest");
  }
  parse_manifest(manifest, manifest_size);

  for (size_t index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
    inputs[index].fd = open_pinned(inputs[index].path, inputs[index].mode_a,
                                   inputs[index].mode_b,
                                   index == 0 ? MAX_NODE_BYTES : MAX_INPUT_BYTES,
                                   &inputs[index].initial);
    unsigned char observed[32];
    sha256_fd(inputs[index].fd, inputs[index].initial.st_size, observed);
    if (memcmp(observed, inputs[index].expected, 32) != 0) {
      die("pinned input SHA-256 differs from the launcher manifest");
    }
  }

  validate_path_identity(MANIFEST_PATH, &manifest_stat);
  struct stat manifest_final;
  if (fstat(manifest_fd, &manifest_final) != 0 ||
      !same_stat(&manifest_stat, &manifest_final)) {
    die("launcher manifest changed during verification");
  }
  for (size_t index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
    validate_path_identity(inputs[index].path, &inputs[index].initial);
    struct stat final;
    if (fstat(inputs[index].fd, &final) != 0 ||
        !same_stat(&inputs[index].initial, &final)) {
      die("pinned input changed during verification");
    }
  }

  if (clearenv() != 0 || setenv("PATH", "/usr/sbin:/usr/bin", 1) != 0 ||
      setenv("LANG", "C.UTF-8", 1) != 0 || setenv("LC_ALL", "C.UTF-8", 1) != 0 ||
      setenv("TZ", "UTC", 1) != 0) {
    die_errno("failed to construct the closed executor environment");
  }
  umask(077);
  if (chdir("/") != 0) die_errno("chdir failed");

  char **exec_argv = calloc((size_t)argc + 1, sizeof(char *));
  if (exec_argv == NULL) die_errno("argv allocation failed");
  exec_argv[0] = (char *)NODE_PATH;
  exec_argv[1] = (char *)EXECUTOR_PATH;
  for (int index = 6; index < argc; index++) exec_argv[index - 4] = argv[index];
  exec_argv[argc - 4] = NULL;

  syscall(SYS_execveat, inputs[0].fd, "", exec_argv, environ, AT_EMPTY_PATH);
  die_errno("descriptor-bound Node execveat failed");
  return 111;
}
