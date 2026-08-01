#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_alg.h>
#include <linux/magic.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

#define STRINGIFY_LITERAL(value) #value
#define XSTR(value) STRINGIFY_LITERAL(value)

#define MANIFEST_PATH "/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256"
#define LAUNCHER_ROOT "/opt/bitcoinpir/publisher-netns-launcher"
#define LAUNCHER_NAME "payment-v1-publisher-netns-launcher"
#define NODE_PATH "/usr/bin/node"
#define EXECUTOR_PATH "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs"
#define PUBLISHER_NAMESPACE_PATH "/run/netns/bpir-directory-publisher"
#define PRIVATE_HEALTH_COMMAND "publisher-private-health-probe"
#define INTEGRATED_GATE_PATH "/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs"
#define PUBLISHER_GATE_PATH "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs"
#define SCHEMA_VALIDATOR_PATH "/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-schema.mjs"
#define HEALTH_PROBE_PATH "/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs"
#define NODE_LOADER_CLOSURE_PATH "/etc/bitcoinpir/payment-v1/publisher-netns/node-loader-closure.sha256"
#define MAX_MANIFEST_BYTES 4096
#define MAX_LOADER_CLOSURE_MANIFEST_BYTES 16384
#define MAX_LOADER_OBJECTS 32
#define MAX_INPUT_BYTES (16 * 1024 * 1024)
#define MAX_NODE_BYTES (256 * 1024 * 1024)
#define MODULE_FD_BASE 3
#define CLOSURE_MANIFEST_FD 8
#define NODE_IMAGE_FD 9
#define LOADER_OBJECT_FD_BASE 16
#ifndef BPIR_LD_SO_PRELOAD_PATH
#define BPIR_LD_SO_PRELOAD_PATH "/etc/ld.so.preload"
#endif
#ifdef BPIR_PUBLISHER_LAUNCHER_TEST_HOOKS
#define BPIR_TEST_EXEC_MAP_EXCEPTION \
  "if(pathname==='/run/rosetta/rosetta')continue;"
#else
#define BPIR_TEST_EXEC_MAP_EXCEPTION ""
#endif

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
  { SCHEMA_VALIDATOR_PATH, 0555, 0555, {0}, -1, {0} },
  { HEALTH_PROBE_PATH, 0555, 0555, {0}, -1, {0} },
  { NODE_LOADER_CLOSURE_PATH, 0444, 0444, {0}, -1, {0} },
};

struct loader_object {
  char path[PATH_MAX];
  unsigned char expected[32];
  int fd;
  struct stat initial;
};

static struct loader_object loader_objects[MAX_LOADER_OBJECTS];
static size_t loader_object_count = 0;

static const char node_bootstrap[] =
  "const fs=await import('node:fs');const crypto=await import('node:crypto');"
  "const closureFd=" XSTR(CLOSURE_MANIFEST_FD) ",nodeFd=" XSTR(NODE_IMAGE_FD)
    ",loaderFdBase=" XSTR(LOADER_OBJECT_FD_BASE) ";"
  "const expectedNodeSha256=process.argv[1];"
  "if(!/^[0-9a-f]{64}$/.test(expectedNodeSha256))throw new Error('malformed sealed Node digest');"
  "process.argv.splice(1,1);"
  "const closureText=fs.readFileSync(closureFd,'utf8');"
  "if(!closureText.endsWith('\\n')||closureText.includes('\\r'))throw new Error('malformed loader closure manifest');"
  "const closureLines=closureText.slice(0,-1).split('\\n');"
  "if(closureLines.length<2||closureLines.length>" XSTR(MAX_LOADER_OBJECTS)
    ")throw new Error('invalid loader closure size');"
  "const seenPaths=new Set();"
  "const closure=closureLines.map((line,index)=>{"
    "const match=/^([0-9a-f]{64})  (\\/usr\\/lib\\/x86_64-linux-gnu\\/[A-Za-z0-9+_.-]+)$/.exec(line);"
    "if(!match||seenPaths.has(match[2]))throw new Error('malformed loader closure entry');"
    "if(index===0&&match[2]!=='/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')"
      "throw new Error('loader closure does not begin with the interpreter');"
    "seenPaths.add(match[2]);return{sha256:match[1],path:match[2],fd:loaderFdBase+index};"
  "});"
  "const hashFd=fd=>crypto.createHash('sha256').update(fs.readFileSync('/proc/self/fd/'+fd)).digest('hex');"
  "const snapshotFd=fd=>{const stat=fs.fstatSync(fd,{bigint:true});"
    "if((stat.mode&0o170000n)!==0o100000n||stat.uid!==0n||stat.gid!==0n||stat.nlink!==1n)"
      "throw new Error('sealed runtime descriptor metadata drifted');"
    "return stat;};"
  "const sameStat=(left,right)=>['dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs']"
    ".every(name=>left[name]===right[name]);"
  "const major=dev=>((dev>>8n)&0xfffn)|((dev>>32n)&0xfffff000n);"
  "const minor=dev=>(dev&0xffn)|((dev>>12n)&0xffffff00n);"
  "const identity=stat=>major(stat.dev)+':'+minor(stat.dev)+':'+stat.ino;"
  "const pinned=[{fd:nodeFd,sha256:expectedNodeSha256},...closure];"
  "const baselines=pinned.map(item=>({...item,stat:snapshotFd(item.fd)}));"
  "if(new Set(baselines.map(item=>identity(item.stat))).size!==baselines.length)"
    "throw new Error('sealed runtime descriptors are not unique');"
  "for(const item of baselines)if(hashFd(item.fd)!==item.sha256)"
    "throw new Error('sealed runtime descriptor digest drifted before evaluation');"
  "const allowed=new Set(baselines.map(item=>identity(item.stat)));"
  "function sampleExecutableMaps(label){const observed=new Set();"
    "const lines=fs.readFileSync('/proc/self/maps','utf8').trimEnd().split('\\n');"
    "for(const line of lines){const match=/^[0-9a-f]+-[0-9a-f]+ ([r-][w-][x-][ps]) [0-9a-f]+ ([0-9a-f]+):([0-9a-f]+) ([0-9]+)(?: +(.*))?$/.exec(line);"
      "if(!match)throw new Error(label+' malformed /proc/self/maps line');"
      "const permissions=match[1],pathname=match[5]===undefined?'':match[5];"
      "if(permissions[1]==='w'&&permissions[2]==='x')throw new Error(label+' W+X mapping');"
      "if(permissions[2]!=='x')continue;"
      "if(pathname==='[vdso]'||pathname==='[vsyscall]')continue;"
      BPIR_TEST_EXEC_MAP_EXCEPTION
      "const inode=BigInt(match[4]);"
      "if(inode===0n||!pathname.startsWith('/')||pathname.endsWith(' (deleted)'))"
        "throw new Error(label+' anonymous or deleted executable mapping');"
      "const key=BigInt('0x'+match[2])+':'+BigInt('0x'+match[3])+':'+inode;"
      "if(!allowed.has(key))throw new Error(label+' executable mapping outside sealed closure: '+pathname);"
      "observed.add(key);"
    "}"
    "for(const key of allowed)if(!observed.has(key))throw new Error(label+' sealed object lacks executable mapping');"
  "}"
  "sampleExecutableMaps('pre-evaluation');"
  "const paths=['" INTEGRATED_GATE_PATH "','" EXECUTOR_PATH "','"
    PUBLISHER_GATE_PATH "','" SCHEMA_VALIDATOR_PATH "','" HEALTH_PROBE_PATH "'];"
  "const sources=paths.map((path,index)=>fs.readFileSync(" XSTR(MODULE_FD_BASE) "+index,'utf8'));"
  "for(let index=0;index<paths.length;index++)fs.closeSync(" XSTR(MODULE_FD_BASE) "+index);"
  "const vm=await import('node:vm');"
  "const urls=paths.map(path=>new URL('file://'+path).href);"
  "const modules=new Map(urls.map((url,index)=>[url,new vm.SourceTextModule(sources[index],{"
    "identifier:url,initializeImportMeta(meta){meta.url=url;}})]));"
  "const builtins=new Map();"
  "async function link(specifier,referencing){"
    "if(specifier.startsWith('node:')){"
      "if(!builtins.has(specifier)){"
        "const namespace=await import(specifier);const names=Object.keys(namespace);"
        "builtins.set(specifier,new vm.SyntheticModule(names,function(){"
          "for(const name of names)this.setExport(name,namespace[name]);"
        "},{identifier:specifier}));"
      "}return builtins.get(specifier);"
    "}"
    "const resolved=new URL(specifier,referencing.identifier).href;"
    "const found=modules.get(resolved);if(found===undefined)throw new Error('unsealed local import '+resolved);"
    "return found;"
  "}"
  "const health=process.argv[1]==='" PRIVATE_HEALTH_COMMAND "';"
  "const entryIndex=health?4:1;"
  "process.argv=['" NODE_PATH "',health?'" HEALTH_PROBE_PATH "':'" EXECUTOR_PATH
    "',...process.argv.slice(1)];"
  "const entry=modules.get(urls[entryIndex]);await entry.link(link);await entry.evaluate();"
  "for(const item of baselines){const final=snapshotFd(item.fd);"
    "if(!sameStat(item.stat,final)||hashFd(item.fd)!==item.sha256)"
      "throw new Error('sealed runtime descriptor drifted during evaluation');}"
  "sampleExecutableMaps('post-evaluation');"
  "for(const item of baselines)fs.closeSync(item.fd);fs.closeSync(closureFd);";

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

static void format_digest(const unsigned char digest[32], char output[65]) {
  static const char hexadecimal[] = "0123456789abcdef";
  for (size_t index = 0; index < 32; index++) {
    output[index * 2] = hexadecimal[digest[index] >> 4];
    output[index * 2 + 1] = hexadecimal[digest[index] & 15];
  }
  output[64] = '\0';
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
      die("launcher manifest is not the exact canonical sealed-input manifest");
    }
    parse_digest(bytes + offset, inputs[index].expected);
    offset += line_size;
  }
  if (offset != size) die("launcher manifest contains trailing or missing data");
}

static void parse_loader_closure_manifest(const unsigned char *bytes, size_t size) {
  static const char prefix[] = "/usr/lib/x86_64-linux-gnu/";
  size_t offset = 0;
  while (offset < size) {
    if (loader_object_count >= MAX_LOADER_OBJECTS || offset + 68 > size) {
      die("Node loader closure has an invalid object count or truncated entry");
    }
    size_t newline = offset;
    while (newline < size && bytes[newline] != '\n') newline++;
    if (newline == size || newline - offset < 68 || bytes[offset + 64] != ' ' ||
        bytes[offset + 65] != ' ') {
      die("Node loader closure is not canonical sha256sum text");
    }
    size_t path_size = newline - (offset + 66);
    if (path_size < sizeof(prefix) || path_size >= PATH_MAX ||
        memcmp(bytes + offset + 66, prefix, sizeof(prefix) - 1) != 0) {
      die("Node loader closure path is outside the reviewed host ABI directory");
    }
    for (size_t index = sizeof(prefix) - 1; index < path_size; index++) {
      unsigned char value = bytes[offset + 66 + index];
      bool canonical = (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
        value == '+' || value == '_' || value == '.' || value == '-';
      if (!canonical) die("Node loader closure basename is not canonical");
    }
    struct loader_object *object = &loader_objects[loader_object_count];
    parse_digest(bytes + offset, object->expected);
    memcpy(object->path, bytes + offset + 66, path_size);
    object->path[path_size] = '\0';
    object->fd = -1;
    for (size_t previous = 0; previous < loader_object_count; previous++) {
      if (strcmp(loader_objects[previous].path, object->path) == 0) {
        die("Node loader closure paths are not unique");
      }
    }
    loader_object_count++;
    offset = newline + 1;
  }
  if (loader_object_count < 2 ||
      strcmp(loader_objects[0].path,
             "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2") != 0) {
    die("Node loader closure does not begin with the exact resolved interpreter");
  }
}

static int open_loader_object(struct loader_object *object) {
  int fd = open(object->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) die_errno("open Node loader object failed");
  if (fstat(fd, &object->initial) != 0) die_errno("fstat Node loader object failed");
  mode_t permissions = object->initial.st_mode & 07777;
  if (!S_ISREG(object->initial.st_mode) || object->initial.st_uid != 0 ||
      object->initial.st_gid != 0 || object->initial.st_nlink != 1 ||
      (permissions != 0444 && permissions != 0555 && permissions != 0644 &&
       permissions != 0755) || object->initial.st_size < 1 ||
      (uintmax_t)object->initial.st_size > MAX_NODE_BYTES) {
    die("Node loader object type, owner, mode, link count, or size drifted");
  }
  validate_path_identity(object->path, &object->initial);
  unsigned char observed[32];
  sha256_fd(fd, object->initial.st_size, observed);
  if (memcmp(observed, object->expected, 32) != 0) {
    die("Node loader object SHA-256 differs from the approved closure");
  }
  return fd;
}

static void reject_global_loader_preload(void) {
  struct stat ignored;
  if (lstat(BPIR_LD_SO_PRELOAD_PATH, &ignored) == 0) {
    die("global dynamic-loader preload file must not exist");
  }
  if (errno != ENOENT) die_errno("inspect global dynamic-loader preload path failed");
}

static void reject_influential_environment(void) {
  static const char *exact[] = {
    "BASH_ENV", "ENV", "GLIBC_TUNABLES", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD",
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

static uintmax_t parse_canonical_positive_decimal(const char *text,
                                                   const char *label) {
  if (text == NULL || text[0] < '1' || text[0] > '9') die(label);
  for (const unsigned char *cursor = (const unsigned char *)text;
       *cursor != '\0'; cursor++) {
    if (*cursor < '0' || *cursor > '9') die(label);
  }
  errno = 0;
  char *end = NULL;
  uintmax_t value = strtoumax(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0) die(label);
  return value;
}

static void enter_publisher_namespace_for_private_health(int argc, char **argv) {
  if (argc < 7 || strcmp(argv[6], PRIVATE_HEALTH_COMMAND) != 0) return;
  if (argc != 13 || strcmp(argv[7], "--namespace-device") != 0 ||
      strcmp(argv[9], "--namespace-inode") != 0 ||
      strcmp(argv[11], "--check-base64") != 0 || argv[12][0] == '\0' ||
      strlen(argv[12]) > 16384) {
    die("publisher private health command has an unreviewed argv shape");
  }
  for (const unsigned char *cursor = (const unsigned char *)argv[12];
       *cursor != '\0'; cursor++) {
    bool base64 = (*cursor >= 'A' && *cursor <= 'Z') ||
      (*cursor >= 'a' && *cursor <= 'z') ||
      (*cursor >= '0' && *cursor <= '9') || *cursor == '+' ||
      *cursor == '/' || *cursor == '=';
    if (!base64) die("publisher private health check is not canonical base64");
  }
  uintmax_t expected_device = parse_canonical_positive_decimal(
    argv[8], "publisher namespace device is not canonical positive decimal");
  uintmax_t expected_inode = parse_canonical_positive_decimal(
    argv[10], "publisher namespace inode is not canonical positive decimal");

  int namespace_fd = open(PUBLISHER_NAMESPACE_PATH,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (namespace_fd < 0) die_errno("open publisher namespace failed");
  struct stat before;
  struct statfs filesystem;
  if (fstat(namespace_fd, &before) != 0 ||
      fstatfs(namespace_fd, &filesystem) != 0) {
    die_errno("inspect publisher namespace failed");
  }
  if ((uintmax_t)before.st_dev != expected_device ||
      (uintmax_t)before.st_ino != expected_inode ||
      (unsigned long)filesystem.f_type != (unsigned long)NSFS_MAGIC) {
    die("publisher namespace descriptor differs from the approved receipt");
  }
  validate_path_identity(PUBLISHER_NAMESPACE_PATH, &before);
  if (setns(namespace_fd, CLONE_NEWNET) != 0) {
    die_errno("enter publisher network namespace failed");
  }
  if (close(namespace_fd) != 0) die_errno("close publisher namespace failed");

  int current_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
  if (current_fd < 0) die_errno("open current network namespace failed");
  struct stat current;
  struct statfs current_filesystem;
  if (fstat(current_fd, &current) != 0 ||
      fstatfs(current_fd, &current_filesystem) != 0) {
    die_errno("inspect current network namespace failed");
  }
  if ((uintmax_t)current.st_dev != expected_device ||
      (uintmax_t)current.st_ino != expected_inode ||
      (unsigned long)current_filesystem.f_type != (unsigned long)NSFS_MAGIC) {
    die("current network namespace differs after setns");
  }
  if (close(current_fd) != 0) die_errno("close current network namespace failed");
}

#ifdef BPIR_PUBLISHER_LAUNCHER_TEST_HOOKS
static void test_pause_after_verify(void) {
  const char *directory = getenv("BPIR_LAUNCHER_TEST_PAUSE_DIRECTORY");
  if (directory == NULL) return;
  if (strncmp(directory, "/tmp/payment-v1-launcher-pause.", 31) != 0 ||
      strlen(directory) > 160) {
    die("test pause directory is malformed");
  }
  char ready[192];
  char proceed[192];
  if (snprintf(ready, sizeof(ready), "%s/ready", directory) <= 0 ||
      snprintf(proceed, sizeof(proceed), "%s/continue", directory) <= 0) {
    die("test pause path is too long");
  }
  int fd = open(ready, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0 || close(fd) != 0) die_errno("test pause marker failed");
  for (unsigned attempt = 0; attempt < 1000; attempt++) {
    if (access(proceed, F_OK) == 0) return;
    if (errno != ENOENT) die_errno("test pause continuation probe failed");
    usleep(10000);
  }
  die("test pause timed out");
}
#else
static void test_pause_after_verify(void) {}
#endif

static void seal_inherited_descriptors(void) {
  if (syscall(SYS_close_range, 3U, ~0U, CLOSE_RANGE_CLOEXEC) == 0) return;
#ifdef BPIR_PUBLISHER_LAUNCHER_TEST_HOOKS
  if (errno == ENOSYS) {
    long maximum = sysconf(_SC_OPEN_MAX);
    if (maximum < 3 || maximum > 16 * 1024 * 1024) {
      die("test fallback inherited-descriptor bound is invalid");
    }
    for (int fd = 3; fd < maximum; fd++) {
      int flags = fcntl(fd, F_GETFD);
      if (flags < 0) {
        if (errno == EBADF) continue;
        die_errno("test fallback inspect inherited descriptor failed");
      }
      if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
        die_errno("test fallback seal inherited descriptor failed");
      }
    }
    return;
  }
#endif
  die_errno("close_range inherited-descriptor seal failed");
}

static int prepare_descriptor_bound_child(void) {
  const size_t closure_input_index = (sizeof(inputs) / sizeof(inputs[0])) - 1;
  const size_t source_count = closure_input_index - 1;
  int node = fcntl(inputs[0].fd, F_DUPFD_CLOEXEC, 64);
  if (node < 0) die_errno("duplicate Node descriptor failed");
  int closure = fcntl(inputs[closure_input_index].fd, F_DUPFD_CLOEXEC, 64);
  if (closure < 0) die_errno("duplicate loader closure descriptor failed");
  int sources[5];
  if (source_count != sizeof(sources) / sizeof(sources[0])) {
    die("compiled sealed-module descriptor count drifted");
  }
  for (size_t index = 0; index < source_count; index++) {
    sources[index] = fcntl(inputs[index + 1].fd, F_DUPFD_CLOEXEC, 64);
    if (sources[index] < 0) die_errno("duplicate module descriptor failed");
  }
  int loader_descriptors[MAX_LOADER_OBJECTS];
  for (size_t index = 0; index < loader_object_count; index++) {
    loader_descriptors[index] = fcntl(loader_objects[index].fd, F_DUPFD_CLOEXEC, 64);
    if (loader_descriptors[index] < 0) {
      die_errno("duplicate Node loader object descriptor failed");
    }
  }
  seal_inherited_descriptors();
  for (size_t index = 0; index < source_count; index++) {
    if (dup3(sources[index], MODULE_FD_BASE + (int)index, 0) < 0) {
      die_errno("install module descriptor failed");
    }
    close(sources[index]);
  }
  if (dup3(closure, CLOSURE_MANIFEST_FD, 0) < 0) {
    die_errno("install loader closure descriptor failed");
  }
  close(closure);
  if (dup3(node, NODE_IMAGE_FD, 0) < 0) {
    die_errno("install Node image descriptor failed");
  }
  close(node);
  for (size_t index = 0; index < loader_object_count; index++) {
    if (dup3(loader_descriptors[index], LOADER_OBJECT_FD_BASE + (int)index, 0) < 0) {
      die_errno("install Node loader object descriptor failed");
    }
    close(loader_descriptors[index]);
  }
  return LOADER_OBJECT_FD_BASE;
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
  reject_global_loader_preload();

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

  const size_t closure_input_index = (sizeof(inputs) / sizeof(inputs[0])) - 1;
  for (size_t index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
    size_t maximum = index == 0 ? MAX_NODE_BYTES :
      index == closure_input_index ? MAX_LOADER_CLOSURE_MANIFEST_BYTES :
      MAX_INPUT_BYTES;
    inputs[index].fd = open_pinned(inputs[index].path, inputs[index].mode_a,
                                   inputs[index].mode_b,
                                   maximum,
                                   &inputs[index].initial);
    unsigned char observed[32];
    sha256_fd(inputs[index].fd, inputs[index].initial.st_size, observed);
    if (memcmp(observed, inputs[index].expected, 32) != 0) {
      die("pinned input SHA-256 differs from the launcher manifest");
    }
  }
  size_t closure_size = (size_t)inputs[closure_input_index].initial.st_size;
  unsigned char closure_manifest[MAX_LOADER_CLOSURE_MANIFEST_BYTES];
  ssize_t closure_read = pread(inputs[closure_input_index].fd, closure_manifest,
                               closure_size, 0);
  if (closure_read != (ssize_t)closure_size) {
    die_errno("Node loader closure manifest read failed");
  }
  parse_loader_closure_manifest(closure_manifest, closure_size);
  for (size_t index = 0; index < loader_object_count; index++) {
    loader_objects[index].fd = open_loader_object(&loader_objects[index]);
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
  for (size_t index = 0; index < loader_object_count; index++) {
    validate_path_identity(loader_objects[index].path, &loader_objects[index].initial);
    struct stat final;
    if (fstat(loader_objects[index].fd, &final) != 0 ||
        !same_stat(&loader_objects[index].initial, &final)) {
      die("Node loader object changed during verification");
    }
  }

  if (close(manifest_fd) != 0) die_errno("close launcher manifest failed");
  test_pause_after_verify();
  enter_publisher_namespace_for_private_health(argc, argv);
  int loader_exec_fd = prepare_descriptor_bound_child();

  if (clearenv() != 0 || setenv("PATH", "/usr/sbin:/usr/bin", 1) != 0 ||
      setenv("LANG", "C.UTF-8", 1) != 0 || setenv("LC_ALL", "C.UTF-8", 1) != 0 ||
      setenv("TZ", "UTC", 1) != 0) {
    die_errno("failed to construct the closed executor environment");
  }
  umask(077);
  if (chdir("/") != 0) die_errno("chdir failed");

  char preload[(MAX_LOADER_OBJECTS - 1) * 32];
  size_t preload_size = 0;
  for (size_t index = 1; index < loader_object_count; index++) {
    int count = snprintf(preload + preload_size, sizeof(preload) - preload_size,
                         "%s/proc/self/fd/%d", index == 1 ? "" : ":",
                         LOADER_OBJECT_FD_BASE + (int)index);
    if (count <= 0 || (size_t)count >= sizeof(preload) - preload_size) {
      die("descriptor-bound loader preload list is too long");
    }
    preload_size += (size_t)count;
  }
  if (preload_size == 0) die("descriptor-bound loader preload list is empty");

  char node_sha256[65];
  format_digest(inputs[0].expected, node_sha256);
  const size_t exec_argv_capacity = (size_t)argc + 17;
  char **exec_argv = calloc(exec_argv_capacity, sizeof(char *));
  if (exec_argv == NULL) die_errno("argv allocation failed");
  size_t exec_index = 0;
  exec_argv[exec_index++] = loader_objects[0].path;
  exec_argv[exec_index++] = "--inhibit-cache";
  exec_argv[exec_index++] = "--library-path";
  exec_argv[exec_index++] = "/__bitcoinpir_no_library_fallback__";
  exec_argv[exec_index++] = "--glibc-hwcaps-mask";
  exec_argv[exec_index++] = "";
  exec_argv[exec_index++] = "--inhibit-rpath";
  exec_argv[exec_index++] = "";
  exec_argv[exec_index++] = "--preload";
  exec_argv[exec_index++] = preload;
  exec_argv[exec_index++] = "--argv0";
  exec_argv[exec_index++] = (char *)NODE_PATH;
  exec_argv[exec_index++] = "/proc/self/fd/" XSTR(NODE_IMAGE_FD);
  exec_argv[exec_index++] = "--no-expose-wasm";
  exec_argv[exec_index++] = "--jitless";
  exec_argv[exec_index++] = "--use-openssl-ca";
  exec_argv[exec_index++] = "--no-warnings";
  exec_argv[exec_index++] = "--experimental-vm-modules";
  exec_argv[exec_index++] = "--input-type=module";
  exec_argv[exec_index++] = "--eval";
  exec_argv[exec_index++] = (char *)node_bootstrap;
  exec_argv[exec_index++] = node_sha256;
  for (int index = 6; index < argc; index++) exec_argv[exec_index++] = argv[index];
  if (exec_index + 1 != exec_argv_capacity) {
    die("descriptor-bound loader argv allocation contract drifted");
  }
  exec_argv[exec_index] = NULL;

  reject_global_loader_preload();
  syscall(SYS_execveat, loader_exec_fd, "", exec_argv, environ, AT_EMPTY_PATH);
  die_errno("descriptor-bound Node loader execveat failed");
  return 111;
}
