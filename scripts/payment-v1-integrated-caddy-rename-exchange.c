#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

static void fail_errno(const char *message) {
    fprintf(stderr, "payment-v1 rename-exchange: %s: %s\n", message, strerror(errno));
    exit(1);
}

static void fail(const char *message) {
    fprintf(stderr, "payment-v1 rename-exchange: %s\n", message);
    exit(2);
}

static unsigned long long parse_canonical_positive_u64(
    const char *value,
    const char *message) {
    if (value == NULL || value[0] < '1' || value[0] > '9') {
        fail(message);
    }
    for (const char *cursor = value + 1; *cursor != '\0'; cursor++) {
        if (*cursor < '0' || *cursor > '9') fail(message);
    }
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno == ERANGE || end == value || *end != '\0' || parsed == 0) fail(message);
    char canonical[32];
    int length = snprintf(canonical, sizeof(canonical), "%llu", parsed);
    if (length < 1 || (size_t)length >= sizeof(canonical) || strcmp(value, canonical) != 0) {
        fail(message);
    }
    return parsed;
}

static pid_t parse_expected_parent_pid(const char *value) {
    unsigned long long parsed = parse_canonical_positive_u64(
        value,
        "expected parent PID must be one canonical positive decimal integer");
    if (parsed <= 1 || parsed > INT_MAX) {
        fail("expected parent PID must identify one non-init Linux process");
    }
    return (pid_t)parsed;
}

static unsigned long long read_process_start_ticks(pid_t pid) {
    char path[64];
    int path_length = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (path_length < 1 || (size_t)path_length >= sizeof(path)) {
        fail("expected parent procfs path is out of range");
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) fail_errno("open expected parent procfs stat");

    char bytes[8192];
    size_t used = 0;
    while (used < sizeof(bytes) - 1) {
        ssize_t count = read(fd, bytes + used, sizeof(bytes) - 1 - used);
        if (count < 0) {
            if (errno == EINTR) continue;
            fail_errno("read expected parent procfs stat");
        }
        if (count == 0) break;
        used += (size_t)count;
    }
    if (used == sizeof(bytes) - 1) {
        char extra;
        ssize_t count;
        do {
            count = read(fd, &extra, 1);
        } while (count < 0 && errno == EINTR);
        if (count < 0) fail_errno("finish expected parent procfs stat read");
        if (count != 0) fail("expected parent procfs stat exceeded its bounded read");
    }
    if (close(fd) != 0) fail_errno("close expected parent procfs stat");
    bytes[used] = '\0';

    char *comm_close = strrchr(bytes, ')');
    if (used == 0 || bytes[0] < '1' || bytes[0] > '9' || comm_close == NULL) {
        fail("expected parent procfs stat is malformed");
    }
    char *cursor = comm_close + 1;
    for (int field = 3; field <= 22; field++) {
        while (
            *cursor == ' ' || *cursor == '\t' || *cursor == '\n' ||
            *cursor == '\r' || *cursor == '\v' || *cursor == '\f') {
            cursor++;
        }
        char *token = cursor;
        while (
            *cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
            *cursor != '\n' && *cursor != '\r' && *cursor != '\v' &&
            *cursor != '\f') {
            cursor++;
        }
        if (cursor == token) fail("expected parent procfs stat is missing fields");
        if (field == 22) {
            size_t length = (size_t)(cursor - token);
            if (length >= 32) fail("expected parent procfs start ticks are out of range");
            char start_ticks[32];
            memcpy(start_ticks, token, length);
            start_ticks[length] = '\0';
            return parse_canonical_positive_u64(
                start_ticks,
                "expected parent procfs start ticks are malformed");
        }
    }
    fail("expected parent procfs stat is missing start ticks");
    return 0;
}

static void require_expected_parent_generation(
    pid_t expected_parent,
    unsigned long long expected_start_ticks) {
    if (getppid() != expected_parent) {
        fail("current parent PID does not match the expected supervising generation");
    }
    if (read_process_start_ticks(expected_parent) != expected_start_ticks) {
        fail("current parent start ticks do not match the expected supervising generation");
    }
    if (getppid() != expected_parent) {
        fail("supervising parent changed while its process generation was verified");
    }
}

static void bind_to_parent_lifetime(
    pid_t expected_parent,
    unsigned long long expected_start_ticks) {
    require_expected_parent_generation(expected_parent, expected_start_ticks);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
        fail_errno("install parent-death signal");
    }
    require_expected_parent_generation(expected_parent, expected_start_ticks);
}

static void split_path(const char *path, char parent[PATH_MAX], char base[NAME_MAX + 1]) {
    size_t length = strlen(path);
    if (length < 3 || length >= PATH_MAX || path[0] != '/' || path[length - 1] == '/') {
        fail("paths must be bounded canonical absolute file paths");
    }
    if (strstr(path, "//") != NULL || strstr(path, "/./") != NULL ||
        strstr(path, "/../") != NULL) {
        fail("paths must not contain empty, dot or dot-dot components");
    }
    const char *slash = strrchr(path, '/');
    if (slash == NULL || slash == path || slash[1] == '\0') {
        fail("the exchange parent must not be the filesystem root");
    }
    size_t parent_length = (size_t)(slash - path);
    size_t base_length = length - parent_length - 1;
    if (parent_length >= PATH_MAX || base_length < 1 || base_length > NAME_MAX) {
        fail("path component is out of range");
    }
    memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';
    memcpy(base, slash + 1, base_length + 1);
    if (strcmp(base, ".") == 0 || strcmp(base, "..") == 0 || strchr(base, '/') != NULL) {
        fail("non-canonical exchange basename");
    }
}

static void require_regular_at(int directory_fd, const char *base, const char *label) {
    struct stat metadata;
    if (fstatat(directory_fd, base, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        fail_errno(label);
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1) {
        fail("both exchange entries must be single-link regular files");
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("bitcoinpir-payment-v1-rename-exchange 4");
        return 0;
    }
    if (argc != 6 ||
        (strcmp(argv[1], "--exchange") != 0 && strcmp(argv[1], "--publish") != 0)) {
        fail(
            "usage: helper --exchange expected-parent-pid expected-parent-start-ticks "
            "existing-a existing-b | --publish expected-parent-pid "
            "expected-parent-start-ticks pending absent-final");
    }

    pid_t expected_parent = parse_expected_parent_pid(argv[2]);
    unsigned long long expected_start_ticks = parse_canonical_positive_u64(
        argv[3],
        "expected parent start ticks must be one canonical positive decimal integer");
    bind_to_parent_lifetime(expected_parent, expected_start_ticks);

    char left_parent[PATH_MAX];
    char right_parent[PATH_MAX];
    char left_base[NAME_MAX + 1];
    char right_base[NAME_MAX + 1];
    split_path(argv[4], left_parent, left_base);
    split_path(argv[5], right_parent, right_base);
    if (strcmp(left_parent, right_parent) != 0 || strcmp(left_base, right_base) == 0) {
        fail("exchange entries must be distinct and share one exact parent path");
    }

    int directory_fd = open(left_parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) fail_errno("open exchange parent");
    require_regular_at(directory_fd, left_base, "inspect left exchange entry");
    if (strcmp(argv[1], "--exchange") == 0) {
        require_regular_at(directory_fd, right_base, "inspect right exchange entry");
#ifdef PAYMENT_V1_TEST_DELAY_BEFORE_RENAME_MS
        usleep((useconds_t)PAYMENT_V1_TEST_DELAY_BEFORE_RENAME_MS * 1000U);
#endif
        if (syscall(
                SYS_renameat2,
                directory_fd,
                left_base,
                directory_fd,
                right_base,
                RENAME_EXCHANGE) != 0) {
            fail_errno("renameat2(RENAME_EXCHANGE)");
        }
    } else {
        struct stat unexpected;
        if (fstatat(directory_fd, right_base, &unexpected, AT_SYMLINK_NOFOLLOW) == 0) {
            fail("publish destination already exists");
        }
        if (errno != ENOENT) fail_errno("inspect absent publish destination");
        if (syscall(
                SYS_renameat2,
                directory_fd,
                left_base,
                directory_fd,
                right_base,
                RENAME_NOREPLACE) != 0) {
            fail_errno("renameat2(RENAME_NOREPLACE)");
        }
    }
#ifdef PAYMENT_V1_TEST_FAIL_AFTER_RENAME
    errno = EIO;
    fail_errno("injected failure after renameat2");
#endif
    if (fsync(directory_fd) != 0) fail_errno("fsync exchange parent");
    if (close(directory_fd) != 0) fail_errno("close exchange parent");
    return 0;
}
