#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
        puts("bitcoinpir-payment-v1-rename-exchange 2");
        return 0;
    }
    if (argc != 4 ||
        (strcmp(argv[1], "--exchange") != 0 && strcmp(argv[1], "--publish") != 0)) {
        fail("usage: helper --exchange existing-a existing-b | --publish pending absent-final");
    }

    char left_parent[PATH_MAX];
    char right_parent[PATH_MAX];
    char left_base[NAME_MAX + 1];
    char right_base[NAME_MAX + 1];
    split_path(argv[2], left_parent, left_base);
    split_path(argv[3], right_parent, right_base);
    if (strcmp(left_parent, right_parent) != 0 || strcmp(left_base, right_base) == 0) {
        fail("exchange entries must be distinct and share one exact parent path");
    }

    int directory_fd = open(left_parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) fail_errno("open exchange parent");
    require_regular_at(directory_fd, left_base, "inspect left exchange entry");
    if (strcmp(argv[1], "--exchange") == 0) {
        require_regular_at(directory_fd, right_base, "inspect right exchange entry");
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
    if (fsync(directory_fd) != 0) fail_errno("fsync exchange parent");
    if (close(directory_fd) != 0) fail_errno("close exchange parent");
    return 0;
}
