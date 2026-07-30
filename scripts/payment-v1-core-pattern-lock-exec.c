#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static const char *NODE = "/usr/bin/node";
static const char *CEREMONY_SOURCE =
    "/usr/local/libexec/bitcoinpir/payment-v1-core-pattern-ceremony.mjs";

static const char *LOCKS[] = {
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/lib/apt/lists/lock",
    "/var/cache/apt/archives/lock",
};

static void fail_errno(const char *message) {
    fprintf(stderr, "core-pattern-lock-exec: %s: %s\n", message, strerror(errno));
    exit(1);
}

static void fail(const char *message) {
    fprintf(stderr, "core-pattern-lock-exec: %s\n", message);
    exit(2);
}

struct command_spec {
    const char *command;
    const char *const *options;
    size_t option_count;
};

static const char *const APPLY_OPTIONS[] = {
    "--approval",
    "--approved-approval-sha256",
    "--approved-plan-sha256",
    "--approved-source-sha256",
    "--plan",
};

static const char *const RECOVER_OPTIONS[] = {
    "--approved-plan-sha256",
    "--approved-recovery-approval-sha256",
    "--approved-source-sha256",
    "--plan",
    "--recovery-approval",
};

static const char *const ROLLBACK_OPTIONS[] = {
    "--approved-plan-sha256",
    "--approved-receipt-sha256",
    "--approved-rollback-approval-sha256",
    "--approved-source-sha256",
    "--plan",
    "--rollback-approval",
};

static const struct command_spec COMMANDS[] = {
    { "apply", APPLY_OPTIONS, sizeof(APPLY_OPTIONS) / sizeof(APPLY_OPTIONS[0]) },
    { "recover", RECOVER_OPTIONS, sizeof(RECOVER_OPTIONS) / sizeof(RECOVER_OPTIONS[0]) },
    { "rollback", ROLLBACK_OPTIONS, sizeof(ROLLBACK_OPTIONS) / sizeof(ROLLBACK_OPTIONS[0]) },
};

static int environment_name_equals(
    const char *entry,
    size_t name_length,
    const char *expected) {
    return strlen(expected) == name_length &&
        memcmp(entry, expected, name_length) == 0;
}

static int environment_name_has_prefix(
    const char *entry,
    size_t name_length,
    const char *prefix) {
    const size_t prefix_length = strlen(prefix);
    return name_length >= prefix_length &&
        memcmp(entry, prefix, prefix_length) == 0;
}

static void reject_injected_environment(void) {
    for (char **item = environ; item != NULL && *item != NULL; item++) {
        const char *equals = strchr(*item, '=');
        if (equals == NULL || equals == *item) {
            fail("malformed environment entry");
        }
        const size_t name_length = (size_t)(equals - *item);
        if (environment_name_has_prefix(*item, name_length, "LD_") ||
            environment_name_has_prefix(*item, name_length, "DYLD_") ||
            environment_name_has_prefix(*item, name_length, "NODE_") ||
            environment_name_equals(*item, name_length, "GLIBC_TUNABLES") ||
            environment_name_equals(
                *item,
                name_length,
                "BITCOINPIR_CORE_PATTERN_MAINTENANCE_LOCK_FDS")) {
            fail("prohibited loader, Node, or inherited-lock environment");
        }
    }
}

static const struct command_spec *find_command(const char *command) {
    for (size_t index = 0; index < sizeof(COMMANDS) / sizeof(COMMANDS[0]); index++) {
        if (strcmp(command, COMMANDS[index].command) == 0) return &COMMANDS[index];
    }
    return NULL;
}

static void validate_invocation(int argc, char **argv) {
    if (argc < 5 || strcmp(argv[1], "--") != 0 ||
        strcmp(argv[2], NODE) != 0 || strcmp(argv[3], CEREMONY_SOURCE) != 0) {
        fail("unreviewed execution request");
    }
    const struct command_spec *spec = find_command(argv[4]);
    if (spec == NULL || argc != 5 + (int)(2 * spec->option_count)) {
        fail("unreviewed ceremony subcommand argv");
    }
    unsigned int seen = 0;
    for (int argument = 5; argument < argc; argument += 2) {
        size_t option = 0;
        while (option < spec->option_count &&
               strcmp(argv[argument], spec->options[option]) != 0) {
            option++;
        }
        if (option == spec->option_count || (seen & (1U << option)) != 0 ||
            argv[argument + 1][0] == '\0') {
            fail("unreviewed ceremony subcommand argv");
        }
        seen |= 1U << option;
    }
    if (seen != (1U << spec->option_count) - 1U) {
        fail("unreviewed ceremony subcommand argv");
    }
}

int main(int argc, char **argv) {
    reject_injected_environment();
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("bitcoinpir-payment-v1-core-pattern-lock-exec 2");
        return 0;
    }
    validate_invocation(argc, argv);

    char inherited[128];
    size_t used = 0;
    for (size_t index = 0; index < sizeof(LOCKS) / sizeof(LOCKS[0]); index++) {
        int fd = open(LOCKS[index], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) fail_errno("open package maintenance lock");
        struct flock lock = {
            .l_type = F_WRLCK,
            .l_whence = SEEK_SET,
            .l_start = 0,
            .l_len = 0,
        };
        if (fcntl(fd, F_SETLK, &lock) != 0) {
            fail_errno("acquire package maintenance fcntl lock");
        }
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
            fail_errno("retain package maintenance lock across exec");
        }
        int count = snprintf(
            inherited + used,
            sizeof(inherited) - used,
            index == 0 ? "%d" : ",%d",
            fd);
        if (count < 1 || (size_t)count >= sizeof(inherited) - used) {
            fail("inherited descriptor list overflow");
        }
        used += (size_t)count;
    }
    char lock_environment[192];
    int environment_count = snprintf(
        lock_environment,
        sizeof(lock_environment),
        "BITCOINPIR_CORE_PATTERN_MAINTENANCE_LOCK_FDS=%s",
        inherited);
    if (environment_count < 1 || (size_t)environment_count >= sizeof(lock_environment)) {
        fail("inherited descriptor environment overflow");
    }
    char *environment[] = {
        lock_environment,
        "LANG=C",
        "LC_ALL=C",
        "PATH=/usr/sbin:/usr/bin",
        "TZ=UTC",
        NULL,
    };
    execve(NODE, &argv[2], environment);
    fail_errno("exec ceremony");
    return 1;
}
