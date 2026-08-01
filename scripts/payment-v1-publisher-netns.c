#define _GNU_SOURCE

/*
 * BitcoinPIR Payment V1 directory-publisher network namespace helper.
 *
 * This is intentionally a small, Linux-only, no-shell program.  It owns one
 * fixed namespace and one fixed veth pair.  Every mutation is preceded by an
 * append-only, fsync'd intent record.  Recovery removes an object only when
 * the recorded namespace inode or transaction-specific interface alias and
 * MAC still match.  Anything else is an unknown preimage and fails closed.
 *
 * The long-running process retains two read-only rtnetlink sockets (one in the
 * host namespace and one in the publisher namespace), drops all capabilities,
 * installs a seccomp allowlist, and monitors the closed topology.  systemd
 * runs the same pinned binary with `cleanup` in ExecStopPost; cleanup retains
 * CAP_SYS_ADMIN/CAP_NET_ADMIN and performs the exact-identity teardown.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/rtnetlink.h>
#include <linux/seccomp.h>
#include <linux/veth.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

#ifndef SYS_renameat2
#if defined(__x86_64__)
#define SYS_renameat2 316
#elif defined(__aarch64__)
#define SYS_renameat2 276
#else
#error "SYS_renameat2 is required on this Linux architecture"
#endif
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define MAX_RECORD 1024
#define MAX_NL 8192

#ifdef BPIR_PUBLISHER_NETNS_TEST_PROFILE
#define STATE_DIRECTORY "/tmp/bitcoinpir-publisher-netns-test-state"
#define FINAL_NAMESPACE_PATH "/run/netns/bpir-pub-test"
#define NAMESPACE_NAME "bpir-pub-test"
#define HOST_IFNAME "bpirtsth"
#define CLIENT_IFNAME "bpirtstc"
#define HOST_ADDRESS_TEXT "10.203.254.1"
#define CLIENT_ADDRESS_TEXT "10.203.254.2"
#else
#define STATE_DIRECTORY "/var/lib/bitcoinpir-publisher-netns"
#define FINAL_NAMESPACE_PATH "/run/netns/bpir-directory-publisher"
#define NAMESPACE_NAME "bpir-directory-publisher"
#define HOST_IFNAME "bpir-pub-h"
#define CLIENT_IFNAME "bpir-pub-c"
#define HOST_ADDRESS_TEXT "10.203.0.1"
#define CLIENT_ADDRESS_TEXT "10.203.0.2"
#endif

#define NETNS_DIRECTORY "/run/netns"
#define ACTIVE_RECORD "active.v1"
#define PENDING_RECORD "pending.v1"
#define JOURNAL_VERSION 1U
#define ADDRESS_PREFIX 30U
#define IF_ALIAS_PREFIX "bitcoinpir-payment-v1-publisher-netns:"
#define TX_NAMESPACE_PREFIX NETNS_DIRECTORY "/.bpir-pub-"

static volatile sig_atomic_t stop_requested;
struct topology;
static int write_all(int fd, const void *bytes, size_t length);
static int remove_owned_mount_target(const char *path,
                                     const struct topology *topology,
                                     uint64_t placeholder_dev,
                                     uint64_t placeholder_ino,
                                     bool may_be_missing);

#ifdef BPIR_PUBLISHER_NETNS_TEST_PROFILE
#define TEST_PAUSE_MARKER "/tmp/bitcoinpir-publisher-netns-test-pause"
static void test_pause_at(const char *stage)
{
    const char *wanted = getenv("BPIR_TEST_PAUSE_AT");
    if (wanted == NULL || strcmp(wanted, stage) != 0) return;
    int fd = open(TEST_PAUSE_MARKER,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || write_all(fd, stage, strlen(stage)) != 0 || fsync(fd) != 0 ||
        close(fd) != 0) _exit(121);
    for (;;) pause();
}
#else
static void test_pause_at(const char *stage)
{
    (void)stage;
}
#endif

struct topology {
    char txid[33];
    char boot_id[37];
    char tx_namespace_path[128];
    char final_placeholder_path[128];
    char host_temp_ifname[IFNAMSIZ];
    char client_temp_ifname[IFNAMSIZ];
    unsigned char host_mac[6];
    unsigned char client_mac[6];
    uint64_t tx_placeholder_dev;
    uint64_t tx_placeholder_ino;
    uint64_t final_placeholder_dev;
    uint64_t final_placeholder_ino;
    uint64_t namespace_dev;
    uint64_t namespace_ino;
    unsigned host_ifindex;
    unsigned client_ifindex;
};

struct nl_request {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
    unsigned char data[MAX_NL];
};

struct link_snapshot {
    bool found;
    unsigned ifindex;
    unsigned flags;
    char name[IFNAMSIZ];
    char alias[128];
    char kind[32];
    unsigned char mac[6];
    bool has_mac;
};

struct ipv6_monitor_fds {
    int all;
    int default_value;
    int loopback;
    int endpoint;
};

struct xtables_lock_guard {
    int directory_fd;
    int lock_fd;
    struct stat identity;
};

static void log_error(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    fputs("payment-v1-publisher-netns: ", stderr);
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static int fail_errno(const char *what)
{
    log_error("%s: %s", what, strerror(errno));
    return -1;
}

static void on_signal(int signo)
{
    (void)signo;
    stop_requested = 1;
}

static int write_all(int fd, const void *bytes, size_t length)
{
    const unsigned char *cursor = bytes;
    while (length != 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_exact_file_at(int directory_fd, const char *name, char *output,
                              size_t capacity)
{
    int fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != 0 || (st.st_mode & 0777) != 0600 || st.st_size < 0 ||
        (uint64_t)st.st_size >= capacity) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    size_t offset = 0;
    while (offset < (size_t)st.st_size) {
        ssize_t count = read(fd, output + offset, (size_t)st.st_size - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (count == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }
    struct stat after;
    if (fstat(fd, &after) != 0 || after.st_dev != st.st_dev ||
        after.st_ino != st.st_ino || after.st_size != st.st_size ||
        after.st_ctim.tv_sec != st.st_ctim.tv_sec ||
        after.st_ctim.tv_nsec != st.st_ctim.tv_nsec) {
        close(fd);
        errno = ESTALE;
        return -1;
    }
    close(fd);
    output[offset] = '\0';
    return 0;
}

static int durable_no_replace_at(int directory_fd, const char *name,
                                 const char *content)
{
    char pending[128];
    unsigned char random_bytes[8];
    if (getrandom(random_bytes, sizeof(random_bytes), 0) !=
        (ssize_t)sizeof(random_bytes)) return fail_errno("getrandom journal suffix");
    int n = snprintf(pending, sizeof(pending), ".pending-%ld-", (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(pending)) {
        errno = EOVERFLOW;
        return -1;
    }
    for (size_t i = 0; i < sizeof(random_bytes); ++i) {
        int wrote = snprintf(pending + n + (int)(i * 2),
                             sizeof(pending) - (size_t)n - i * 2,
                             "%02x", random_bytes[i]);
        if (wrote != 2) {
            errno = EOVERFLOW;
            return -1;
        }
    }
    int fd = openat(directory_fd, pending,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t length = strlen(content);
    int result = 0;
    if (write_all(fd, content, length) != 0 || fdatasync(fd) != 0) result = -1;
    if (close(fd) != 0 && result == 0) result = -1;
    if (result == 0 && syscall(SYS_renameat2, directory_fd, pending, directory_fd,
                               name, RENAME_NOREPLACE) != 0) {
        if (errno == EEXIST) {
            char existing[MAX_RECORD];
            if (read_exact_file_at(directory_fd, name, existing,
                                   sizeof(existing)) == 0 &&
                strcmp(existing, content) == 0) {
                result = 0;
            } else {
                errno = EEXIST;
                result = -1;
            }
        } else {
            result = -1;
        }
    }
    if (result == 0 && fsync(directory_fd) != 0) result = -1;
    (void)unlinkat(directory_fd, pending, 0);
    return result;
}

static bool valid_hex(const char *value, size_t length)
{
    if (strlen(value) != length) return false;
    for (size_t i = 0; i < length; ++i) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return false;
    }
    return true;
}

static bool valid_boot_id(const char *value)
{
    if (strlen(value) != 36) return false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static int format_pending(const struct topology *topology, char output[MAX_RECORD])
{
    int count = snprintf(output, MAX_RECORD,
        "version=1\ntxid=%s\nboot_id=%s\ntx_namespace_path=%s\n"
        "final_placeholder_path=%s\n",
        topology->txid, topology->boot_id, topology->tx_namespace_path,
        topology->final_placeholder_path);
    return count > 0 && count < MAX_RECORD ? 0 : -1;
}

static int parse_pending(const char *record, struct topology *topology)
{
    char trailing;
    unsigned version;
    int count = sscanf(record,
        "version=%u\ntxid=%32[a-f0-9]\nboot_id=%36[a-f0-9-]\n"
        "tx_namespace_path=%127s\nfinal_placeholder_path=%127s\n%c",
        &version, topology->txid, topology->boot_id,
        topology->tx_namespace_path, topology->final_placeholder_path,
        &trailing);
    if (count != 5 || version != JOURNAL_VERSION ||
        !valid_hex(topology->txid, 32) || !valid_boot_id(topology->boot_id) ||
        strncmp(topology->tx_namespace_path, TX_NAMESPACE_PREFIX,
                sizeof(TX_NAMESPACE_PREFIX) - 1) != 0 ||
        strcmp(topology->tx_namespace_path + sizeof(TX_NAMESPACE_PREFIX) - 1,
               topology->txid) != 0 ||
        strncmp(topology->final_placeholder_path,
                NETNS_DIRECTORY "/.bpir-final-",
                sizeof(NETNS_DIRECTORY "/.bpir-final-") - 1) != 0 ||
        strcmp(topology->final_placeholder_path +
                   sizeof(NETNS_DIRECTORY "/.bpir-final-") - 1,
               topology->txid) != 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int read_boot_id(char output[37])
{
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char buffer[38];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    close(fd);
    if (count != 37 || buffer[36] != '\n') {
        errno = EINVAL;
        return -1;
    }
    buffer[36] = '\0';
    if (!valid_boot_id(buffer)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(output, buffer, 37);
    return 0;
}

static void encode_mac(char output[18], const unsigned char mac[6])
{
    snprintf(output, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int decode_mac(const char *input, unsigned char mac[6])
{
    unsigned values[6];
    char tail;
    if (sscanf(input, "%2x:%2x:%2x:%2x:%2x:%2x%c", &values[0], &values[1],
               &values[2], &values[3], &values[4], &values[5], &tail) != 6) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < 6; ++i) mac[i] = (unsigned char)values[i];
    return 0;
}

static int random_txid(char output[33])
{
    unsigned char bytes[16];
    if (getrandom(bytes, sizeof(bytes), 0) != (ssize_t)sizeof(bytes)) return -1;
    for (size_t i = 0; i < sizeof(bytes); ++i)
        snprintf(output + i * 2, 3, "%02x", bytes[i]);
    output[32] = '\0';
    return 0;
}

static int random_mac(unsigned char output[6])
{
    if (getrandom(output, 6, 0) != 6) return -1;
    output[0] = (unsigned char)((output[0] & 0xfcU) | 0x02U);
    return 0;
}

static int ensure_secure_directory(const char *path, mode_t mode)
{
    bool created = false;
    if (mkdir(path, mode) == 0) {
        created = true;
    } else if (errno != EEXIST) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (created && fchmod(fd, mode) != 0) {
        close(fd);
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        st.st_gid != 0 || (st.st_mode & 0777) != mode) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

static int create_placeholder(const char *path, uint64_t *device, uint64_t *inode)
{
    int fd = open(path, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    struct stat st;
    int result = 0;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_gid != 0 || st.st_nlink != 1 || (st.st_mode & 0777) != 0600) {
        errno = EPERM;
        result = -1;
    } else {
        *device = (uint64_t)st.st_dev;
        *inode = (uint64_t)st.st_ino;
    }
    if (close(fd) != 0 && result == 0) result = -1;
    return result;
}

static int verify_placeholder(const char *path, uint64_t device, uint64_t inode)
{
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
        st.st_nlink != 1 || (st.st_mode & 0777) != 0600 ||
        (uint64_t)st.st_dev != device || (uint64_t)st.st_ino != inode) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int path_exists_nofollow(const char *path, bool *exists)
{
    struct stat st;
    if (lstat(path, &st) == 0) {
        *exists = true;
        return 0;
    }
    if (errno == ENOENT) {
        *exists = false;
        return 0;
    }
    return -1;
}

static int add_attr(struct nlmsghdr *nlh, size_t capacity, unsigned short type,
                    const void *data, size_t length)
{
    size_t aligned = NLMSG_ALIGN(nlh->nlmsg_len);
    size_t attribute_length = RTA_LENGTH(length);
    if (aligned + RTA_ALIGN(attribute_length) > capacity) {
        errno = EOVERFLOW;
        return -1;
    }
    struct rtattr *attr = (struct rtattr *)((unsigned char *)nlh + aligned);
    attr->rta_type = type;
    attr->rta_len = (unsigned short)attribute_length;
    if (length != 0) memcpy(RTA_DATA(attr), data, length);
    nlh->nlmsg_len = (unsigned)(aligned + RTA_ALIGN(attribute_length));
    return 0;
}

static struct rtattr *begin_nested(struct nlmsghdr *nlh, size_t capacity,
                                   unsigned short type)
{
    size_t offset = NLMSG_ALIGN(nlh->nlmsg_len);
    if (add_attr(nlh, capacity, type, NULL, 0) != 0) return NULL;
    return (struct rtattr *)((unsigned char *)nlh + offset);
}

static void end_nested(struct nlmsghdr *nlh, struct rtattr *nested)
{
    nested->rta_len = (unsigned short)((unsigned char *)nlh + nlh->nlmsg_len -
                                       (unsigned char *)nested);
}

static int nl_open(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl address = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int nl_ack(int fd, struct nlmsghdr *request)
{
    static uint32_t sequence = 1000;
    request->nlmsg_seq = ++sequence;
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = request, .iov_len = request->nlmsg_len };
    struct msghdr message = {
        .msg_name = &kernel,
        .msg_namelen = sizeof(kernel),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    if (sendmsg(fd, &message, 0) < 0) return -1;
    unsigned char buffer[MAX_NL];
    for (;;) {
        ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned)count); header = NLMSG_NEXT(header, count)) {
            if (header->nlmsg_seq != request->nlmsg_seq) continue;
            if (header->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *error = NLMSG_DATA(header);
                if (error->error == 0) return 0;
                errno = -error->error;
                return -1;
            }
        }
    }
}

static int add_string_attr(struct nlmsghdr *nlh, size_t capacity,
                           unsigned short type, const char *value)
{
    return add_attr(nlh, capacity, type, value, strlen(value) + 1);
}

static int create_veth(int fd, const struct topology *topology)
{
    struct nl_request request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.nlh.nlmsg_type = RTM_NEWLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    request.ifi.ifi_family = AF_UNSPEC;
    if (add_string_attr(&request.nlh, sizeof(request), IFLA_IFNAME,
                        topology->host_temp_ifname) != 0 ||
        add_attr(&request.nlh, sizeof(request), IFLA_ADDRESS, topology->host_mac, 6) != 0)
        return -1;
    struct rtattr *link_info = begin_nested(&request.nlh, sizeof(request), IFLA_LINKINFO);
    if (link_info == NULL ||
        add_string_attr(&request.nlh, sizeof(request), IFLA_INFO_KIND, "veth") != 0)
        return -1;
    struct rtattr *info_data = begin_nested(&request.nlh, sizeof(request), IFLA_INFO_DATA);
    if (info_data == NULL) return -1;
    struct rtattr *peer = begin_nested(&request.nlh, sizeof(request), VETH_INFO_PEER);
    if (peer == NULL) return -1;
    size_t aligned = NLMSG_ALIGN(request.nlh.nlmsg_len);
    if (aligned + sizeof(struct ifinfomsg) > sizeof(request)) {
        errno = EOVERFLOW;
        return -1;
    }
    struct ifinfomsg *peer_info = (struct ifinfomsg *)((unsigned char *)&request + aligned);
    memset(peer_info, 0, sizeof(*peer_info));
    peer_info->ifi_family = AF_UNSPEC;
    request.nlh.nlmsg_len = (unsigned)(aligned + sizeof(*peer_info));
    if (add_string_attr(&request.nlh, sizeof(request), IFLA_IFNAME,
                        topology->client_temp_ifname) != 0 ||
        add_attr(&request.nlh, sizeof(request), IFLA_ADDRESS, topology->client_mac, 6) != 0)
        return -1;
    end_nested(&request.nlh, peer);
    end_nested(&request.nlh, info_data);
    end_nested(&request.nlh, link_info);
    return nl_ack(fd, &request.nlh);
}

static int set_link_namespace(int fd, unsigned ifindex, int namespace_fd)
{
    struct nl_request request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.nlh.nlmsg_type = RTM_NEWLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.ifi.ifi_family = AF_UNSPEC;
    request.ifi.ifi_index = (int)ifindex;
    if (add_attr(&request.nlh, sizeof(request), IFLA_NET_NS_FD,
                 &namespace_fd, sizeof(namespace_fd)) != 0) return -1;
    return nl_ack(fd, &request.nlh);
}

static int set_link_up(int fd, unsigned ifindex)
{
    struct nl_request request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.nlh.nlmsg_type = RTM_NEWLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.ifi.ifi_family = AF_UNSPEC;
    request.ifi.ifi_index = (int)ifindex;
    request.ifi.ifi_flags = IFF_UP;
    request.ifi.ifi_change = IFF_UP;
    return nl_ack(fd, &request.nlh);
}

static int set_link_alias(int fd, unsigned ifindex, const char *alias)
{
    struct nl_request request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.nlh.nlmsg_type = RTM_NEWLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.ifi.ifi_family = AF_UNSPEC;
    request.ifi.ifi_index = (int)ifindex;
    if (add_string_attr(&request.nlh, sizeof(request), IFLA_IFALIAS, alias) != 0)
        return -1;
    return nl_ack(fd, &request.nlh);
}

static int set_link_name(int fd, unsigned ifindex, const char *name)
{
    struct nl_request request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.nlh.nlmsg_type = RTM_NEWLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.ifi.ifi_family = AF_UNSPEC;
    request.ifi.ifi_index = (int)ifindex;
    if (add_string_attr(&request.nlh, sizeof(request), IFLA_IFNAME, name) != 0)
        return -1;
    return nl_ack(fd, &request.nlh);
}

static int delete_link(int fd, unsigned ifindex)
{
    struct nl_request request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.nlh.nlmsg_type = RTM_DELLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.ifi.ifi_family = AF_UNSPEC;
    request.ifi.ifi_index = (int)ifindex;
    return nl_ack(fd, &request.nlh);
}

static int add_ipv4_address(int fd, unsigned ifindex, const char *address_text)
{
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
        unsigned char data[256];
    } request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    request.nlh.nlmsg_type = RTM_NEWADDR;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    request.ifa.ifa_family = AF_INET;
    request.ifa.ifa_prefixlen = ADDRESS_PREFIX;
    request.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
    request.ifa.ifa_index = ifindex;
    struct in_addr address;
    if (inet_pton(AF_INET, address_text, &address) != 1) {
        errno = EINVAL;
        return -1;
    }
    if (add_attr(&request.nlh, sizeof(request), IFA_LOCAL, &address, sizeof(address)) != 0 ||
        add_attr(&request.nlh, sizeof(request), IFA_ADDRESS, &address, sizeof(address)) != 0)
        return -1;
    return nl_ack(fd, &request.nlh);
}

static int send_dump_request(int fd, unsigned type, unsigned char family, uint32_t sequence)
{
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg gen;
    } request;
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    request.nlh.nlmsg_type = (unsigned short)type;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.nlh.nlmsg_seq = sequence;
    request.gen.rtgen_family = family;
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    return sendto(fd, &request, request.nlh.nlmsg_len, 0,
                  (struct sockaddr *)&kernel, sizeof(kernel)) < 0 ? -1 : 0;
}

static void parse_link(struct nlmsghdr *header, struct link_snapshot *snapshot)
{
    struct ifinfomsg *info = NLMSG_DATA(header);
    snapshot->found = true;
    snapshot->ifindex = (unsigned)info->ifi_index;
    snapshot->flags = info->ifi_flags;
    int length = IFLA_PAYLOAD(header);
    for (struct rtattr *attr = IFLA_RTA(info); RTA_OK(attr, length);
         attr = RTA_NEXT(attr, length)) {
        if (attr->rta_type == IFLA_IFNAME) {
            snprintf(snapshot->name, sizeof(snapshot->name), "%s", (char *)RTA_DATA(attr));
        } else if (attr->rta_type == IFLA_IFALIAS) {
            snprintf(snapshot->alias, sizeof(snapshot->alias), "%s", (char *)RTA_DATA(attr));
        } else if (attr->rta_type == IFLA_ADDRESS && RTA_PAYLOAD(attr) == 6) {
            memcpy(snapshot->mac, RTA_DATA(attr), 6);
            snapshot->has_mac = true;
        } else if ((attr->rta_type & NLA_TYPE_MASK) == IFLA_LINKINFO) {
            int nested_length = RTA_PAYLOAD(attr);
            for (struct rtattr *nested = RTA_DATA(attr);
                 RTA_OK(nested, nested_length);
                 nested = RTA_NEXT(nested, nested_length)) {
                if ((nested->rta_type & NLA_TYPE_MASK) == IFLA_INFO_KIND &&
                    RTA_PAYLOAD(nested) > 1 &&
                    memchr(RTA_DATA(nested), '\0', RTA_PAYLOAD(nested)) != NULL) {
                    snprintf(snapshot->kind, sizeof(snapshot->kind), "%s",
                             (char *)RTA_DATA(nested));
                }
            }
        }
    }
}

static int link_by_name(int fd, const char *wanted, struct link_snapshot *output)
{
    static uint32_t sequence = 5000;
    uint32_t current = ++sequence;
    if (send_dump_request(fd, RTM_GETLINK, AF_UNSPEC, current) != 0) return -1;
    memset(output, 0, sizeof(*output));
    unsigned char buffer[MAX_NL];
    for (;;) {
        ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned)count); header = NLMSG_NEXT(header, count)) {
            if (header->nlmsg_seq != current) continue;
            if (header->nlmsg_type == NLMSG_DONE) return 0;
            if (header->nlmsg_type == NLMSG_ERROR) {
                errno = EPROTO;
                return -1;
            }
            if (header->nlmsg_type != RTM_NEWLINK) continue;
            struct link_snapshot candidate = {0};
            parse_link(header, &candidate);
            if (strcmp(candidate.name, wanted) == 0) *output = candidate;
        }
    }
}

static int count_links(int fd, unsigned *count, bool *only_expected)
{
    static uint32_t sequence = 7000;
    uint32_t current = ++sequence;
    if (send_dump_request(fd, RTM_GETLINK, AF_UNSPEC, current) != 0) return -1;
    *count = 0;
    *only_expected = true;
    unsigned char buffer[MAX_NL];
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned)received); header = NLMSG_NEXT(header, received)) {
            if (header->nlmsg_seq != current) continue;
            if (header->nlmsg_type == NLMSG_DONE) return 0;
            if (header->nlmsg_type != RTM_NEWLINK) continue;
            struct link_snapshot link = {0};
            parse_link(header, &link);
            ++*count;
            if (strcmp(link.name, "lo") != 0 && strcmp(link.name, CLIENT_IFNAME) != 0) {
                static const struct {
                    const char *name;
                    const char *kind;
                } inert_kernel_links[] = {
                    { "erspan0", "erspan" }, { "gre0", "gre" },
                    { "gretap0", "gretap" }, { "ip6_vti0", "vti6" },
                    { "ip6gre0", "ip6gre" }, { "ip6tnl0", "ip6tnl" },
                    { "ip_vti0", "vti" }, { "sit0", "sit" },
                    { "tunl0", "ipip" },
                };
                bool known_inert = false;
                for (size_t i = 0; i < ARRAY_LEN(inert_kernel_links); ++i) {
                    if (strcmp(link.name, inert_kernel_links[i].name) == 0 &&
                        strcmp(link.kind, inert_kernel_links[i].kind) == 0) {
                        known_inert = true;
                        break;
                    }
                }
                if (!known_inert || (link.flags & IFF_UP) != 0 || link.alias[0] != '\0')
                    *only_expected = false;
            }
        }
    }
}

static int exact_ipv4_address(int fd, unsigned ifindex, const char *wanted,
                              bool *result)
{
    static uint32_t sequence = 9000;
    uint32_t current = ++sequence;
    if (send_dump_request(fd, RTM_GETADDR, AF_UNSPEC, current) != 0) return -1;
    struct in_addr expected;
    if (inet_pton(AF_INET, wanted, &expected) != 1) return -1;
    unsigned matching = 0;
    unsigned other = 0;
    unsigned char buffer[MAX_NL];
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned)received); header = NLMSG_NEXT(header, received)) {
            if (header->nlmsg_seq != current) continue;
            if (header->nlmsg_type == NLMSG_DONE) {
                *result = matching == 1 && other == 0;
                return 0;
            }
            if (header->nlmsg_type != RTM_NEWADDR) continue;
            struct ifaddrmsg *address = NLMSG_DATA(header);
            if (address->ifa_index != ifindex) continue;
            if (address->ifa_family != AF_INET || address->ifa_prefixlen != ADDRESS_PREFIX) {
                ++other;
                continue;
            }
            bool found = false;
            int length = IFA_PAYLOAD(header);
            for (struct rtattr *attr = IFA_RTA(address); RTA_OK(attr, length);
                 attr = RTA_NEXT(attr, length)) {
                if (attr->rta_type == IFA_LOCAL && RTA_PAYLOAD(attr) == 4 &&
                    memcmp(RTA_DATA(attr), &expected, 4) == 0) found = true;
            }
            if (found) ++matching; else ++other;
        }
    }
}

static int namespace_addresses_closed(int fd, unsigned loopback_ifindex,
                                      unsigned client_ifindex, bool *result)
{
    static uint32_t sequence = 10000;
    uint32_t current = ++sequence;
    if (send_dump_request(fd, RTM_GETADDR, AF_UNSPEC, current) != 0) return -1;
    unsigned loopback_v4 = 0;
    *result = true;
    unsigned char buffer[MAX_NL];
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned)received); header = NLMSG_NEXT(header, received)) {
            if (header->nlmsg_seq != current) continue;
            if (header->nlmsg_type == NLMSG_DONE) {
                if (loopback_v4 != 1) *result = false;
                return 0;
            }
            if (header->nlmsg_type != RTM_NEWADDR) continue;
            struct ifaddrmsg *address = NLMSG_DATA(header);
            if (address->ifa_index == client_ifindex) continue;
            if (address->ifa_index != loopback_ifindex ||
                address->ifa_family != AF_INET || address->ifa_prefixlen != 8) {
                *result = false;
                continue;
            }
            struct in_addr expected;
            (void)inet_pton(AF_INET, "127.0.0.1", &expected);
            bool matched = false;
            int length = IFA_PAYLOAD(header);
            for (struct rtattr *attr = IFA_RTA(address); RTA_OK(attr, length);
                 attr = RTA_NEXT(attr, length)) {
                if (attr->rta_type == IFA_LOCAL && RTA_PAYLOAD(attr) == 4 &&
                    memcmp(RTA_DATA(attr), &expected, 4) == 0) matched = true;
            }
            if (matched) ++loopback_v4; else *result = false;
        }
    }
}

static int has_default_route(int fd, bool *result)
{
    static uint32_t sequence = 11000;
    uint32_t current = ++sequence;
    if (send_dump_request(fd, RTM_GETROUTE, AF_UNSPEC, current) != 0) return -1;
    *result = false;
    unsigned char buffer[MAX_NL];
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, (unsigned)received); header = NLMSG_NEXT(header, received)) {
            if (header->nlmsg_seq != current) continue;
            if (header->nlmsg_type == NLMSG_DONE) return 0;
            if (header->nlmsg_type != RTM_NEWROUTE) continue;
            struct rtmsg *route = NLMSG_DATA(header);
            if ((route->rtm_family == AF_INET || route->rtm_family == AF_INET6) &&
                route->rtm_dst_len == 0 && route->rtm_table == RT_TABLE_MAIN &&
                route->rtm_type == RTN_UNICAST) *result = true;
        }
    }
}

static int write_sysctl_one(const char *path)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    int result = write_all(fd, "1\n", 2);
    if (close(fd) != 0 && result == 0) result = -1;
    return result;
}

static int read_sysctl_one(const char *path, bool *result)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char bytes[4] = {0};
    ssize_t count = read(fd, bytes, sizeof(bytes));
    close(fd);
    if (count < 1) return -1;
    *result = bytes[0] == '1';
    return 0;
}

static int open_ipv6_monitor_fds(const char *endpoint,
                                 struct ipv6_monitor_fds *fds)
{
    char endpoint_path[192];
    snprintf(endpoint_path, sizeof(endpoint_path),
             "/proc/sys/net/ipv6/conf/%s/disable_ipv6", endpoint);
    fds->all = open("/proc/sys/net/ipv6/conf/all/disable_ipv6",
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    fds->default_value = open("/proc/sys/net/ipv6/conf/default/disable_ipv6",
                              O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    fds->loopback = open("/proc/sys/net/ipv6/conf/lo/disable_ipv6",
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    fds->endpoint = open(endpoint_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fds->all < 0 || fds->default_value < 0 || fds->loopback < 0 ||
        fds->endpoint < 0) return -1;
    return 0;
}

static void close_ipv6_monitor_fds(struct ipv6_monitor_fds *fds)
{
    if (fds->all >= 0) close(fds->all);
    if (fds->default_value >= 0) close(fds->default_value);
    if (fds->loopback >= 0) close(fds->loopback);
    if (fds->endpoint >= 0) close(fds->endpoint);
}

static int monitor_fd_is_one(int fd)
{
    char bytes[2];
    ssize_t count = pread(fd, bytes, sizeof(bytes), 0);
    return count >= 1 && bytes[0] == '1' ? 0 : -1;
}

static int ipv6_monitor_fds_are_disabled(const struct ipv6_monitor_fds *fds)
{
    return monitor_fd_is_one(fds->all) == 0 &&
           monitor_fd_is_one(fds->default_value) == 0 &&
           monitor_fd_is_one(fds->loopback) == 0 &&
           monitor_fd_is_one(fds->endpoint) == 0 ? 0 : -1;
}

static int open_nftables_generation_monitor(void)
{
    if (NFNLGRP_NFTABLES < 1 || NFNLGRP_NFTABLES > 32) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    int fd = socket(AF_NETLINK,
                    SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    NETLINK_NETFILTER);
    if (fd < 0) return -1;
    int receive_buffer = 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                   &receive_buffer, sizeof(receive_buffer)) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_nl address;
    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = 1U << ((unsigned)NFNLGRP_NFTABLES - 1U);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_nl observed;
    memset(&observed, 0, sizeof(observed));
    socklen_t observed_length = sizeof(observed);
    if (getsockname(fd, (struct sockaddr *)&observed, &observed_length) != 0 ||
        observed_length != sizeof(observed) || observed.nl_family != AF_NETLINK ||
        observed.nl_pid == 0 ||
        (observed.nl_groups & address.nl_groups) != address.nl_groups) {
        close(fd);
        errno = ESTALE;
        return -1;
    }
    return fd;
}

static int nftables_generation_is_quiet(int fd)
{
    unsigned char bytes[65536];
    for (;;) {
        struct sockaddr_nl sender;
        memset(&sender, 0, sizeof(sender));
        socklen_t sender_length = sizeof(sender);
        ssize_t count = recvfrom(fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC,
                                 (struct sockaddr *)&sender, &sender_length);
        if (count < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (count == 0 || (size_t)count > sizeof(bytes) ||
            sender_length != sizeof(sender) || sender.nl_family != AF_NETLINK ||
            sender.nl_pid != 0) {
            errno = ESTALE;
            return -1;
        }
        int remaining = (int)count;
        bool saw_generation_event = false;
        for (struct nlmsghdr *header = (struct nlmsghdr *)bytes;
             NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type == NLMSG_NOOP) continue;
            if (header->nlmsg_type == NLMSG_ERROR ||
                NFNL_SUBSYS_ID(header->nlmsg_type) != NFNL_SUBSYS_NFTABLES) {
                errno = ESTALE;
                return -1;
            }
            saw_generation_event = true;
        }
        if (remaining != 0 || !saw_generation_event) {
            errno = ESTALE;
            return -1;
        }
        errno = ESTALE;
        return -1;
    }
}

static int open_xtables_lock_guard(struct xtables_lock_guard *guard)
{
    memset(guard, 0, sizeof(*guard));
    guard->directory_fd = -1;
    guard->lock_fd = -1;
    guard->directory_fd = open("/run",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (guard->directory_fd < 0) return -1;
    struct stat directory;
    if (fstat(guard->directory_fd, &directory) != 0 ||
        !S_ISDIR(directory.st_mode) || directory.st_uid != 0 ||
        directory.st_gid != 0 || (directory.st_mode & 0777) != 0755) {
        errno = EPERM;
        return -1;
    }
    guard->lock_fd = openat(guard->directory_fd, "xtables.lock",
                            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (guard->lock_fd < 0) return -1;
    if (fstat(guard->lock_fd, &guard->identity) != 0) return -1;
    if (!S_ISREG(guard->identity.st_mode) || guard->identity.st_uid != 0 ||
        guard->identity.st_gid != 0 || guard->identity.st_nlink != 1 ||
        (guard->identity.st_mode & 0777) != 0600 || guard->identity.st_size != 0) {
        errno = EPERM;
        return -1;
    }
    if (flock(guard->lock_fd, LOCK_EX | LOCK_NB) != 0) return -1;
    return 0;
}

static int xtables_lock_guard_is_held(const struct xtables_lock_guard *guard)
{
    struct stat observed;
    if (fstatat(guard->directory_fd, "xtables.lock", &observed,
                AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(observed.st_mode) ||
        observed.st_dev != guard->identity.st_dev ||
        observed.st_ino != guard->identity.st_ino ||
        observed.st_uid != guard->identity.st_uid ||
        observed.st_gid != guard->identity.st_gid ||
        observed.st_mode != guard->identity.st_mode ||
        observed.st_nlink != guard->identity.st_nlink ||
        observed.st_size != guard->identity.st_size) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static void close_xtables_lock_guard(struct xtables_lock_guard *guard)
{
    if (guard->lock_fd >= 0) close(guard->lock_fd);
    if (guard->directory_fd >= 0) close(guard->directory_fd);
    guard->lock_fd = -1;
    guard->directory_fd = -1;
}

static int namespace_identity(const char *path, uint64_t *device, uint64_t *inode)
{
    struct stat st;
    struct statfs filesystem;
    if (lstat(path, &st) != 0 || statfs(path, &filesystem) != 0) return -1;
    if (!S_ISREG(st.st_mode) || (unsigned long)filesystem.f_type != NSFS_MAGIC) {
        errno = ESTALE;
        return -1;
    }
    *device = (uint64_t)st.st_dev;
    *inode = (uint64_t)st.st_ino;
    return 0;
}

static int proc_namespace_identity(const char *path, uint64_t *device, uint64_t *inode)
{
    struct stat st;
    struct statfs filesystem;
    if (stat(path, &st) != 0 || statfs(path, &filesystem) != 0) return -1;
    if (!S_ISREG(st.st_mode) || (unsigned long)filesystem.f_type != NSFS_MAGIC) {
        errno = ESTALE;
        return -1;
    }
    *device = (uint64_t)st.st_dev;
    *inode = (uint64_t)st.st_ino;
    return 0;
}

static int parse_prepared(const char *record, struct topology *topology)
{
    char host_mac[18];
    char client_mac[18];
    char trailing;
    unsigned version;
    unsigned long long tx_placeholder_dev;
    unsigned long long tx_placeholder_ino;
    unsigned long long final_placeholder_dev;
    unsigned long long final_placeholder_ino;
    int count = sscanf(record,
        "version=%u\ntxid=%32[a-f0-9]\nboot_id=%36[a-f0-9-]\n"
        "namespace=" NAMESPACE_NAME "\ntx_namespace_path=%127s\n"
        "final_placeholder_path=%127s\n"
        "tx_placeholder_dev=%llu\ntx_placeholder_ino=%llu\n"
        "final_placeholder_dev=%llu\nfinal_placeholder_ino=%llu\n"
        "host_temp_ifname=%15s\nclient_temp_ifname=%15s\n"
        "host_ifname=" HOST_IFNAME "\nclient_ifname=" CLIENT_IFNAME "\n"
        "host_address=" HOST_ADDRESS_TEXT "/30\nclient_address=" CLIENT_ADDRESS_TEXT "/30\n"
        "host_mac=%17s\nclient_mac=%17s\n%c",
        &version, topology->txid, topology->boot_id, topology->tx_namespace_path,
        topology->final_placeholder_path, &tx_placeholder_dev,
        &tx_placeholder_ino, &final_placeholder_dev, &final_placeholder_ino,
        topology->host_temp_ifname, topology->client_temp_ifname,
        host_mac, client_mac, &trailing);
    if (count != 13 || version != JOURNAL_VERSION || !valid_hex(topology->txid, 32) ||
        !valid_boot_id(topology->boot_id) ||
        strncmp(topology->tx_namespace_path, TX_NAMESPACE_PREFIX,
                sizeof(TX_NAMESPACE_PREFIX) - 1) != 0 ||
        strcmp(topology->tx_namespace_path + sizeof(TX_NAMESPACE_PREFIX) - 1,
               topology->txid) != 0 ||
        strncmp(topology->final_placeholder_path,
                NETNS_DIRECTORY "/.bpir-final-",
                sizeof(NETNS_DIRECTORY "/.bpir-final-") - 1) != 0 ||
        strcmp(topology->final_placeholder_path +
                   sizeof(NETNS_DIRECTORY "/.bpir-final-") - 1,
               topology->txid) != 0 ||
        tx_placeholder_dev == 0 || tx_placeholder_ino == 0 ||
        final_placeholder_dev == 0 || final_placeholder_ino == 0 ||
        strncmp(topology->host_temp_ifname, "bph", 3) != 0 ||
        strncmp(topology->host_temp_ifname + 3, topology->txid, 12) != 0 ||
        topology->host_temp_ifname[15] != '\0' ||
        strncmp(topology->client_temp_ifname, "bpc", 3) != 0 ||
        strncmp(topology->client_temp_ifname + 3, topology->txid, 12) != 0 ||
        topology->client_temp_ifname[15] != '\0' ||
        decode_mac(host_mac, topology->host_mac) != 0 ||
        decode_mac(client_mac, topology->client_mac) != 0) {
        errno = EINVAL;
        return -1;
    }
    topology->tx_placeholder_dev = (uint64_t)tx_placeholder_dev;
    topology->tx_placeholder_ino = (uint64_t)tx_placeholder_ino;
    topology->final_placeholder_dev = (uint64_t)final_placeholder_dev;
    topology->final_placeholder_ino = (uint64_t)final_placeholder_ino;
    return 0;
}

static int format_prepared(const struct topology *topology, char output[MAX_RECORD])
{
    char host_mac[18];
    char client_mac[18];
    encode_mac(host_mac, topology->host_mac);
    encode_mac(client_mac, topology->client_mac);
    int count = snprintf(output, MAX_RECORD,
        "version=1\ntxid=%s\nboot_id=%s\nnamespace=%s\ntx_namespace_path=%s\n"
        "final_placeholder_path=%s\ntx_placeholder_dev=%llu\n"
        "tx_placeholder_ino=%llu\nfinal_placeholder_dev=%llu\n"
        "final_placeholder_ino=%llu\n"
        "host_temp_ifname=%s\nclient_temp_ifname=%s\n"
        "host_ifname=%s\nclient_ifname=%s\nhost_address=%s/30\n"
        "client_address=%s/30\nhost_mac=%s\nclient_mac=%s\n",
        topology->txid, topology->boot_id, NAMESPACE_NAME,
        topology->tx_namespace_path, topology->final_placeholder_path,
        (unsigned long long)topology->tx_placeholder_dev,
        (unsigned long long)topology->tx_placeholder_ino,
        (unsigned long long)topology->final_placeholder_dev,
        (unsigned long long)topology->final_placeholder_ino,
        topology->host_temp_ifname, topology->client_temp_ifname,
        HOST_IFNAME, CLIENT_IFNAME,
        HOST_ADDRESS_TEXT, CLIENT_ADDRESS_TEXT, host_mac, client_mac);
    return count > 0 && count < MAX_RECORD ? 0 : -1;
}

static int parse_namespace_record(const char *record, struct topology *topology)
{
    char trailing;
    unsigned long long device;
    unsigned long long inode;
    int count = sscanf(record, "namespace_dev=%llu\nnamespace_ino=%llu\n%c",
                       &device, &inode, &trailing);
    if (count != 2 || device == 0 || inode == 0) {
        errno = EINVAL;
        return -1;
    }
    topology->namespace_dev = (uint64_t)device;
    topology->namespace_ino = (uint64_t)inode;
    return 0;
}

static int parse_veth_record(const char *record, struct topology *topology)
{
    char trailing;
    int count = sscanf(record, "host_ifindex=%u\nclient_ifindex=%u\n%c",
                       &topology->host_ifindex, &topology->client_ifindex, &trailing);
    if (count != 2 || topology->host_ifindex == 0 || topology->client_ifindex == 0 ||
        topology->host_ifindex == topology->client_ifindex) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int open_transaction(int state_fd, const char *txid)
{
    int tx_fd = openat(state_fd, txid, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (tx_fd < 0) return -1;
    struct stat st;
    if (fstat(tx_fd, &st) != 0 || st.st_uid != 0 || st.st_gid != 0 ||
        (st.st_mode & 0777) != 0700) {
        close(tx_fd);
        errno = EPERM;
        return -1;
    }
    return tx_fd;
}

static int remove_pending_record(int state_fd, const char *txid,
                                 bool may_be_missing)
{
    char record[MAX_RECORD];
    if (read_exact_file_at(state_fd, PENDING_RECORD, record, sizeof(record)) != 0) {
        if (may_be_missing && errno == ENOENT) return 0;
        return -1;
    }
    struct topology pending;
    memset(&pending, 0, sizeof(pending));
    if (parse_pending(record, &pending) != 0 || strcmp(pending.txid, txid) != 0) {
        errno = ESTALE;
        return -1;
    }
    if (unlinkat(state_fd, PENDING_RECORD, 0) != 0 || fsync(state_fd) != 0)
        return -1;
    return 0;
}

static int remove_unrecorded_placeholder(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
        st.st_nlink != 1 || (st.st_mode & 0777) != 0600 || st.st_size != 0) {
        errno = ESTALE;
        return -1;
    }
    return unlink(path);
}

static int cleanup_pending_before_active(int state_fd)
{
    char pending_record[MAX_RECORD];
    if (read_exact_file_at(state_fd, PENDING_RECORD, pending_record,
                           sizeof(pending_record)) != 0)
        return errno == ENOENT ? 0 : -1;
    struct topology pending;
    memset(&pending, 0, sizeof(pending));
    if (parse_pending(pending_record, &pending) != 0) return -1;
    int tx_fd = open_transaction(state_fd, pending.txid);
    if (tx_fd < 0) {
        if (errno != ENOENT ||
            remove_unrecorded_placeholder(pending.tx_namespace_path) != 0 ||
            remove_unrecorded_placeholder(pending.final_placeholder_path) != 0)
            return -1;
        return remove_pending_record(state_fd, pending.txid, false);
    }
    char intent[MAX_RECORD];
    bool intent_present =
        read_exact_file_at(tx_fd, "00-placeholder-intent", intent,
                           sizeof(intent)) == 0;
    if (!intent_present && errno != ENOENT) {
        close(tx_fd);
        return -1;
    }
    if (intent_present && strcmp(intent, pending_record) != 0) {
        close(tx_fd);
        errno = ESTALE;
        return -1;
    }
    char prepared[MAX_RECORD];
    struct topology recorded;
    memset(&recorded, 0, sizeof(recorded));
    bool prepared_present =
        read_exact_file_at(tx_fd, "00-prepared", prepared, sizeof(prepared)) == 0;
    if (!prepared_present && errno != ENOENT) {
        close(tx_fd);
        return -1;
    }
    if (prepared_present) {
        if (parse_prepared(prepared, &recorded) != 0 ||
            strcmp(recorded.txid, pending.txid) != 0 ||
            strcmp(recorded.boot_id, pending.boot_id) != 0 ||
            strcmp(recorded.tx_namespace_path, pending.tx_namespace_path) != 0 ||
            strcmp(recorded.final_placeholder_path,
                   pending.final_placeholder_path) != 0 ||
            (remove_owned_mount_target(recorded.tx_namespace_path, &recorded,
                                       recorded.tx_placeholder_dev,
                                       recorded.tx_placeholder_ino, true) != 0) ||
            (remove_owned_mount_target(recorded.final_placeholder_path, &recorded,
                                       recorded.final_placeholder_dev,
                                       recorded.final_placeholder_ino, true) != 0)) {
            close(tx_fd);
            return -1;
        }
    } else if (intent_present) {
        if (remove_unrecorded_placeholder(pending.tx_namespace_path) != 0 ||
            remove_unrecorded_placeholder(pending.final_placeholder_path) != 0) {
            close(tx_fd);
            return -1;
        }
    } else {
        bool tx_exists = false;
        bool final_exists = false;
        if (path_exists_nofollow(pending.tx_namespace_path, &tx_exists) != 0 ||
            path_exists_nofollow(pending.final_placeholder_path,
                                 &final_exists) != 0 ||
            tx_exists || final_exists) {
            close(tx_fd);
            errno = ESTALE;
            return -1;
        }
    }
    int result = durable_no_replace_at(tx_fd, "90-clean-preactive",
                                       "clean_preactive=1\n");
    if (result == 0) result = remove_pending_record(state_fd, pending.txid, false);
    close(tx_fd);
    return result;
}

static int load_active(int state_fd, struct topology *topology, int *tx_fd_out)
{
    char active[64];
    if (read_exact_file_at(state_fd, ACTIVE_RECORD, active, sizeof(active)) != 0) return -1;
    size_t length = strlen(active);
    if (length != 33 || active[32] != '\n') {
        errno = EINVAL;
        return -1;
    }
    active[32] = '\0';
    if (!valid_hex(active, 32)) {
        errno = EINVAL;
        return -1;
    }
    int tx_fd = open_transaction(state_fd, active);
    if (tx_fd < 0) return -1;
    char prepared[MAX_RECORD];
    if (read_exact_file_at(tx_fd, "00-prepared", prepared, sizeof(prepared)) != 0 ||
        parse_prepared(prepared, topology) != 0 || strcmp(active, topology->txid) != 0) {
        close(tx_fd);
        return -1;
    }
    char record[MAX_RECORD];
    if (read_exact_file_at(tx_fd, "10-namespace", record, sizeof(record)) == 0) {
        if (parse_namespace_record(record, topology) != 0) {
            close(tx_fd);
            return -1;
        }
    } else if (errno != ENOENT) {
        close(tx_fd);
        return -1;
    } else if (read_exact_file_at(tx_fd, "05-namespace-intent", record,
                                  sizeof(record)) == 0) {
        if (parse_namespace_record(record, topology) != 0) {
            close(tx_fd);
            return -1;
        }
    } else if (errno != ENOENT) {
        close(tx_fd);
        return -1;
    }
    if (read_exact_file_at(tx_fd, "50-veth", record, sizeof(record)) == 0) {
        if (parse_veth_record(record, topology) != 0) {
            close(tx_fd);
            return -1;
        }
    } else if (errno != ENOENT) {
        close(tx_fd);
        return -1;
    }
    *tx_fd_out = tx_fd;
    return 0;
}

static int exact_phase_record(int tx_fd, const char *name, const char *expected,
                              bool *present)
{
    char record[MAX_RECORD];
    if (read_exact_file_at(tx_fd, name, record, sizeof(record)) == 0) {
        if (strcmp(record, expected) != 0) {
            errno = ESTALE;
            return -1;
        }
        *present = true;
        return 0;
    }
    if (errno != ENOENT) return -1;
    *present = false;
    return 0;
}

static int exact_link(const struct link_snapshot *link, const struct topology *topology,
                      bool host, bool require_index, unsigned alias_state)
{
    char alias[128];
    snprintf(alias, sizeof(alias), IF_ALIAS_PREFIX "%s:%s", topology->txid,
             host ? "host" : "client");
    const unsigned char *mac = host ? topology->host_mac : topology->client_mac;
    unsigned index = host ? topology->host_ifindex : topology->client_ifindex;
    bool alias_matches = alias_state == 1 ? strcmp(link->alias, alias) == 0
                         : alias_state == 2 ? (link->alias[0] == '\0' ||
                                               strcmp(link->alias, alias) == 0)
                                            : link->alias[0] == '\0';
    if (!link->found || !link->has_mac || strcmp(link->kind, "veth") != 0 ||
        !alias_matches ||
        memcmp(link->mac, mac, 6) != 0 || (require_index && link->ifindex != index)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int enter_namespace(int namespace_fd, int *original_fd)
{
    *original_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (*original_fd < 0) return -1;
    if (setns(namespace_fd, CLONE_NEWNET) != 0) {
        close(*original_fd);
        *original_fd = -1;
        return -1;
    }
    return 0;
}

static int leave_namespace(int original_fd)
{
    int result = setns(original_fd, CLONE_NEWNET);
    close(original_fd);
    return result;
}

static int snapshot_link_in_namespace(int namespace_fd, const char *name,
                                      struct link_snapshot *snapshot)
{
    int original = -1;
    if (enter_namespace(namespace_fd, &original) != 0) return -1;
    int fd = nl_open();
    int result = fd >= 0 ? link_by_name(fd, name, snapshot) : -1;
    int saved = errno;
    if (fd >= 0) close(fd);
    if (leave_namespace(original) != 0) result = -1;
    errno = saved;
    return result;
}

static int verify_namespace_mount(const char *path, const struct topology *topology)
{
    uint64_t device;
    uint64_t inode;
    if (namespace_identity(path, &device, &inode) != 0) return -1;
    if (device != topology->namespace_dev || inode != topology->namespace_ino) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int verify_host_topology(int host_nl, const struct topology *topology,
                                bool require_ready)
{
    struct link_snapshot host;
    if (verify_namespace_mount(FINAL_NAMESPACE_PATH, topology) != 0) {
        log_error("verification failed at final namespace identity");
        return -1;
    }
    if (verify_namespace_mount(topology->tx_namespace_path, topology) != 0) {
        log_error("verification failed at transaction namespace identity");
        return -1;
    }
    if (link_by_name(host_nl, HOST_IFNAME, &host) != 0) {
        log_error("verification failed while reading host veth link");
        return -1;
    }
    if (exact_link(&host, topology, true, require_ready, 1) != 0) {
        char got_mac[18] = "missing";
        char expected_mac[18];
        if (host.has_mac) encode_mac(got_mac, host.mac);
        encode_mac(expected_mac, topology->host_mac);
        log_error("verification failed at host veth identity "
                  "(found=%u index=%u expected_index=%u alias=%s mac=%s expected_mac=%s)",
                  host.found, host.ifindex, topology->host_ifindex, host.alias,
                  got_mac, expected_mac);
        return -1;
    }
    if (require_ready) {
        bool host_address = false;
        if ((host.flags & IFF_UP) == 0) {
            log_error("verification failed because the host veth endpoint is down");
            errno = ESTALE;
            return -1;
        }
        if (exact_ipv4_address(host_nl, host.ifindex, HOST_ADDRESS_TEXT,
                               &host_address) != 0 || !host_address) {
            log_error("verification failed at host IPv4 address");
            errno = ESTALE;
            return -1;
        }
    }
    return 0;
}

static int verify_client_topology(int client_nl, const struct topology *topology,
                                  bool require_ready)
{
    struct link_snapshot client;
    if (link_by_name(client_nl, CLIENT_IFNAME, &client) != 0) {
        log_error("verification failed while reading client veth link");
        return -1;
    }
    if (exact_link(&client, topology, false, require_ready, 1) != 0) {
        log_error("verification failed at client veth identity");
        return -1;
    }
    if (require_ready) {
        bool client_address = false;
        bool default_route = false;
        bool addresses_closed = false;
        unsigned link_count = 0;
        bool only_expected = false;
        struct link_snapshot loopback;
        if ((client.flags & IFF_UP) == 0) {
            log_error("verification failed because the client veth endpoint is down");
            errno = ESTALE;
            return -1;
        }
        if (exact_ipv4_address(client_nl, client.ifindex, CLIENT_ADDRESS_TEXT,
                               &client_address) != 0 || !client_address) {
            log_error("verification failed at client IPv4 address");
            errno = ESTALE;
            return -1;
        }
        if (has_default_route(client_nl, &default_route) != 0 || default_route) {
            log_error("verification failed at client default-route exclusion");
            errno = ESTALE;
            return -1;
        }
        if (count_links(client_nl, &link_count, &only_expected) != 0 ||
            link_count < 2 || link_count > 11 || !only_expected) {
            log_error("verification failed at client closed interface set "
                      "(count=%u only_expected=%u)", link_count, only_expected);
            errno = ESTALE;
            return -1;
        }
        if (link_by_name(client_nl, "lo", &loopback) != 0 || !loopback.found ||
            (loopback.flags & IFF_UP) == 0 ||
            namespace_addresses_closed(client_nl, loopback.ifindex,
                                       client.ifindex, &addresses_closed) != 0 ||
            !addresses_closed) {
            log_error("verification failed at client closed address set");
            errno = ESTALE;
            return -1;
        }
    }
    return 0;
}

static int create_namespace_mount(struct topology *topology, int tx_fd)
{
    int ready_pipe[2];
    int release_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC) != 0 || pipe2(release_pipe, O_CLOEXEC) != 0)
        return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        close(ready_pipe[0]);
        close(release_pipe[1]);
        char byte = '0';
        if (unshare(CLONE_NEWNET) == 0) byte = '1';
        if (write(ready_pipe[1], &byte, 1) != 1) _exit(1);
        if (byte == '1') {
            char release = 0;
            if (read(release_pipe[0], &release, 1) != 1) _exit(1);
        }
        _exit(byte == '1' ? 0 : 1);
    }
    close(ready_pipe[1]);
    close(release_pipe[0]);
    char byte = '0';
    int result = 0;
    if (read(ready_pipe[0], &byte, 1) != 1 || byte != '1') result = -1;
    char source[64];
    snprintf(source, sizeof(source), "/proc/%ld/ns/net", (long)child);
    if (result == 0) {
        if (proc_namespace_identity(source, &topology->namespace_dev,
                                    &topology->namespace_ino) != 0) {
            result = -1;
        }
    }
    if (result == 0) {
        char namespace_intent[128];
        snprintf(namespace_intent, sizeof(namespace_intent),
                 "namespace_dev=%llu\nnamespace_ino=%llu\n",
                 (unsigned long long)topology->namespace_dev,
                 (unsigned long long)topology->namespace_ino);
        if (durable_no_replace_at(tx_fd, "05-namespace-intent",
                                  namespace_intent) != 0) result = -1;
    }
    if (result == 0) {
        if (verify_placeholder(topology->tx_namespace_path,
                               topology->tx_placeholder_dev,
                               topology->tx_placeholder_ino) != 0 ||
            mount(source, topology->tx_namespace_path, NULL, MS_BIND, NULL) != 0 ||
            verify_namespace_mount(topology->tx_namespace_path, topology) != 0)
            result = -1;
    }
    if (result == 0) test_pause_at("after-namespace-mount");
    if (write(release_pipe[1], "x", 1) != 1) result = -1;
    close(ready_pipe[0]);
    close(release_pipe[1]);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) result = -1;
    return result;
}

static int bind_final_namespace(const struct topology *topology, int tx_fd,
                                const char *namespace_record)
{
    if (durable_no_replace_at(tx_fd, "20-final-intent", namespace_record) != 0 ||
        verify_placeholder(topology->final_placeholder_path,
                           topology->final_placeholder_dev,
                           topology->final_placeholder_ino) != 0 ||
        syscall(SYS_renameat2, AT_FDCWD, topology->final_placeholder_path,
                AT_FDCWD, FINAL_NAMESPACE_PATH, RENAME_NOREPLACE) != 0)
        return -1;
    int netns_fd = open(NETNS_DIRECTORY,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (netns_fd < 0 || fsync(netns_fd) != 0 || close(netns_fd) != 0) return -1;
    if (verify_placeholder(FINAL_NAMESPACE_PATH,
                           topology->final_placeholder_dev,
                           topology->final_placeholder_ino) != 0)
        return -1;
    test_pause_at("after-final-rename");
    if (mount(topology->tx_namespace_path, FINAL_NAMESPACE_PATH, NULL, MS_BIND, NULL) != 0)
        return -1;
    test_pause_at("after-final-mount");
    return verify_namespace_mount(FINAL_NAMESPACE_PATH, topology);
}

static int configure_client_namespace(int namespace_fd, unsigned *client_index)
{
    int original = -1;
    if (enter_namespace(namespace_fd, &original) != 0) return -1;
    int result = -1;
    int fd = nl_open();
    if (fd >= 0) {
        unsigned lo = if_nametoindex("lo");
        unsigned client = if_nametoindex(CLIENT_IFNAME);
        char client_ipv6[192];
        snprintf(client_ipv6, sizeof(client_ipv6),
                 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", CLIENT_IFNAME);
        if (lo != 0 && client != 0 &&
            write_sysctl_one("/proc/sys/net/ipv6/conf/all/disable_ipv6") == 0 &&
            write_sysctl_one("/proc/sys/net/ipv6/conf/default/disable_ipv6") == 0 &&
            write_sysctl_one("/proc/sys/net/ipv6/conf/lo/disable_ipv6") == 0 &&
            write_sysctl_one(client_ipv6) == 0 &&
            set_link_up(fd, lo) == 0 && set_link_up(fd, client) == 0 &&
            add_ipv4_address(fd, client, CLIENT_ADDRESS_TEXT) == 0) {
            *client_index = client;
            result = 0;
        }
        close(fd);
    }
    int saved = errno;
    if (leave_namespace(original) != 0) return -1;
    errno = saved;
    return result;
}

struct ready_notifier {
    int fd;
    struct sockaddr_un address;
    socklen_t address_length;
};

static int prepare_ready_notifier(struct ready_notifier *notifier)
{
    memset(notifier, 0, sizeof(*notifier));
    notifier->fd = -1;
#ifdef BPIR_PUBLISHER_NETNS_TEST_PROFILE
    if (getenv("BPIR_TEST_SKIP_NOTIFY") != NULL) return 0;
#endif
    const char *path = getenv("NOTIFY_SOCKET");
    if (path == NULL || path[0] == '\0') {
        errno = ENOENT;
        return -1;
    }
    notifier->address.sun_family = AF_UNIX;
    size_t length = strlen(path);
    if (length >= sizeof(notifier->address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(notifier->address.sun_path, path, length + 1);
    if (notifier->address.sun_path[0] == '@') notifier->address.sun_path[0] = '\0';
    notifier->fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (notifier->fd < 0) return -1;
    notifier->address_length =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1);
    return 0;
}

static void close_ready_notifier(struct ready_notifier *notifier)
{
    if (notifier->fd >= 0) close(notifier->fd);
    notifier->fd = -1;
}

static int notify_ready(struct ready_notifier *notifier)
{
    if (notifier->fd < 0) return 0;
    const char *message =
        "READY=1\nSTATUS=publisher namespace and firewall generation sealed and monitored";
    int result = sendto(notifier->fd, message, strlen(message), MSG_NOSIGNAL,
                        (struct sockaddr *)&notifier->address,
                        notifier->address_length) < 0 ? -1 : 0;
    close_ready_notifier(notifier);
    return result;
}

static int wait_for_client_monitor_ready(int fd, pid_t child)
{
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
    for (unsigned attempt = 0; attempt < 100U; ++attempt) {
        char byte = 0;
        ssize_t count = read(fd, &byte, 1);
        if (count == 1) return byte == '1' ? 0 : -1;
        if (count == 0) {
            errno = EPIPE;
            return -1;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            errno = ECHILD;
            return -1;
        }
        if (waited < 0) return -1;
        struct timespec remaining = delay;
        while (clock_nanosleep(CLOCK_MONOTONIC, 0, &remaining, &remaining) == EINTR) {}
    }
    errno = ETIMEDOUT;
    return -1;
}

static int drop_capabilities(void)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));
    return syscall(SYS_capset, &header, data) == 0 ? 0 : -1;
}

#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)__NR_##name, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int install_monitor_seccomp(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__aarch64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(sendto),
        ALLOW_SYSCALL(recvfrom),
        ALLOW_SYSCALL(pread64),
        ALLOW_SYSCALL(newfstatat),
        ALLOW_SYSCALL(statfs),
        ALLOW_SYSCALL(clock_nanosleep),
        ALLOW_SYSCALL(kill),
        ALLOW_SYSCALL(wait4),
        ALLOW_SYSCALL(rt_sigreturn),
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog program = {
        .len = (unsigned short)ARRAY_LEN(filter),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return -1;
    return 0;
}

static int check_ipv6_disabled(int namespace_fd)
{
    int original = -1;
    if (enter_namespace(namespace_fd, &original) != 0) return -1;
    bool all = false, default_value = false, lo = false, client = false;
    char client_path[192];
    snprintf(client_path, sizeof(client_path),
             "/proc/sys/net/ipv6/conf/%s/disable_ipv6", CLIENT_IFNAME);
    int result = read_sysctl_one("/proc/sys/net/ipv6/conf/all/disable_ipv6", &all) == 0 &&
                 read_sysctl_one("/proc/sys/net/ipv6/conf/default/disable_ipv6",
                                 &default_value) == 0 &&
                 read_sysctl_one("/proc/sys/net/ipv6/conf/lo/disable_ipv6", &lo) == 0 &&
                 read_sysctl_one(client_path, &client) == 0 && all && default_value && lo && client
                     ? 0 : -1;
    int saved = errno;
    if (leave_namespace(original) != 0) return -1;
    errno = saved;
    return result;
}

static int verify_client_in_namespace(int namespace_fd,
                                      const struct topology *topology)
{
    int original = -1;
    if (enter_namespace(namespace_fd, &original) != 0) return -1;
    int fd = nl_open();
    int result = fd >= 0 ? verify_client_topology(fd, topology, true) : -1;
    int saved = errno;
    if (fd >= 0) close(fd);
    if (leave_namespace(original) != 0) result = -1;
    errno = saved;
    return result;
}

static int inspect_no_owned_names(int host_nl)
{
    struct stat st;
    if (lstat(FINAL_NAMESPACE_PATH, &st) == 0 || errno != ENOENT) {
        errno = EEXIST;
        return -1;
    }
    struct link_snapshot host;
    struct link_snapshot client;
    if (link_by_name(host_nl, HOST_IFNAME, &host) != 0 ||
        link_by_name(host_nl, CLIENT_IFNAME, &client) != 0) return -1;
    if (host.found || client.found) {
        errno = EEXIST;
        return -1;
    }
    return 0;
}

static int remove_owned_mount_target(const char *path,
                                     const struct topology *topology,
                                     uint64_t placeholder_dev,
                                     uint64_t placeholder_ino,
                                     bool may_be_missing)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (may_be_missing && errno == ENOENT) return 0;
        return -1;
    }
    struct statfs filesystem;
    if (statfs(path, &filesystem) != 0) return -1;
    if ((unsigned long)filesystem.f_type == NSFS_MAGIC) {
        if (verify_namespace_mount(path, topology) != 0 || umount2(path, 0) != 0)
            return -1;
    }
    if (verify_placeholder(path, placeholder_dev, placeholder_ino) != 0 ||
        unlink(path) != 0)
        return -1;
    return 0;
}

static int finish_transaction(int state_fd, int tx_fd, const char *txid)
{
    if (durable_no_replace_at(tx_fd, "90-clean", "clean=1\n") != 0) return -1;
    char active[MAX_RECORD];
    if (read_exact_file_at(state_fd, ACTIVE_RECORD, active, sizeof(active)) != 0)
        return -1;
    char expected[40];
    snprintf(expected, sizeof(expected), "%s\n", txid);
    if (strcmp(active, expected) != 0) {
        errno = ESTALE;
        return -1;
    }
    if (unlinkat(state_fd, ACTIVE_RECORD, 0) != 0 || fsync(state_fd) != 0 ||
        remove_pending_record(state_fd, txid, true) != 0) return -1;
    return 0;
}

static int cleanup_active(int state_fd, const struct topology *topology, int tx_fd)
{
    if (durable_no_replace_at(tx_fd, "70-cleanup-intent", "cleanup=1\n") != 0)
        return -1;
    int host_nl = nl_open();
    if (host_nl < 0) return -1;
    bool namespace_mount_present = false;
    int namespace_fd = -1;
    {
        struct stat namespace_path;
        if (lstat(topology->tx_namespace_path, &namespace_path) == 0) {
            struct statfs filesystem;
            if (statfs(topology->tx_namespace_path, &filesystem) != 0) {
                close(host_nl);
                return -1;
            }
            if ((unsigned long)filesystem.f_type == NSFS_MAGIC) {
                if (topology->namespace_ino == 0 ||
                    verify_namespace_mount(topology->tx_namespace_path,
                                           topology) != 0) {
                    close(host_nl);
                    return -1;
                }
                namespace_mount_present = true;
            } else if (verify_placeholder(topology->tx_namespace_path,
                                          topology->tx_placeholder_dev,
                                          topology->tx_placeholder_ino) != 0) {
                close(host_nl);
                return -1;
            }
        } else if (errno != ENOENT) {
            close(host_nl);
            return -1;
        }
        if (namespace_mount_present) {
            namespace_fd = open(topology->tx_namespace_path,
                                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (namespace_fd < 0) {
                close(host_nl);
                return -1;
            }
        }
    }
    struct link_snapshot host_fixed;
    struct link_snapshot host_temp;
    struct link_snapshot client_fixed_host;
    struct link_snapshot client_temp_host;
    struct link_snapshot client_fixed_ns = {0};
    struct link_snapshot client_temp_ns = {0};
    if (link_by_name(host_nl, HOST_IFNAME, &host_fixed) != 0 ||
        link_by_name(host_nl, topology->host_temp_ifname, &host_temp) != 0 ||
        link_by_name(host_nl, CLIENT_IFNAME, &client_fixed_host) != 0 ||
        link_by_name(host_nl, topology->client_temp_ifname, &client_temp_host) != 0 ||
        (namespace_fd >= 0 &&
         (snapshot_link_in_namespace(namespace_fd, CLIENT_IFNAME,
                                     &client_fixed_ns) != 0 ||
          snapshot_link_in_namespace(namespace_fd, topology->client_temp_ifname,
                                     &client_temp_ns) != 0))) {
        goto failed;
    }
    bool veth_intended = false;
    if (exact_phase_record(tx_fd, "40-veth-intent", "create_veth=1\n",
                           &veth_intended) != 0)
        goto failed;
    bool veth_branded = false;
    bool veth_brand_intended = false;
    if (exact_phase_record(tx_fd, "41-veth-brand-intent", "brand=1\n",
                           &veth_brand_intended) != 0)
        goto failed;
    if (exact_phase_record(tx_fd, "42-veth-branded", "branded=1\n",
                           &veth_branded) != 0)
        goto failed;
    unsigned host_found = (unsigned)host_fixed.found + (unsigned)host_temp.found;
    unsigned client_found = (unsigned)client_fixed_host.found +
                            (unsigned)client_temp_host.found +
                            (unsigned)client_fixed_ns.found +
                            (unsigned)client_temp_ns.found;
    if (host_found > 1 || client_found > 1) {
        errno = ESTALE;
        goto failed;
    }
    bool veth_recorded = topology->host_ifindex != 0;
    if (!veth_intended && (host_found != 0 || client_found != 0)) {
        errno = ESTALE;
        goto failed;
    }
    if (host_found == 1) {
        if (client_found != 1) {
            errno = ESTALE;
            goto failed;
        }
        const struct link_snapshot *host = host_fixed.found ? &host_fixed : &host_temp;
        const struct link_snapshot *peer = client_fixed_host.found ? &client_fixed_host :
                                           client_temp_host.found ? &client_temp_host :
                                           client_fixed_ns.found ? &client_fixed_ns :
                                                                   &client_temp_ns;
        if (!veth_branded &&
            (!host_temp.found || !client_temp_host.found)) {
            errno = ESTALE;
            goto failed;
        }
        unsigned alias_state = veth_branded ? 1U : veth_brand_intended ? 2U : 0U;
        if (exact_link(host, topology, true, veth_recorded, alias_state) != 0 ||
            exact_link(peer, topology, false, veth_recorded, alias_state) != 0 ||
            delete_link(host_nl, host->ifindex) != 0)
            goto failed;
        test_pause_at("after-veth-delete-cleanup");
    } else if (client_found != 0) {
        errno = ESTALE;
        goto failed;
    }
    if (namespace_fd >= 0) close(namespace_fd);
    close(host_nl);
    char namespace_record[128];
    snprintf(namespace_record, sizeof(namespace_record),
             "namespace_dev=%llu\nnamespace_ino=%llu\n",
             (unsigned long long)topology->namespace_dev,
             (unsigned long long)topology->namespace_ino);
    bool final_intended = false;
    if (exact_phase_record(tx_fd, "20-final-intent", namespace_record,
                           &final_intended) != 0)
        return -1;
    if (final_intended) {
        bool final_exists = false;
        bool alternate_exists = false;
        if (path_exists_nofollow(FINAL_NAMESPACE_PATH, &final_exists) != 0 ||
            path_exists_nofollow(topology->final_placeholder_path,
                                 &alternate_exists) != 0)
            return -1;
        if (final_exists && alternate_exists) {
            errno = ESTALE;
            return -1;
        }
        if (final_exists) {
            if (remove_owned_mount_target(FINAL_NAMESPACE_PATH, topology,
                                          topology->final_placeholder_dev,
                                          topology->final_placeholder_ino,
                                          false) != 0)
                return -1;
        } else if (alternate_exists &&
                   (verify_placeholder(topology->final_placeholder_path,
                                      topology->final_placeholder_dev,
                                      topology->final_placeholder_ino) != 0 ||
                    unlink(topology->final_placeholder_path) != 0)) {
            return -1;
        }
    } else {
        struct stat st;
        if (lstat(FINAL_NAMESPACE_PATH, &st) == 0 || errno != ENOENT) {
            errno = ESTALE;
            return -1;
        }
        if (lstat(topology->final_placeholder_path, &st) == 0) {
            if (verify_placeholder(topology->final_placeholder_path,
                                   topology->final_placeholder_dev,
                                   topology->final_placeholder_ino) != 0 ||
                unlink(topology->final_placeholder_path) != 0)
                return -1;
        } else if (errno != ENOENT) {
            return -1;
        }
    }
    test_pause_at("after-final-remove-cleanup");
    if (remove_owned_mount_target(topology->tx_namespace_path, topology,
                                  topology->tx_placeholder_dev,
                                  topology->tx_placeholder_ino, true) != 0)
        return -1;
    test_pause_at("after-tx-remove-cleanup");
    return finish_transaction(state_fd, tx_fd, topology->txid);

failed:
    if (namespace_fd >= 0) close(namespace_fd);
    close(host_nl);
    return -1;
}

static int setup_transaction(int state_fd, int host_nl, struct topology *topology,
                             int *tx_fd_out, int *namespace_fd_out)
{
    const char *stage = "randomize-transaction";
    if (random_txid(topology->txid) != 0 || read_boot_id(topology->boot_id) != 0 ||
        random_mac(topology->host_mac) != 0 || random_mac(topology->client_mac) != 0)
        return -1;
    snprintf(topology->tx_namespace_path, sizeof(topology->tx_namespace_path),
             TX_NAMESPACE_PREFIX "%s", topology->txid);
    snprintf(topology->final_placeholder_path,
             sizeof(topology->final_placeholder_path),
             NETNS_DIRECTORY "/.bpir-final-%s", topology->txid);
    snprintf(topology->host_temp_ifname, sizeof(topology->host_temp_ifname),
             "bph%.12s", topology->txid);
    snprintf(topology->client_temp_ifname, sizeof(topology->client_temp_ifname),
             "bpc%.12s", topology->txid);
    char pending[MAX_RECORD];
    stage = "publish-pre-mutation-journal";
    if (format_pending(topology, pending) != 0 ||
        durable_no_replace_at(state_fd, PENDING_RECORD, pending) != 0)
        return -1;
    test_pause_at("after-pre-mutation-journal");
    stage = "create-transaction-directory";
    if (mkdirat(state_fd, topology->txid, 0700) != 0 || fsync(state_fd) != 0) return -1;
    test_pause_at("after-transaction-directory");
    int tx_fd = open_transaction(state_fd, topology->txid);
    if (tx_fd < 0) return -1;
    stage = "publish-placeholder-intent";
    if (durable_no_replace_at(tx_fd, "00-placeholder-intent", pending) != 0)
        goto failed;
    test_pause_at("after-placeholder-intent");
    stage = "create-identity-bound-mount-placeholders";
    if (create_placeholder(topology->tx_namespace_path,
                           &topology->tx_placeholder_dev,
                           &topology->tx_placeholder_ino) != 0)
        goto failed;
    test_pause_at("after-transaction-placeholder");
    if (create_placeholder(topology->final_placeholder_path,
                           &topology->final_placeholder_dev,
                           &topology->final_placeholder_ino) != 0)
        goto failed;
    test_pause_at("after-final-placeholder");
    char prepared[MAX_RECORD];
    stage = "publish-prepared-record";
    if (format_prepared(topology, prepared) != 0 ||
        durable_no_replace_at(tx_fd, "00-prepared", prepared) != 0) goto failed;
    test_pause_at("after-prepared-record");
    char active[40];
    snprintf(active, sizeof(active), "%s\n", topology->txid);
    stage = "publish-active-record";
    if (durable_no_replace_at(state_fd, ACTIVE_RECORD, active) != 0) goto failed;
    test_pause_at("after-active-record");
    if (remove_pending_record(state_fd, topology->txid, false) != 0) goto failed;
    stage = "create-transaction-namespace-mount";
    if (create_namespace_mount(topology, tx_fd) != 0) goto failed;
    char namespace_record[128];
    snprintf(namespace_record, sizeof(namespace_record),
             "namespace_dev=%llu\nnamespace_ino=%llu\n",
             (unsigned long long)topology->namespace_dev,
             (unsigned long long)topology->namespace_ino);
    stage = "bind-final-namespace";
    if (durable_no_replace_at(tx_fd, "10-namespace", namespace_record) != 0 ||
        bind_final_namespace(topology, tx_fd, namespace_record) != 0 ||
        durable_no_replace_at(tx_fd, "30-final", namespace_record) != 0 ||
        durable_no_replace_at(tx_fd, "40-veth-intent", "create_veth=1\n") != 0 ||
        create_veth(host_nl, topology) != 0) goto failed;
    test_pause_at("after-veth-create");
    stage = "brand-and-install-veth";
    unsigned host_temp_index = if_nametoindex(topology->host_temp_ifname);
    unsigned client_temp_index = if_nametoindex(topology->client_temp_ifname);
    if (host_temp_index == 0 || client_temp_index == 0) goto failed;
    char host_alias[128];
    char client_alias[128];
    snprintf(host_alias, sizeof(host_alias), IF_ALIAS_PREFIX "%s:host", topology->txid);
    snprintf(client_alias, sizeof(client_alias), IF_ALIAS_PREFIX "%s:client", topology->txid);
    if (durable_no_replace_at(tx_fd, "41-veth-brand-intent", "brand=1\n") != 0 ||
        set_link_alias(host_nl, host_temp_index, host_alias) != 0 ||
        set_link_alias(host_nl, client_temp_index, client_alias) != 0 ||
        durable_no_replace_at(tx_fd, "42-veth-branded", "branded=1\n") != 0 ||
        durable_no_replace_at(tx_fd, "43-veth-install-intent", "install=1\n") != 0 ||
        set_link_name(host_nl, host_temp_index, HOST_IFNAME) != 0 ||
        set_link_name(host_nl, client_temp_index, CLIENT_IFNAME) != 0 ||
        durable_no_replace_at(tx_fd, "44-veth-installed", "installed=1\n") != 0)
        goto failed;
    stage = "move-and-configure-veth";
    topology->host_ifindex = if_nametoindex(HOST_IFNAME);
    unsigned client_host_index = if_nametoindex(CLIENT_IFNAME);
    if (topology->host_ifindex == 0 || client_host_index == 0) goto failed;
    int namespace_fd = open(topology->tx_namespace_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char host_ipv6[192];
    snprintf(host_ipv6, sizeof(host_ipv6),
             "/proc/sys/net/ipv6/conf/%s/disable_ipv6", HOST_IFNAME);
    if (namespace_fd < 0 || set_link_namespace(host_nl, client_host_index, namespace_fd) != 0 ||
        configure_client_namespace(namespace_fd, &topology->client_ifindex) != 0 ||
        write_sysctl_one(host_ipv6) != 0 ||
        set_link_up(host_nl, topology->host_ifindex) != 0 ||
        add_ipv4_address(host_nl, topology->host_ifindex, HOST_ADDRESS_TEXT) != 0)
        goto failed_namespace;
    test_pause_at("after-veth-move");
    char veth_record[128];
    snprintf(veth_record, sizeof(veth_record),
             "host_ifindex=%u\nclient_ifindex=%u\n",
             topology->host_ifindex, topology->client_ifindex);
    stage = "publish-veth-record";
    if (durable_no_replace_at(tx_fd, "50-veth", veth_record) != 0) goto failed_namespace;
    stage = "verify-ready-topology";
    if (verify_host_topology(host_nl, topology, true) != 0 ||
        verify_client_in_namespace(namespace_fd, topology) != 0 ||
        check_ipv6_disabled(namespace_fd) != 0 ||
        durable_no_replace_at(tx_fd, "60-ready", "ready=1\n") != 0)
        goto failed_namespace;
    *tx_fd_out = tx_fd;
    *namespace_fd_out = namespace_fd;
    return 0;
failed_namespace:
    if (namespace_fd >= 0) close(namespace_fd);
failed:
    {
        int saved = errno;
        log_error("setup stage %s failed: %s", stage, strerror(saved));
        errno = saved;
    }
    close(tx_fd);
    return -1;
}

static int recover_before_start(int state_fd, int host_nl)
{
    struct topology prior;
    memset(&prior, 0, sizeof(prior));
    int tx_fd = -1;
    if (load_active(state_fd, &prior, &tx_fd) == 0) {
        char current_boot[37];
        if (read_boot_id(current_boot) != 0) {
            close(tx_fd);
            return -1;
        }
        if (strcmp(current_boot, prior.boot_id) != 0) {
            /* Across boots kernel objects cannot retain their old identity. */
            if (inspect_no_owned_names(host_nl) != 0) {
                close(tx_fd);
                return -1;
            }
            if (finish_transaction(state_fd, tx_fd, prior.txid) != 0) {
                close(tx_fd);
                return -1;
            }
        } else if (cleanup_active(state_fd, &prior, tx_fd) != 0) {
            close(tx_fd);
            return -1;
        }
        close(tx_fd);
    } else if (errno == ENOENT) {
        if (cleanup_pending_before_active(state_fd) != 0 ||
            inspect_no_owned_names(host_nl) != 0) return -1;
    } else {
        return -1;
    }
    return 0;
}

static int run_service(void)
{
    if (geteuid() != 0) {
        log_error("run requires euid 0");
        return 1;
    }
    int firewall_monitor_fd = open_nftables_generation_monitor();
    if (firewall_monitor_fd < 0)
        return fail_errno("open host nftables generation monitor");
    struct xtables_lock_guard xtables_guard;
    if (open_xtables_lock_guard(&xtables_guard) != 0 ||
        nftables_generation_is_quiet(firewall_monitor_fd) != 0 ||
        xtables_lock_guard_is_held(&xtables_guard) != 0) {
        close_xtables_lock_guard(&xtables_guard);
        close(firewall_monitor_fd);
        return fail_errno("seal host firewall generation before setup");
    }
    int netns_fd = ensure_secure_directory(NETNS_DIRECTORY, 0755);
    if (netns_fd < 0) return fail_errno("secure /run/netns");
    close(netns_fd);
    int state_fd = ensure_secure_directory(STATE_DIRECTORY, 0700);
    if (state_fd < 0) return fail_errno("secure state directory");
    int lock_fd = openat(state_fd, "lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        close(state_fd);
        return fail_errno("exclusive helper lock");
    }
    int host_nl = nl_open();
    if (host_nl < 0 || recover_before_start(state_fd, host_nl) != 0) {
        if (host_nl >= 0) close(host_nl);
        close(lock_fd);
        close(state_fd);
        return fail_errno("pre-start exact recovery");
    }
    struct topology topology;
    memset(&topology, 0, sizeof(topology));
    int tx_fd = -1, namespace_fd = -1;
    if (setup_transaction(state_fd, host_nl, &topology, &tx_fd,
                          &namespace_fd) != 0) {
        log_error("setup failed; the durable journal is retained for exact recovery");
        close(host_nl);
        close(lock_fd);
        close(state_fd);
        return 1;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    char host_ipv6_path[192];
    snprintf(host_ipv6_path, sizeof(host_ipv6_path),
             "/proc/sys/net/ipv6/conf/%s/disable_ipv6", HOST_IFNAME);
    int host_ipv6_fd = open(host_ipv6_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (host_ipv6_fd < 0 || monitor_fd_is_one(host_ipv6_fd) != 0)
        return fail_errno("open disabled host IPv6 monitor");
    struct ready_notifier notifier;
    if (prepare_ready_notifier(&notifier) != 0)
        return fail_errno("prepare systemd readiness notification");
    int monitor_ready_pipe[2];
    if (pipe2(monitor_ready_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        close_ready_notifier(&notifier);
        return fail_errno("create client monitor readiness pipe");
    }
#ifdef BPIR_PUBLISHER_NETNS_TEST_PROFILE
    const char *test_failure = getenv("BPIR_TEST_FAIL_MONITOR_INIT");
    bool fail_client_monitor =
        test_failure != NULL && strcmp(test_failure, "client") == 0;
    bool fail_firewall_monitor =
        test_failure != NULL && strcmp(test_failure, "firewall") == 0;
#else
    bool fail_client_monitor = false;
    bool fail_firewall_monitor = false;
#endif
    pid_t monitor_child = fork();
    if (monitor_child < 0) {
        close(monitor_ready_pipe[0]);
        close(monitor_ready_pipe[1]);
        close_ready_notifier(&notifier);
        return fail_errno("fork client namespace monitor");
    }
    if (monitor_child == 0) {
        close(monitor_ready_pipe[0]);
        close_ready_notifier(&notifier);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() == 1 ||
            setns(namespace_fd, CLONE_NEWNET) != 0) _exit(1);
        int client_nl = nl_open();
        struct ipv6_monitor_fds ipv6_fds = { -1, -1, -1, -1 };
        int ipv6_result = open_ipv6_monitor_fds(CLIENT_IFNAME, &ipv6_fds);
        close(namespace_fd);
        close(tx_fd);
        close(state_fd);
        close(host_nl);
        close(host_ipv6_fd);
        close_xtables_lock_guard(&xtables_guard);
        close(firewall_monitor_fd);
        close(lock_fd);
        if (client_nl < 0 || ipv6_result != 0 || drop_capabilities() != 0 ||
            install_monitor_seccomp() != 0) _exit(1);
        if (fail_client_monitor ||
            verify_client_topology(client_nl, &topology, true) != 0 ||
            ipv6_monitor_fds_are_disabled(&ipv6_fds) != 0 ||
            write(monitor_ready_pipe[1], "1", 1) != 1) _exit(1);
        close(monitor_ready_pipe[1]);
        struct timespec client_delay = { .tv_sec = 1, .tv_nsec = 0 };
        while (!stop_requested) {
            if (verify_client_topology(client_nl, &topology, true) != 0 ||
                ipv6_monitor_fds_are_disabled(&ipv6_fds) != 0) {
                log_error("client namespace topology drifted");
                _exit(1);
            }
            int sleep_result;
            do {
                sleep_result = clock_nanosleep(CLOCK_MONOTONIC, 0,
                                               &client_delay, &client_delay);
            } while (sleep_result == EINTR && !stop_requested);
            client_delay.tv_sec = 1;
            client_delay.tv_nsec = 0;
        }
        close_ipv6_monitor_fds(&ipv6_fds);
        close(client_nl);
        _exit(0);
    }
    close(monitor_ready_pipe[1]);
    if (drop_capabilities() != 0) {
        close(monitor_ready_pipe[0]);
        close_ready_notifier(&notifier);
        return fail_errno("drop monitor capabilities");
    }
    /* The mount path and sysctl proof were checked before privilege drop. */
    close(namespace_fd);
    close(tx_fd);
    close(state_fd);
    if (install_monitor_seccomp() != 0) {
        close(monitor_ready_pipe[0]);
        close_ready_notifier(&notifier);
        return fail_errno("install monitor seccomp");
    }
    if (fail_firewall_monitor ||
        nftables_generation_is_quiet(firewall_monitor_fd) != 0 ||
        xtables_lock_guard_is_held(&xtables_guard) != 0 ||
        verify_host_topology(host_nl, &topology, true) != 0 ||
        monitor_fd_is_one(host_ipv6_fd) != 0 ||
        wait_for_client_monitor_ready(monitor_ready_pipe[0], monitor_child) != 0) {
        close(monitor_ready_pipe[0]);
        close_ready_notifier(&notifier);
        log_error("monitor initialization failed before readiness");
        (void)kill(monitor_child, SIGTERM);
        while (waitpid(monitor_child, NULL, 0) < 0 && errno == EINTR) {}
        close(host_ipv6_fd);
        close_xtables_lock_guard(&xtables_guard);
        close(firewall_monitor_fd);
        close(host_nl);
        close(lock_fd);
        return 1;
    }
    close(monitor_ready_pipe[0]);
    if (notify_ready(&notifier) != 0) {
        log_error("systemd readiness notification failed");
        (void)kill(monitor_child, SIGTERM);
        while (waitpid(monitor_child, NULL, 0) < 0 && errno == EINTR) {}
        close(host_ipv6_fd);
        close_xtables_lock_guard(&xtables_guard);
        close(firewall_monitor_fd);
        close(host_nl);
        close(lock_fd);
        return 1;
    }
    int result = 0;
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
    while (!stop_requested) {
        int child_status = 0;
        pid_t waited = waitpid(monitor_child, &child_status, WNOHANG);
        if (waited == monitor_child) {
            log_error("client namespace monitor exited; refusing service continuation");
            result = 1;
            break;
        }
        if (nftables_generation_is_quiet(firewall_monitor_fd) != 0 ||
            xtables_lock_guard_is_held(&xtables_guard) != 0 ||
            waited < 0 || verify_host_topology(host_nl, &topology, true) != 0 ||
            monitor_fd_is_one(host_ipv6_fd) != 0) {
            log_error("monitored firewall generation or topology drifted; "
                      "refusing service continuation");
            result = 1;
            break;
        }
        int sleep_result;
        do {
            sleep_result = clock_nanosleep(CLOCK_MONOTONIC, 0, &delay, &delay);
        } while (sleep_result == EINTR && !stop_requested);
        delay.tv_sec = 0;
        delay.tv_nsec = 100000000L;
    }
    if (result == 0 &&
        (nftables_generation_is_quiet(firewall_monitor_fd) != 0 ||
         xtables_lock_guard_is_held(&xtables_guard) != 0)) {
        log_error("firewall generation drifted during graceful shutdown");
        result = 1;
    }
    (void)kill(monitor_child, SIGTERM);
    int child_status = 0;
    while (waitpid(monitor_child, &child_status, 0) < 0 && errno == EINTR) {}
    close(host_ipv6_fd);
    close_xtables_lock_guard(&xtables_guard);
    close(firewall_monitor_fd);
    close(host_nl);
    close(lock_fd);
    return result;
}

static int publisher_sandbox_self_test(void)
{
    if (geteuid() == 0) {
        log_error("publisher sandbox self-test must run as the unprivileged publisher");
        return 1;
    }
    int runtime_directory = open("/run", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (runtime_directory < 0) return fail_errno("publisher private /run probe");
    struct statfs runtime_filesystem;
    struct statvfs runtime_mount;
    if (fstatfs(runtime_directory, &runtime_filesystem) != 0 ||
        runtime_filesystem.f_type != TMPFS_MAGIC ||
        fstatvfs(runtime_directory, &runtime_mount) != 0 ||
        (runtime_mount.f_flag & ST_RDONLY) == 0) {
        close(runtime_directory);
        log_error("publisher sandbox /run is not a private read-only tmpfs");
        return 1;
    }
    static const char *const host_runtime_entries[] = {
        "bitcoinpir-payment-v1-publisher-host-visibility-probe",
        "dbus/system_bus_socket",
        "netns/bpir-directory-publisher",
        "systemd/notify",
        "systemd/private",
    };
    for (size_t i = 0; i < ARRAY_LEN(host_runtime_entries); i++) {
        struct stat metadata;
        if (fstatat(runtime_directory, host_runtime_entries[i], &metadata,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            close(runtime_directory);
            log_error("publisher sandbox private /run exposes a host runtime entry");
            return 1;
        }
        if (errno != ENOENT) {
            int saved = errno;
            close(runtime_directory);
            errno = saved;
            return fail_errno("publisher private /run host-entry probe");
        }
    }
    close(runtime_directory);
    int runtime_write = open("/run/.bitcoinpir-publisher-write-probe",
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                             0600);
    if (runtime_write >= 0) {
        close(runtime_write);
        (void)unlink("/run/.bitcoinpir-publisher-write-probe");
        log_error("publisher sandbox private /run is writable");
        return 1;
    }
    if (errno != EROFS && errno != EACCES && errno != EPERM) {
        return fail_errno("publisher private /run write-denial probe");
    }
    int local = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (local >= 0) {
        close(local);
        log_error("publisher sandbox unexpectedly permits AF_UNIX sockets");
        return 1;
    }
    if (errno != EAFNOSUPPORT && errno != EPERM && errno != EACCES) {
        return fail_errno("publisher AF_UNIX denial probe");
    }
    int internet = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (internet < 0) return fail_errno("publisher AF_INET availability probe");
    close(internet);
    return 0;
}

static int cleanup_service(void)
{
    if (geteuid() != 0) {
        log_error("cleanup requires euid 0");
        return 1;
    }
    int state_fd = ensure_secure_directory(STATE_DIRECTORY, 0700);
    if (state_fd < 0) return fail_errno("secure state directory");
    int lock_fd = openat(state_fd, "lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        close(state_fd);
        return fail_errno("exclusive cleanup lock");
    }
    struct topology topology;
    memset(&topology, 0, sizeof(topology));
    int tx_fd = -1;
    int result = 0;
    if (load_active(state_fd, &topology, &tx_fd) == 0) {
        if (cleanup_active(state_fd, &topology, tx_fd) != 0) result = -1;
        close(tx_fd);
    } else if (errno == ENOENT) {
        if (cleanup_pending_before_active(state_fd) != 0) result = -1;
    } else {
        result = -1;
    }
    close(lock_fd);
    close(state_fd);
    if (result != 0) return fail_errno("exact cleanup refused");
    return 0;
}

static int self_test(void)
{
    struct topology first;
    memset(&first, 0, sizeof(first));
    strcpy(first.txid, "00112233445566778899aabbccddeeff");
    strcpy(first.boot_id, "00112233-4455-6677-8899-aabbccddeeff");
    snprintf(first.tx_namespace_path, sizeof(first.tx_namespace_path),
             TX_NAMESPACE_PREFIX "%s", first.txid);
    snprintf(first.final_placeholder_path, sizeof(first.final_placeholder_path),
             NETNS_DIRECTORY "/.bpir-final-%s", first.txid);
    snprintf(first.host_temp_ifname, sizeof(first.host_temp_ifname),
             "bph%.12s", first.txid);
    snprintf(first.client_temp_ifname, sizeof(first.client_temp_ifname),
             "bpc%.12s", first.txid);
    first.tx_placeholder_dev = 7;
    first.tx_placeholder_ino = 8;
    first.final_placeholder_dev = 9;
    first.final_placeholder_ino = 10;
    const unsigned char host_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const unsigned char client_mac[6] = {0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    memcpy(first.host_mac, host_mac, 6);
    memcpy(first.client_mac, client_mac, 6);
    char record[MAX_RECORD];
    if (format_pending(&first, record) != 0) return 1;
    struct topology pending;
    memset(&pending, 0, sizeof(pending));
    if (parse_pending(record, &pending) != 0 ||
        strcmp(first.txid, pending.txid) != 0 ||
        strcmp(first.boot_id, pending.boot_id) != 0 ||
        strcmp(first.tx_namespace_path, pending.tx_namespace_path) != 0 ||
        strcmp(first.final_placeholder_path, pending.final_placeholder_path) != 0 ||
        parse_pending("version=1\ntxid=../bad\n", &pending) == 0) return 1;
    if (format_prepared(&first, record) != 0) return 1;
    struct topology second;
    memset(&second, 0, sizeof(second));
    if (parse_prepared(record, &second) != 0 || strcmp(first.txid, second.txid) != 0 ||
        strcmp(first.boot_id, second.boot_id) != 0 ||
        strcmp(first.tx_namespace_path, second.tx_namespace_path) != 0 ||
        strcmp(first.final_placeholder_path, second.final_placeholder_path) != 0 ||
        strcmp(first.host_temp_ifname, second.host_temp_ifname) != 0 ||
        strcmp(first.client_temp_ifname, second.client_temp_ifname) != 0 ||
        first.tx_placeholder_dev != second.tx_placeholder_dev ||
        first.tx_placeholder_ino != second.tx_placeholder_ino ||
        first.final_placeholder_dev != second.final_placeholder_dev ||
        first.final_placeholder_ino != second.final_placeholder_ino ||
        memcmp(first.host_mac, second.host_mac, 6) != 0 ||
        memcmp(first.client_mac, second.client_mac, 6) != 0) return 1;
    if (parse_prepared("version=1\ntxid=../bad\n", &second) == 0) return 1;
    if (parse_namespace_record("namespace_dev=7\nnamespace_ino=9\n", &second) != 0 ||
        second.namespace_dev != 7 || second.namespace_ino != 9) return 1;
    if (parse_namespace_record("namespace_dev=0\nnamespace_ino=9\n", &second) == 0)
        return 1;
    if (parse_veth_record("host_ifindex=5\nclient_ifindex=6\n", &second) != 0 ||
        parse_veth_record("host_ifindex=5\nclient_ifindex=5\n", &second) == 0)
        return 1;
    puts("payment-v1-publisher-netns self-test: ok");
    return 0;
}

static void usage(FILE *stream)
{
    fputs("usage: payment-v1-publisher-netns run|cleanup|self-test|publisher-sandbox-self-test\n",
          stream);
}

int main(int argc, char **argv)
{
    umask(0077);
    if (argc != 2) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "run") == 0) return run_service();
    if (strcmp(argv[1], "cleanup") == 0) return cleanup_service();
    if (strcmp(argv[1], "self-test") == 0) return self_test();
    if (strcmp(argv[1], "publisher-sandbox-self-test") == 0)
        return publisher_sandbox_self_test();
    usage(stderr);
    return 2;
}
