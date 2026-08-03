#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/capability.h>
#include <linux/securebits.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#endif

static int failure_code = 126;
static void fail(void) { _exit(failure_code); }

#ifdef __linux__
#define BOOTSTRAP_CAPABILITY_MASK                                                  \
    ((UINT64_C(1) << CAP_CHOWN) | (UINT64_C(1) << CAP_DAC_OVERRIDE) |            \
     (UINT64_C(1) << CAP_FOWNER) | (UINT64_C(1) << CAP_KILL) |                   \
     (UINT64_C(1) << CAP_SETGID) | (UINT64_C(1) << CAP_SETUID) |                 \
     (UINT64_C(1) << CAP_SETPCAP) | (UINT64_C(1) << CAP_SYS_ADMIN))

static int last_capability(void) {
    char bytes[16];
    int descriptor = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) fail();
    ssize_t length = read(descriptor, bytes, sizeof(bytes) - 1);
    if (length <= 0 || length >= (ssize_t)sizeof(bytes) || close(descriptor) != 0) fail();
    bytes[length] = '\0';
    char *end = NULL;
    long value = strtol(bytes, &end, 10);
    if (end == bytes || (*end != '\0' && *end != '\n') || value < 0 || value > 63) fail();
    return (int)value;
}

static uint64_t capability_words(const struct __user_cap_data_struct data[2], int field) {
    uint64_t low;
    uint64_t high;
    if (field == 0) {
        low = data[0].effective;
        high = data[1].effective;
    } else if (field == 1) {
        low = data[0].permitted;
        high = data[1].permitted;
    } else {
        low = data[0].inheritable;
        high = data[1].inheritable;
    }
    return low | (high << 32);
}

static void read_capabilities(struct __user_cap_data_struct data[2]) {
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    memset(data, 0, sizeof(struct __user_cap_data_struct) * 2);
    if (syscall(SYS_capget, &header, data) != 0) fail();
}

static void write_capabilities(uint64_t effective, uint64_t permitted,
                               uint64_t inheritable) {
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}};
    data[0].effective = (uint32_t)effective;
    data[1].effective = (uint32_t)(effective >> 32);
    data[0].permitted = (uint32_t)permitted;
    data[1].permitted = (uint32_t)(permitted >> 32);
    data[0].inheritable = (uint32_t)inheritable;
    data[1].inheritable = (uint32_t)(inheritable >> 32);
    if (syscall(SYS_capset, &header, data) != 0) fail();
}

static uint64_t bounding_capabilities(int maximum) {
    uint64_t result = 0;
    for (int capability = 0; capability <= maximum; ++capability) {
        int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (present < 0) fail();
        if (present != 0) result |= UINT64_C(1) << capability;
    }
    return result;
}

static uint64_t ambient_capabilities(int maximum) {
    uint64_t result = 0;
    for (int capability = 0; capability <= maximum; ++capability) {
        int present = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
        if (present < 0) fail();
        if (present != 0) result |= UINT64_C(1) << capability;
    }
    return result;
}

static void require_capability_state(uint64_t expected) {
    struct __user_cap_data_struct data[2];
    int maximum = last_capability();
    read_capabilities(data);
    if (capability_words(data, 0) != expected || capability_words(data, 1) != expected ||
        capability_words(data, 2) != 0 || bounding_capabilities(maximum) != expected ||
        ambient_capabilities(maximum) != 0 || prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != 0)
        fail();
}

static void reject_file_capability(int descriptor) {
    uint8_t value[64];
    errno = 0;
    ssize_t length = fgetxattr(descriptor, "security.capability", value, sizeof(value));
    if (length >= 0 || errno != ENODATA) fail();
}

static void normalize_bootstrap_authority(void) {
    int maximum = last_capability();
    struct __user_cap_data_struct data[2];
    read_capabilities(data);
    uint64_t effective = capability_words(data, 0);
    uint64_t permitted = capability_words(data, 1);
    uint64_t bounding = bounding_capabilities(maximum);
    if ((effective & BOOTSTRAP_CAPABILITY_MASK) != BOOTSTRAP_CAPABILITY_MASK ||
        (permitted & BOOTSTRAP_CAPABILITY_MASK) != BOOTSTRAP_CAPABILITY_MASK ||
        (bounding & BOOTSTRAP_CAPABILITY_MASK) != BOOTSTRAP_CAPABILITY_MASK)
        fail();
    if (prctl(PR_SET_SECUREBITS, 0, 0, 0, 0) != 0 ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0)
        fail();
    for (int capability = 0; capability <= maximum; ++capability) {
        if ((BOOTSTRAP_CAPABILITY_MASK & (UINT64_C(1) << capability)) == 0 &&
            prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0)
            fail();
    }
    write_capabilities(BOOTSTRAP_CAPABILITY_MASK, BOOTSTRAP_CAPABILITY_MASK, 0);
    require_capability_state(BOOTSTRAP_CAPABILITY_MASK);
}

static void drop_all_capabilities(void) {
    int maximum = last_capability();
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) fail();
    for (int capability = 0; capability <= maximum; ++capability) {
        if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0) fail();
    }
}

static void require_final_authority(void) {
    struct __user_cap_data_struct data[2];
    int maximum = last_capability();
    read_capabilities(data);
    if (capability_words(data, 0) != 0 || capability_words(data, 1) != 0 ||
        capability_words(data, 2) != 0 || bounding_capabilities(maximum) != 0 ||
        ambient_capabilities(maximum) != 0 || prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        fail();
}

static void close_linux_fds(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) fail();
    int scan_fd = dirfd(directory);
    if (scan_fd < 3) fail();
    errno = 0;
    for (struct dirent *entry = readdir(directory); entry != NULL; entry = readdir(directory)) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0') continue;
        if (fd > 2 && fd != scan_fd && close((int)fd) != 0 && errno != EBADF) fail();
        errno = 0;
    }
    if (errno != 0 || closedir(directory) != 0) fail();

    directory = opendir("/proc/self/fd");
    if (directory == NULL) fail();
    scan_fd = dirfd(directory);
    errno = 0;
    for (struct dirent *entry = readdir(directory); entry != NULL; entry = readdir(directory)) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0') continue;
        if (fd > 2 && fd != scan_fd) fail();
    }
    if (errno != 0 || closedir(directory) != 0) fail();
}
#endif

static void close_unrelated_fds(void) {
#ifdef __linux__
    close_linux_fds();
#else
    long maximum = sysconf(_SC_OPEN_MAX);
    if (maximum < 3 || maximum > 1048576) fail();
    for (int fd = 3; fd < maximum; ++fd) {
        if (close(fd) != 0 && errno != EBADF) fail();
    }
#endif
    for (int fd = 0; fd < 3; ++fd) {
        if (fcntl(fd, F_GETFD) < 0) fail();
    }
#ifndef __linux__
    for (int fd = 3; fd < maximum; ++fd) {
        if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) fail();
    }
#endif
}

#ifndef KAPSEL_RUNNER_PRE_EXEC_TEST
int main(int argc, char **argv) {
#ifdef __linux__
    if (argc == 1) {
        int self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
        if (self < 0) fail();
        reject_file_capability(self);
        reject_file_capability(STDERR_FILENO);
        if (close(self) != 0) fail();
        failure_code = 121;
        normalize_bootstrap_authority();
        char *const bootstrap_argv[] = {(char *)"kapsel-sandbox-runner-pre-exec",
                                        (char *)"fixed-bootstrap-v1", NULL};
        char *const empty_env[] = {NULL};
        execve("/proc/self/exe", bootstrap_argv, empty_env);
        fail();
    }
    if (argc != 2 || strcmp(argv[1], "fixed-bootstrap-v1") != 0) fail();
    failure_code = 122;
    int self = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (self < 0) fail();
    reject_file_capability(self);
    reject_file_capability(STDERR_FILENO);
    if (close(self) != 0) fail();
    require_capability_state(BOOTSTRAP_CAPABILITY_MASK);
#else
    (void)argv;
    if (argc != 1) fail();
#endif
    struct stat state;
    if (fstat(STDOUT_FILENO, &state) != 0 || !S_ISDIR(state.st_mode)) fail();

#ifdef __linux__
    failure_code = 123;
    pid_t parent = getppid();
    if (parent <= 1) fail();
    if (unshare(CLONE_NEWNS) != 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        fail();
    if (mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "mode=0755,size=1048576") != 0 || chmod("/run", 0755) != 0)
        fail();
    if (mkdir("/run/kapsel-sandbox", 0700) != 0) fail();
    char state_path[4096];
    ssize_t state_path_length = readlink("/proc/self/fd/1", state_path, sizeof(state_path) - 1);
    if (state_path_length <= 0 || state_path_length >= (ssize_t)(sizeof(state_path) - 1)) fail();
    state_path[state_path_length] = '\0';
    if (mount(state_path, "/run/kapsel-sandbox", NULL, MS_BIND, NULL) != 0) fail();
    failure_code = 124;
    drop_all_capabilities();
    if (setgroups(0, NULL) != 0 || setresgid(state.st_gid, state.st_gid, state.st_gid) != 0 ||
        setresuid(state.st_uid, state.st_uid, state.st_uid) != 0)
        fail();
    write_capabilities(0, 0, 0);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) fail();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) fail();
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0) fail();
    if (real_uid != state.st_uid || effective_uid != state.st_uid || saved_uid != state.st_uid ||
        real_gid != state.st_gid || effective_gid != state.st_gid || saved_gid != state.st_gid)
        fail();
    if (getgroups(0, NULL) != 0) fail();
    failure_code = 125;
    require_final_authority();
#endif

    umask(0077);
    if (fchdir(STDOUT_FILENO) != 0) fail();
    close_unrelated_fds();
    if (fcntl(STDERR_FILENO, F_SETFD, FD_CLOEXEC) != 0) fail();
    char *const child_argv[] = {(char *)"kapsel-sandbox", (char *)"runner-bootstrap", NULL};
    char *const child_env[] = {NULL};
#ifdef __linux__
    reject_file_capability(STDERR_FILENO);
    execve("/proc/self/fd/2", child_argv, child_env);
#else
    char executable_path[1024];
    if (fcntl(STDERR_FILENO, F_GETPATH, executable_path) != 0) fail();
    execve(executable_path, child_argv, child_env);
#endif
    fail();
}
#endif
