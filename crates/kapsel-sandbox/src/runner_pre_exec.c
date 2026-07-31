#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

static void fail(void) { _exit(126); }

#ifdef __linux__
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

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) fail();
    struct stat state;
    if (fstat(STDOUT_FILENO, &state) != 0 || !S_ISDIR(state.st_mode)) fail();

#ifdef __linux__
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
    if (setgroups(0, NULL) != 0 || setresgid(state.st_gid, state.st_gid, state.st_gid) != 0 ||
        setresuid(state.st_uid, state.st_uid, state.st_uid) != 0)
        fail();
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
#endif

    umask(0077);
    if (fchdir(STDOUT_FILENO) != 0) fail();
    close_unrelated_fds();
    if (fcntl(STDERR_FILENO, F_SETFD, FD_CLOEXEC) != 0) fail();
    char *const child_argv[] = {(char *)"kapsel-sandbox", (char *)"runner-bootstrap", NULL};
    char *const child_env[] = {NULL};
#ifdef __linux__
    execve("/proc/self/fd/2", child_argv, child_env);
#else
    char executable_path[1024];
    if (fcntl(STDERR_FILENO, F_GETPATH, executable_path) != 0) fail();
    execve(executable_path, child_argv, child_env);
#endif
    fail();
}
