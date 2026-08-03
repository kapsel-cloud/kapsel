#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *message) {
    perror(message);
    exit(126);
}

static uint32_t capability_mask(int retain_installer_caps) {
    if (!retain_installer_caps) {
        return 0;
    }
    return (1U << CAP_CHOWN) | (1U << CAP_DAC_OVERRIDE) | (1U << CAP_FOWNER);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: fixed-staging-identity-exec <uid> <gid> <installer-caps:0|1> <command> [args...]\n");
        return 2;
    }
    char *end = NULL;
    unsigned long uid_value = strtoul(argv[1], &end, 10);
    if (*argv[1] == '\0' || *end != '\0' || uid_value > UINT32_MAX) {
        return 2;
    }
    unsigned long gid_value = strtoul(argv[2], &end, 10);
    if (*argv[2] == '\0' || *end != '\0' || gid_value > UINT32_MAX) {
        return 2;
    }
    int retain_caps = atoi(argv[3]);
    if (retain_caps != 0 && retain_caps != 1) {
        return 2;
    }
    if (prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) != 0) {
        fail("PR_SET_KEEPCAPS");
    }
    if (setgroups(0, NULL) != 0) {
        fail("setgroups");
    }
    if (setresgid((gid_t)gid_value, (gid_t)gid_value, (gid_t)gid_value) != 0) {
        fail("setresgid");
    }
    if (setresuid((uid_t)uid_value, (uid_t)uid_value, (uid_t)uid_value) != 0) {
        fail("setresuid");
    }
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}};
    uint32_t mask = capability_mask(retain_caps);
    data[0].effective = mask;
    data[0].permitted = mask;
    data[0].inheritable = mask;
    if (syscall(SYS_capset, &header, data) != 0) {
        fail("capset");
    }
    if (retain_caps) {
        const int capabilities[] = {CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER};
        for (size_t index = 0; index < sizeof(capabilities) / sizeof(capabilities[0]); index++) {
            if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, capabilities[index], 0L, 0L) != 0) {
                fail("PR_CAP_AMBIENT_RAISE");
            }
        }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0) {
        fail("PR_SET_NO_NEW_PRIVS");
    }
    execvp(argv[4], &argv[4]);
    fail("execvp");
}
