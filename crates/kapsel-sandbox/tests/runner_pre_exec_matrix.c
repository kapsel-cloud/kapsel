#define KAPSEL_RUNNER_PRE_EXEC_TEST
#include "../src/runner_pre_exec.c"
#include <stdio.h>
#include <sys/wait.h>

#define REPRESENTATIVE (UINT64_C(1) << CAP_NET_RAW)

enum matrix_case {
    CANONICAL,
    EXTRA_EFFECTIVE,
    EXTRA_PERMITTED,
    EXTRA_INHERITABLE,
    EXTRA_AMBIENT,
    EXTRA_BOUNDING,
    UNLOCKED_KEEP_CAPS,
    UNLOCKED_NO_SETUID_FIXUP,
    LOCKED_KEEP_CAPS,
    LOCKED_NO_SETUID_FIXUP,
};

static void configure_bounding(uint64_t wanted) {
    int maximum = last_capability();
    for (int capability = 0; capability <= maximum; ++capability) {
        if ((wanted & (UINT64_C(1) << capability)) == 0 &&
            prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0)
            fail();
    }
}

static void run_case(enum matrix_case test) {
    uint64_t effective = BOOTSTRAP_CAPABILITY_MASK;
    uint64_t permitted = BOOTSTRAP_CAPABILITY_MASK;
    uint64_t inheritable = 0;
    uint64_t bounding = BOOTSTRAP_CAPABILITY_MASK;
    int securebits = 0;

    switch (test) {
    case EXTRA_EFFECTIVE:
        effective |= REPRESENTATIVE;
        permitted |= REPRESENTATIVE; /* Linux requires effective to be permitted. */
        bounding |= REPRESENTATIVE;
        break;
    case EXTRA_PERMITTED:
        permitted |= REPRESENTATIVE;
        bounding |= REPRESENTATIVE;
        break;
    case EXTRA_INHERITABLE:
        inheritable |= REPRESENTATIVE;
        bounding |= REPRESENTATIVE;
        break;
    case EXTRA_AMBIENT:
        effective |= REPRESENTATIVE;
        permitted |= REPRESENTATIVE;
        inheritable |= REPRESENTATIVE;
        bounding |= REPRESENTATIVE;
        break;
    case EXTRA_BOUNDING:
        bounding |= REPRESENTATIVE;
        break;
    case UNLOCKED_KEEP_CAPS:
        securebits = SECBIT_KEEP_CAPS;
        break;
    case UNLOCKED_NO_SETUID_FIXUP:
        securebits = SECBIT_NO_SETUID_FIXUP;
        break;
    case LOCKED_KEEP_CAPS:
        securebits = SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED;
        break;
    case LOCKED_NO_SETUID_FIXUP:
        securebits = SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED;
        break;
    case CANONICAL:
        break;
    }

    if (prctl(PR_SET_SECUREBITS, securebits, 0, 0, 0) != 0) fail();
    configure_bounding(bounding);
    write_capabilities(effective, permitted, inheritable);
    if (test == EXTRA_AMBIENT &&
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW, 0, 0) != 0)
        fail();
    normalize_bootstrap_authority();
    require_capability_state(BOOTSTRAP_CAPABILITY_MASK);
    drop_all_capabilities();
    write_capabilities(0, 0, 0);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) fail();
    require_final_authority();
    _exit(0);
}

int main(void) {
    (void)close_unrelated_fds;
    (void)require_final_authority;
    (void)drop_all_capabilities;
    (void)reject_file_capability;
    const char *names[] = {"canonical", "effective", "permitted", "inheritable", "ambient",
                           "bounding", "keep-caps", "no-setuid-fixup", "locked-keep-caps",
                           "locked-no-setuid-fixup"};
    for (int test = CANONICAL; test <= LOCKED_NO_SETUID_FIXUP; ++test) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) run_case((enum matrix_case)test);
        int status = 0;
        if (waitpid(child, &status, 0) != child) return 1;
        int locked = test == LOCKED_KEEP_CAPS || test == LOCKED_NO_SETUID_FIXUP;
        int passed = locked ? WIFEXITED(status) && WEXITSTATUS(status) == 126
                            : WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (!passed) {
            dprintf(STDERR_FILENO, "runner capability matrix case failed: %s status=%d\n",
                    names[test], status);
            return 1;
        }
    }
    return 0;
}
