/*
 * Bug: SOLID env enumeration mutates global `environ` via `environ.add(1)`
 *      instead of a local cursor; second enumeration sees an empty environment.
 * Target: armv7a-none-eabi (SOLID, target_os = "solid_asp3")
 * Expected: env() does not mutate the process-global environ pointer.
 * Observed: walking advances the global symbol; later vars_os() returns empty.
 *
 * Build/run (POSIX clone of the buggy loop, demonstrating the same defect):
 *   cc 104-global-environ-pointer-advanced-during-enumeration.c \
 *     -o /tmp/poc104 && /tmp/poc104
 */

#include <stdio.h>
#include <string.h>

extern char **environ;

static int enumerate_buggy(void) {
    int n = 0;
    if (environ != NULL) {
        while (*environ != NULL) {
            n++;
            environ = environ + 1;
        }
    }
    return n;
}

int main(void) {
    int first = enumerate_buggy();
    int second = enumerate_buggy();
    printf("first=%d second=%d\n", first, second);
    if (second == 0 && first > 0) {
        printf("BUG REPRODUCED: second enumeration empty after first\n");
        return 0;
    }
    return 1;
}
