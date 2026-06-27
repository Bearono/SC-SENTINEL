/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-0014
 * Target file: uaf_direct.c
 * Target function: challenge
 * CWE: CWE-416
 * Strategy: flag_path_trigger
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void challenge(int flag);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) {
        return 0;
    }

    /*
     * Non-zero input triggers the vulnerable flag branch.
     */
    int flag = (Size > 0 && Data[0] != 0) ? 1 : 0;
    challenge(flag);

    return 0;
}
