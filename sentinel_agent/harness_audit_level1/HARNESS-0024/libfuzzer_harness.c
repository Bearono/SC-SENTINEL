/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-0024
 * Target file: uaf_cross_function.c
 * Target function: main
 * CWE: CWE-416
 * Strategy: flag_path_trigger
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void main(int flag);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) {
        return 0;
    }

    /*
     * Non-zero input triggers the vulnerable flag branch.
     */
    int flag = (Size > 0 && Data[0] != 0) ? 1 : 0;
    main(flag);

    return 0;
}
