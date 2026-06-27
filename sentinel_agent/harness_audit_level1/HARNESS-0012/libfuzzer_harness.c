/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-0012
 * Target file: double_free_error_path.c
 * Target function: update_profile
 * CWE: CWE-415
 * Strategy: flag_path_trigger
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void update_profile(int flag);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) {
        return 0;
    }

    /*
     * Non-zero input triggers the vulnerable flag branch.
     */
    int flag = (Size > 0 && Data[0] != 0) ? 1 : 0;
    update_profile(flag);

    return 0;
}
