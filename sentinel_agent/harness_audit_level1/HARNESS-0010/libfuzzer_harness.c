/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-0010
 * Target file: uaf_array_slot.c
 * Target function: create_slot
 * CWE: CWE-122
 * Strategy: oversized_string_input
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void create_slot(const char *input);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) {
        return 0;
    }

    /*
     * Make a null-terminated string from fuzzer bytes.
     */
    char *buf = (char *)malloc(Size + 1);
    if (!buf) {
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    create_slot((const char *)buf);

    free(buf);

    return 0;
}
