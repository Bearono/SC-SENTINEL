/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-0012
 * Target file: heap_overflow_strcpy.c
 * Target function: create_and_edit
 * CWE: CWE-122
 * Strategy: oversized_string_input
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void create_and_edit(const char *input);

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

    create_and_edit((const char *)buf);

    free(buf);

    return 0;
}
