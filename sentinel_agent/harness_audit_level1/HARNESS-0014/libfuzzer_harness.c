/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-0014
 * Target file: stack_overflow_strcpy.c
 * Target function: set_player_name
 * CWE: CWE-121
 * Strategy: oversized_string_input
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void set_player_name(const char *input);

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

    set_player_name((const char *)buf);

    free(buf);

    return 0;
}
