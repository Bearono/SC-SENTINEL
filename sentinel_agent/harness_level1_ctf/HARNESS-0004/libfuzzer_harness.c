/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-0004
 * Target file: format_string_fprintf.c
 * Target function: log_event
 * CWE: CWE-134
 * Strategy: format_string_payload
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void log_event(const char *input);

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

    log_event((const char *)buf);

    free(buf);

    return 0;
}
