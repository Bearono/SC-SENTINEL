/*
 * SENTINEL Agent D - libFuzzer-style harness
 *
 * Finding ID: FINDING-TEST
 * Target file: stack_overflow_loop.c
 * Target function: copy_loop
 * CWE: CWE-121
 * Strategy: original_main_file_replay
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sentinel_original_main(int argc, char **argv);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) {
        return 0;
    }

    /*
     * Materialize libFuzzer bytes as a temporary file and replay the target's
     * original argv-based input path.
     */
    const char *path = "/tmp/sentinel_libfuzzer_input.bin";
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(Data, 1, Size, fp);
    fclose(fp);
    char *target_argv[] = { (char *)"sentinel_original_main", (char *)path, NULL };
    sentinel_original_main(2, target_argv);

    return 0;
}
