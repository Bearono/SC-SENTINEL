/*
 * SENTINEL Agent D - AFL++ / ASan file-input harness
 *
 * Finding ID: FINDING-TEST
 * Target file: stack_overflow_loop.c
 * Target function: copy_loop
 * CWE: CWE-121
 * Strategy: original_main_file_replay
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int sentinel_original_main(int argc, char **argv);

static unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size < 0) {
        fclose(fp);
        return NULL;
    }

    unsigned char *buf = (unsigned char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t n = fread(buf, 1, (size_t)size, fp);
    fclose(fp);

    buf[n] = '\0';
    *out_size = n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }

    size_t size = 0;
    unsigned char *data = read_file(argv[1], &size);
    if (!data) {
        return 0;
    }

    /*
     * Reuse the target program's real input path. The target source is compiled
     * with -Dmain=sentinel_original_main, so static helper functions remain
     * reachable through the original main().
     */
    char *target_argv[] = { (char *)"sentinel_original_main", argv[1], NULL };
    sentinel_original_main(2, target_argv);

    free(data);
    return 0;
}
