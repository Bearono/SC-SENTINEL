/*
 * SENTINEL Agent D - AFL++ / ASan file-input harness
 *
 * Finding ID: FINDING-0013
 * Target file: stack_overflow_sprintf.c
 * Target function: make_banner
 * CWE: CWE-121
 * Strategy: oversized_string_input
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void make_banner(const char *input);

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
     * data is null-terminated by read_file().
     * Passing it as a string can trigger unsafe strcpy/memcpy-style code.
     */
    if (size > 0) {
        make_banner((const char *)data);
    }

    free(data);
    return 0;
}
