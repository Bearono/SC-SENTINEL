#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int handle_message(const char *msg) {
    char local[256];
    size_t len = strlen(msg);
    if (len >= sizeof(local)) len = sizeof(local) - 1;
    memcpy(local, msg, len);
    local[len] = '\0';
    if (strncmp(local, "FMT:", 4) == 0) {
        printf(local + 4);
        puts("");
        return 1;
    }
    puts(local);
    return 0;
}

int main(int argc, char **argv) {
    char buf[512];
    if (argc > 1) return handle_message(argv[1]);
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    return handle_message(buf);
}
