# Makefile for chunked_http
# Vulnerability: CWE-190 Integer Overflow → CWE-122 Heap Overflow (CVE-2017-8798 inspired)

CC     ?= gcc
CFLAGS := -Iinclude -Wall -Wextra
SRCS   := src/chunked_http.c src/main.c
TARGET := chunked_decoder

.PHONY: all normal asan afl clean

all: normal

normal:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS)

asan:
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer \
	      -g -O0 -o $(TARGET)_asan $(SRCS)

# afl-fuzz -i seeds/ -o out/ -- ./chunked_decoder_afl @@
afl:
	afl-clang-fast $(CFLAGS) -fsanitize=address \
	      -fno-omit-frame-pointer -g -O1 \
	      -o $(TARGET)_afl $(SRCS)

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl
