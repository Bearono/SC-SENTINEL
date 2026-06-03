# Makefile for adpcm_decoder
# Vulnerability: CWE-125 OOB Read + CWE-122 Heap OOB Write (CVE-2021-3246 inspired)

CC     ?= gcc
CFLAGS := -Iinclude -Wall -Wextra
SRCS   := src/adpcm_decoder.c src/main.c
TARGET := adpcm_decode

.PHONY: all normal asan afl clean

all: normal

normal:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS)

asan:
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer \
	      -g -O0 -o $(TARGET)_asan $(SRCS)

# afl-fuzz -i seeds/ -o out/ -- ./adpcm_decode_afl @@
afl:
	afl-clang-fast $(CFLAGS) -fsanitize=address \
	      -fno-omit-frame-pointer -g -O1 \
	      -o $(TARGET)_afl $(SRCS)

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl
