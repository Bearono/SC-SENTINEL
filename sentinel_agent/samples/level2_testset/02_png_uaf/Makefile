# Makefile for png_loader
# Vulnerability: CWE-416 Use-After-Free (CVE-2019-7317 inspired)

CC     ?= gcc
CFLAGS := -Iinclude -Wall -Wextra
SRCS   := src/png_loader.c src/main.c
TARGET := png_loader

.PHONY: all normal asan afl clean

all: normal

normal:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS)

asan:
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer \
	      -g -O0 -o $(TARGET)_asan $(SRCS)

# afl-fuzz -i seeds/ -o out/ -- ./png_loader_afl @@
afl:
	afl-clang-fast $(CFLAGS) -fsanitize=address \
	      -fno-omit-frame-pointer -g -O1 \
	      -o $(TARGET)_afl $(SRCS)

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl
