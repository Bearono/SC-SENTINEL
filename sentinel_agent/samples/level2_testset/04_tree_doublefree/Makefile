# Makefile for ast_tree
# Vulnerability: CWE-415 Double Free (cJSON issue #833 inspired)

CC     ?= gcc
CFLAGS := -Iinclude -Wall -Wextra
SRCS   := src/ast_tree.c src/main.c
TARGET := ast_parser

.PHONY: all normal asan afl clean

all: normal

normal:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS)

asan:
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer \
	      -g -O0 -o $(TARGET)_asan $(SRCS)

afl:
	afl-clang-fast $(CFLAGS) -fsanitize=address \
	      -fno-omit-frame-pointer -g -O1 \
	      -o $(TARGET)_afl $(SRCS)

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl
