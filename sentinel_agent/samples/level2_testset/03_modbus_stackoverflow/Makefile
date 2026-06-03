# Makefile for modbus_proto
# Vulnerability: CWE-121 Stack-based Buffer Overflow (CVE-2022-0367 / CVE-2024-10918 inspired)

CC     ?= gcc
CFLAGS := -Iinclude -Wall -Wextra
SRCS   := src/modbus_proto.c src/main.c
TARGET := modbus_parser

.PHONY: all normal asan afl clean

all: normal

normal:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS)

asan:
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer \
	      -g -O0 -o $(TARGET)_asan $(SRCS)

# afl-fuzz -i seeds/ -o out/ -- ./modbus_parser_afl @@
afl:
	afl-clang-fast $(CFLAGS) -fsanitize=address \
	      -fno-omit-frame-pointer -g -O1 \
	      -o $(TARGET)_afl $(SRCS)

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl
