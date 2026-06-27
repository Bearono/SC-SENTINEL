# SENTINEL Agent D generated Makefile - Part 4.1
#
# This Makefile fixes the -Dmain problem:
# - target source is compiled with -Dmain=sentinel_original_main
# - harness source is compiled without -Dmain
#
# Linux / WSL2 / Docker recommended.

TARGET_SRC ?= D:/SC-SENTINEL/sentinel_agent/samples/level2_testset/02_png_uaf/src/png_loader.c
TARGET_ROOT ?= /sentinel-work/target
CC ?= clang
AFL_CC ?= afl-clang

COMMON_FLAGS ?= -g -O0 -fsanitize=address -fno-omit-frame-pointer -I$(TARGET_ROOT)/include -I$(TARGET_ROOT)/src
TARGET_RENAME_MAIN ?= -Dmain=sentinel_original_main
PROJECT_OBJECTS ?= src_main.o src_png_loader.o

.PHONY: all asan afl libfuzzer clean run-asan run-afl

all: asan

src_main.o:
	$(CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c $(TARGET_ROOT)/src/main.c -o src_main.o
src_png_loader.o:
	$(CC) $(COMMON_FLAGS) -c $(TARGET_ROOT)/src/png_loader.c -o src_png_loader.o

harness_asan.o:
	$(CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_asan.o

asan: src_main.o src_png_loader.o harness_asan.o
	$(CC) $(COMMON_FLAGS) harness_asan.o src_main.o src_png_loader.o -o asan_target

src_main.afl.o:
	$(AFL_CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c $(TARGET_ROOT)/src/main.c -o src_main.afl.o
src_png_loader.afl.o:
	$(AFL_CC) $(COMMON_FLAGS) -c $(TARGET_ROOT)/src/png_loader.c -o src_png_loader.afl.o

harness_afl.o:
	$(AFL_CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_afl.o

afl: src_main.afl.o src_png_loader.afl.o harness_afl.o
	$(AFL_CC) $(COMMON_FLAGS) harness_afl.o src_main.afl.o src_png_loader.afl.o -o afl_target

src_main.fuzz.o:
	$(CC) -g -O0 -fsanitize=fuzzer-no-link,address $(TARGET_RENAME_MAIN) -c $(TARGET_ROOT)/src/main.c -o src_main.fuzz.o
src_png_loader.fuzz.o:
	$(CC) -g -O0 -fsanitize=fuzzer-no-link,address -c $(TARGET_ROOT)/src/png_loader.c -o src_png_loader.fuzz.o

harness_libfuzzer.o:
	$(CC) -g -O0 -fsanitize=fuzzer-no-link,address -c libfuzzer_harness.c -o harness_libfuzzer.o

libfuzzer: src_main.fuzz.o src_png_loader.fuzz.o harness_libfuzzer.o
	$(CC) -g -O0 -fsanitize=fuzzer,address harness_libfuzzer.o src_main.fuzz.o src_png_loader.fuzz.o -o libfuzzer_target

run-asan: asan
	./asan_target seeds/seed_001.bin

run-afl: afl
	afl-fuzz -i seeds -o findings -- ./afl_target @@

clean:
	rm -f *.o *.afl.o *.fuzz.o asan_target afl_target libfuzzer_target
	rm -rf findings/default findings/*/queue findings/*/crashes findings/*/hangs
