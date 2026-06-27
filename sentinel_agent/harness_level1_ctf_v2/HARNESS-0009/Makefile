# SENTINEL Agent D generated Makefile - Part 4.1
#
# This Makefile fixes the -Dmain problem:
# - target source is compiled with -Dmain=sentinel_original_main
# - harness source is compiled without -Dmain
#
# Linux / WSL2 / Docker recommended.

TARGET_SRC ?= ../../samples/vulnerable_project/heap_overflow_integer_trunc.c
CC ?= clang
AFL_CC ?= afl-clang

COMMON_FLAGS ?= -g -O1 -fsanitize=address -fno-omit-frame-pointer
TARGET_RENAME_MAIN ?= -Dmain=sentinel_original_main

.PHONY: all asan afl libfuzzer clean run-asan run-afl

all: asan

target_asan.o:
	$(CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c $(TARGET_SRC) -o target_asan.o

harness_asan.o:
	$(CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_asan.o

asan: target_asan.o harness_asan.o
	$(CC) $(COMMON_FLAGS) harness_asan.o target_asan.o -o asan_target

target_afl.o:
	$(AFL_CC) $(COMMON_FLAGS) $(TARGET_RENAME_MAIN) -c $(TARGET_SRC) -o target_afl.o

harness_afl.o:
	$(AFL_CC) $(COMMON_FLAGS) -c afl_harness.c -o harness_afl.o

afl: target_afl.o harness_afl.o
	$(AFL_CC) $(COMMON_FLAGS) harness_afl.o target_afl.o -o afl_target

target_libfuzzer.o:
	$(CC) -g -O1 -fsanitize=fuzzer-no-link,address $(TARGET_RENAME_MAIN) -c $(TARGET_SRC) -o target_libfuzzer.o

harness_libfuzzer.o:
	$(CC) -g -O1 -fsanitize=fuzzer-no-link,address -c libfuzzer_harness.c -o harness_libfuzzer.o

libfuzzer: target_libfuzzer.o harness_libfuzzer.o
	$(CC) -g -O1 -fsanitize=fuzzer,address harness_libfuzzer.o target_libfuzzer.o -o libfuzzer_target

run-asan: asan
	./asan_target seeds/seed_001.bin

run-afl: afl
	afl-fuzz -i seeds -o findings -- ./afl_target @@

clean:
	rm -f *.o asan_target afl_target libfuzzer_target
	rm -rf findings/default findings/*/queue findings/*/crashes findings/*/hangs
