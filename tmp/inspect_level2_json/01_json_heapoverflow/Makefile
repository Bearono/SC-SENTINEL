# ─────────────────────────────────────────────────────────────────────────────
# microjson — POSIX Makefile
#
# Vulnerability: CWE-122 Heap Buffer Overflow (CVE-2019-11834 inspired)
# Build targets:
#   make           release build
#   make asan      AddressSanitizer build (vulnerability verification)
#   make afl       AFL++ instrumented build (fuzzing)
#   make test      run regression cases against seeds/
#   make install   install to $(DESTDIR)$(PREFIX)
# ─────────────────────────────────────────────────────────────────────────────

CC      ?= gcc
AFLCC   ?= afl-clang-fast
PREFIX  ?= /usr/local
CFLAGS  := -Iinclude -Wall -Wextra -Wno-unused-parameter
SRCS    := src/json_parser.c src/main.c
TARGET  := json_parser

# Optional OpenSSL linkage (for the JWT extension). Set MICROJSON_JWT=1.
ifeq ($(MICROJSON_JWT),1)
    CFLAGS += -DMICROJSON_HAVE_JWT=1 $(shell pkg-config --cflags openssl)
    LDLIBS += $(shell pkg-config --libs openssl)
endif

.PHONY: all normal asan afl test clean install

all: normal

normal:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS) $(LDLIBS)

asan:
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g -O0 \
	      -o $(TARGET)_asan $(SRCS) $(LDLIBS)

afl:
	$(AFLCC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g -O1 \
	      -o $(TARGET)_afl $(SRCS) $(LDLIBS)

test: normal
	@echo "Running regression tests..."
	@for s in seeds/seed_01.json seeds/seed_02.json seeds/seed_03.json; do \
	    printf "  %-30s " $$s;                                            \
	    timeout 5 ./$(TARGET) $$s > /dev/null && echo OK || echo "exit=$$?"; \
	done

install: normal
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/include/microjson
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	install -m 644 include/json_parser.h $(DESTDIR)$(PREFIX)/include/microjson/

clean:
	rm -f $(TARGET) $(TARGET)_asan $(TARGET)_afl
	rm -rf out findings build
