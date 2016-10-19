# Copyright 2016 Ben Trask
# MIT licensed (see LICENSE for details)

DESTDIR ?=
PREFIX ?= /usr/local

ROOT_DIR := .
BUILD_DIR := $(ROOT_DIR)/build
DEPS_DIR := $(ROOT_DIR)/deps
SRC_DIR := $(ROOT_DIR)/src
INCLUDE_DIR := $(ROOT_DIR)/include

CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=500
CFLAGS += -fPIC
CFLAGS += -g -fno-omit-frame-pointer
CFLAGS += -DLIBCO_MP
CFLAGS += -fstack-protector
CFLAGS += -DHAVE_TIMEGM -DMAP_ANON -I$(DEPS_DIR)/libressl-portable/include/compat
CFLAGS += -iquote $(DEPS_DIR)


WARNINGS := -Werror -Wall -Wextra -Wunused -Wuninitialized -Wvla

# TODO: Unsupported under Clang.
#WARNINGS += -Wlogical-op

# Disabled because it causes a lot of problems on Raspbian (GCC 4.6.3)
# without much perceivable benefit.
#WARNINGS += -Wshadow

# TODO: Useful with GCC but Clang doesn't like it.
#WARNINGS += -Wmaybe-uninitialized

# Causes all string literals to be marked const.
# This would be way too annoying if we don't use const everywhere already.
# The only problem is uv_buf_t, which is const sometimes and not others.
WARNINGS += -Wwrite-strings

# A function's interface is an abstraction and shouldn't strictly reflect
# its implementation. I don't believe in cluttering the code with UNUSED(X).
WARNINGS += -Wno-unused-parameter

# Seems too noisy for static functions in headers.
WARNINGS += -Wno-unused-function

# For OS X.
WARNINGS += -Wno-deprecated

# Checking that an unsigned variable is less than a constant which happens
# to be zero should be okay.
WARNINGS += -Wno-type-limits

# Usually happens for a ssize_t after already being checked for non-negative,
# or a constant that I don't want to stick a "u" on.
WARNINGS += -Wno-sign-compare

# Checks that format strings are literals amongst other things.
WARNINGS += -Wformat=2


RAW_OBJECTS := $(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/http/*.c)
OBJECTS := $(subst $(SRC_DIR),$(BUILD_DIR)/src,$(RAW_OBJECTS))
OBJECTS := $(subst .c,.o,$(OBJECTS))

OBJECTS += $(BUILD_DIR)/deps/http_parser/http_parser.o
OBJECTS += $(BUILD_DIR)/deps/multipart_parser.o

ifdef USE_VALGRIND
OBJECTS += $(BUILD_DIR)/deps/libcoro/coro.o $(BUILD_DIR)/util/libco_coro.o
CFLAGS += -DCORO_USE_VALGRIND
else
OBJECTS += $(BUILD_DIR)/deps/libco/libco.o
endif


SHARED_OBJECTS += $(DEPS_DIR)/uv/.libs/libuv.so

SHARED_OBJECTS += $(DEPS_DIR)/libressl-portable/tls/.libs/libtls.so
SHARED_OBJECTS += $(DEPS_DIR)/libressl-portable/ssl/.libs/libssl.so
SHARED_OBJECTS += $(DEPS_DIR)/libressl-portable/crypto/.libs/libcrypto.so
CFLAGS += -I$(DEPS_DIR)/libressl-portable/include

RAW_HEADERS := $(wildcard $(SRC_DIR)/*.h $(SRC_DIR)/http/*.h)
HEADERS := $(subst $(SRC_DIR),$(INCLUDE_DIR)/async,$(RAW_HEADERS))

all: $(BUILD_DIR)/libasync.so $(BUILD_DIR)/libasync.a $(HEADERS)

$(BUILD_DIR)/libasync.so: $(OBJECTS) $(SHARED_OBJECTS)
	@- mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared $^ -o $@

$(BUILD_DIR)/libasync.a: $(OBJECTS)
	@- mkdir -p $(dir $@)
	$(AR) rs $@ $^

$(BUILD_DIR)/src/%.o: $(SRC_DIR)/%.c
	@- mkdir -p $(dir $@)
	@- mkdir -p $(dir $(BUILD_DIR)/h/src/$*.d)
	$(CC) -c $(CFLAGS) $(WARNINGS) -MMD -MP -MF $(BUILD_DIR)/h/src/$*.d $< -o $@

# TODO: Find files in subdirectories without using shell?
-include $(shell find $(BUILD_DIR)/h -name "*.d")

$(INCLUDE_DIR)/async/%.h: $(SRC_DIR)/%.h
	@- mkdir -p $(dir $@)
	cp $^ $@

$(BUILD_DIR)/tools/async-curl: $(ROOT_DIR)/tools/async-curl.c $(BUILD_DIR)/libasync.a $(HEADERS)
	@- mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(WARNINGS) -I$(INCLUDE_DIR) -iquote $(DEPS_DIR) -I$(DEPS_DIR)/libressl-portable/include $(ROOT_DIR)/tools/async-curl.c $(BUILD_DIR)/libasync.a $(DEPS_DIR)/libressl-portable/tls/.libs/libtls.a $(DEPS_DIR)/libressl-portable/ssl/.libs/libssl.a $(DEPS_DIR)/libressl-portable/crypto/.libs/libcrypto.a $(DEPS_DIR)/uv/.libs/libuv.a -lpthread -o $@

.PHONY: async-curl
async-curl: $(BUILD_DIR)/tools/async-curl

.PHONY: tools
tools: async-curl

.PHONY: install-root-certs
install-root-certs:
	@- mkdir -p $(dir $(DESTDIR)$(PREFIX)/etc/ssl/cert.pem)
	install $(DEPS_DIR)/libressl-portable/apps/openssl/cert.pem $(DESTDIR)$(PREFIX)/etc/ssl/cert.pem

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(INCLUDE_DIR)

.PHONY: distclean
distclean: clean
	- $(MAKE) distclean -C $(DEPS_DIR)/libressl-portable
	- $(MAKE) distclean -C $(DEPS_DIR)/uv

$(DEPS_DIR)/libressl-portable/crypto/.libs/libcrypto.so: | libressl
$(DEPS_DIR)/libressl-portable/ssl/.libs/libssl.so: | libressl
$(DEPS_DIR)/libressl-portable/tls/.libs/libtls.so: | libressl
.PHONY: libressl
libressl:
	$(MAKE) -C $(DEPS_DIR)/libressl-portable --no-print-directory

$(DEPS_DIR)/uv/.libs/libuv.so: | libuv
.PHONY: libuv
libuv:
	$(MAKE) -C $(DEPS_DIR)/uv --no-print-directory
#	$(MAKE) -C $(DEPS_DIR)/uv check --no-print-directory

$(BUILD_DIR)/deps/libco/%.o: $(DEPS_DIR)/libco/%.c $(DEPS_DIR)/libco/libco.h
	@- mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -Wno-parentheses -o $@ $<

$(BUILD_DIR)/deps/libcoro/%.o: $(DEPS_DIR)/libcoro/%.c $(DEPS_DIR)/libcoro/coro.h
	@- mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -std=gnu99 -o $@ $<

$(BUILD_DIR)/deps/http_parser/http_parser.o: $(DEPS_DIR)/http_parser/http_parser.c $(DEPS_DIR)/http_parser/http_parser.h
	@- mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -o $@ $<

$(BUILD_DIR)/deps/multipart_parser.o: $(DEPS_DIR)/multipart-parser-c/multipart_parser.c $(DEPS_DIR)/multipart-parser-c/multipart_parser.h
	@- mkdir -p $(dir $@)
	$(CC) -c -std=c89 -ansi -pedantic -fPIC $(WARNINGS) -o $@ $<

