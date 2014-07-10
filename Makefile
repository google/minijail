# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

LIBDIR = lib
PRELOADNAME = libminijailpreload.so
PRELOADPATH = \"/$(LIBDIR)/$(PRELOADNAME)\"
CFLAGS += -fPIC -Wall -Wextra -Werror -DPRELOADPATH="$(PRELOADPATH)"
CFLAGS += -fvisibility=internal

ifneq ($(HAVE_SECUREBITS_H),no)
CFLAGS += -DHAVE_SECUREBITS_H
endif

all : minijail0 libminijail.so libminijailpreload.so

tests : libminijail_unittest.wrapper syscall_filter_unittest

minijail0 : libsyscalls.gen.o libminijail.o syscall_filter.o \
		signal.o bpf.o util.o elfparse.o minijail0.c
	$(CC) $(CFLAGS) -o $@ $^ -lcap -ldl

libminijail.so : libminijail.o syscall_filter.o signal.o bpf.o util.o \
		libsyscalls.gen.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -lcap

# Allow unittests to access what are normally internal symbols.
libminijail_unittest.wrapper :
	$(MAKE) $(MAKEARGS) test-clean
	$(MAKE) $(MAKEARGS) libminijail_unittest
	$(MAKE) $(MAKEARGS) test-clean

libminijail_unittest : CFLAGS := $(filter-out -fvisibility=%,$(CFLAGS))
libminijail_unittest : CFLAGS := $(filter-out -DPRELOADPATH=%,$(CFLAGS))
libminijail_unittest : CFLAGS := $(CFLAGS) -DPRELOADPATH=\"./$(PRELOADNAME)\"
libminijail_unittest : libminijail_unittest.o libminijail.o \
		syscall_filter.o signal.o bpf.o util.o libsyscalls.gen.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(filter-out $(CFLAGS_FILE),$^) -lcap

libminijailpreload.so : libminijailpreload.c libminijail.o libsyscalls.gen.o \
		syscall_filter.o signal.o bpf.o util.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -ldl -lcap

libminijail.o : libminijail.c libminijail.h

libminijail_unittest.o : libminijail_unittest.c test_harness.h
	$(CC) $(CFLAGS) -c -o $@ $<

libsyscalls.gen.o : libsyscalls.gen.c libsyscalls.h

syscall_filter_unittest : syscall_filter_unittest.o syscall_filter.o \
		bpf.o util.o libsyscalls.gen.o
	$(CC) $(CFLAGS) -o $@ $^

syscall_filter_unittest.o : syscall_filter_unittest.c test_harness.h
	$(CC) $(CFLAGS) -c -o $@ $<

syscall_filter.o : syscall_filter.c syscall_filter.h

signal.o : signal.c signal.h

bpf.o : bpf.c bpf.h

util.o : util.c util.h

elfparse.o : elfparse.c elfparse.h

# Only regenerate libsyscalls.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
libsyscalls.gen.c : Makefile libsyscalls.h
	@printf "Generating target-arch specific $@ . . . "
	@./gen_syscalls.sh $@
	@printf "done.\n"

# Only clean up files affected by the CFLAGS change for testing.
test-clean :
	@rm -f libminijail.o libminijail_unittest.o

clean : test-clean
	@rm -f libminijail.o libminijailpreload.so minijail0
	@rm -f libminijail.so
	@rm -f libminijail_unittest
	@rm -f libsyscalls.gen.o libsyscalls.gen.c
	@rm -f syscall_filter.o signal.o bpf.o util.o elfparse.o
	@rm -f syscall_filter_unittest syscall_filter_unittest.o
