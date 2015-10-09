# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

LIBDIR = lib
PRELOADNAME = libminijailpreload.so
PRELOADPATH = \"/$(LIBDIR)/$(PRELOADNAME)\"
CPPFLAGS += -DPRELOADPATH="$(PRELOADPATH)"

ifneq ($(HAVE_SECUREBITS_H),no)
CPPFLAGS += -DHAVE_SECUREBITS_H
endif
ifneq ($(USE_seccomp),yes)
CPPFLAGS += -DUSE_SECCOMP_SOFTFAIL
endif

all: CC_BINARY(minijail0) CC_LIBRARY(libminijail.so) \
		CC_LIBRARY(libminijailpreload.so)

# TODO(jorgelo): convert to TEST().
tests: CC_BINARY(libminijail_unittest) CC_BINARY(syscall_filter_unittest)

CC_BINARY(minijail0): LDLIBS += -lcap -ldl
CC_BINARY(minijail0): libconstants.gen.o libsyscalls.gen.o libminijail.o \
		syscall_filter.o signal_handler.o bpf.o util.o elfparse.o minijail0.o
clean: CLEAN(minijail0)

CC_LIBRARY(libminijail.so): LDLIBS += -lcap
CC_LIBRARY(libminijail.so): libminijail.o syscall_filter.o signal_handler.o \
    bpf.o util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(libminijail.so)

CC_BINARY(libminijail_unittest): LDLIBS += -lcap
CC_BINARY(libminijail_unittest): libminijail_unittest.o libminijail.o \
		syscall_filter.o signal_handler.o bpf.o util.o libconstants.gen.o \
		libsyscalls.gen.o
clean: CLEAN(libminijail_unittest)

CC_LIBRARY(libminijailpreload.so): LDLIBS += -lcap -ldl
CC_LIBRARY(libminijailpreload.so): libminijailpreload.o libminijail.o \
		libconstants.gen.o libsyscalls.gen.o syscall_filter.o signal_handler.o \
		bpf.o util.o
clean: CLEAN(libminijailpreload.so)

CC_BINARY(syscall_filter_unittest): syscall_filter_unittest.o syscall_filter.o \
		bpf.o util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(syscall_filter_unittest)

libsyscalls.gen.o: CPPFLAGS += -I$(SRC)

libsyscalls.gen.o.depends: libsyscalls.gen.c

# Only regenerate libsyscalls.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
# TODO(jorgelo): fix generation when 'CC' env variable is not set.
libsyscalls.gen.c: $(SRC)/Makefile $(SRC)/libsyscalls.h
	@printf "Generating target-arch specific $@... "
	$(QUIET)$(SRC)/gen_syscalls.sh $@
	@printf "done.\n"
clean: CLEAN(libsyscalls.gen.c)

$(eval $(call add_object_rules,libsyscalls.gen.o,CC,c,CFLAGS))

libconstants.gen.o: CPPFLAGS += -I$(SRC)

libconstants.gen.o.depends: libconstants.gen.c

# Only regenerate libconstants.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
# TODO(jorgelo): fix generation when 'CC' env variable is not set.
libconstants.gen.c: $(SRC)/Makefile $(SRC)/libconstants.h
	@printf "Generating target-arch specific $@... "
	$(QUIET)$(SRC)/gen_constants.sh $@
	@printf "done.\n"
clean: CLEAN(libconstants.gen.c)

$(eval $(call add_object_rules,libconstants.gen.o,CC,c,CFLAGS))
