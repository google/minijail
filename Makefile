# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PRELOADPATH ?= \"/lib/libminijailpreload.so\"
CFLAGS += -fPIC -Wall -Wextra -Werror -DPRELOADPATH="$(PRELOADPATH)"

all : minijail0 libminijail.so libminijailpreload.so

minijail0 : libminijail.o minijail0.c
	$(CC) $(CFLAGS) -o $@ $^ -lcap

libminijail.so : libminijail.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -lcap

libminijailpreload.so : libminijailpreload.c libminijail.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -ldl -lcap

libminijail.o : libminijail.c libminijail.h libsyscalls.h

# sed expression which extracts system calls that are
# defined via asm/unistd.h.  It converts them from:
#  #define __NR_read		42
# to:
#  { "read", __NR_read },
# All other lines will be deleted.
# The sed expression lives in its own macro to allow clean
# line wrapping. Thanks, make!
define sed-multiline
	's/#define \(__NR_\)\(.*\)$$/  { "\2", \1\2 },/g; \
	/^\(#\|$$\)/ d;'
endef

# Generates a header file with a system call table
# made up of "name", syscall_nr entries by including
# the build target <asm/unistd.h> and emitting the list
# of defines.  Use of the compiler is needed to dereference
# the actual provider of syscall definitions.
#   E.g., asm/unistd_32.h or asm/unistd_64.h, etc.
define gen_syscalls
	(set -e; \
	 echo "#ifndef MINIJAIL_LIBSYSCALL_H_ "; \
	 echo "#define MINIJAIL_LIBSYSCALL_H_"; \
	 echo "struct syscall_entry {"; \
	 echo "  const char *name;"; \
	 echo "  int nr;"; \
	 echo "};"; \
	 echo "struct syscall_entry syscall_table[] = {"; \
	 echo "#include <asm/unistd.h>" | \
	   $(CC) $(CFLAGS) -dN - -E | sed -e $(sed-multiline); \
	 echo "  { NULL, -1 },"; \
	 echo "};"; \
	 echo "#endif" ) > $1
endef

libsyscalls.h :
	@printf "Generating target-arch specific libsyscalls.h . . . "
	@$(call gen_syscalls,$@)
	@printf "done.\n"

clean :
	@rm -f libminijail.o libminijailpreload.so libsyscalls.h minijail0
