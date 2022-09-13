/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef MINIJAIL_LIBSYSCALLS_H_
#define MINIJAIL_LIBSYSCALLS_H_
#include <sys/types.h>

struct syscall_entry {
	const char *name;
	int nr;
};

extern const struct syscall_entry syscall_table[];
extern const size_t syscall_table_size;

#endif /* MINIJAIL_LIBSYSCALLS_H_ */
