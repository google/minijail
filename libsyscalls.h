/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
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

#endif  /* MINIJAIL_LIBSYSCALLS_H_ */
