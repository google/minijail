/* Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "syscall_wrapper.h"

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

int sys_seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(SYS_seccomp, operation, flags, args);
}
