/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "syscall_wrapper.h"

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Older glibc builds predate seccomp inclusion.  These arches are the ones
 * AOSP needs and doesn't provide anything newer.  All other targets can upgrade
 * their kernel headers.
 */
#ifndef SYS_seccomp
# if defined(__x86_64__)
#  define SYS_seccomp 317
# elif defined(__i386__)
#  define SYS_seccomp 354
# elif defined(__aarch64__)
#  define SYS_seccomp 277
# elif defined(__arm__)
#  define SYS_seccomp 383
# else
#  error "Update your kernel headers"
# endif
#endif

int sys_seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(SYS_seccomp, operation, flags, args);
}
