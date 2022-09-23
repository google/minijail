/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <asm/unistd.h>

/* Ideally minijail is compiled against a modern libc, which has modern copies
 * of Linux uapi for ioctls, and unistd.h for syscalls. However, sometimes this
 * isn't possible - such as when building with the Android host toolchain - so
 * locally define the system calls in use in active seccomp policy files.
 * This UAPI is taken from sanitized bionic headers.
 */

#ifndef __NR_copy_file_range
#ifdef __x86_64__
#define __NR_copy_file_range 326
#elif __i386__
#define __NR_copy_file_range 377
#elif __arm64__
#define __NR_copy_file_range 285
#endif
#endif /* __NR_copy_file_range */

#ifndef __NR_getrandom
#ifdef __x86_64__
#define __NR_getrandom 318
#elif __i386__
#define __NR_getrandom 355
#elif __arm64__
#define __NR_getrandom 278
#endif
#endif /* __NR_getrandom */

#ifndef __NR_memfd_create
#ifdef __x86_64__
#define __NR_memfd_create 319
#elif __i386__
#define __NR_memfd_create 356
#elif __arm64__
#define __NR_memfd_create 279
#endif
#endif /* __NR_memfd_create */

#ifndef __NR_renameat2
#ifdef __x86_64__
#define __NR_renameat2 316
#elif __i386__
#define __NR_renameat2 353
#elif __arm64__
#define __NR_renameat2 276
#endif
#endif /* __NR_renameat2 */

#ifndef __NR_statx
#ifdef __x86_64__
#define __NR_statx 332
#elif __i386__
#define __NR_statx 383
#elif __arm64__
#define __NR_statx 291
#endif
#endif /* __NR_statx */

#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

#ifndef __NR_rseq
#ifdef __x86_64__
#define __NR_rseq 334
#elif __i386__
#define __NR_rseq 386
#elif __arm64__
#define __NR_rseq 293
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#endif /* __NR_rseq */
