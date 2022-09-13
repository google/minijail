/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef _SYSCALL_WRAPPER_H_
#define _SYSCALL_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Seccomp filter related flags. */
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2 /* Uses user-supplied filter. */
#endif

#ifndef SECCOMP_SET_MODE_STRICT
# define SECCOMP_SET_MODE_STRICT 0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
# define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
# define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
# define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1 << 2)
#endif
/* End seccomp filter related flags. */

int sys_seccomp(unsigned int operation, unsigned int flags, void *args);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _SYSCALL_WRAPPER_H_ */
