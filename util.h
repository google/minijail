/* util.h
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Logging and other utility functions.
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define die(_msg, ...) do { \
	syslog(LOG_ERR, "libminijail[%d]: " _msg, getpid(), ## __VA_ARGS__); \
	abort(); \
} while (0)

#define pdie(_msg, ...) \
	die(_msg ": %m", ## __VA_ARGS__)

#define warn(_msg, ...) \
	syslog(LOG_WARNING, "libminijail[%d]: " _msg, getpid(), ## __VA_ARGS__)

#define pwarn(_msg, ...) \
	warn(_msg ": %m", ## __VA_ARGS__)

#define info(_msg, ...) \
	syslog(LOG_INFO, "libminijail[%d]: " _msg, getpid(), ## __VA_ARGS__)

extern const char *log_syscalls[];
extern const size_t log_syscalls_len;

static inline int is_android() {
#if defined(__ANDROID__)
	return 1;
#else
	return 0;
#endif
}

static inline int running_with_asan() {
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(address_sanitizer)
	return 1;
#else
	return 0;
#endif
}

int lookup_syscall(const char *name);
const char *lookup_syscall_name(int nr);

long int parse_constant(char *constant_str, char **endptr);

char *strip(char *s);
char *tokenize(char **stringp, const char *delim);

int kernel_lessthan_3_8();

char *path_join(const char *external_path, const char *internal_path);
int write_proc_file(pid_t pid, const char *content, const char *basename);
int write_pid_to_path(pid_t pid, const char *path);

/*
 * consumebytes: consumes @length bytes from a buffer @buf of length @buflength
 * @length    Number of bytes to consume
 * @buf       Buffer to consume from
 * @buflength Size of @buf
 *
 * Returns a pointer to the base of the bytes, or NULL for errors.
 */
void *consumebytes(size_t length, char **buf, size_t *buflength);

/*
 * consumestr: consumes a C string from a buffer @buf of length @length
 * @buf    Buffer to consume
 * @length Length of buffer
 *
 * Returns a pointer to the base of the string, or NULL for errors.
 */
char *consumestr(char **buf, size_t *buflength);

#endif /* _UTIL_H_ */
