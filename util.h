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
#include <syslog.h>

#define die(_msg, ...) do { \
	syslog(LOG_ERR, "libminijail: " _msg, ## __VA_ARGS__); \
	abort(); \
} while (0)

#define pdie(_msg, ...) \
	die(_msg ": %m", ## __VA_ARGS__)

#define warn(_msg, ...) \
	syslog(LOG_WARNING, "libminijail: " _msg, ## __VA_ARGS__)

#define info(_msg, ...) \
	syslog(LOG_INFO, "libminijail: " _msg, ## __VA_ARGS__)

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

#endif /* _UTIL_H_ */
