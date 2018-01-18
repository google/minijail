/* util.h
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Logging and other utility functions.
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(USE_EXIT_ON_DIE)
#define do_abort() exit(1)
#else
#define do_abort() abort()
#endif

/* clang-format off */
#define die(_msg, ...) do { \
	do_log(LOG_ERR, "libminijail[%d]: " _msg, getpid(), ## __VA_ARGS__); \
	do_abort(); \
} while (0)

#define pdie(_msg, ...) \
	die(_msg ": %m", ## __VA_ARGS__)

#define warn(_msg, ...) \
	do_log(LOG_WARNING, "libminijail[%d]: " _msg, getpid(), ## __VA_ARGS__)

#define pwarn(_msg, ...) \
	warn(_msg ": %m", ## __VA_ARGS__)

#define info(_msg, ...) \
	do_log(LOG_INFO, "libminijail[%d]: " _msg, getpid(), ## __VA_ARGS__)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/* clang-format on */

extern const char *log_syscalls[];
extern const size_t log_syscalls_len;

enum logging_system_t {
	/* Log to syslog. This is the default. */
	LOG_TO_SYSLOG = 0,

	/* Log to a file descriptor. */
	LOG_TO_FD,
};

extern void do_log(int priority, const char *format, ...)
    __attribute__((__format__(__printf__, 2, 3)));

static inline int is_android(void)
{
#if defined(__ANDROID__)
	return 1;
#else
	return 0;
#endif
}

void __asan_init(void) __attribute__((weak));

static inline int running_with_asan(void)
{
	return &__asan_init != 0;
}

int lookup_syscall(const char *name);
const char *lookup_syscall_name(int nr);

long int parse_constant(char *constant_str, char **endptr);
int parse_size(size_t *size, const char *sizespec);

char *strip(char *s);

/*
 * tokenize: locate the next token in @stringp using the @delim
 * @stringp A pointer to the string to scan for tokens
 * @delim   The delimiter to split by
 *
 * Note that, unlike strtok, @delim is not a set of characters, but the full
 * delimiter.  e.g. "a,;b,;c" with a delim of ",;" will yield ["a","b","c"].
 *
 * Note that, unlike strtok, this may return an empty token.  e.g. "a,,b" with
 * strtok will yield ["a","b"], but this will yield ["a","","b"].
 */
char *tokenize(char **stringp, const char *delim);

char *path_join(const char *external_path, const char *internal_path);

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

/*
 * init_logging: initializes the module-wide logging.
 * @logger       The logging system to use.
 * @fd           The file descriptor to log into. Ignored unless
 *               @logger = LOG_TO_FD.
 * @min_priority The minimum priority to display. Corresponds to syslog's
                 priority parameter. Ignored unless @logger = LOG_TO_FD.
 */
void init_logging(enum logging_system_t logger, int fd, int min_priority);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _UTIL_H_ */
