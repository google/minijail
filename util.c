/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

#include "libconstants.h"
#include "libsyscalls.h"

/*
 * These are syscalls used by the syslog() C library call.  You can find them
 * by running a simple test program.  See below for x86_64 behavior:
 * $ cat test.c
 * #include <syslog.h>
 * main() { syslog(0, "foo"); }
 * $ gcc test.c -static
 * $ strace ./a.out
 * ...
 * socket(PF_FILE, SOCK_DGRAM|SOCK_CLOEXEC, 0) = 3 <- look for socket connection
 * connect(...)                                    <- important
 * sendto(...)                                     <- important
 * exit_group(0)                                   <- finish!
 */
#if defined(__x86_64__)
#if defined(__ANDROID__)
const char *log_syscalls[] = {"socket", "connect", "fcntl", "writev"};
#else
const char *log_syscalls[] = {"connect", "sendto"};
#endif
#elif defined(__i386__)
#if defined(__ANDROID__)
const char *log_syscalls[] = {"socketcall", "writev", "fcntl64",
			      "clock_gettime"};
#else
const char *log_syscalls[] = {"socketcall", "time"};
#endif
#elif defined(__arm__)
#if defined(__ANDROID__)
const char *log_syscalls[] = {"clock_gettime", "connect", "fcntl64", "socket",
			      "writev"};
#else
const char *log_syscalls[] = {"connect", "gettimeofday", "send"};
#endif
#elif defined(__aarch64__)
#if defined(__ANDROID__)
const char *log_syscalls[] = {"connect", "fcntl", "sendto", "socket", "writev"};
#else
const char *log_syscalls[] = {"connect", "send"};
#endif
#elif defined(__powerpc__) || defined(__ia64__) || defined(__hppa__) ||        \
      defined(__sparc__) || defined(__mips__)
const char *log_syscalls[] = {"connect", "send"};
#else
#error "Unsupported platform"
#endif

const size_t log_syscalls_len = sizeof(log_syscalls)/sizeof(log_syscalls[0]);

long int parse_single_constant(char *constant_str, char **endptr);

int lookup_syscall(const char *name)
{
	const struct syscall_entry *entry = syscall_table;
	for (; entry->name && entry->nr >= 0; ++entry)
		if (!strcmp(entry->name, name))
			return entry->nr;
	return -1;
}

const char *lookup_syscall_name(int nr)
{
	const struct syscall_entry *entry = syscall_table;
	for (; entry->name && entry->nr >= 0; ++entry)
		if (entry->nr == nr)
			return entry->name;
	return NULL;
}

long int parse_constant(char *constant_str, char **endptr)
{
	long int value = 0;
	char *group, *lastpos = constant_str;
	char *original_constant_str = constant_str;

	/*
	 * Try to parse constants separated by pipes.  Note that since
	 * |constant_str| is an atom, there can be no spaces between the
	 * constant and the pipe.  Constants can be either a named constant
	 * defined in libconstants.gen.c or a number parsed with strtol.
	 *
	 * If there is an error parsing any of the constants, the whole process
	 * fails.
	 */
	while ((group = tokenize(&constant_str, "|")) != NULL) {
		char *end = group;
		value |= parse_single_constant(group, &end);
		if (end == group) {
			lastpos = original_constant_str;
			value = 0;
			break;
		}
		lastpos = end;
	}
	if (endptr)
		*endptr = lastpos;
	return value;
}

long int parse_single_constant(char *constant_str, char **endptr)
{
	const struct constant_entry *entry = constant_table;
	for (; entry->name; ++entry) {
		if (!strcmp(entry->name, constant_str)) {
			if (endptr)
				*endptr = constant_str + strlen(constant_str);

			return entry->value;
		}
	}

	return strtol(constant_str, endptr, 0);
}

char *strip(char *s)
{
	char *end;
	while (*s && isblank(*s))
		s++;
	end = s + strlen(s) - 1;
	while (end >= s && *end && (isblank(*end) || *end == '\n'))
		end--;
	*(end + 1) = '\0';
	return s;
}

char *tokenize(char **stringp, const char *delim)
{
	char *ret = NULL;

	/* If the string is NULL or empty, there are no tokens to be found. */
	if (stringp == NULL || *stringp == NULL || **stringp == '\0')
		return NULL;

	/*
	 * If the delimiter is NULL or empty,
	 * the full string makes up the only token.
	 */
	if (delim == NULL || *delim == '\0') {
		ret = *stringp;
		*stringp = NULL;
		return ret;
	}

	char *found;
	while (**stringp != '\0') {
		found = strstr(*stringp, delim);

		if (!found) {
			/*
			 * The delimiter was not found, so the full string
			 * makes up the only token, and we're done.
			 */
			ret = *stringp;
			*stringp = NULL;
			break;
		}

		if (found != *stringp) {
			/* There's a non-empty token before the delimiter. */
			*found = '\0';
			ret = *stringp;
			*stringp = found + strlen(delim);
			break;
		}

		/*
		 * The delimiter was found at the start of the string,
		 * skip it and keep looking for a non-empty token.
		 */
		*stringp += strlen(delim);
	}

	return ret;
}
