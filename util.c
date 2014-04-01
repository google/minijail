/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ctype.h>
#include <string.h>

#include "util.h"

#include "libsyscalls.h"

/*
 * These are syscalls used by the syslog() C library call.  You can find them
 * by running a simple test program.  See below for x86_64 behavior:
 * $ cat test.c
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
const char *log_syscalls[] = { "connect", "sendto" };
#elif defined(__i386__)
const char *log_syscalls[] = { "socketcall", "time" };
#elif defined(__arm__)
const char *log_syscalls[] = { "connect", "gettimeofday", "send" };
#elif defined(__powerpc__) || defined(__ia64__) || defined(__hppa__) || \
      defined(__sparc__) || defined(__mips__)
const char *log_syscalls[] = { "connect", "send" };
#else
#error "Unsupported platform"
#endif

const size_t log_syscalls_len = sizeof(log_syscalls)/sizeof(log_syscalls[0]);

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

char *tokenize(char **stringp, const char *delim) {
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
