/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

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

const size_t log_syscalls_len = ARRAY_SIZE(log_syscalls);

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

long int parse_single_constant(char *constant_str, char **endptr)
{
	const struct constant_entry *entry = constant_table;
	long int res = 0;
	for (; entry->name; ++entry) {
		if (!strcmp(entry->name, constant_str)) {
			if (endptr)
				*endptr = constant_str + strlen(constant_str);

			return entry->value;
		}
	}

	errno = 0;
	res = strtol(constant_str, endptr, 0);
	if (errno == ERANGE) {
		if (res == LONG_MAX) {
			/* See if the constant fits in an unsigned long int. */
			errno = 0;
			res = strtoul(constant_str, endptr, 0);
			if (errno == ERANGE) {
				/*
				 * On unsigned overflow, use the same convention
				 * as when strtol(3) finds no digits: set
				 * |*endptr| to |constant_str| and return 0.
				 */
				warn("unsigned overflow: '%s'", constant_str);
				*endptr = constant_str;
				res = 0;
			}
		} else if (res == LONG_MIN) {
			/*
			 * Same for signed underflow: set |*endptr| to
			 * |constant_str| and return 0.
			 */
			warn("signed underflow: '%s'", constant_str);
			*endptr = constant_str;
			res = 0;
		}
	}
	return res;
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
	 * defined in libconstants.gen.c or a number parsed with strtol(3).
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

/*
 * parse_size, specified as a string with a decimal number in bytes,
 * possibly with one 1-character suffix like "10K" or "6G".
 * Assumes both pointers are non-NULL.
 *
 * Returns 0 on success, negative errno on failure.
 * Only writes to result on success.
 */
int parse_size(size_t *result, const char *sizespec)
{
	const char prefixes[] = "KMGTPE";
	size_t i, multiplier = 1, nsize, size = 0;
	unsigned long long parsed;
	const size_t len = strlen(sizespec);
	char *end;

	if (len == 0 || sizespec[0] == '-')
		return -EINVAL;

	for (i = 0; i < sizeof(prefixes); ++i) {
		if (sizespec[len - 1] == prefixes[i]) {
#if __WORDSIZE == 32
			if (i >= 3)
				return -ERANGE;
#endif
			multiplier = 1024;
			while (i-- > 0)
				multiplier *= 1024;
			break;
		}
	}

	/* We only need size_t but strtoul(3) is too small on IL32P64. */
	parsed = strtoull(sizespec, &end, 10);
	if (parsed == ULLONG_MAX)
		return -errno;
	if (parsed >= SIZE_MAX)
		return -ERANGE;
	if ((multiplier != 1 && end != sizespec + len - 1) ||
	    (multiplier == 1 && end != sizespec + len))
		return -EINVAL;
	size = (size_t)parsed;

	nsize = size * multiplier;
	if (nsize / multiplier != size)
		return -ERANGE;
	*result = nsize;
	return 0;
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

char *path_join(const char *external_path, const char *internal_path)
{
	char *path;
	size_t pathlen;

	/* One extra char for '/' and one for '\0', hence + 2. */
	pathlen = strlen(external_path) + strlen(internal_path) + 2;
	path = malloc(pathlen);
	snprintf(path, pathlen, "%s/%s", external_path, internal_path);

	return path;
}

int write_proc_file(pid_t pid, const char *content, const char *basename)
{
	int fd, ret;
	size_t sz, len;
	ssize_t written;
	char filename[32];

	sz = sizeof(filename);
	ret = snprintf(filename, sz, "/proc/%d/%s", pid, basename);
	if (ret < 0 || (size_t)ret >= sz) {
		warn("failed to generate %s filename", basename);
		return -1;
	}

	fd = open(filename, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		pwarn("failed to open '%s'", filename);
		return -errno;
	}

	len = strlen(content);
	written = write(fd, content, len);
	if (written < 0) {
		pwarn("failed to write '%s'", filename);
		return -1;
	}

	if ((size_t)written < len) {
		warn("failed to write %zu bytes to '%s'", len, filename);
		return -1;
	}
	close(fd);
	return 0;
}

int write_pid_to_path(pid_t pid, const char *path)
{
	FILE *fp = fopen(path, "w");

	if (!fp) {
		pwarn("failed to open '%s'", path);
		return -errno;
	}
	if (fprintf(fp, "%d\n", (int)pid) < 0) {
		/* fprintf(3) does not set errno on failure. */
		warn("fprintf(%s) failed", path);
		return -1;
	}
	if (fclose(fp)) {
		pwarn("fclose(%s) failed", path);
		return -errno;
	}

	return 0;
}

void *consumebytes(size_t length, char **buf, size_t *buflength)
{
	char *p = *buf;
	if (length > *buflength)
		return NULL;
	*buf += length;
	*buflength -= length;
	return p;
}

char *consumestr(char **buf, size_t *buflength)
{
	size_t len = strnlen(*buf, *buflength);
	if (len == *buflength)
		/* There's no null-terminator. */
		return NULL;
	return consumebytes(len + 1, buf, buflength);
}
