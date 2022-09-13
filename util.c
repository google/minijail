/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
const char *const log_syscalls[] = {
#if defined(__x86_64__)
# if defined(__ANDROID__)
  "socket", "connect", "fcntl", "writev",
# else
  "socket", "connect", "sendto", "writev",
# endif
#elif defined(__i386__)
# if defined(__ANDROID__)
  "socketcall", "writev", "fcntl64", "clock_gettime",
# else
  "socketcall", "time", "writev",
# endif
#elif defined(__arm__)
# if defined(__ANDROID__)
  "clock_gettime", "connect", "fcntl64", "socket", "writev",
# else
  "socket", "connect", "gettimeofday", "send", "writev",
# endif
#elif defined(__aarch64__)
# if defined(__ANDROID__)
  "connect", "fcntl", "sendto", "socket", "writev",
# else
  "socket", "connect", "send", "writev",
# endif
#elif defined(__hppa__) || \
      defined(__ia64__) || \
      defined(__mips__) || \
      defined(__powerpc__) || \
      defined(__sparc__)
  "socket", "connect", "send",
#elif defined(__riscv)
# if defined(__ANDROID__)
  "connect", "fcntl", "sendto", "socket", "writev",
# else
  "socket", "connect", "sendto",
# endif
#else
# error "Unsupported platform"
#endif
};

const size_t log_syscalls_len = ARRAY_SIZE(log_syscalls);

/* clang-format off */
static struct logging_config_t {
	/* The logging system to use. The default is syslog. */
	enum logging_system_t logger;

	/* File descriptor to log to. Only used when logger is LOG_TO_FD. */
	int fd;

	/* Minimum priority to log. Only used when logger is LOG_TO_FD. */
	int min_priority;
} logging_config = {
	.logger = LOG_TO_SYSLOG,
};
/* clang-format on */

#if defined(USE_EXIT_ON_DIE)
#define do_abort() exit(1)
#else
#define do_abort() abort()
#endif

#if defined(__clang__)
#define attribute_no_optimize __attribute__((optnone))
#else
#define attribute_no_optimize __attribute__((__optimize__(0)))
#endif

/* Forces the compiler to perform no optimizations on |var|. */
static void attribute_no_optimize alias(const void *var)
{
	(void)var;
}

void do_fatal_log(int priority, const char *format, ...)
{
	va_list args, stack_args;
	va_start(args, format);
	va_copy(stack_args, args);
	if (logging_config.logger == LOG_TO_SYSLOG) {
		vsyslog(priority, format, args);
	} else {
		vdprintf(logging_config.fd, format, args);
		dprintf(logging_config.fd, "\n");
	}
	va_end(args);

	/*
	 * Write another copy of the first few characters of the message into a
	 * stack-based buffer so that it can appear in minidumps. Choosing a
	 * small-ish buffer size since breakpad will only pick up the first few
	 * kilobytes of each stack, so that will prevent this buffer from
	 * kicking out other stack frames.
	 */
	char log_line[512];
	vsnprintf(log_line, sizeof(log_line), format, stack_args);
	va_end(stack_args);
	alias(log_line);
	do_abort();
}

void do_log(int priority, const char *format, ...)
{
	if (logging_config.logger == LOG_TO_SYSLOG) {
		va_list args;
		va_start(args, format);
		vsyslog(priority, format, args);
		va_end(args);
		return;
	}

	if (logging_config.min_priority < priority)
		return;

	va_list args;
	va_start(args, format);
	vdprintf(logging_config.fd, format, args);
	va_end(args);
	dprintf(logging_config.fd, "\n");
}

/*
 * Returns the syscall nr and optionally populates the index in the pointer
 * |ind| if it is non-NULL.
 */
int lookup_syscall(const char *name, size_t *ind)
{
	size_t ind_tmp = 0;
	const struct syscall_entry *entry = syscall_table;
	for (; entry->name && entry->nr >= 0; ++entry) {
		if (streq(entry->name, name)) {
			if (ind != NULL)
				*ind = ind_tmp;
			return entry->nr;
		}
		ind_tmp++;
	}
	if (ind != NULL)
		*ind = -1;
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
		if (streq(entry->name, constant_str)) {
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
				return 0;
			}
		} else if (res == LONG_MIN) {
			/*
			 * Same for signed underflow: set |*endptr| to
			 * |constant_str| and return 0.
			 */
			warn("signed underflow: '%s'", constant_str);
			*endptr = constant_str;
			return 0;
		}
	}
	if (**endptr != '\0') {
		warn("trailing garbage after constant: '%s'", constant_str);
		*endptr = constant_str;
		return 0;
	}
	return res;
}

static char *tokenize_parenthesized_expression(char **stringp)
{
	char *ret = NULL, *found = NULL;
	size_t paren_count = 1;

	/* If the string is NULL, there are no parens to be found. */
	if (stringp == NULL || *stringp == NULL)
		return NULL;

	/* If the string is not on an open paren, the results are undefined. */
	if (**stringp != '(')
		return NULL;

	for (found = *stringp + 1; *found; ++found) {
		switch (*found) {
		case '(':
			++paren_count;
			break;
		case ')':
			--paren_count;
			if (!paren_count) {
				*found = '\0';
				ret = *stringp + 1;
				*stringp = found + 1;
				return ret;
			}
			break;
		}
	}

	/* We got to the end without finding the closing paren. */
	warn("unclosed parenthesis: '%s'", *stringp);
	return NULL;
}

long int parse_constant(char *constant_str, char **endptr)
{
	long int value = 0, current_value;
	char *group, *lastpos = constant_str;

	/*
	 * If |endptr| is provided, parsing errors are signaled as |endptr|
	 * pointing to |constant_str|.
	 */
	if (endptr)
		*endptr = constant_str;

	/*
	 * Try to parse constant expressions. Valid constant expressions are:
	 *
	 * - A number that can be parsed with strtol(3).
	 * - A named constant expression.
	 * - A parenthesized, valid constant expression.
	 * - A valid constant expression prefixed with the unary bitwise
	 *   complement operator ~.
	 * - A series of valid constant expressions separated by pipes.  Note
	 *   that since |constant_str| is an atom, there can be no spaces
	 *   between the constant and the pipe.
	 *
	 * If there is an error parsing any of the constants, the whole process
	 * fails.
	 */
	while (constant_str && *constant_str) {
		bool negate = false;
		if (*constant_str == '~') {
			negate = true;
			++constant_str;
		}
		if (*constant_str == '(') {
			group =
			    tokenize_parenthesized_expression(&constant_str);
			if (group == NULL)
				return 0;
			char *end = group;
			/* Recursively parse the parenthesized subexpression. */
			current_value = parse_constant(group, &end);
			if (end == group)
				return 0;
			if (constant_str && *constant_str) {
				/*
				 * If this is not the end of the atom, there
				 * should be another | followed by more stuff.
				 */
				if (*constant_str != '|') {
					warn("unterminated constant "
					     "expression: '%s'",
					     constant_str);
					return 0;
				}
				++constant_str;
				if (*constant_str == '\0') {
					warn("unterminated constant "
					     "expression: '%s'",
					     constant_str);
					return 0;
				}
			}
			lastpos = end;
		} else {
			group = tokenize(&constant_str, "|");
			char *end = group;
			current_value = parse_single_constant(group, &end);
			if (end == group)
				return 0;
			lastpos = end;
		}
		if (negate)
			current_value = ~current_value;
		value |= current_value;
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

	/* If the string is NULL, there are no tokens to be found. */
	if (stringp == NULL || *stringp == NULL)
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

	char *found = strstr(*stringp, delim);
	if (!found) {
		/*
		 * The delimiter was not found, so the full string
		 * makes up the only token, and we're done.
		 */
		ret = *stringp;
		*stringp = NULL;
	} else {
		/* There's a token here, possibly empty.  That's OK. */
		*found = '\0';
		ret = *stringp;
		*stringp = found + strlen(delim);
	}

	return ret;
}

char *path_join(const char *external_path, const char *internal_path)
{
	char *path = NULL;
	return asprintf(&path, "%s/%s", external_path, internal_path) < 0
		   ? NULL
		   : path;
}

bool path_is_parent(const char *parent, const char *child)
{
	/*
	 * -Make sure |child| starts with |parent|.
	 * -Make sure that if |child| is longer than |parent|, either:
	 * --the last character in |parent| is a path separator, or
	 * --the character immediately following |parent| in |child| is a path
	 *  separator.
	 */
	size_t parent_len = strlen(parent);
	return strncmp(parent, child, parent_len) == 0 &&
	       (strlen(child) > parent_len ? (parent[parent_len - 1] == '/' ||
					      child[parent_len] == '/')
					   : false);
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

void init_logging(enum logging_system_t logger, int fd, int min_priority)
{
	logging_config.logger = logger;
	logging_config.fd = fd;
	logging_config.min_priority = min_priority;
}

void minijail_free_env(char **env)
{
	if (!env)
		return;

	for (char **entry = env; *entry; ++entry) {
		free(*entry);
	}

	free(env);
}

char **minijail_copy_env(char *const *env)
{
	if (!env)
		return calloc(1, sizeof(char *));

	int len = 0;
	while (env[len])
		++len;

	char **copy = calloc(len + 1, sizeof(char *));
	if (!copy)
		return NULL;

	for (char **entry = copy; *env; ++env, ++entry) {
		*entry = strdup(*env);
		if (!*entry) {
			minijail_free_env(copy);
			return NULL;
		}
	}

	return copy;
}

/*
 * Utility function used by minijail_setenv, minijail_unsetenv and
 * minijail_getenv, returns true if |name| is found, false if not.
 * If found, |*i| is |name|'s index. If not, |*i| is the length of |envp|.
 */
static bool getenv_index(char **envp, const char *name, int *i) {
	if (!envp || !name || !i)
		return false;

	size_t name_len = strlen(name);
	for (*i = 0; envp[*i]; ++(*i)) {
		/*
		 * If we find a match the size of |name|, we must check
		 * that the next character is a '=', indicating that
		 * the full varname of envp[i] is exactly |name| and
		 * not just happening to start with |name|.
		 */
		if (!strncmp(envp[*i], name, name_len) &&
		    (envp[*i][name_len] == '=')) {
			return true;
		}
	}
	/* No match found, |*i| contains the number of elements in |envp|. */
	return false;
}

int minijail_setenv(char ***env, const char *name, const char *value,
		    int overwrite)
{
	if (!env || !*env || !name || !*name || !value)
		return EINVAL;

	char **dest = NULL;
	int i;

	/* Look in env to check if this var name already exists. */
	if (getenv_index(*env, name, &i)) {
		if (!overwrite)
			return 0;
		dest = &(*env)[i];
	}

	char *new_entry = NULL;
	if (asprintf(&new_entry, "%s=%s", name, value) == -1)
		return ENOMEM;

	if (dest) {
		free(*dest);
		*dest = new_entry;
		return 0;
	}

	/* getenv_index has set |i| to the length of |env|. */
	++i;
	char **new_env = realloc(*env, (i + 1) * sizeof(char *));
	if (!new_env) {
		free(new_entry);
		return ENOMEM;
	}

	new_env[i - 1] = new_entry;
	new_env[i] = NULL;
	*env = new_env;
	return 0;
}

/*
 * This is like getline() but supports line wrapping with \.
 */
ssize_t getmultiline(char **lineptr, size_t *n, FILE *stream)
{
	ssize_t ret = getline(lineptr, n, stream);
	if (ret < 0)
		return ret;

	char *line = *lineptr;
	/* Eat the newline to make processing below easier. */
	if (ret > 0 && line[ret - 1] == '\n')
		line[--ret] = '\0';

	/* If the line doesn't end in a backslash, we're done. */
	if (ret <= 0 || line[ret - 1] != '\\')
		return ret;

	/* This line ends in a backslash. Get the nextline. */
	line[--ret] = '\0';
	size_t next_n = 0;
	attribute_cleanup_str char *next_line = NULL;
	ssize_t next_ret = getmultiline(&next_line, &next_n, stream);
	if (next_ret == -1) {
		/* We couldn't fully read the line, so return an error. */
		return -1;
	}

	/* Merge the lines. */
	*n = ret + next_ret + 2;
	line = realloc(line, *n);
	if (!line)
		return -1;
	line[ret] = ' ';
	memcpy(&line[ret + 1], next_line, next_ret + 1);
	*lineptr = line;
	return *n - 1;
}

char *minijail_getenv(char **envp, const char *name) {
	if (!envp || !name)
		return NULL;

	int i;
	if (!getenv_index(envp, name, &i))
		return NULL;

	/* Return a ptr to the value after the '='. */
	return envp[i] + strlen(name) + 1;
}

bool minijail_unsetenv(char **envp, const char *name)
{
	if (!envp || !name)
		return false;

	int i;
	if (!getenv_index(envp, name, &i))
		return false;

	/* We found a match, replace it by the last entry of the array. */
	int last;
	for (last = i; envp[last]; ++last)
		continue;
	--last;
	envp[i] = envp[last];
	envp[last] = NULL;

	return true;
}
