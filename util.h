/* util.h
 * Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Logging and other utility functions.
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "libsyscalls.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Silence compiler warnings for unused variables/functions.
 *
 * If the definition is actually used, the attribute should be removed, but if
 * it's forgotten or left in place, it doesn't cause a problem.
 *
 * If the definition is actually unused, the compiler is free to remove it from
 * the output so as to save size.  If you want to make sure the definition is
 * kept (e.g. for ABI compatibility), look at the "used" attribute instead.
 */
#define attribute_unused __attribute__((__unused__))

/*
 * Mark the symbol as "weak" in the ELF output.  This provides a fallback symbol
 * that may be overriden at link time.  See this page for more details:
 * https://en.wikipedia.org/wiki/Weak_symbol
 */
#define attribute_weak __attribute__((__weak__))

/*
 * Mark the function as a printf-style function.
 * @format_idx The index in the function argument list where the format string
 *             is passed (where the first argument is "1").
 * @check_idx The index in the function argument list where the first argument
 *            used in the format string is passed.
 * Some examples:
 *   foo([1] const char *format, [2] ...): format=1 check=2
 *   foo([1] int, [2] const char *format, [3] ...): format=2 check=3
 *   foo([1] const char *format, [2] const char *, [3] ...): format=1 check=3
 */
#define attribute_printf(format_idx, check_idx) \
	__attribute__((__format__(__printf__, format_idx, check_idx)))

#ifndef __cplusplus
/* If writing C++, use std::unique_ptr with a destructor instead. */

/*
 * Mark a local variable for automatic cleanup when exiting its scope.
 * See attribute_cleanup_fp as an example below.
 * Make sure any variable using this is always initialized to something.
 * @func The function to call on (a pointer to) the variable.
 */
#define attribute_cleanup(func) \
	__attribute__((__cleanup__(func)))

/*
 * Automatically close a FILE* when exiting its scope.
 * Make sure the pointer is always initialized.
 * Some examples:
 *   attribute_cleanup_fp FILE *fp = fopen(...);
 *   attribute_cleanup_fp FILE *fp = NULL;
 *   ...
 *   fp = fopen(...);
 *
 * NB: This will automatically close the underlying fd, so do not use this
 * with fdopen calls if the fd should be left open.
 */
#define attribute_cleanup_fp attribute_cleanup(_cleanup_fp)
static inline void _cleanup_fp(FILE **fp)
{
	if (*fp)
		fclose(*fp);
}

/*
 * Automatically close a fd when exiting its scope.
 * Make sure the fd is always initialized.
 * Some examples:
 *   attribute_cleanup_fd int fd = open(...);
 *   attribute_cleanup_fd int fd = -1;
 *   ...
 *   fd = open(...);
 *
 * NB: Be careful when using this with attribute_cleanup_fp and fdopen.
 */
#define attribute_cleanup_fd attribute_cleanup(_cleanup_fd)
static inline void _cleanup_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}

/*
 * Automatically free a heap allocation when exiting its scope.
 * Make sure the pointer is always initialized.
 * Some examples:
 *   attribute_cleanup_str char *s = strdup(...);
 *   attribute_cleanup_str char *s = NULL;
 *   ...
 *   s = strdup(...);
 */
#define attribute_cleanup_str attribute_cleanup(_cleanup_str)
static inline void _cleanup_str(char **ptr)
{
	free(*ptr);
}

#endif /* __cplusplus */

/* clang-format off */
#define die(_msg, ...) \
	do_fatal_log(LOG_ERR, "libminijail[%d]: " _msg, getpid(), ## __VA_ARGS__)

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

extern const char *const log_syscalls[];
extern const size_t log_syscalls_len;

enum logging_system_t {
	/* Log to syslog. This is the default. */
	LOG_TO_SYSLOG = 0,

	/* Log to a file descriptor. */
	LOG_TO_FD,
};

/*
 * Even though this function internally calls abort(2)/exit(2), it is
 * intentionally not marked with the noreturn attribute. When marked as
 * noreturn, clang coalesces several of the do_fatal_log() calls in methods that
 * have a large number of such calls (like minijail_enter()), making it
 * impossible for breakpad to correctly identify the line where it was called,
 * making the backtrace somewhat useless.
 */
extern void do_fatal_log(int priority, const char *format, ...)
    attribute_printf(2, 3);

extern void do_log(int priority, const char *format, ...)
    attribute_printf(2, 3);

static inline int is_android(void)
{
#if defined(__ANDROID__)
	return 1;
#else
	return 0;
#endif
}

static inline bool compiled_with_asan(void)
{
#if defined(__SANITIZE_ADDRESS__)
	/* For gcc. */
	return true;
#elif defined(__has_feature)
	/* For clang. */
	return __has_feature(address_sanitizer) ||
	       __has_feature(hwaddress_sanitizer);
#else
	return false;
#endif
}

void __asan_init(void) attribute_weak;
void __hwasan_init(void) attribute_weak;

static inline bool running_with_asan(void)
{
	/*
	 * There are some configurations under which ASan needs a dynamic (as
	 * opposed to compile-time) test. Some Android processes that start
	 * before /data is mounted run with non-instrumented libminijail.so, so
	 * the symbol-sniffing code must be present to make the right decision.
	 */
	return compiled_with_asan() || &__asan_init != 0 || &__hwasan_init != 0;
}

static inline bool debug_logging_allowed(void)
{
#if defined(ALLOW_DEBUG_LOGGING)
	return true;
#else
	return false;
#endif
}

static inline bool seccomp_default_ret_log(void)
{
#if defined(SECCOMP_DEFAULT_RET_LOG)
	return true;
#else
	return false;
#endif
}

static inline bool block_symlinks_in_bindmount_paths(void)
{
#if defined(BLOCK_SYMLINKS_IN_BINDMOUNT_PATHS)
	return true;
#else
	return false;
#endif
}

static inline bool block_symlinks_in_noninit_mountns_tmp(void)
{
#if defined(BLOCK_SYMLINKS_IN_NONINIT_MOUNTNS_TMP)
	return true;
#else
	return false;
#endif
}

static inline size_t get_num_syscalls(void)
{
	return syscall_table_size;
}

int lookup_syscall(const char *name, size_t *ind);
const char *lookup_syscall_name(int nr);

long int parse_single_constant(char *constant_str, char **endptr);
long int parse_constant(char *constant_str, char **endptr);
int parse_size(size_t *size, const char *sizespec);

char *strip(char *s);

/*
 * streq: determine whether two strings are equal.
 */
static inline bool streq(const char *s1, const char *s2)
{
	return strcmp(s1, s2) == 0;
}

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
 * path_is_parent: checks whether @parent is a parent of @child.
 * Note: this function does not evaluate '.' or '..' nor does it resolve
 * symlinks.
 */
bool path_is_parent(const char *parent, const char *child);

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
 *               priority parameter. Ignored unless @logger = LOG_TO_FD.
 */
void init_logging(enum logging_system_t logger, int fd, int min_priority);

/*
 * minjail_free_env: Frees an environment array plus the environment strings it
 * points to. The environment and its constituent strings must have been
 * allocated (as opposed to pointing to static data), e.g. by using
 * minijail_copy_env() and minijail_setenv().
 *
 * @env The environment to free.
 */
void minijail_free_env(char **env);

/*
 * minjail_copy_env: Copy an environment array (such as passed to execve),
 * duplicating the environment strings and the array pointing at them.
 *
 * @env The environment to copy.
 *
 * Returns a pointer to the copied environment or NULL on memory allocation
 * failure.
 */
char **minijail_copy_env(char *const *env);

/*
 * minjail_setenv: Set an environment variable in @env. Semantics match the
 * standard setenv() function, but this operates on @env, not the global
 * environment. @env must be dynamically allocated (as opposed to pointing to
 * static data), e.g. via minijail_copy_env(). @name and @value get copied into
 * newly-allocated memory.
 *
 * @env       Address of the environment to modify. Might be re-allocated to
 *            make room for the new entry.
 * @name      Name of the key to set.
 * @value     The value to set.
 * @overwrite Whether to replace the existing value for @name. If non-zero and
 *            the entry is already present, no changes will be made.
 *
 * Returns 0 and modifies *@env on success, returns an error code otherwise.
 */
int minijail_setenv(char ***env, const char *name, const char *value,
		    int overwrite);

/*
 * getmultiline: This is like getline() but supports line wrapping with \.
 *
 * @lineptr    Address of a buffer that a mutli-line is stored.
 * @n          Number of bytes stored in *lineptr.
 * @stream     Input stream to read from.
 *
 * Returns number of bytes read or -1 on failure to read (including EOF).
 */
ssize_t getmultiline(char **lineptr, size_t *n, FILE *stream);

/*
 * minjail_getenv: Get an environment variable from @envp. Semantics match the
 * standard getenv() function, but this operates on @envp, not the global
 * environment (usually referred to as `extern char **environ`).
 *
 * @env       Address of the environment to read from.
 * @name      Name of the key to get.
 *
 * Returns a pointer to the corresponding environment value. The caller must
 * take care not to modify the pointed value, as this points directly to memory
 * pointed to by @envp.
 * If the environment variable name is not found, returns NULL.
 */
char *minijail_getenv(char **env, const char *name);

/*
 * minjail_unsetenv: Clear the environment variable @name from the @envp array
 * of pointers to strings that have the KEY=VALUE format. If the operation is
 * successful, the array will contain one item less than before the call.
 * Only the first occurence is removed.
 *
 * @envp      Address of the environment to clear the variable from.
 * @name      Name of the variable to clear.
 *
 * Returns false and modifies *@envp on success, returns true otherwise.
 */
bool minijail_unsetenv(char **envp, const char *name);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _UTIL_H_ */
