/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ctype.h>
#include <string.h>

#include "util.h"

#include "libsyscalls.h"

#if defined(__x86_64__)
const char *log_syscalls[] = { "connect", "sendto" };
#elif defined(__i386__)
const char *log_syscalls[] = { "socketcall", "time" };
#elif defined(__arm__)
const char *log_syscalls[] = { "connect", "gettimeofday", "send" };
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
