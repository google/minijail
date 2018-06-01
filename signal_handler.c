/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "signal_handler.h"

#include "util.h"

/*
 * si_syscall was added in glibc-2.17+, but Android still uses glibc-2.15
 * for its prebuilt binary host toolchains.  Add a compat hack for it.
 */
static int get_si_syscall(const siginfo_t *info)
{
#if defined(si_syscall)
	return info->si_syscall;
#endif

	typedef struct {
		void		*ip;
		int		nr;
		unsigned int	arch;
	} local_siginfo_t;

	union {
		const siginfo_t *info;
		const local_siginfo_t *local_info;
	} local_info = {
		.info = info,
	};
	return local_info.local_info->nr;
}

void log_sigsys_handler(int sig attribute_unused, siginfo_t *info,
			void *void_context attribute_unused)
{
	const char *syscall_name;
	int nr = get_si_syscall(info);
	syscall_name = lookup_syscall_name(nr);

	if (syscall_name)
		die("blocked syscall: %s", syscall_name);
	else
		die("blocked syscall: %d", nr);

	/*
	 * We trapped on a syscall that should have killed the process.
	 * This should never ever return, but we're paranoid.
	 */
	for (;;)
		_exit(1);
}

int install_sigsys_handler()
{
	int ret = 0;
	struct sigaction act;
	sigset_t mask;

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &log_sigsys_handler;
	act.sa_flags = SA_SIGINFO;

	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	ret = sigaction(SIGSYS, &act, NULL);
	if (ret < 0)
		return ret;

	ret = sigprocmask(SIG_UNBLOCK, &mask, NULL);
	if (ret < 0)
		return ret;

	return 0;
}
