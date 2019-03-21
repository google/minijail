/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libminijail.h"

#include "elfparse.h"
#include "minijail0_cli.h"
#include "util.h"

int main(int argc, char *argv[])
{
	struct minijail *j = minijail_new();
	const char *dl_mesg = NULL;
	const char *preload_path = PRELOADPATH;
	int exit_immediately = 0;
	ElfType elftype = ELFERROR;
	int consumed = parse_args(j, argc, argv, &exit_immediately, &elftype,
				  &preload_path);
	argc -= consumed;
	argv += consumed;

	/*
	 * Make the process group ID of this process equal to its PID.
	 * In the non-interactive case (e.g. when minijail0 is started from
	 * init) this ensures the parent process and the jailed process
	 * can be killed together.
	 *
	 * Don't fail on EPERM, since setpgid(0, 0) can only EPERM when
	 * the process is already a process group leader.
	 */
	if (setpgid(0 /* use calling PID */, 0 /* make PGID = PID */)) {
		if (errno != EPERM) {
			fprintf(stderr, "setpgid(0, 0) failed\n");
			exit(1);
		}
	}

	if (elftype == ELFSTATIC) {
		/*
		 * Target binary is statically linked so we cannot use
		 * libminijailpreload.so.
		 */
		minijail_run_no_preload(j, argv[0], argv);
	} else if (elftype == ELFDYNAMIC) {
		/*
		 * Target binary is dynamically linked so we can
		 * inject libminijailpreload.so into it.
		 */

		/* Check that we can dlopen() libminijailpreload.so. */
		if (!dlopen(preload_path, RTLD_LAZY | RTLD_LOCAL)) {
			dl_mesg = dlerror();
			fprintf(stderr, "dlopen(): %s\n", dl_mesg);
			return 1;
		}
		minijail_set_preload_path(j, preload_path);
		minijail_run(j, argv[0], argv);
	} else {
		fprintf(stderr,
			"Target program '%s' is not a valid ELF file.\n",
			argv[0]);
		return 1;
	}

	if (exit_immediately)
		return 0;

	int ret = minijail_wait(j);
#if defined(__SANITIZE_ADDRESS__)
	minijail_destroy(j);
#endif /* __SANITIZE_ADDRESS__ */
	return ret;
}
