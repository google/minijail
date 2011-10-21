/* libminijailpreload.c - preload hack library
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * This library is preloaded into every program launched by minijail_run().
 * DO NOT EXPORT ANY SYMBOLS FROM THIS LIBRARY. They will replace other symbols
 * in the programs it is preloaded into and cause impossible-to-debug failures.
 * See the minijail0.1 for a design explanation.
 */

#include "libminijail.h"
#include "libminijail-private.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

static int (*real_main) (int, char **, char **);
static void *libc_handle;

static void die(const char *failed)
{
	syslog(LOG_ERR, "libminijail: %s", failed);
	abort();
}

static void unset_in_env(char **envp, const char *name)
{
	int i;
	for (i = 0; envp[i]; i++)
		if (!strncmp(envp[i], name, strlen(name)))
			envp[i][0] = '\0';
}

/** @brief Fake main(), spliced in before the real call to main() by
 *         __libc_start_main (see below).
 *  We get serialized commands from our invoking process over an fd specified
 *  by an environment variable (kFdEnvVar). The environment variable is a list
 *  of key=value pairs (see move_commands_to_env); we use them to construct a
 *  jail, then enter it.
 */
static int fake_main(int argc, char **argv, char **envp)
{
	char *fd_name = getenv(kFdEnvVar);
	int fd = -1;
	struct minijail *j;
	if (geteuid() != getuid() || getegid() != getgid())
		/* If we didn't do this check, an attacker could set kFdEnvVar
		 * for any setuid program that uses libminijail to cause it to
		 * get capabilities or a uid it did not expect.
		 */
		/* TODO(wad) why would libminijail interact here? */
		return MINIJAIL_ERR_PRELOAD;
	if (!fd_name)
		return MINIJAIL_ERR_PRELOAD;
	fd = atoi(fd_name);
	if (fd < 0)
		return MINIJAIL_ERR_PRELOAD;

	j = minijail_new();
	if (!j)
		die("preload: out of memory");
	if (minijail_from_fd(fd, j))
		die("preload: failed to parse minijail from parent");
	close(fd);

	/* TODO(ellyjones): this trashes existing preloads, so one can't do:
	 * LD_PRELOAD="/tmp/test.so libminijailpreload.so" prog; the
	 * descendants of prog will have no LD_PRELOAD set at all.
	 */
	unset_in_env(envp, kLdPreloadEnvVar);
	/* Strip out flags meant for the parent. */
	minijail_preenter(j);
	minijail_enter(j);
	minijail_destroy(j);
	dlclose(libc_handle);
	return real_main(argc, argv, envp);
}

/** @brief LD_PRELOAD override of __libc_start_main.
 *
 *  It is really best if you do not look too closely at this function.  We need
 *  to ensure that some of our code runs before the target program (see the
 *  minijail0.1 file in this directory for high-level details about this), and
 *  the only available place to hook is this function, which is normally
 *  responsible for calling main(). Our LD_PRELOAD will overwrite the real
 *  __libc_start_main with this one, so we have to look up the real one from
 *  libc and invoke it with a pointer to the fake main() we'd like to run before
 *  the real main(). We can't just run our setup code *here* because
 *  __libc_start_main is responsible for setting up the C runtime environment,
 *  so we can't rely on things like malloc() being available yet.
 */

int API __libc_start_main(int (*main) (int, char **, char **),
		      int argc, char **ubp_av, void (*init) (void),
		      void (*fini) (void), void (*rtld_fini) (void),
		      void (*stack_end))
{
	void *sym;
	/* This hack is unfortunately required by C99 - casting directly from
	 * void* to function pointers is left undefined. See POSIX.1-2003, the
	 * Rationale for the specification of dlsym(), and dlsym(3). This
	 * deliberately violates strict-aliasing rules, but gcc can't tell.
	 */
	union {
		int (*fn) (int (*main) (int, char **, char **), int argc,
			   char **ubp_av, void (*init) (void),
			   void (*fini) (void), void (*rtld_fini) (void),
			   void (*stack_end));
		void *symval;
	} real_libc_start_main;

	/* We hold this handle for the duration of the real __libc_start_main()
	 * and drop it just before calling the real main().
	 */
	libc_handle = dlopen("libc.so.6", RTLD_NOW);

	if (!libc_handle) {
		syslog(LOG_ERR, "can't dlopen() libc");
		/* We dare not use abort() here because it will run atexit()
		 * handlers and try to flush stdio.
		 */
		_exit(1);
	}
	sym = dlsym(libc_handle, "__libc_start_main");
	if (!sym) {
		syslog(LOG_ERR, "can't find the real __libc_start_main()");
		_exit(1);
	}
	real_libc_start_main.symval = sym;
	real_main = main;

	/* Note that we swap fake_main in for main - fake_main knows that it
	 * should call real_main after it's done.
	 */
	return real_libc_start_main.fn(fake_main, argc, ubp_av, init, fini,
				       rtld_fini, stack_end);
}
