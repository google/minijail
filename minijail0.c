/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libminijail.h"
#include "libsyscalls.h"

#include "util.h"

static void set_user(struct minijail *j, const char *arg)
{
	char *end = NULL;
	int uid = strtod(arg, &end);
	if (!*end && *arg) {
		minijail_change_uid(j, uid);
		return;
	}

	if (minijail_change_user(j, arg)) {
		fprintf(stderr, "Bad user: '%s'\n", arg);
		exit(1);
	}
}

static void set_group(struct minijail *j, const char *arg)
{
	char *end = NULL;
	int gid = strtod(arg, &end);
	if (!*end && *arg) {
		minijail_change_gid(j, gid);
		return;
	}

	if (minijail_change_group(j, arg)) {
		fprintf(stderr, "Bad group: '%s'\n", arg);
		exit(1);
	}
}

static void use_caps(struct minijail *j, const char *arg)
{
	uint64_t caps;
	char *end = NULL;
	caps = strtoull(arg, &end, 16);
	if (*end) {
		fprintf(stderr, "Invalid cap set: '%s'\n", arg);
		exit(1);
	}
	minijail_use_caps(j, caps);
}

static void add_binding(struct minijail *j, char *arg) {
	char *src = strtok(arg, ",");
	char *dest = strtok(NULL, ",");
	char *flags = strtok(NULL, ",");
	if (!src || !dest) {
		fprintf(stderr, "Bad binding: %s %s\n", src, dest);
		exit(1);
	}
	if (minijail_bind(j, src, dest, flags ? atoi(flags) : 0)) {
		fprintf(stderr, "Bind failure\n");
		exit(1);
	}
}

static void usage(const char *progn)
{
	size_t i;

	printf("Usage: %s [-Ghinprsvt] [-b <src>,<dest>[,<writeable>]] "
	       "[-c <caps>] [-C <dir>] [-g <group>] [-S <file>] [-u <user>] "
	       "<program> [args...]\n"
	       "  -b:         binds <src> to <dest> in chroot. Multiple "
	       "instances allowed\n"
	       "  -c <caps>:  restrict caps to <caps>\n"
	       "  -C <dir>:   chroot to <dir>\n"
	       "  -t:         mount tmpfs at /tmp inside chroot\n"
	       "  -e:         enter a network namespace\n"
	       "  -G:         inherit secondary groups from uid\n"
	       "  -g <group>: change gid to <group>\n"
	       "  -h:         help (this message)\n"
	       "  -H:         seccomp filter help message\n"
	       "  -i:         exit immediately after fork (do not act as init)\n"
	       "              Not compatible with -p\n"
	       "  -L:         log blocked syscalls when using seccomp filter. "
	       "Forces the following syscalls to be allowed:\n"
	       "              ", progn);
	for (i = 0; i < log_syscalls_len; i++)
		printf("%s ", log_syscalls[i]);

	printf("\n"
	       "  -n:         set no_new_privs\n"
	       "  -p:         use pid namespace (implies -vr)\n"
	       "  -r:         remount /proc readonly (implies -v)\n"
	       "  -s:         use seccomp\n"
	       "  -S <file>:  set seccomp filter using <file>\n"
	       "              E.g., -S /usr/share/filters/<prog>.$(uname -m)\n"
	       "  -u <user>:  change uid to <user>\n"
	       "  -v:         use vfs namespace\n");
}

static void seccomp_filter_usage(const char *progn)
{
	const struct syscall_entry *entry = syscall_table;
	printf("Usage: %s -S <policy.file> <program> [args...]\n\n"
	       "System call names supported:\n", progn);
	for (; entry->name && entry->nr >= 0; ++entry)
		printf("  %s [%d]\n", entry->name, entry->nr);
	printf("\nSee minijail0(5) for example policies.\n");
}

static int parse_args(struct minijail *j, int argc, char *argv[],
		      int *exit_immediately)
{
	int opt;
	int use_pid_ns = 0;
	int chroot = 0;
	int mount_tmp = 0;
	if (argc > 1 && argv[1][0] != '-')
		return 1;
	while ((opt = getopt(argc, argv, "u:g:sS:c:C:b:vrGhHinpLet")) != -1) {
		switch (opt) {
		case 'u':
			set_user(j, optarg);
			break;
		case 'g':
			set_group(j, optarg);
			break;
		case 'n':
			minijail_no_new_privs(j);
			break;
		case 's':
			minijail_use_seccomp(j);
			break;
		case 'S':
			minijail_parse_seccomp_filters(j, optarg);
			minijail_use_seccomp_filter(j);
			break;
		case 'L':
			minijail_log_seccomp_filter_failures(j);
			break;
		case 'b':
			add_binding(j, optarg);
			break;
		case 'c':
			use_caps(j, optarg);
			break;
		case 'C':
			if (0 != minijail_enter_chroot(j, optarg))
				exit(1);
			chroot = 1;
			break;
		case 't':
			minijail_mount_tmp(j);
			mount_tmp = 1;
			break;
		case 'v':
			minijail_namespace_vfs(j);
			break;
		case 'r':
			minijail_remount_readonly(j);
			break;
		case 'G':
			minijail_inherit_usergroups(j);
			break;
		case 'p':
			if (*exit_immediately) {
				fprintf(stderr,
					"Could not enter pid namespace because "
					"'-i' was specified.\n");
				exit(1);
			}
			use_pid_ns = 1;
			minijail_namespace_pids(j);
			break;
		case 'e':
			minijail_namespace_net(j);
			break;
		case 'i':
			if (use_pid_ns) {
				fprintf(stderr,
					"Could not disable init loop because "
					"'-p' was specified.\n");
				exit(1);
			}
			*exit_immediately = 1;
			break;
		case 'H':
			seccomp_filter_usage(argv[0]);
			exit(1);
		default:
			usage(argv[0]);
			exit(1);
		}
		if (optind < argc && argv[optind][0] != '-')
			break;
	}

	if (argc == optind) {
		usage(argv[0]);
		exit(1);
	}

	if (mount_tmp && !chroot) {
		fprintf(stderr,
		        "Could not mount tmpfs at /tmp "
		        "because '-C' was not specified.\n");
		exit(1);
	}

	return optind;
}

int main(int argc, char *argv[])
{
	struct minijail *j = minijail_new();
	char *dl_mesg = NULL;
	int exit_immediately = 0;
	int consumed = parse_args(j, argc, argv, &exit_immediately);
	argc -= consumed;
	argv += consumed;
	/* Check that we can access the target program. */
	if (access(argv[0], X_OK)) {
		fprintf(stderr, "Target program '%s' not accessible\n",
		        argv[0]);
		return 1;
	}
	/* Check that we can dlopen() libminijailpreload.so. */
	if (!dlopen(PRELOADPATH, RTLD_LAZY | RTLD_LOCAL)) {
		dl_mesg = dlerror();
		fprintf(stderr, "dlopen(): %s\n", dl_mesg);
		return 1;
	}
	minijail_run(j, argv[0], argv);
	if (exit_immediately) {
		info("not running init loop, exiting immediately");
		return 0;
	}
	return minijail_wait(j);
}
