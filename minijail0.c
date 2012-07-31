/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libminijail.h"
#include "libsyscalls.h"

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
	printf("Usage: %s [-Ghnprsv] [-b <src>,<dest>[,<writeable>]] "
	       "[-c <caps>] [-C <dir>] [-g <group>] [-S <file>] [-u <user>] "
	       "<program> [args...]\n"
	       "  -b:         binds <src> to <dest> in chroot. Multiple "
	       "instances allowed\n"
	       "  -c <caps>:  restrict caps to <caps>\n"
	       "  -C <dir>:   chroot to <dir>\n"
	       "  -G:         inherit secondary groups from uid\n"
	       "  -g <group>: change gid to <group>\n"
	       "  -h:         help (this message)\n"
	       "  -H:         seccomp filter help message\n"
	       "  -n:         set no_new_privs\n"
	       "  -p:         use pid namespace (implies -vr)\n"
	       "  -r:         remount /proc readonly (implies -v)\n"
	       "  -s:         use seccomp\n"
	       "  -S <file>:  set seccomp filters using <file>\n"
	       "              E.g., -S /usr/share/filters/<prog>.$(uname -m)\n"
	       "  -u <user>:  change uid to <user>\n"
	       "  -v:         use vfs namespace\n", progn);
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

int main(int argc, char *argv[])
{
	struct minijail *j = minijail_new();

	int opt;
	while ((opt = getopt(argc, argv, "u:g:sS:c:C:b:vrGhHnp")) != -1) {
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
		case 'b':
			add_binding(j, optarg);
			break;
		case 'c':
			use_caps(j, optarg);
			break;
		case 'C':
			minijail_enter_chroot(j, optarg);
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
			minijail_namespace_pids(j);
			break;
		case 'H':
			seccomp_filter_usage(argv[0]);
			exit(1);
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (argc == optind) {
		usage(argv[0]);
		exit(1);
	}

	argc -= optind;
	argv += optind;

	minijail_run(j, argv[0], argv);
	return minijail_wait(j);
}
