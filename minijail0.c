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

#include "elfparse.h"
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

static void add_binding(struct minijail *j, char *arg)
{
	char *src = strtok(arg, ",");
	char *dest = strtok(NULL, ",");
	char *flags = strtok(NULL, ",");
	if (!src || !dest) {
		fprintf(stderr, "Bad binding: %s %s\n", src, dest);
		exit(1);
	}
	if (minijail_bind(j, src, dest, flags ? atoi(flags) : 0)) {
		fprintf(stderr, "minijail_bind failed.\n");
		exit(1);
	}
}

static void add_mount(struct minijail *j, char *arg)
{
	char *src = strtok(arg, ",");
	char *dest = strtok(NULL, ",");
	char *type = strtok(NULL, ",");
	char *flags = strtok(NULL, ",");
	if (!src || !dest || !type) {
		fprintf(stderr, "Bad mount: %s %s %s\n", src, dest, type);
		exit(1);
	}
	if (minijail_mount(j, src, dest, type,
			   flags ? strtoul(flags, NULL, 16) : 0)) {
		fprintf(stderr, "minijail_mount failed.\n");
		exit(1);
	}
}

static void usage(const char *progn)
{
	size_t i;

	printf("Usage: %s [-GhiInprsvtUl] [-b <src>,<dest>[,<writeable>]] [-f <file>]"
	       "[-c <caps>] [-C <dir>] [-g <group>] [-S <file>] [-u <user>] "
	       "[-k <src>,<dest>,<type>[,<flags>]] "
	       "[-m \"<uid> <loweruid> <count>[,<uid> <loweruid> <count>]\"] "
	       "[-M \"<gid> <lowergid> <count>[,<uid> <loweruid> <count>]\"] "
	       "<program> [args...]\n"
	       "  -a <table>: use alternate syscall table <table>\n"
	       "  -b:         binds <src> to <dest> in chroot. Multiple "
	       "instances allowed\n"
	       "  -k:         mount <src> to <dest> in chroot. Multiple "
	       "instances allowed, flags are passed to mount(2)\n"
	       "  -c <caps>:  restrict caps to <caps>\n"
	       "  -C <dir>:   chroot to <dir>\n"
	       "              Not compatible with -P\n"
	       "  -e[file]:   enter new network namespace, or existing one if 'file' is provided\n"
	       "  -f <file>:  write the pid of the jailed process to <file>\n"
	       "  -G:         inherit secondary groups from uid\n"
	       "  -g <group>: change gid to <group>\n"
	       "  -h:         help (this message)\n"
	       "  -H:         seccomp filter help message\n"
	       "  -i:         exit immediately after fork (do not act as init)\n"
	       "              Not compatible with -p\n"
	       "  -I:         run <program> as init (pid 1) inside a new pid namespace (implies -p)\n"
	       "  -l:         enter new IPC namespace\n"
	       "  -L:         report blocked syscalls to syslog when using seccomp filter.\n"
	       "              Forces the following syscalls to be allowed:\n"
	       "                  ", progn);
	for (i = 0; i < log_syscalls_len; i++)
		printf("%s ", log_syscalls[i]);

	printf("\n"
	       "  -m:         set the uid mapping of a user namespace (implies -pU).\n"
	       "              Same arguments as newuidmap(1), multiple mappings should be separated by ',' (comma).\n"
	       "              Not compatible with -b without writable\n"
	       "  -M:         set the gid mapping of a user namespace (implies -pU).\n"
	       "              Same arguments as newgidmap(1), multiple mappings should be separated by ',' (comma).\n"
	       "              Not compatible with -b without writable\n"
	       "  -n:         set no_new_privs\n"
	       "  -p:         enter new pid namespace (implies -vr)\n"
	       "  -P <dir>:   pivot_root to <dir> (implies -v)\n"
	       "              Not compatible with -C\n"
	       "  -r:         remount /proc read-only (implies -v)\n"
	       "  -s:         use seccomp\n"
	       "  -S <file>:  set seccomp filter using <file>\n"
	       "              E.g., -S /usr/share/filters/<prog>.$(uname -m)\n"
	       "              Requires -n when not running as root\n"
	       "  -t:         mount tmpfs at /tmp inside chroot\n"
	       "  -u <user>:  change uid to <user>\n"
	       "  -U          enter new user namespace (implies -p)\n"
	       "  -v:         enter new mount namespace\n"
	       "  -V <file>:  enter specified mount namespace\n");
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
	int use_seccomp_filter = 0;
	int binding = 0;
	int pivot_root = 0, chroot = 0;
	const size_t path_max = 4096;
	const char *filter_path;
	if (argc > 1 && argv[1][0] != '-')
		return 1;
	while ((opt = getopt(argc, argv,
			     "u:g:sS:c:C:P:b:V:f:m:M:k:a:e::vrGhHinplLtIU"))
	       != -1) {
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
			minijail_use_seccomp_filter(j);
			if (strlen(optarg) >= path_max) {
				fprintf(stderr, "Filter path is too long.\n");
				exit(1);
			}
			filter_path = strndup(optarg, path_max);
			if (!filter_path) {
				fprintf(stderr,
					"Could not strndup(3) filter path.\n");
				exit(1);
			}
			use_seccomp_filter = 1;
			break;
		case 'l':
			minijail_namespace_ipc(j);
			break;
		case 'L':
			minijail_log_seccomp_filter_failures(j);
			break;
		case 'b':
			add_binding(j, optarg);
			binding = 1;
			break;
		case 'c':
			use_caps(j, optarg);
			break;
		case 'C':
			if (pivot_root) {
				fprintf(stderr, "Could not set chroot because "
						"'-P' was specified.\n");
				exit(1);
			}
			if (0 != minijail_enter_chroot(j, optarg)) {
				fprintf(stderr, "Could not set chroot.\n");
				exit(1);
			}
			chroot = 1;
			break;
		case 'k':
			add_mount(j, optarg);
			break;
		case 'P':
			if (chroot) {
				fprintf(stderr,
					"Could not set pivot_root because "
					"'-C' was specified.\n");
				exit(1);
			}
			if (0 != minijail_enter_pivot_root(j, optarg)) {
				fprintf(stderr, "Could not set pivot_root.\n");
				exit(1);
			}
			minijail_namespace_vfs(j);
			pivot_root = 1;
			break;
		case 'f':
			if (0 != minijail_write_pid_file(j, optarg)) {
				fprintf(stderr,
					"Could not prepare pid file path.\n");
				exit(1);
			}
			break;
		case 't':
			minijail_mount_tmp(j);
			break;
		case 'v':
			minijail_namespace_vfs(j);
			break;
		case 'V':
			minijail_namespace_enter_vfs(j, optarg);
			break;
		case 'r':
			minijail_remount_proc_readonly(j);
			break;
		case 'G':
			minijail_inherit_usergroups(j);
			break;
		case 'p':
			minijail_namespace_pids(j);
			break;
		case 'e':
			if (optarg)
				minijail_namespace_enter_net(j, optarg);
			else
				minijail_namespace_net(j);
			break;
		case 'i':
			*exit_immediately = 1;
			break;
		case 'H':
			seccomp_filter_usage(argv[0]);
			exit(1);
		case 'I':
			minijail_namespace_pids(j);
			minijail_run_as_init(j);
			break;
		case 'U':
			minijail_namespace_user(j);
			minijail_namespace_pids(j);
			break;
		case 'm':
			minijail_namespace_user(j);
			minijail_namespace_pids(j);
			if (0 != minijail_uidmap(j, optarg)) {
				fprintf(stderr, "Could not set uidmap.\n");
				exit(1);
			}
			break;
		case 'M':
			minijail_namespace_user(j);
			minijail_namespace_pids(j);
			if (0 != minijail_gidmap(j, optarg)) {
				fprintf(stderr, "Could not set gidmap.\n");
				exit(1);
			}
			break;
		case 'a':
			if (0 != minijail_use_alt_syscall(j, optarg)) {
				fprintf(stderr,
					"Could not set alt-syscall table.\n");
				exit(1);
			}
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
		if (optind < argc && argv[optind][0] != '-')
			break;
	}

	/* Only allow bind mounts when entering a chroot or using pivot_root. */
	if (binding && !(chroot || pivot_root)) {
		fprintf(stderr, "Can't add bind mounts without chroot or"
				" pivot_root.\n");
		exit(1);
	}

	/*
	 * We parse seccomp filters here to make sure we've collected all
	 * cmdline options.
	 */
	if (use_seccomp_filter) {
		minijail_parse_seccomp_filters(j, filter_path);
		free((void*)filter_path);
	}

	if (argc == optind) {
		usage(argv[0]);
		exit(1);
	}

	return optind;
}

int main(int argc, char *argv[])
{
	struct minijail *j = minijail_new();
	const char *dl_mesg = NULL;
	int exit_immediately = 0;
	char *program_path;
	int consumed = parse_args(j, argc, argv, &exit_immediately);
	ElfType elftype = ELFERROR;
	argc -= consumed;
	argv += consumed;

	/* Get the path to the program adjusted for changing root. */
	program_path = minijail_get_original_path(j, argv[0]);

	/* Check that we can access the target program. */
	if (access(program_path, X_OK)) {
		fprintf(stderr, "Target program '%s' is not accessible.\n",
			argv[0]);
		return 1;
	}

	/* Check if target is statically or dynamically linked. */
	elftype = get_elf_linkage(program_path);
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
		if (!dlopen(PRELOADPATH, RTLD_LAZY | RTLD_LOCAL)) {
			    dl_mesg = dlerror();
			    fprintf(stderr, "dlopen(): %s\n", dl_mesg);
			    return 1;
		}
		minijail_run(j, argv[0], argv);
	} else {
		fprintf(stderr,
			"Target program '%s' is not a valid ELF file.\n",
			argv[0]);
		return 1;
	}

	free(program_path);

	if (exit_immediately) {
		info("not running init loop, exiting immediately");
		return 0;
	}
	return minijail_wait(j);
}
