/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _BSD_SOURCE
#define _GNU_SOURCE

#include <asm/unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "libminijail.h"
#include "libminijail-private.h"

#include "signal_handler.h"
#include "syscall_filter.h"
#include "util.h"

#ifdef HAVE_SECUREBITS_H
#include <linux/securebits.h>
#else
#define SECURE_ALL_BITS         0x15
#define SECURE_ALL_LOCKS        (SECURE_ALL_BITS << 1)
#endif

/* Until these are reliably available in linux/prctl.h */
#ifndef PR_SET_SECCOMP
# define PR_SET_SECCOMP 22
#endif

#ifndef PR_ALT_SYSCALL
# define PR_ALT_SYSCALL 0x43724f53
#endif

/* For seccomp_filter using BPF. */
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER 2 /* uses user-supplied filter. */
#endif

#ifdef USE_SECCOMP_SOFTFAIL
# define SECCOMP_SOFTFAIL 1
#else
# define SECCOMP_SOFTFAIL 0
#endif

#define MAX_CGROUPS 10 /* 10 different controllers supported by Linux. */

struct mountpoint {
	char *src;
	char *dest;
	char *type;
	unsigned long flags;
	struct mountpoint *next;
};

struct minijail {
	/*
	 * WARNING: if you add a flag here you need to make sure it's
	 * accounted for in minijail_pre{enter|exec}() below.
	 */
	struct {
		int uid:1;
		int gid:1;
		int usergroups:1;
		int suppl_gids:1;
		int caps:1;
		int vfs:1;
		int enter_vfs:1;
		int pids:1;
		int ipc:1;
		int net:1;
		int enter_net:1;
		int userns:1;
		int seccomp:1;
		int remount_proc_ro:1;
		int no_new_privs:1;
		int seccomp_filter:1;
		int log_seccomp_filter:1;
		int chroot:1;
		int pivot_root:1;
		int mount_tmp:1;
		int do_init:1;
		int pid_file:1;
		int cgroups:1;
		int alt_syscall:1;
		int reset_signal_mask:1;
	} flags;
	uid_t uid;
	gid_t gid;
	gid_t usergid;
	char *user;
	size_t suppl_gid_count;
	gid_t *suppl_gid_list;
	uint64_t caps;
	pid_t initpid;
	int mountns_fd;
	int netns_fd;
	char *chrootdir;
	char *pid_file_path;
	char *uidmap;
	char *gidmap;
	size_t filter_len;
	struct sock_fprog *filter_prog;
	char *alt_syscall_table;
	struct mountpoint *mounts_head;
	struct mountpoint *mounts_tail;
	size_t mounts_count;
	char *cgroups[MAX_CGROUPS];
	size_t cgroup_count;
};

/*
 * Strip out flags meant for the parent.
 * We keep things that are not inherited across execve(2) (e.g. capabilities),
 * or are easier to set after execve(2) (e.g. seccomp filters).
 */
void minijail_preenter(struct minijail *j)
{
	j->flags.vfs = 0;
	j->flags.enter_vfs = 0;
	j->flags.remount_proc_ro = 0;
	j->flags.pids = 0;
	j->flags.do_init = 0;
	j->flags.pid_file = 0;
	j->flags.cgroups = 0;
}

/*
 * Strip out flags meant for the child.
 * We keep things that are inherited across execve(2).
 */
void minijail_preexec(struct minijail *j)
{
	int vfs = j->flags.vfs;
	int enter_vfs = j->flags.enter_vfs;
	int remount_proc_ro = j->flags.remount_proc_ro;
	int userns = j->flags.userns;
	if (j->user)
		free(j->user);
	j->user = NULL;
	if (j->suppl_gid_list)
		free(j->suppl_gid_list);
	j->suppl_gid_list = NULL;
	memset(&j->flags, 0, sizeof(j->flags));
	/* Now restore anything we meant to keep. */
	j->flags.vfs = vfs;
	j->flags.enter_vfs = enter_vfs;
	j->flags.remount_proc_ro = remount_proc_ro;
	j->flags.userns = userns;
	/* Note, |pids| will already have been used before this call. */
}

/* Returns true if the kernel version is less than 3.8. */
int seccomp_kernel_support_not_required()
{
	int major, minor;
	struct utsname uts;
	return (uname(&uts) != -1 &&
			sscanf(uts.release, "%d.%d", &major, &minor) == 2 &&
			((major < 3) || ((major == 3) && (minor < 8))));
}

/* Allow seccomp soft-fail on Android devices with kernel version < 3.8. */
int can_softfail()
{
#if SECCOMP_SOFTFAIL
	if (is_android()) {
		if (seccomp_kernel_support_not_required())
			return 1;
		else
			return 0;
	} else {
		return 1;
	}
#endif
	return 0;
}

/* Minijail API. */

struct minijail API *minijail_new(void)
{
	return calloc(1, sizeof(struct minijail));
}

void API minijail_change_uid(struct minijail *j, uid_t uid)
{
	if (uid == 0)
		die("useless change to uid 0");
	j->uid = uid;
	j->flags.uid = 1;
}

void API minijail_change_gid(struct minijail *j, gid_t gid)
{
	if (gid == 0)
		die("useless change to gid 0");
	j->gid = gid;
	j->flags.gid = 1;
}

void API minijail_set_supplementary_gids(struct minijail *j, size_t size,
					 const gid_t *list)
{
	size_t i;

	if (j->flags.usergroups)
		die("cannot inherit *and* set supplementary groups");

	if (size == 0) {
		/* Clear supplementary groups. */
		j->suppl_gid_list = NULL;
		j->suppl_gid_count = 0;
		j->flags.suppl_gids = 1;
		return;
	}

	/* Copy the gid_t array. */
	j->suppl_gid_list = calloc(size, sizeof(gid_t));
	if (!j->suppl_gid_list) {
		die("failed to allocate internal supplementary group array");
	}
	for (i = 0; i < size; i++) {
		j->suppl_gid_list[i] = list[i];
	}
	j->suppl_gid_count = size;
	j->flags.suppl_gids = 1;
}

int API minijail_change_user(struct minijail *j, const char *user)
{
	char *buf = NULL;
	struct passwd pw;
	struct passwd *ppw = NULL;
	ssize_t sz = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (sz == -1)
		sz = 65536;	/* your guess is as good as mine... */

	/*
	 * sysconf(_SC_GETPW_R_SIZE_MAX), under glibc, is documented to return
	 * the maximum needed size of the buffer, so we don't have to search.
	 */
	buf = malloc(sz);
	if (!buf)
		return -ENOMEM;
	getpwnam_r(user, &pw, buf, sz, &ppw);
	/*
	 * We're safe to free the buffer here. The strings inside |pw| point
	 * inside |buf|, but we don't use any of them; this leaves the pointers
	 * dangling but it's safe. |ppw| points at |pw| if getpwnam_r(3) succeeded.
	 */
	free(buf);
	/* getpwnam_r(3) does *not* set errno when |ppw| is NULL. */
	if (!ppw)
		return -1;
	minijail_change_uid(j, ppw->pw_uid);
	j->user = strdup(user);
	if (!j->user)
		return -ENOMEM;
	j->usergid = ppw->pw_gid;
	return 0;
}

int API minijail_change_group(struct minijail *j, const char *group)
{
	char *buf = NULL;
	struct group gr;
	struct group *pgr = NULL;
	ssize_t sz = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (sz == -1)
		sz = 65536;	/* and mine is as good as yours, really */

	/*
	 * sysconf(_SC_GETGR_R_SIZE_MAX), under glibc, is documented to return
	 * the maximum needed size of the buffer, so we don't have to search.
	 */
	buf = malloc(sz);
	if (!buf)
		return -ENOMEM;
	getgrnam_r(group, &gr, buf, sz, &pgr);
	/*
	 * We're safe to free the buffer here. The strings inside gr point
	 * inside buf, but we don't use any of them; this leaves the pointers
	 * dangling but it's safe. pgr points at gr if getgrnam_r succeeded.
	 */
	free(buf);
	/* getgrnam_r(3) does *not* set errno when |pgr| is NULL. */
	if (!pgr)
		return -1;
	minijail_change_gid(j, pgr->gr_gid);
	return 0;
}

void API minijail_use_seccomp(struct minijail *j)
{
	j->flags.seccomp = 1;
}

void API minijail_no_new_privs(struct minijail *j)
{
	j->flags.no_new_privs = 1;
}

void API minijail_use_seccomp_filter(struct minijail *j)
{
	j->flags.seccomp_filter = 1;
}

void API minijail_log_seccomp_filter_failures(struct minijail *j)
{
	j->flags.log_seccomp_filter = 1;
}

void API minijail_use_caps(struct minijail *j, uint64_t capmask)
{
	j->caps = capmask;
	j->flags.caps = 1;
}

void API minijail_reset_signal_mask(struct minijail* j) {
	j->flags.reset_signal_mask = 1;
}

void API minijail_namespace_vfs(struct minijail *j)
{
	j->flags.vfs = 1;
}

void API minijail_namespace_enter_vfs(struct minijail *j, const char *ns_path)
{
	int ns_fd = open(ns_path, O_RDONLY);
	if (ns_fd < 0) {
		pdie("failed to open namespace '%s'", ns_path);
	}
	j->mountns_fd = ns_fd;
	j->flags.enter_vfs = 1;
}

void API minijail_namespace_pids(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.remount_proc_ro = 1;
	j->flags.pids = 1;
	j->flags.do_init = 1;
}

void API minijail_namespace_ipc(struct minijail *j)
{
	j->flags.ipc = 1;
}

void API minijail_namespace_net(struct minijail *j)
{
	j->flags.net = 1;
}

void API minijail_namespace_enter_net(struct minijail *j, const char *ns_path)
{
	int ns_fd = open(ns_path, O_RDONLY);
	if (ns_fd < 0) {
		pdie("failed to open namespace '%s'", ns_path);
	}
	j->netns_fd = ns_fd;
	j->flags.enter_net = 1;
}

void API minijail_remount_proc_readonly(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.remount_proc_ro = 1;
}

void API minijail_namespace_user(struct minijail *j)
{
	j->flags.userns = 1;
}

int API minijail_uidmap(struct minijail *j, const char *uidmap)
{
	j->uidmap = strdup(uidmap);
	if (!j->uidmap)
		return -ENOMEM;
	char *ch;
	for (ch = j->uidmap; *ch; ch++) {
		if (*ch == ',')
			*ch = '\n';
	}
	return 0;
}

int API minijail_gidmap(struct minijail *j, const char *gidmap)
{
	j->gidmap = strdup(gidmap);
	if (!j->gidmap)
		return -ENOMEM;
	char *ch;
	for (ch = j->gidmap; *ch; ch++) {
		if (*ch == ',')
			*ch = '\n';
	}
	return 0;
}

void API minijail_inherit_usergroups(struct minijail *j)
{
	j->flags.usergroups = 1;
}

void API minijail_run_as_init(struct minijail *j)
{
	/*
	 * Since the jailed program will become 'init' in the new PID namespace,
	 * Minijail does not need to fork an 'init' process.
	 */
	j->flags.do_init = 0;
}

int API minijail_enter_chroot(struct minijail *j, const char *dir)
{
	if (j->chrootdir)
		return -EINVAL;
	j->chrootdir = strdup(dir);
	if (!j->chrootdir)
		return -ENOMEM;
	j->flags.chroot = 1;
	return 0;
}

int API minijail_enter_pivot_root(struct minijail *j, const char *dir)
{
	if (j->chrootdir)
		return -EINVAL;
	j->chrootdir = strdup(dir);
	if (!j->chrootdir)
		return -ENOMEM;
	j->flags.pivot_root = 1;
	return 0;
}

static char *append_external_path(const char *external_path,
				  const char *path_inside_chroot)
{
	char *path;
	size_t pathlen;

	/* One extra char for '/' and one for '\0', hence + 2. */
	pathlen = strlen(path_inside_chroot) + strlen(external_path) + 2;
	path = malloc(pathlen);
	snprintf(path, pathlen, "%s/%s", external_path, path_inside_chroot);

	return path;
}

char API *minijail_get_original_path(struct minijail *j,
				     const char *path_inside_chroot)
{
	struct mountpoint *b;

	b = j->mounts_head;
	while (b) {
		/*
		 * If |path_inside_chroot| is the exact destination of a
		 * mount, then the original path is exactly the source of
		 * the mount.
		 *  for example: "-b /some/path/exe,/chroot/path/exe"
		 *    mount source = /some/path/exe, mount dest =
		 *    /chroot/path/exe Then when getting the original path of
		 *    "/chroot/path/exe", the source of that mount,
		 *    "/some/path/exe" is what should be returned.
		 */
		if (!strcmp(b->dest, path_inside_chroot))
			return strdup(b->src);

		/*
		 * If |path_inside_chroot| is within the destination path of a
		 * mount, take the suffix of the chroot path relative to the
		 * mount destination path, and append it to the mount source
		 * path.
		 */
		if (!strncmp(b->dest, path_inside_chroot, strlen(b->dest))) {
			const char *relative_path =
				path_inside_chroot + strlen(b->dest);
			return append_external_path(b->src, relative_path);
		}
		b = b->next;
	}

	/* If there is a chroot path, append |path_inside_chroot| to that. */
	if (j->chrootdir)
		return append_external_path(j->chrootdir, path_inside_chroot);

	/* No chroot, so the path outside is the same as it is inside. */
	return strdup(path_inside_chroot);
}

void API minijail_mount_tmp(struct minijail *j)
{
	j->flags.mount_tmp = 1;
}

int API minijail_write_pid_file(struct minijail *j, const char *path)
{
	j->pid_file_path = strdup(path);
	if (!j->pid_file_path)
		return -ENOMEM;
	j->flags.pid_file = 1;
	return 0;
}

int API minijail_add_to_cgroup(struct minijail *j, const char *path)
{
	if (j->cgroup_count >= MAX_CGROUPS)
		return -ENOMEM;
	j->cgroups[j->cgroup_count] = strdup(path);
	if (!j->cgroups[j->cgroup_count])
		return -ENOMEM;
	j->cgroup_count++;
	j->flags.cgroups = 1;
	return 0;
}

int API minijail_mount(struct minijail *j, const char *src, const char *dest,
		       const char *type, unsigned long flags)
{
	struct mountpoint *m;

	if (*dest != '/')
		return -EINVAL;
	m = calloc(1, sizeof(*m));
	if (!m)
		return -ENOMEM;
	m->dest = strdup(dest);
	if (!m->dest)
		goto error;
	m->src = strdup(src);
	if (!m->src)
		goto error;
	m->type = strdup(type);
	if (!m->type)
		goto error;
	m->flags = flags;

	info("mount %s -> %s type '%s'", src, dest, type);

	/*
	 * Force vfs namespacing so the mounts don't leak out into the
	 * containing vfs namespace.
	 */
	minijail_namespace_vfs(j);

	if (j->mounts_tail)
		j->mounts_tail->next = m;
	else
		j->mounts_head = m;
	j->mounts_tail = m;
	j->mounts_count++;

	return 0;

error:
	free(m->src);
	free(m->dest);
	free(m);
	return -ENOMEM;
}

int API minijail_bind(struct minijail *j, const char *src, const char *dest,
		      int writeable)
{
	unsigned long flags = MS_BIND;

	if (!writeable)
		flags |= MS_RDONLY;

	return minijail_mount(j, src, dest, "", flags);
}

void API minijail_parse_seccomp_filters(struct minijail *j, const char *path)
{
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL)) {
		if ((errno == EINVAL) && can_softfail()) {
			warn("not loading seccomp filter,"
			     " seccomp not supported");
			j->flags.seccomp_filter = 0;
			j->flags.log_seccomp_filter = 0;
			j->filter_len = 0;
			j->filter_prog = NULL;
			j->flags.no_new_privs = 0;
		}
	}
	FILE *file = fopen(path, "r");
	if (!file) {
		pdie("failed to open seccomp filter file '%s'", path);
	}

	struct sock_fprog *fprog = malloc(sizeof(struct sock_fprog));
	if (compile_filter(file, fprog, j->flags.log_seccomp_filter)) {
		die("failed to compile seccomp filter BPF program in '%s'",
		    path);
	}

	j->filter_len = fprog->len;
	j->filter_prog = fprog;

	fclose(file);
}

int API minijail_use_alt_syscall(struct minijail *j, const char *table)
{
	j->alt_syscall_table = strdup(table);
	if (!j->alt_syscall_table)
		return -ENOMEM;
	j->flags.alt_syscall = 1;
	return 0;
}

struct marshal_state {
	size_t available;
	size_t total;
	char *buf;
};

void marshal_state_init(struct marshal_state *state,
			char *buf, size_t available)
{
	state->available = available;
	state->buf = buf;
	state->total = 0;
}

void marshal_append(struct marshal_state *state,
		    void *src, size_t length)
{
	size_t copy_len = MIN(state->available, length);

	/* Up to |available| will be written. */
	if (copy_len) {
		memcpy(state->buf, src, copy_len);
		state->buf += copy_len;
		state->available -= copy_len;
	}
	/* |total| will contain the expected length. */
	state->total += length;
}

void minijail_marshal_helper(struct marshal_state *state,
			     const struct minijail *j)
{
	struct mountpoint *m = NULL;
	size_t i;

	marshal_append(state, (char *)j, sizeof(*j));
	if (j->user)
		marshal_append(state, j->user, strlen(j->user) + 1);
	if (j->suppl_gid_list) {
		marshal_append(state, j->suppl_gid_list,
			       j->suppl_gid_count * sizeof(gid_t));
	}
	if (j->chrootdir)
		marshal_append(state, j->chrootdir, strlen(j->chrootdir) + 1);
	if (j->alt_syscall_table) {
		marshal_append(state, j->alt_syscall_table,
			       strlen(j->alt_syscall_table) + 1);
	}
	if (j->flags.seccomp_filter && j->filter_prog) {
		struct sock_fprog *fp = j->filter_prog;
		marshal_append(state, (char *)fp->filter,
				fp->len * sizeof(struct sock_filter));
	}
	for (m = j->mounts_head; m; m = m->next) {
		marshal_append(state, m->src, strlen(m->src) + 1);
		marshal_append(state, m->dest, strlen(m->dest) + 1);
		marshal_append(state, m->type, strlen(m->type) + 1);
		marshal_append(state, (char *)&m->flags, sizeof(m->flags));
	}
	for (i = 0; i < j->cgroup_count; ++i)
		marshal_append(state, j->cgroups[i], strlen(j->cgroups[i]) + 1);
}

size_t API minijail_size(const struct minijail *j)
{
	struct marshal_state state;
	marshal_state_init(&state, NULL, 0);
	minijail_marshal_helper(&state, j);
	return state.total;
}

int minijail_marshal(const struct minijail *j, char *buf, size_t available)
{
	struct marshal_state state;
	marshal_state_init(&state, buf, available);
	minijail_marshal_helper(&state, j);
	return (state.total > available);
}

/*
 * consumebytes: consumes @length bytes from a buffer @buf of length @buflength
 * @length    Number of bytes to consume
 * @buf       Buffer to consume from
 * @buflength Size of @buf
 *
 * Returns a pointer to the base of the bytes, or NULL for errors.
 */
void *consumebytes(size_t length, char **buf, size_t *buflength)
{
	char *p = *buf;
	if (length > *buflength)
		return NULL;
	*buf += length;
	*buflength -= length;
	return p;
}

/*
 * consumestr: consumes a C string from a buffer @buf of length @length
 * @buf    Buffer to consume
 * @length Length of buffer
 *
 * Returns a pointer to the base of the string, or NULL for errors.
 */
char *consumestr(char **buf, size_t *buflength)
{
	size_t len = strnlen(*buf, *buflength);
	if (len == *buflength)
		/* There's no null-terminator. */
		return NULL;
	return consumebytes(len + 1, buf, buflength);
}

int minijail_unmarshal(struct minijail *j, char *serialized, size_t length)
{
	size_t i;
	size_t count;
	int ret = -EINVAL;

	if (length < sizeof(*j))
		goto out;
	memcpy((void *)j, serialized, sizeof(*j));
	serialized += sizeof(*j);
	length -= sizeof(*j);

	/* Potentially stale pointers not used as signals. */
	j->mounts_head = NULL;
	j->mounts_tail = NULL;
	j->filter_prog = NULL;

	if (j->user) {		/* stale pointer */
		char *user = consumestr(&serialized, &length);
		if (!user)
			goto clear_pointers;
		j->user = strdup(user);
		if (!j->user)
			goto clear_pointers;
	}

	if (j->suppl_gid_list) {	/* stale pointer */
		if (j->suppl_gid_count > NGROUPS_MAX) {
			goto bad_gid_list;
		}
		size_t gid_list_size = j->suppl_gid_count * sizeof(gid_t);
		void *gid_list_bytes =
		    consumebytes(gid_list_size, &serialized, &length);
		if (!gid_list_bytes)
			goto bad_gid_list;

		j->suppl_gid_list = calloc(j->suppl_gid_count, sizeof(gid_t));
		if (!j->suppl_gid_list)
			goto bad_gid_list;

		memcpy(j->suppl_gid_list, gid_list_bytes, gid_list_size);
	}

	if (j->chrootdir) {	/* stale pointer */
		char *chrootdir = consumestr(&serialized, &length);
		if (!chrootdir)
			goto bad_chrootdir;
		j->chrootdir = strdup(chrootdir);
		if (!j->chrootdir)
			goto bad_chrootdir;
	}

	if (j->alt_syscall_table) {	/* stale pointer */
		char *alt_syscall_table = consumestr(&serialized, &length);
		if (!alt_syscall_table)
			goto bad_syscall_table;
		j->alt_syscall_table = strdup(alt_syscall_table);
		if (!j->alt_syscall_table)
			goto bad_syscall_table;
	}

	if (j->flags.seccomp_filter && j->filter_len > 0) {
		size_t ninstrs = j->filter_len;
		if (ninstrs > (SIZE_MAX / sizeof(struct sock_filter)) ||
		    ninstrs > USHRT_MAX)
			goto bad_filters;

		size_t program_len = ninstrs * sizeof(struct sock_filter);
		void *program = consumebytes(program_len, &serialized, &length);
		if (!program)
			goto bad_filters;

		j->filter_prog = malloc(sizeof(struct sock_fprog));
		if (!j->filter_prog)
			goto bad_filters;

		j->filter_prog->len = ninstrs;
		j->filter_prog->filter = malloc(program_len);
		if (!j->filter_prog->filter)
			goto bad_filter_prog_instrs;

		memcpy(j->filter_prog->filter, program, program_len);
	}

	count = j->mounts_count;
	j->mounts_count = 0;
	for (i = 0; i < count; ++i) {
		unsigned long *flags;
		const char *dest;
		const char *type;
		const char *src = consumestr(&serialized, &length);
		if (!src)
			goto bad_mounts;
		dest = consumestr(&serialized, &length);
		if (!dest)
			goto bad_mounts;
		type = consumestr(&serialized, &length);
		if (!type)
			goto bad_mounts;
		flags = consumebytes(sizeof(*flags), &serialized, &length);
		if (!flags)
			goto bad_mounts;
		if (minijail_mount(j, src, dest, type, *flags))
			goto bad_mounts;
	}

	count = j->cgroup_count;
	j->cgroup_count = 0;
	for (i = 0; i < count; ++i) {
		char *cgroup = consumestr(&serialized, &length);
		if (!cgroup)
			goto bad_cgroups;
		j->cgroups[i] = strdup(cgroup);
		if (!j->cgroups[i])
			goto bad_cgroups;
		++j->cgroup_count;
	}

	return 0;

bad_cgroups:
	while (j->mounts_head) {
		struct mountpoint *m = j->mounts_head;
		j->mounts_head = j->mounts_head->next;
		free(m->type);
		free(m->dest);
		free(m->src);
		free(m);
	}
	for (i = 0; i < j->cgroup_count; ++i)
		free(j->cgroups[i]);
bad_mounts:
	if (j->flags.seccomp_filter && j->filter_len > 0) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}
bad_filter_prog_instrs:
	if (j->filter_prog)
		free(j->filter_prog);
bad_filters:
	if (j->alt_syscall_table)
		free(j->alt_syscall_table);
bad_syscall_table:
	if (j->chrootdir)
		free(j->chrootdir);
bad_chrootdir:
	if (j->suppl_gid_list)
		free(j->suppl_gid_list);
bad_gid_list:
	if (j->user)
		free(j->user);
clear_pointers:
	j->user = NULL;
	j->suppl_gid_list = NULL;
	j->chrootdir = NULL;
	j->alt_syscall_table = NULL;
	j->cgroup_count = 0;
out:
	return ret;
}

static void write_ugid_mappings(const struct minijail *j)
{
	int fd, ret, len;
	size_t sz;
	char fname[32];

	sz = sizeof(fname);
	if (j->uidmap) {
		ret = snprintf(fname, sz, "/proc/%d/uid_map", j->initpid);
		if (ret < 0 || (size_t)ret >= sz)
			die("failed to write file name of uid_map");
		fd = open(fname, O_WRONLY);
		if (fd < 0)
			pdie("failed to open '%s'", fname);
		len = strlen(j->uidmap);
		if (write(fd, j->uidmap, len) < len)
			die("failed to set uid_map");
		close(fd);
	}
	if (j->gidmap) {
		ret = snprintf(fname, sz, "/proc/%d/gid_map", j->initpid);
		if (ret < 0 || (size_t)ret >= sz)
			die("failed to write file name of gid_map");
		fd = open(fname, O_WRONLY);
		if (fd < 0)
			pdie("failed to open '%s'", fname);
		len = strlen(j->gidmap);
		if (write(fd, j->gidmap, len) < len)
			die("failed to set gid_map");
		close(fd);
	}
}

static void parent_setup_complete(int *pipe_fds)
{
	close(pipe_fds[0]);
	close(pipe_fds[1]);
}

/*
 * wait_for_parent_setup: Called by the child process to wait for any
 * further parent-side setup to complete before continuing.
 */
static void wait_for_parent_setup(int *pipe_fds)
{
	char buf;

	close(pipe_fds[1]);

	/* Wait for parent to complete setup and close the pipe. */
	if (read(pipe_fds[0], &buf, 1) != 0)
		die("failed to sync with parent");
	close(pipe_fds[0]);
}

static void enter_user_namespace(const struct minijail *j)
{
	if (j->uidmap && setresuid(0, 0, 0))
		pdie("setresuid");
	if (j->gidmap && setresgid(0, 0, 0))
		pdie("setresgid");
}

/*
 * mount_one: Applies mounts from @m for @j, recursing as needed.
 * @j Minijail these mounts are for
 * @m Head of list of mounts
 *
 * Returns 0 for success.
 */
static int mount_one(const struct minijail *j, struct mountpoint *m)
{
	int ret;
	char *dest;
	int remount_ro = 0;

	/* |dest| has a leading "/". */
	if (asprintf(&dest, "%s%s", j->chrootdir, m->dest) < 0)
		return -ENOMEM;

	/*
	 * R/O bind mounts have to be remounted since 'bind' and 'ro'
	 * can't both be specified in the original bind mount.
	 * Remount R/O after the initial mount.
	 */
	if ((m->flags & MS_BIND) && (m->flags & MS_RDONLY)) {
		remount_ro = 1;
		m->flags &= ~MS_RDONLY;
	}

	ret = mount(m->src, dest, m->type, m->flags, NULL);
	if (ret)
		pdie("mount: %s -> %s", m->src, dest);

	if (remount_ro) {
		m->flags |= MS_RDONLY;
		ret = mount(m->src, dest, NULL,
			    m->flags | MS_REMOUNT, NULL);
		if (ret)
			pdie("bind ro: %s -> %s", m->src, dest);
	}

	free(dest);
	if (m->next)
		return mount_one(j, m->next);
	return ret;
}

int enter_chroot(const struct minijail *j)
{
	int ret;

	if (j->mounts_head && (ret = mount_one(j, j->mounts_head)))
		return ret;

	if (chroot(j->chrootdir))
		return -errno;

	if (chdir("/"))
		return -errno;

	return 0;
}

int enter_pivot_root(const struct minijail *j)
{
	int ret, oldroot, newroot;

	if (j->mounts_head && (ret = mount_one(j, j->mounts_head)))
		return ret;

	/*
	 * Keep the fd for both old and new root.
	 * It will be used in fchdir later.
	 */
	oldroot = open("/", O_DIRECTORY | O_RDONLY);
	if (oldroot < 0)
		pdie("failed to open / for fchdir");
	newroot = open(j->chrootdir, O_DIRECTORY | O_RDONLY);
	if (newroot < 0)
		pdie("failed to open %s for fchdir", j->chrootdir);

	/*
	 * To ensure chrootdir is the root of a file system,
	 * do a self bind mount.
	 */
	if (mount(j->chrootdir, j->chrootdir, "bind", MS_BIND | MS_REC, ""))
		pdie("failed to bind mount '%s'", j->chrootdir);
	if (chdir(j->chrootdir))
		return -errno;
	if (syscall(SYS_pivot_root, ".", "."))
		pdie("pivot_root");

	/*
	 * Now the old root is mounted on top of the new root. Use fchdir to
	 * change to the old root and unmount it.
	 */
	if (fchdir(oldroot))
		pdie("failed to fchdir to old /");
	/* The old root might be busy, so use lazy unmount. */
	if (umount2(".", MNT_DETACH))
		pdie("umount(/)");
	/* Change back to the new root. */
	if (fchdir(newroot))
		return -errno;
	if (chroot("/"))
		return -errno;
	/* Set correct CWD for getcwd(3). */
	if (chdir("/"))
		return -errno;

	return 0;
}

int mount_tmp(void)
{
	return mount("none", "/tmp", "tmpfs", 0, "size=64M,mode=777");
}

int remount_proc_readonly(const struct minijail *j)
{
	const char *kProcPath = "/proc";
	const unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;
	/*
	 * Right now, we're holding a reference to our parent's old mount of
	 * /proc in our namespace, which means using MS_REMOUNT here would
	 * mutate our parent's mount as well, even though we're in a VFS
	 * namespace (!). Instead, remove their mount from our namespace
	 * and make our own. However, if we are in a new user namespace, /proc
	 * is not seen as mounted, so don't return error if umount() fails.
	 */
	if (umount2(kProcPath, MNT_DETACH) && !j->flags.userns)
		return -errno;
	if (mount("", kProcPath, "proc", kSafeFlags | MS_RDONLY, ""))
		return -errno;
	return 0;
}

static void write_pid_to_path(pid_t pid, const char *path)
{
	FILE *fp = fopen(path, "w");

	if (!fp)
		pdie("failed to open '%s'", path);
	if (fprintf(fp, "%d\n", (int)pid) < 0)
		pdie("fprintf(%s)", path);
	if (fclose(fp))
		pdie("fclose(%s)", path);
}

static void write_pid_file(const struct minijail *j)
{
	write_pid_to_path(j->initpid, j->pid_file_path);
}

static void add_to_cgroups(const struct minijail *j)
{
	size_t i;

	for (i = 0; i < j->cgroup_count; ++i)
		write_pid_to_path(j->initpid, j->cgroups[i]);
}

void drop_ugid(const struct minijail *j)
{
	if (j->flags.usergroups && j->flags.suppl_gids) {
		die("tried to inherit *and* set supplementary groups;"
		    " can only do one");
	}

	if (j->flags.usergroups) {
		if (initgroups(j->user, j->usergid))
			pdie("initgroups");
	} else if (j->flags.suppl_gids) {
		if (setgroups(j->suppl_gid_count, j->suppl_gid_list)) {
			pdie("setgroups");
		}
	} else {
		/*
		 * Only attempt to clear supplementary groups if we are changing
		 * users.
		 */
		if ((j->uid || j->gid) && setgroups(0, NULL))
			pdie("setgroups");
	}

	if (j->flags.gid && setresgid(j->gid, j->gid, j->gid))
		pdie("setresgid");

	if (j->flags.uid && setresuid(j->uid, j->uid, j->uid))
		pdie("setresuid");
}

/*
 * We specifically do not use cap_valid() as that only tells us the last
 * valid cap we were *compiled* against (i.e. what the version of kernel
 * headers says). If we run on a different kernel version, then it's not
 * uncommon for that to be less (if an older kernel) or more (if a newer
 * kernel).
 * Normally, we suck up the answer via /proc. On Android, not all processes are
 * guaranteed to be able to access '/proc/sys/kernel/cap_last_cap' so we
 * programmatically find the value by calling prctl(PR_CAPBSET_READ).
 */
static unsigned int get_last_valid_cap()
{
	unsigned int last_valid_cap = 0;
	if (is_android()) {
		for (; prctl(PR_CAPBSET_READ, last_valid_cap, 0, 0, 0) >= 0;
		     ++last_valid_cap);

		/* |last_valid_cap| will be the first failing value. */
		if (last_valid_cap > 0) {
			last_valid_cap--;
		}
	} else {
		const char cap_file[] = "/proc/sys/kernel/cap_last_cap";
		FILE *fp = fopen(cap_file, "re");
		if (fscanf(fp, "%u", &last_valid_cap) != 1)
			pdie("fscanf(%s)", cap_file);
		fclose(fp);
	}
	return last_valid_cap;
}

void drop_caps(const struct minijail *j, unsigned int last_valid_cap)
{
	cap_t caps = cap_get_proc();
	cap_value_t flag[1];
	const uint64_t one = 1;
	unsigned int i;
	if (!caps)
		die("can't get process caps");
	if (cap_clear_flag(caps, CAP_INHERITABLE))
		die("can't clear inheritable caps");
	if (cap_clear_flag(caps, CAP_EFFECTIVE))
		die("can't clear effective caps");
	if (cap_clear_flag(caps, CAP_PERMITTED))
		die("can't clear permitted caps");
	for (i = 0; i < sizeof(j->caps) * 8 && i <= last_valid_cap; ++i) {
		/* Keep CAP_SETPCAP for dropping bounding set bits. */
		if (i != CAP_SETPCAP && !(j->caps & (one << i)))
			continue;
		flag[0] = i;
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, flag, CAP_SET))
			die("can't add effective cap");
		if (cap_set_flag(caps, CAP_PERMITTED, 1, flag, CAP_SET))
			die("can't add permitted cap");
		if (cap_set_flag(caps, CAP_INHERITABLE, 1, flag, CAP_SET))
			die("can't add inheritable cap");
	}
	if (cap_set_proc(caps))
		die("can't apply initial cleaned capset");

	/*
	 * Instead of dropping bounding set first, do it here in case
	 * the caller had a more permissive bounding set which could
	 * have been used above to raise a capability that wasn't already
	 * present. This requires CAP_SETPCAP, so we raised/kept it above.
	 */
	for (i = 0; i < sizeof(j->caps) * 8 && i <= last_valid_cap; ++i) {
		if (j->caps & (one << i))
			continue;
		if (prctl(PR_CAPBSET_DROP, i))
			pdie("prctl(PR_CAPBSET_DROP)");
	}

	/* If CAP_SETPCAP wasn't specifically requested, now we remove it. */
	if ((j->caps & (one << CAP_SETPCAP)) == 0) {
		flag[0] = CAP_SETPCAP;
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, flag, CAP_CLEAR))
			die("can't clear effective cap");
		if (cap_set_flag(caps, CAP_PERMITTED, 1, flag, CAP_CLEAR))
			die("can't clear permitted cap");
		if (cap_set_flag(caps, CAP_INHERITABLE, 1, flag, CAP_CLEAR))
			die("can't clear inheritable cap");
	}

	if (cap_set_proc(caps))
		die("can't apply final cleaned capset");

	cap_free(caps);
}

void set_seccomp_filter(const struct minijail *j)
{
	/*
	 * Set no_new_privs. See </kernel/seccomp.c> and </kernel/sys.c>
	 * in the kernel source tree for an explanation of the parameters.
	 */
	if (j->flags.no_new_privs) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			pdie("prctl(PR_SET_NO_NEW_PRIVS)");
	}

	/*
	 * Code running with ASan
	 * (https://github.com/google/sanitizers/wiki/AddressSanitizer)
	 * will make system calls not included in the syscall filter policy,
	 * which will likely crash the program. Skip setting seccomp filter in
	 * that case.
	 * 'running_with_asan()' has no inputs and is completely defined at
	 * build time, so this cannot be used by an attacker to skip setting
	 * seccomp filter.
	 */
	if (j->flags.seccomp_filter && running_with_asan()) {
		warn("running with ASan, not setting seccomp filter");
		return;
	}

	/*
	 * If we're logging seccomp filter failures,
	 * install the SIGSYS handler first.
	 */
	if (j->flags.seccomp_filter && j->flags.log_seccomp_filter) {
		if (install_sigsys_handler())
			pdie("install SIGSYS handler");
		warn("logging seccomp filter failures");
	}

	/*
	 * Install the syscall filter.
	 */
	if (j->flags.seccomp_filter) {
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
			  j->filter_prog)) {
			if ((errno == EINVAL) && can_softfail()) {
				warn("seccomp not supported");
				return;
			}
			pdie("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)");
		}
	}
}

void API minijail_enter(const struct minijail *j)
{
	/*
	 * If we're dropping caps, get the last valid cap from /proc now,
	 * since /proc can be unmounted before drop_caps() is called.
	 */
	unsigned int last_valid_cap = 0;
	if (j->flags.caps)
		last_valid_cap = get_last_valid_cap();

	if (j->flags.pids)
		die("tried to enter a pid-namespaced jail;"
		    " try minijail_run()?");

	if (j->flags.usergroups && !j->user)
		die("usergroup inheritance without username");

	/*
	 * We can't recover from failures if we've dropped privileges partially,
	 * so we don't even try. If any of our operations fail, we abort() the
	 * entire process.
	 */
	if (j->flags.enter_vfs && setns(j->mountns_fd, CLONE_NEWNS))
		pdie("setns(CLONE_NEWNS)");

	if (j->flags.vfs) {
		if (unshare(CLONE_NEWNS))
			pdie("unshare(vfs)");
		/*
		 * Remount all filesystems as private. If they are shared
		 * new bind mounts will creep out of our namespace.
		 * https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt
		 */
		if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
			pdie("mount(/, private)");
	}

	if (j->flags.ipc && unshare(CLONE_NEWIPC)) {
		pdie("unshare(ipc)");
	}

	if (j->flags.enter_net) {
		if (setns(j->netns_fd, CLONE_NEWNET))
			pdie("setns(CLONE_NEWNET)");
	} else if (j->flags.net && unshare(CLONE_NEWNET)) {
		pdie("unshare(net)");
	}

	if (j->flags.chroot && enter_chroot(j))
		pdie("chroot");

	if (j->flags.pivot_root && enter_pivot_root(j))
		pdie("pivot_root");

	if (j->flags.mount_tmp && mount_tmp())
		pdie("mount_tmp");

	if (j->flags.remount_proc_ro && remount_proc_readonly(j))
		pdie("remount");

	if (j->flags.caps) {
		/*
		 * POSIX capabilities are a bit tricky. If we drop our
		 * capability to change uids, our attempt to use setuid()
		 * below will fail. Hang on to root caps across setuid(), then
		 * lock securebits.
		 */
		if (prctl(PR_SET_KEEPCAPS, 1))
			pdie("prctl(PR_SET_KEEPCAPS)");
		if (prctl
		    (PR_SET_SECUREBITS, SECURE_ALL_BITS | SECURE_ALL_LOCKS))
			pdie("prctl(PR_SET_SECUREBITS)");
	}

	/*
	 * If we're setting no_new_privs, we can drop privileges
	 * before setting seccomp filter. This way filter policies
	 * don't need to allow privilege-dropping syscalls.
	 */
	if (j->flags.no_new_privs) {
		drop_ugid(j);
		if (j->flags.caps)
			drop_caps(j, last_valid_cap);

		set_seccomp_filter(j);
	} else {
		/*
		 * If we're not setting no_new_privs,
		 * we need to set seccomp filter *before* dropping privileges.
		 * WARNING: this means that filter policies *must* allow
		 * setgroups()/setresgid()/setresuid() for dropping root and
		 * capget()/capset()/prctl() for dropping caps.
		 */
		set_seccomp_filter(j);

		drop_ugid(j);
		if (j->flags.caps)
			drop_caps(j, last_valid_cap);
	}

	/*
	 * Select the specified alternate syscall table.  The table must not
	 * block prctl(2) if we're using seccomp as well.
	 */
	if (j->flags.alt_syscall) {
		if (prctl(PR_ALT_SYSCALL, 1, j->alt_syscall_table))
			pdie("prctl(PR_ALT_SYSCALL)");
	}

	/*
	 * seccomp has to come last since it cuts off all the other
	 * privilege-dropping syscalls :)
	 */
	if (j->flags.seccomp && prctl(PR_SET_SECCOMP, 1)) {
		if ((errno == EINVAL) && can_softfail()) {
			warn("seccomp not supported");
			return;
		}
		pdie("prctl(PR_SET_SECCOMP)");
	}
}

/* TODO(wad) will visibility affect this variable? */
static int init_exitstatus = 0;

void init_term(int __attribute__ ((unused)) sig)
{
	_exit(init_exitstatus);
}

int init(pid_t rootpid)
{
	pid_t pid;
	int status;
	/* so that we exit with the right status */
	signal(SIGTERM, init_term);
	/* TODO(wad) self jail with seccomp_filters here. */
	while ((pid = wait(&status)) > 0) {
		/*
		 * This loop will only end when either there are no processes
		 * left inside our pid namespace or we get a signal.
		 */
		if (pid == rootpid)
			init_exitstatus = status;
	}
	if (!WIFEXITED(init_exitstatus))
		_exit(MINIJAIL_ERR_INIT);
	_exit(WEXITSTATUS(init_exitstatus));
}

int API minijail_from_fd(int fd, struct minijail *j)
{
	size_t sz = 0;
	size_t bytes = read(fd, &sz, sizeof(sz));
	char *buf;
	int r;
	if (sizeof(sz) != bytes)
		return -EINVAL;
	if (sz > USHRT_MAX)	/* arbitrary sanity check */
		return -E2BIG;
	buf = malloc(sz);
	if (!buf)
		return -ENOMEM;
	bytes = read(fd, buf, sz);
	if (bytes != sz) {
		free(buf);
		return -EINVAL;
	}
	r = minijail_unmarshal(j, buf, sz);
	free(buf);
	return r;
}

int API minijail_to_fd(struct minijail *j, int fd)
{
	char *buf;
	size_t sz = minijail_size(j);
	ssize_t written;
	int r;

	if (!sz)
		return -EINVAL;
	buf = malloc(sz);
	r = minijail_marshal(j, buf, sz);
	if (r) {
		free(buf);
		return r;
	}
	/* Sends [size][minijail]. */
	written = write(fd, &sz, sizeof(sz));
	if (written != sizeof(sz)) {
		free(buf);
		return -EFAULT;
	}
	written = write(fd, buf, sz);
	if (written < 0 || (size_t) written != sz) {
		free(buf);
		return -EFAULT;
	}
	free(buf);
	return 0;
}

int setup_preload(void)
{
#if defined(__ANDROID__)
	/* Don't use LDPRELOAD on Brillo. */
	return 0;
#else
	char *oldenv = getenv(kLdPreloadEnvVar) ? : "";
	char *newenv = malloc(strlen(oldenv) + 2 + strlen(PRELOADPATH));
	if (!newenv)
		return -ENOMEM;

	/* Only insert a separating space if we have something to separate... */
	sprintf(newenv, "%s%s%s", oldenv, strlen(oldenv) ? " " : "",
		PRELOADPATH);

	/* setenv() makes a copy of the string we give it. */
	setenv(kLdPreloadEnvVar, newenv, 1);
	free(newenv);
	return 0;
#endif
}

int setup_pipe(int fds[2])
{
	int r = pipe(fds);
	char fd_buf[11];
	if (r)
		return r;
	r = snprintf(fd_buf, sizeof(fd_buf), "%d", fds[0]);
	if (r <= 0)
		return -EINVAL;
	setenv(kFdEnvVar, fd_buf, 1);
	return 0;
}

int setup_pipe_end(int fds[2], size_t index)
{
	if (index > 1)
		return -1;

	close(fds[1 - index]);
	return fds[index];
}

int setup_and_dupe_pipe_end(int fds[2], size_t index, int fd)
{
	if (index > 1)
		return -1;

	close(fds[1 - index]);
	/* dup2(2) the corresponding end of the pipe into |fd|. */
	return dup2(fds[index], fd);
}

int minijail_run_internal(struct minijail *j, const char *filename,
			  char *const argv[], pid_t *pchild_pid,
			  int *pstdin_fd, int *pstdout_fd, int *pstderr_fd,
			  int use_preload);

int API minijail_run(struct minijail *j, const char *filename,
		     char *const argv[])
{
	return minijail_run_internal(j, filename, argv, NULL, NULL, NULL, NULL,
				     true);
}

int API minijail_run_pid(struct minijail *j, const char *filename,
			 char *const argv[], pid_t *pchild_pid)
{
	return minijail_run_internal(j, filename, argv, pchild_pid,
				     NULL, NULL, NULL, true);
}

int API minijail_run_pipe(struct minijail *j, const char *filename,
			  char *const argv[], int *pstdin_fd)
{
	return minijail_run_internal(j, filename, argv, NULL, pstdin_fd,
				     NULL, NULL, true);
}

int API minijail_run_pid_pipes(struct minijail *j, const char *filename,
			       char *const argv[], pid_t *pchild_pid,
			       int *pstdin_fd, int *pstdout_fd, int *pstderr_fd)
{
	return minijail_run_internal(j, filename, argv, pchild_pid,
				     pstdin_fd, pstdout_fd, pstderr_fd, true);
}

int API minijail_run_no_preload(struct minijail *j, const char *filename,
				char *const argv[])
{
	return minijail_run_internal(j, filename, argv, NULL, NULL, NULL, NULL,
				     false);
}

int API minijail_run_pid_pipes_no_preload(struct minijail *j,
					  const char *filename,
					  char *const argv[],
					  pid_t *pchild_pid,
					  int *pstdin_fd, int *pstdout_fd,
					  int *pstderr_fd) {
	return minijail_run_internal(j, filename, argv, pchild_pid,
				     pstdin_fd, pstdout_fd, pstderr_fd, false);
}

int minijail_run_internal(struct minijail *j, const char *filename,
			  char *const argv[], pid_t *pchild_pid,
			  int *pstdin_fd, int *pstdout_fd, int *pstderr_fd,
			  int use_preload)
{
	char *oldenv, *oldenv_copy = NULL;
	pid_t child_pid;
	int pipe_fds[2];
	int stdin_fds[2];
	int stdout_fds[2];
	int stderr_fds[2];
	int child_sync_pipe_fds[2];
	int sync_child = 0;
	int ret;
	/* We need to remember this across the minijail_preexec() call. */
	int pid_namespace = j->flags.pids;
	int do_init = j->flags.do_init;

	if (use_preload) {
		oldenv = getenv(kLdPreloadEnvVar);
		if (oldenv) {
			oldenv_copy = strdup(oldenv);
			if (!oldenv_copy)
				return -ENOMEM;
		}

		if (setup_preload())
			return -EFAULT;
	}

	if (!use_preload) {
		if (j->flags.caps)
			die("capabilities are not supported without "
			    "LD_PRELOAD");
	}

	/*
	 * Make the process group ID of this process equal to its PID, so that
	 * both the Minijail process and the jailed process can be killed
	 * together.
	 * Don't fail on EPERM, since setpgid(0, 0) can only EPERM when
	 * the process is already a process group leader.
	 */
	if (setpgid(0 /* use calling PID */, 0 /* make PGID = PID */)) {
		if (errno != EPERM) {
			pdie("setpgid(0, 0)");
		}
	}

	if (use_preload) {
		/*
		 * Before we fork(2) and execve(2) the child process, we need
		 * to open a pipe(2) to send the minijail configuration over.
		 */
		if (setup_pipe(pipe_fds))
			return -EFAULT;
	}

	/*
	 * If we want to write to the child process' standard input,
	 * create the pipe(2) now.
	 */
	if (pstdin_fd) {
		if (pipe(stdin_fds))
			return -EFAULT;
	}

	/*
	 * If we want to read from the child process' standard output,
	 * create the pipe(2) now.
	 */
	if (pstdout_fd) {
		if (pipe(stdout_fds))
			return -EFAULT;
	}

	/*
	 * If we want to read from the child process' standard error,
	 * create the pipe(2) now.
	 */
	if (pstderr_fd) {
		if (pipe(stderr_fds))
			return -EFAULT;
	}

	/*
	 * If we want to set up a new uid/gid mapping in the user namespace,
	 * or if we need to add the child process to cgroups, create the pipe(2)
	 * to sync between parent and child.
	 */
	if (j->flags.userns || j->flags.cgroups) {
		sync_child = 1;
		if (pipe(child_sync_pipe_fds))
			return -EFAULT;
	}

	/*
	 * Use sys_clone() if and only if we're creating a pid namespace.
	 *
	 * tl;dr: WARNING: do not mix pid namespaces and multithreading.
	 *
	 * In multithreaded programs, there are a bunch of locks inside libc,
	 * some of which may be held by other threads at the time that we call
	 * minijail_run_pid(). If we call fork(), glibc does its level best to
	 * ensure that we hold all of these locks before it calls clone()
	 * internally and drop them after clone() returns, but when we call
	 * sys_clone(2) directly, all that gets bypassed and we end up with a
	 * child address space where some of libc's important locks are held by
	 * other threads (which did not get cloned, and hence will never release
	 * those locks). This is okay so long as we call exec() immediately
	 * after, but a bunch of seemingly-innocent libc functions like setenv()
	 * take locks.
	 *
	 * Hence, only call sys_clone() if we need to, in order to get at pid
	 * namespacing. If we follow this path, the child's address space might
	 * have broken locks; you may only call functions that do not acquire
	 * any locks.
	 *
	 * Unfortunately, fork() acquires every lock it can get its hands on, as
	 * previously detailed, so this function is highly likely to deadlock
	 * later on (see "deadlock here") if we're multithreaded.
	 *
	 * We might hack around this by having the clone()d child (init of the
	 * pid namespace) return directly, rather than leaving the clone()d
	 * process hanging around to be init for the new namespace (and having
	 * its fork()ed child return in turn), but that process would be crippled
	 * with its libc locks potentially broken. We might try fork()ing in the
	 * parent before we clone() to ensure that we own all the locks, but
	 * then we have to have the forked child hanging around consuming
	 * resources (and possibly having file descriptors / shared memory
	 * regions / etc attached). We'd need to keep the child around to avoid
	 * having its children get reparented to init.
	 *
	 * TODO(ellyjones): figure out if the "forked child hanging around"
	 * problem is fixable or not. It would be nice if we worked in this
	 * case.
	 */
	if (pid_namespace) {
		int clone_flags = CLONE_NEWPID | SIGCHLD;
		if (j->flags.userns)
			clone_flags |= CLONE_NEWUSER;
		child_pid = syscall(SYS_clone, clone_flags, NULL);
	} else {
		child_pid = fork();
	}

	if (child_pid < 0) {
		if (use_preload) {
			free(oldenv_copy);
		}
		die("failed to fork child");
	}

	if (child_pid) {
		if (use_preload) {
			/* Restore parent's LD_PRELOAD. */
			if (oldenv_copy) {
				setenv(kLdPreloadEnvVar, oldenv_copy, 1);
				free(oldenv_copy);
			} else {
				unsetenv(kLdPreloadEnvVar);
			}
			unsetenv(kFdEnvVar);
		}

		j->initpid = child_pid;

		if (j->flags.pid_file)
			write_pid_file(j);

		if (j->flags.cgroups)
			add_to_cgroups(j);

		if (j->flags.userns)
			write_ugid_mappings(j);

		if (sync_child)
			parent_setup_complete(child_sync_pipe_fds);

		if (use_preload) {
			/* Send marshalled minijail. */
			close(pipe_fds[0]);	/* read endpoint */
			ret = minijail_to_fd(j, pipe_fds[1]);
			close(pipe_fds[1]);	/* write endpoint */
			if (ret) {
				kill(j->initpid, SIGKILL);
				die("failed to send marshalled minijail");
			}
		}

		if (pchild_pid)
			*pchild_pid = child_pid;

		/*
		 * If we want to write to the child process' standard input,
		 * set up the write end of the pipe.
		 */
		if (pstdin_fd)
			*pstdin_fd = setup_pipe_end(stdin_fds,
						    1 /* write end */);

		/*
		 * If we want to read from the child process' standard output,
		 * set up the read end of the pipe.
		 */
		if (pstdout_fd)
			*pstdout_fd = setup_pipe_end(stdout_fds,
						     0 /* read end */);

		/*
		 * If we want to read from the child process' standard error,
		 * set up the read end of the pipe.
		 */
		if (pstderr_fd)
			*pstderr_fd = setup_pipe_end(stderr_fds,
						     0 /* read end */);

		return 0;
	}
	free(oldenv_copy);

	if (j->flags.reset_signal_mask) {
		sigset_t signal_mask;
		if (sigemptyset(&signal_mask) != 0)
			pdie("sigemptyset failed");
		if (sigprocmask(SIG_SETMASK, &signal_mask, NULL) != 0)
			pdie("sigprocmask failed");
	}

	if (sync_child)
		wait_for_parent_setup(child_sync_pipe_fds);

	if (j->flags.userns)
		enter_user_namespace(j);

	/*
	 * If we want to write to the jailed process' standard input,
	 * set up the read end of the pipe.
	 */
	if (pstdin_fd) {
		if (setup_and_dupe_pipe_end(stdin_fds, 0 /* read end */,
					    STDIN_FILENO) < 0)
			die("failed to set up stdin pipe");
	}

	/*
	 * If we want to read from the jailed process' standard output,
	 * set up the write end of the pipe.
	 */
	if (pstdout_fd) {
		if (setup_and_dupe_pipe_end(stdout_fds, 1 /* write end */,
					    STDOUT_FILENO) < 0)
			die("failed to set up stdout pipe");
	}

	/*
	 * If we want to read from the jailed process' standard error,
	 * set up the write end of the pipe.
	 */
	if (pstderr_fd) {
		if (setup_and_dupe_pipe_end(stderr_fds, 1 /* write end */,
					    STDERR_FILENO) < 0)
			die("failed to set up stderr pipe");
	}

	/* If running an init program, let it decide when/how to mount /proc. */
	if (pid_namespace && !do_init)
		j->flags.remount_proc_ro = 0;

	if (use_preload) {
		/* Strip out flags that cannot be inherited across execve(2). */
		minijail_preexec(j);
	} else {
		j->flags.pids = 0;
	}
	/* Jail this process, then execve() the target. */
	minijail_enter(j);

	if (pid_namespace && do_init) {
		/*
		 * pid namespace: this process will become init inside the new
		 * namespace. We don't want all programs we might exec to have
		 * to know how to be init. Normally (do_init == 1) we fork off
		 * a child to actually run the program. If |do_init == 0|, we
		 * let the program keep pid 1 and be init.
		 *
		 * If we're multithreaded, we'll probably deadlock here. See
		 * WARNING above.
		 */
		child_pid = fork();
		if (child_pid < 0)
			_exit(child_pid);
		else if (child_pid > 0)
			init(child_pid);	/* never returns */
	}

	/*
	 * If we aren't pid-namespaced, or the jailed program asked to be init:
	 *   calling process
	 *   -> execve()-ing process
	 * If we are:
	 *   calling process
	 *   -> init()-ing process
	 *      -> execve()-ing process
	 */
	_exit(execve(filename, argv, environ));
}

int API minijail_kill(struct minijail *j)
{
	int st;
	if (kill(j->initpid, SIGTERM))
		return -errno;
	if (waitpid(j->initpid, &st, 0) < 0)
		return -errno;
	return st;
}

int API minijail_wait(struct minijail *j)
{
	int st;
	if (waitpid(j->initpid, &st, 0) < 0)
		return -errno;

	if (!WIFEXITED(st)) {
		int error_status = st;
		if (WIFSIGNALED(st)) {
			int signum = WTERMSIG(st);
			warn("child process %d received signal %d",
			     j->initpid, signum);
			/*
			 * We return MINIJAIL_ERR_JAIL if the process received
			 * SIGSYS, which happens when a syscall is blocked by
			 * seccomp filters.
			 * If not, we do what bash(1) does:
			 * $? = 128 + signum
			 */
			if (signum == SIGSYS) {
				error_status = MINIJAIL_ERR_JAIL;
			} else {
				error_status = 128 + signum;
			}
		}
		return error_status;
	}

	int exit_status = WEXITSTATUS(st);
	if (exit_status != 0)
		info("child process %d exited with status %d",
		     j->initpid, exit_status);

	return exit_status;
}

void API minijail_destroy(struct minijail *j)
{
	size_t i;

	if (j->flags.seccomp_filter && j->filter_prog) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}
	while (j->mounts_head) {
		struct mountpoint *m = j->mounts_head;
		j->mounts_head = j->mounts_head->next;
		free(m->type);
		free(m->dest);
		free(m->src);
		free(m);
	}
	j->mounts_tail = NULL;
	if (j->user)
		free(j->user);
	if (j->suppl_gid_list)
		free(j->suppl_gid_list);
	if (j->chrootdir)
		free(j->chrootdir);
	if (j->alt_syscall_table)
		free(j->alt_syscall_table);
	for (i = 0; i < j->cgroup_count; ++i)
		free(j->cgroups[i]);
	free(j);
}
