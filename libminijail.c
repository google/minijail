/*
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _BSD_SOURCE
#define _GNU_SOURCE

#include <asm/unistd.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "libminijail.h"
#include "libsyscalls.h"
#include "libminijail-private.h"

#include "syscall_filter.h"

/* Until these are reliably available in linux/prctl.h */
#ifndef PR_SET_SECCOMP
# define PR_SET_SECCOMP 22
#endif

/* For seccomp_filter using BPF. */
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER 2 /* uses user-supplied filter. */
#endif

#define die(_msg, ...) do { \
	syslog(LOG_ERR, "libminijail: " _msg, ## __VA_ARGS__); \
	abort(); \
} while (0)

#define pdie(_msg, ...) \
	die(_msg ": %s", ## __VA_ARGS__, strerror(errno))

#define warn(_msg, ...) \
	syslog(LOG_WARNING, "libminijail: " _msg, ## __VA_ARGS__)

struct binding {
	char *src;
	char *dest;
	int writeable;
	struct binding *next;
};

struct minijail {
	struct {
		int uid:1;
		int gid:1;
		int caps:1;
		int vfs:1;
		int pids:1;
		int seccomp:1;
		int readonly:1;
		int usergroups:1;
		int ptrace:1;
		int no_new_privs:1;
		int seccomp_filter:1;
		int chroot:1;
	} flags;
	uid_t uid;
	gid_t gid;
	gid_t usergid;
	char *user;
	uint64_t caps;
	pid_t initpid;
	int filter_len;
	int binding_count;
	char *chrootdir;
	struct sock_fprog *filter_prog;
	struct binding *bindings_head;
	struct binding *bindings_tail;
};

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
	 * We're safe to free the buffer here. The strings inside pw point
	 * inside buf, but we don't use any of them; this leaves the pointers
	 * dangling but it's safe. ppw points at pw if getpwnam_r succeeded.
	 */
	free(buf);
	if (!ppw)
		return -errno;
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
	if (!pgr)
		return -errno;
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

void API minijail_use_caps(struct minijail *j, uint64_t capmask)
{
	j->caps = capmask;
	j->flags.caps = 1;
}

void API minijail_namespace_vfs(struct minijail *j)
{
	j->flags.vfs = 1;
}

void API minijail_namespace_pids(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.readonly = 1;
	j->flags.pids = 1;
}

void API minijail_remount_readonly(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.readonly = 1;
}

void API minijail_inherit_usergroups(struct minijail *j)
{
	j->flags.usergroups = 1;
}

void API minijail_disable_ptrace(struct minijail *j)
{
	j->flags.ptrace = 1;
}

int API minijail_enter_chroot(struct minijail *j, const char *dir) {
	if (j->chrootdir)
		return -EINVAL;
	j->chrootdir = strdup(dir);
	if (!j->chrootdir)
		return -ENOMEM;
	j->flags.chroot = 1;
	return 0;
}

int API minijail_bind(struct minijail *j, const char *src, const char *dest,
                      int writeable) {
	struct binding *b;

	if (*dest != '/')
		return -EINVAL;
	b = calloc(1, sizeof(*b));
	if (!b)
		return -ENOMEM;
	b->dest = strdup(dest);
	if (!b->dest)
		goto error;
	b->src = strdup(src);
	if (!b->src)
		goto error;
	b->writeable = writeable;

	syslog(LOG_INFO, "libminijail: bind %s -> %s", src, dest);

	/*
	 * Force vfs namespacing so the bind mounts don't leak out into the
	 * containing vfs namespace.
	 */
	minijail_namespace_vfs(j);

	if (j->bindings_tail)
		j->bindings_tail->next = b;
	else
		j->bindings_head = b;
	j->bindings_tail = b;
	j->binding_count++;

	return 0;

error:
	free(b->src);
	free(b->dest);
	free(b);
	return -ENOMEM;
}

void API minijail_parse_seccomp_filters(struct minijail *j, const char *path)
{
	FILE *file = fopen(path, "r");
	if (!file) {
		pdie("failed to open seccomp filters file '%s'", path);
	}

	struct sock_fprog *fprog = malloc(sizeof(struct sock_fprog));
	if (compile_filter(file, fprog)) {
		die("failed to compile seccomp filters BPF program in '%s'", path);
	}

	j->filter_len = fprog->len;
	j->filter_prog = fprog;

	fclose(file);
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
		    char *src, size_t length)
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
	struct binding *b = NULL;
	marshal_append(state, (char *)j, sizeof(*j));
	if (j->user)
		marshal_append(state, j->user, strlen(j->user) + 1);
	if (j->chrootdir)
		marshal_append(state, j->chrootdir, strlen(j->chrootdir) + 1);
	if (j->flags.seccomp_filter && j->filter_prog) {
		struct sock_fprog *fp = j->filter_prog;
		marshal_append(state, (char *)fp->filter,
				fp->len * sizeof(struct sock_filter));
	}
	for (b = j->bindings_head; b; b = b->next) {
		marshal_append(state, b->src, strlen(b->src) + 1);
		marshal_append(state, b->dest, strlen(b->dest) + 1);
		marshal_append(state, (char *)&b->writeable, sizeof(b->writeable));
	}
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

/* consumebytes: consumes @length bytes from a buffer @buf of length @buflength
 * @length    Number of bytes to consume
 * @buf       Buffer to consume from
 * @buflength Size of @buf
 *
 * Returns a pointer to the base of the bytes, or NULL for errors.
 */
void *consumebytes(size_t length, char **buf, size_t *buflength) {
	char *p = *buf;
	if (length > *buflength)
		return NULL;
	*buf += length;
	*buflength -= length;
	return p;
}

/* consumestr: consumes a C string from a buffer @buf of length @length
 * @buf    Buffer to consume
 * @length Length of buffer
 *
 * Returns a pointer to the base of the string, or NULL for errors.
 */
char *consumestr(char **buf, size_t *buflength) {
	size_t len = strnlen(*buf, *buflength);
	if (len == *buflength)
		/* There's no null-terminator */
		return NULL;
	return consumebytes(len + 1, buf, buflength);
}

int minijail_unmarshal(struct minijail *j, char *serialized, size_t length)
{
	int i;
	int count;
	int ret = -EINVAL;

	if (length < sizeof(*j))
		goto out;
	memcpy((void *)j, serialized, sizeof(*j));
	serialized += sizeof(*j);
	length -= sizeof(*j);

	/* Potentially stale pointers not used as signals. */
	j->bindings_head = NULL;
	j->bindings_tail = NULL;
	j->filter_prog = NULL;

	if (j->user) {		/* stale pointer */
		char *user = consumestr(&serialized, &length);
		if (!user)
			goto clear_pointers;
		j->user = strdup(user);
		if (!j->user)
			goto clear_pointers;
	}

	if (j->chrootdir) {	/* stale pointer */
		char *chrootdir = consumestr(&serialized, &length);
		if (!chrootdir)
			goto bad_chrootdir;
		j->chrootdir = strdup(chrootdir);
		if (!j->chrootdir)
			goto bad_chrootdir;
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
		j->filter_prog->len = ninstrs;
		j->filter_prog->filter = malloc(program_len);
		memcpy(j->filter_prog->filter, program, program_len);
	}

	count = j->binding_count;
	j->binding_count = 0;
	for (i = 0; i < count; ++i) {
		int *writeable;
		const char *dest;
		const char *src = consumestr(&serialized, &length);
		if (!src)
			goto bad_bindings;
		dest = consumestr(&serialized, &length);
		if (!dest)
			goto bad_bindings;
		writeable = consumebytes(sizeof(*writeable), &serialized, &length);
		if (!writeable)
			goto bad_bindings;
		if (minijail_bind(j, src, dest, *writeable))
			goto bad_bindings;
	}

	return 0;

bad_bindings:
	if (j->flags.seccomp_filter && j->filter_len > 0) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}
bad_filters:
	if (j->chrootdir)
		free(j->chrootdir);
bad_chrootdir:
	if (j->user)
		free(j->user);
clear_pointers:
	j->user = NULL;
	j->chrootdir = NULL;
out:
	return ret;
}

void minijail_preenter(struct minijail *j)
{
	/* Strip out options which are minijail_run() only. */
	j->flags.vfs = 0;
	j->flags.readonly = 0;
	j->flags.pids = 0;
}

void minijail_preexec(struct minijail *j)
{
	int vfs = j->flags.vfs;
	int readonly = j->flags.readonly;
	if (j->user)
		free(j->user);
	j->user = NULL;
	memset(&j->flags, 0, sizeof(j->flags));
	/* Now restore anything we meant to keep. */
	j->flags.vfs = vfs;
	j->flags.readonly = readonly;
	/* Note, pidns will already have been used before this call. */
}

/* bind_one: Applies bindings from @b for @j, recursing as needed.
 * @j Minijail these bindings are for
 * @b Head of list of bindings
 *
 * Returns 0 for success.
 */
int bind_one(const struct minijail *j, struct binding *b) {
	int ret = 0;
	char *dest = NULL;
	if (ret)
		return ret;
	/* dest has a leading "/" */
	if (asprintf(&dest, "%s%s", j->chrootdir, b->dest) < 0)
		return -ENOMEM;
	ret = mount(b->src, dest, NULL, MS_BIND, NULL);
	if (ret)
		pdie("bind: %s -> %s", b->src, dest);
	if (!b->writeable) {
		ret = mount(b->src, dest, NULL,
		            MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
		if (ret)
			pdie("bind ro: %s -> %s", b->src, dest);
	}
	free(dest);
	if (b->next)
		return bind_one(j, b->next);
	return ret;
}

int enter_chroot(const struct minijail *j) {
	int ret;
	if (j->bindings_head && (ret = bind_one(j, j->bindings_head)))
		return ret;

	if (chroot(j->chrootdir))
		return -errno;

	if (chdir("/"))
		return -errno;

	return 0;
}

int remount_readonly(void)
{
	const char *kProcPath = "/proc";
	const unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;
	/*
	 * Right now, we're holding a reference to our parent's old mount of
	 * /proc in our namespace, which means using MS_REMOUNT here would
	 * mutate our parent's mount as well, even though we're in a VFS
	 * namespace (!). Instead, remove their mount from our namespace
	 * and make our own.
	 */
	if (umount(kProcPath))
		return -errno;
	if (mount("", kProcPath, "proc", kSafeFlags | MS_RDONLY, ""))
		return -errno;
	return 0;
}

void drop_caps(const struct minijail *j)
{
	cap_t caps = cap_get_proc();
	cap_value_t raise_flag[1];
	unsigned int i;
	if (!caps)
		die("can't get process caps");
	if (cap_clear_flag(caps, CAP_INHERITABLE))
		die("can't clear inheritable caps");
	if (cap_clear_flag(caps, CAP_EFFECTIVE))
		die("can't clear effective caps");
	if (cap_clear_flag(caps, CAP_PERMITTED))
		die("can't clear permitted caps");
	for (i = 0; i < sizeof(j->caps) * 8 && cap_valid((int)i); ++i) {
		if (i != CAP_SETPCAP && !(j->caps & (1 << i)))
			continue;
		raise_flag[0] = i;
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, raise_flag, CAP_SET))
			die("can't add effective cap");
		if (cap_set_flag(caps, CAP_PERMITTED, 1, raise_flag, CAP_SET))
			die("can't add permitted cap");
		if (cap_set_flag(caps, CAP_INHERITABLE, 1, raise_flag, CAP_SET))
			die("can't add inheritable cap");
	}
	if (cap_set_proc(caps))
		die("can't apply cleaned capset");
	cap_free(caps);
	for (i = 0; i < sizeof(j->caps) * 8 && cap_valid((int)i); ++i) {
		if (j->caps & (1 << i))
			continue;
		if (prctl(PR_CAPBSET_DROP, i))
			pdie("prctl(PR_CAPBSET_DROP)");
	}
}

void API minijail_enter(const struct minijail *j)
{
	if (j->flags.pids)
		die("tried to enter a pid-namespaced jail;"
		    "try minijail_run()?");

	if (j->flags.usergroups && !j->user)
		die("usergroup inheritance without username");

	/*
	 * We can't recover from failures if we've dropped privileges partially,
	 * so we don't even try. If any of our operations fail, we abort() the
	 * entire process.
	 */
	if (j->flags.vfs && unshare(CLONE_NEWNS))
		pdie("unshare");

	if (j->flags.chroot && enter_chroot(j))
		pdie("chroot");

	if (j->flags.readonly && remount_readonly())
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
	 * Set no_new_privs before installing seccomp filter. See
	 * </kernel/seccomp.c> and </kernel/sys.c> in the kernel source tree for
	 * an explanation of the parameters.
	 */
	if (j->flags.no_new_privs) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			pdie("prctl(PR_SET_NO_NEW_PRIVS)");
	}

	/*
	 * Install seccomp filter before dropping root and caps.
	 * WARNING: this means that filter policies *must* allow
	 * setgroups()/setresgid()/setresuid() for dropping root and
	 * capget()/capset()/prctl() for dropping caps.
	 */
	if (j->flags.seccomp_filter) {
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, j->filter_prog))
			pdie("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)");
	}

	if (j->flags.usergroups) {
		if (initgroups(j->user, j->usergid))
			pdie("initgroups");
	} else {
		/* Only attempt to clear supplemental groups if we are changing
		 * users. */
		if ((j->uid || j->gid) && setgroups(0, NULL))
			pdie("setgroups");
	}

	if (j->flags.gid && setresgid(j->gid, j->gid, j->gid))
		pdie("setresgid");

	if (j->flags.uid && setresuid(j->uid, j->uid, j->uid))
		pdie("setresuid");

	if (j->flags.caps)
		drop_caps(j);

	/*
	 * seccomp has to come last since it cuts off all the other
	 * privilege-dropping syscalls :)
	 */
	if (j->flags.seccomp && prctl(PR_SET_SECCOMP, 1))
		pdie("prctl(PR_SET_SECCOMP)");
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
	if (sz > USHRT_MAX)	/* Arbitrary sanity check */
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
	char *oldenv = getenv(kLdPreloadEnvVar) ? : "";
	char *newenv = malloc(strlen(oldenv) + 2 + strlen(PRELOADPATH));
	if (!newenv)
		return -ENOMEM;

	/* Only insert a separating space if we have something to separate... */
	sprintf(newenv, "%s%s%s", oldenv, strlen(oldenv) ? " " : "",
		PRELOADPATH);

	/* setenv() makes a copy of the string we give it */
	setenv(kLdPreloadEnvVar, newenv, 1);
	free(newenv);
	return 0;
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

int API minijail_run(struct minijail *j, const char *filename,
		     char *const argv[])
{
	return minijail_run_pid(j, filename, argv, NULL);
}

int API minijail_run_pid(struct minijail *j, const char *filename,
			 char *const argv[], pid_t *pchild_pid)
{
	char *oldenv, *oldenv_copy = NULL;
	pid_t child_pid;
	int pipe_fds[2];
	int ret;
	/* We need to remember this across the minijail_preexec() call. */
	int pid_namespace = j->flags.pids;

	oldenv = getenv(kLdPreloadEnvVar);
	if (oldenv) {
		oldenv_copy = strdup(oldenv);
		if (!oldenv_copy)
			return -ENOMEM;
	}

	if (setup_preload())
		return -EFAULT;

	/*
	 * Before we fork(2) and execve(2) the child process, we need to open
	 * a pipe(2) to send the minijail configuration over.
	 */
	if (setup_pipe(pipe_fds))
		return -EFAULT;

	/* Use sys_clone() if and only if we're creating a pid namespace.
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
	if (pid_namespace)
		child_pid = syscall(SYS_clone, CLONE_NEWPID | SIGCHLD, NULL);
	else
		child_pid = fork();

	if (child_pid < 0) {
		free(oldenv_copy);
		return child_pid;
	}

	if (child_pid) {
		/* Restore parent's LD_PRELOAD. */
		if (oldenv_copy) {
			setenv(kLdPreloadEnvVar, oldenv_copy, 1);
			free(oldenv_copy);
		} else {
			unsetenv(kLdPreloadEnvVar);
		}
		unsetenv(kFdEnvVar);
		j->initpid = child_pid;
		close(pipe_fds[0]);	/* read endpoint */
		ret = minijail_to_fd(j, pipe_fds[1]);
		close(pipe_fds[1]);	/* write endpoint */
		if (ret) {
			kill(j->initpid, SIGKILL);
			die("failed to send marshalled minijail");
		}
		if (pchild_pid)
			*pchild_pid = child_pid;
		return 0;
	}
	free(oldenv_copy);

	/* Drop everything that cannot be inherited across execve. */
	minijail_preexec(j);
	/* Jail this process and its descendants... */
	minijail_enter(j);

	if (pid_namespace) {
		/*
		 * pid namespace: this process will become init inside the new
		 * namespace, so fork off a child to actually run the program
		 * (we don't want all programs we might exec to have to know
		 * how to be init).
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
	 * If we aren't pid-namespaced:
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
		if (WIFSIGNALED(st))
			warn("child process received signal %d", WTERMSIG(st));
		return MINIJAIL_ERR_JAIL;
	}
	return WEXITSTATUS(st);
}

void API minijail_destroy(struct minijail *j)
{
	if (j->flags.seccomp_filter && j->filter_prog) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}
	while (j->bindings_head) {
		struct binding *b = j->bindings_head;
		j->bindings_head = j->bindings_head->next;
		free(b->dest);
		free(b->src);
		free(b);
	}
	j->bindings_tail = NULL;
	if (j->user)
		free(j->user);
	if (j->chrootdir)
		free(j->chrootdir);
	free(j);
}
