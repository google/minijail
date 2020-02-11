/* Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "system.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/if.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <linux/securebits.h>

#include "util.h"

/*
 * SECBIT_NO_CAP_AMBIENT_RAISE was added in kernel 4.3, so fill in the
 * definition if the securebits header doesn't provide it.
 */
#ifndef SECBIT_NO_CAP_AMBIENT_RAISE
#define SECBIT_NO_CAP_AMBIENT_RAISE (issecure_mask(6))
#endif

#ifndef SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED
#define SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED (issecure_mask(7))
#endif

/*
 * Assert the value of SECURE_ALL_BITS at compile-time.
 * Android devices are currently compiled against 4.4 kernel headers. Kernel 4.3
 * added a new securebit.
 * When a new securebit is added, the new SECURE_ALL_BITS mask will return EPERM
 * when used on older kernels. The compile-time assert will catch this situation
 * at compile time.
 */
#if defined(__ANDROID__)
_Static_assert(SECURE_ALL_BITS == 0x55, "SECURE_ALL_BITS == 0x55.");
#endif

int secure_noroot_set_and_locked(uint64_t mask)
{
	return (mask & (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED)) ==
	       (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED);
}

int lock_securebits(uint64_t skip_mask, bool require_keep_caps)
{
	/* The general idea is to set all bits, subject to exceptions below. */
	unsigned long securebits = SECURE_ALL_BITS | SECURE_ALL_LOCKS;

	/*
	 * SECBIT_KEEP_CAPS is special in that it is automatically cleared on
	 * execve(2). This implies that attempts to set SECBIT_KEEP_CAPS (as is
	 * the default) in processes that have it locked already (such as nested
	 * minijail usage) would fail. Thus, unless the caller requires it,
	 * allow it to remain off if it is already locked.
	 */
	if (!require_keep_caps) {
		int current_securebits = prctl(PR_GET_SECUREBITS);
		if (current_securebits < 0) {
			pwarn("prctl(PR_GET_SECUREBITS) failed");
			return -1;
		}

		if ((current_securebits & SECBIT_KEEP_CAPS_LOCKED) != 0 &&
		    (current_securebits & SECBIT_KEEP_CAPS) == 0) {
			securebits &= ~SECBIT_KEEP_CAPS;
		}
	}

	/*
	 * Ambient capabilities can only be raised if they're already present
	 * in the permitted *and* inheritable set. Therefore, we don't really
	 * need to lock the NO_CAP_AMBIENT_RAISE securebit, since we are already
	 * configuring the permitted and inheritable set.
	 */
	securebits &=
	    ~(SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED);

	/* Don't set any bits that the user requested not to be touched. */
	securebits &= ~skip_mask;

	if (!securebits) {
		warn("not locking any securebits");
		return 0;
	}
	int securebits_ret = prctl(PR_SET_SECUREBITS, securebits);
	if (securebits_ret < 0) {
		pwarn("prctl(PR_SET_SECUREBITS) failed");
		return -1;
	}

	return 0;
}

int write_proc_file(pid_t pid, const char *content, const char *basename)
{
	int fd, ret;
	size_t sz, len;
	ssize_t written;
	char filename[32];

	sz = sizeof(filename);
	ret = snprintf(filename, sz, "/proc/%d/%s", pid, basename);
	if (ret < 0 || (size_t)ret >= sz) {
		warn("failed to generate %s filename", basename);
		return -1;
	}

	fd = open(filename, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		pwarn("failed to open '%s'", filename);
		return -errno;
	}

	len = strlen(content);
	written = write(fd, content, len);
	if (written < 0) {
		pwarn("failed to write '%s'", filename);
		return -errno;
	}

	if ((size_t)written < len) {
		warn("failed to write %zu bytes to '%s'", len, filename);
		return -1;
	}
	close(fd);
	return 0;
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
unsigned int get_last_valid_cap(void)
{
	unsigned int last_valid_cap = 0;
	if (is_android()) {
		for (; prctl(PR_CAPBSET_READ, last_valid_cap, 0, 0, 0) >= 0;
		     ++last_valid_cap)
			;

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

int cap_ambient_supported(void)
{
	return prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) >=
	       0;
}

int config_net_loopback(void)
{
	const char ifname[] = "lo";
	int sock;
	struct ifreq ifr;

	/* Make sure people don't try to add really long names. */
	_Static_assert(sizeof(ifname) <= IFNAMSIZ, "interface name too long");

	sock = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		pwarn("socket(AF_LOCAL) failed");
		return -1;
	}

	/*
	 * Do the equiv of `ip link set up lo`.  The kernel will assign
	 * IPv4 (127.0.0.1) & IPv6 (::1) addresses automatically!
	 */
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		pwarn("ioctl(SIOCGIFFLAGS) failed");
		return -1;
	}

	/* The kernel preserves ifr.ifr_name for use. */
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		pwarn("ioctl(SIOCSIFFLAGS) failed");
		return -1;
	}

	close(sock);
	return 0;
}

int write_pid_to_path(pid_t pid, const char *path)
{
	FILE *fp = fopen(path, "we");

	if (!fp) {
		pwarn("failed to open '%s'", path);
		return -errno;
	}
	if (fprintf(fp, "%d\n", (int)pid) < 0) {
		/* fprintf(3) does not set errno on failure. */
		warn("fprintf(%s) failed", path);
		return -1;
	}
	if (fclose(fp)) {
		pwarn("fclose(%s) failed", path);
		return -errno;
	}

	return 0;
}

/*
 * Create the |path| directory and its parents (if need be) with |mode|.
 * If not |isdir|, then |path| is actually a file, so the last component
 * will not be created.
 */
int mkdir_p(const char *path, mode_t mode, bool isdir)
{
	int rc;
	char *dir = strdup(path);
	if (!dir) {
		rc = errno;
		pwarn("strdup(%s) failed", path);
		return -rc;
	}

	/* Starting from the root, work our way out to the end. */
	char *p = strchr(dir + 1, '/');
	while (p) {
		*p = '\0';
		if (mkdir(dir, mode) && errno != EEXIST) {
			rc = errno;
			pwarn("mkdir(%s, 0%o) failed", dir, mode);
			free(dir);
			return -rc;
		}
		*p = '/';
		p = strchr(p + 1, '/');
	}

	/*
	 * Create the last directory.  We still check EEXIST here in case
	 * of trailing slashes.
	 */
	free(dir);
	if (isdir && mkdir(path, mode) && errno != EEXIST) {
		rc = errno;
		pwarn("mkdir(%s, 0%o) failed", path, mode);
		return -rc;
	}
	return 0;
}

/*
 * setup_mount_destination: Ensures the mount target exists.
 * Creates it if needed and possible.
 */
int setup_mount_destination(const char *source, const char *dest, uid_t uid,
			    uid_t gid, bool bind, unsigned long *mnt_flags)
{
	int rc;
	struct stat st_buf;
	bool domkdir;

	rc = stat(dest, &st_buf);
	if (rc == 0) /* destination exists */
		return 0;

	/*
	 * Try to create the destination.
	 * Either make a directory or touch a file depending on the source type.
	 *
	 * If the source isn't an absolute path, assume it is a filesystem type
	 * such as "tmpfs" and create a directory to mount it on.  The dest will
	 * be something like "none" or "proc" which we shouldn't be checking.
	 */
	if (source[0] == '/') {
		/* The source is an absolute path -- it better exist! */
		rc = stat(source, &st_buf);
		if (rc) {
			rc = errno;
			pwarn("stat(%s) failed", source);
			return -rc;
		}

		/*
		 * If bind mounting, we only create a directory if the source
		 * is a directory, else we always bind mount it as a file to
		 * support device nodes, sockets, etc...
		 *
		 * For all other mounts, we assume a block/char source is
		 * going to want a directory to mount to.  If the source is
		 * something else (e.g. a fifo or socket), this probably will
		 * not do the right thing, but we'll fail later on when we try
		 * to mount(), so shouldn't be a big deal.
		 */
		domkdir = S_ISDIR(st_buf.st_mode) ||
			  (!bind && (S_ISBLK(st_buf.st_mode) ||
				     S_ISCHR(st_buf.st_mode)));

		/* If bind mounting, also grab the mount flags of the source. */
		if (bind && mnt_flags) {
			struct statvfs stvfs_buf;
			rc = statvfs(source, &stvfs_buf);
			if (rc) {
				rc = errno;
				pwarn(
				    "failed to look up mount flags: source=%s",
				    source);
				return -rc;
			}
			*mnt_flags = stvfs_buf.f_flag;
		}
	} else {
		/* The source is a relative path -- assume it's a pseudo fs. */

		/* Disallow relative bind mounts. */
		if (bind) {
			warn("relative bind-mounts are not allowed: source=%s",
			     source);
			return -EINVAL;
		}

		domkdir = true;
	}

	/*
	 * Now that we know what we want to do, do it!
	 * We always create the intermediate dirs and the final path with 0755
	 * perms and root/root ownership.  This shouldn't be a problem because
	 * the actual mount will set those perms/ownership on the mount point
	 * which is all people should need to access it.
	 */
	rc = mkdir_p(dest, 0755, domkdir);
	if (rc)
		return rc;
	if (!domkdir) {
		int fd = open(dest, O_RDWR | O_CREAT | O_CLOEXEC, 0700);
		if (fd < 0) {
			rc = errno;
			pwarn("open(%s) failed", dest);
			return -rc;
		}
		close(fd);
	}
	if (chown(dest, uid, gid)) {
		rc = errno;
		pwarn("chown(%s, %u, %u) failed", dest, uid, gid);
		return -rc;
	}
	return 0;
}

/*
 * lookup_user: Gets the uid/gid for the given username.
 */
int lookup_user(const char *user, uid_t *uid, gid_t *gid)
{
	char *buf = NULL;
	struct passwd pw;
	struct passwd *ppw = NULL;
	ssize_t sz = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (sz == -1)
		sz = 65536; /* your guess is as good as mine... */

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
	 * dangling but it's safe. |ppw| points at |pw| if getpwnam_r(3)
	 * succeeded.
	 */
	free(buf);
	/* getpwnam_r(3) does *not* set errno when |ppw| is NULL. */
	if (!ppw)
		return -1;

	*uid = ppw->pw_uid;
	*gid = ppw->pw_gid;
	return 0;
}

/*
 * lookup_group: Gets the gid for the given group name.
 */
int lookup_group(const char *group, gid_t *gid)
{
	char *buf = NULL;
	struct group gr;
	struct group *pgr = NULL;
	ssize_t sz = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (sz == -1)
		sz = 65536; /* and mine is as good as yours, really */

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

	*gid = pgr->gr_gid;
	return 0;
}

static int seccomp_action_is_available(const char *wanted)
{
	if (is_android()) {
		/*
		 * Accessing |actions_avail| is generating SELinux denials, so
		 * skip for now.
		 * TODO(crbug.com/978022, jorgelo): Remove once the denial is
		 * fixed.
		 */
		return 0;
	}
	const char actions_avail_path[] =
	    "/proc/sys/kernel/seccomp/actions_avail";
	FILE *f = fopen(actions_avail_path, "re");

	if (!f) {
		pwarn("fopen(%s) failed", actions_avail_path);
		return 0;
	}

	char *actions_avail = NULL;
	size_t buf_size = 0;
	if (getline(&actions_avail, &buf_size, f) < 0) {
		pwarn("getline() failed");
		free(actions_avail);
		return 0;
	}

	/*
	 * This is just substring search, which means that partial matches will
	 * match too (e.g. "action" would match "longaction"). There are no
	 * seccomp actions which include other actions though, so we're good for
	 * now. Eventually we might want to split the string by spaces.
	 */
	return strstr(actions_avail, wanted) != NULL;
}

int seccomp_ret_log_available(void)
{
	static int ret_log_available = -1;

	if (ret_log_available == -1)
		ret_log_available = seccomp_action_is_available("log");

	return ret_log_available;
}

int seccomp_ret_kill_process_available(void)
{
	static int ret_kill_process_available = -1;

	if (ret_kill_process_available == -1)
		ret_kill_process_available =
		    seccomp_action_is_available("kill_process");

	return ret_kill_process_available;
}
