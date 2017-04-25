/* Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "system.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

#ifdef HAVE_SECUREBITS_H
#include <linux/securebits.h>
#else
#define SECURE_ALL_BITS 0x55
#define SECURE_ALL_LOCKS (SECURE_ALL_BITS << 1)
#endif

#define SECURE_BITS_NO_AMBIENT 0x15
#define SECURE_LOCKS_NO_AMBIENT (SECURE_BITS_NO_AMBIENT << 1)

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

int lock_securebits(void)
{
	/*
	 * Ambient capabilities can only be raised if they're already present
	 * in the permitted *and* inheritable set. Therefore, we don't really
	 * need to lock the NO_CAP_AMBIENT_RAISE securebit, since we are already
	 * configuring the permitted and inheritable set.
	 */
	int securebits_ret =
	    prctl(PR_SET_SECUREBITS,
		  SECURE_BITS_NO_AMBIENT | SECURE_LOCKS_NO_AMBIENT);
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
		return -1;
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

int write_pid_to_path(pid_t pid, const char *path)
{
	FILE *fp = fopen(path, "w");

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
 * setup_mount_destination: Ensures the mount target exists.
 * Creates it if needed and possible.
 */
int setup_mount_destination(const char *source, const char *dest, uid_t uid,
			    uid_t gid)
{
	int rc;
	struct stat st_buf;

	rc = stat(dest, &st_buf);
	if (rc == 0) /* destination exists */
		return 0;

	/*
	 * Try to create the destination.
	 * Either make a directory or touch a file depending on the source type.
	 * If the source doesn't exist, assume it is a filesystem type such as
	 * "tmpfs" and create a directory to mount it on.
	 */
	rc = stat(source, &st_buf);
	if (rc || S_ISDIR(st_buf.st_mode) || S_ISBLK(st_buf.st_mode)) {
		if (mkdir(dest, 0700))
			return -errno;
	} else {
		int fd = open(dest, O_RDWR | O_CREAT, 0700);
		if (fd < 0)
			return -errno;
		close(fd);
	}
	return chown(dest, uid, gid);
}
