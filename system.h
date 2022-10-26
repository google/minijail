/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Wrappers for system functionality.
 */

#ifndef _SYSTEM_H_
#define _SYSTEM_H_

#include <stdbool.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Control the ambient capability set. */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif

#ifndef PR_CAP_AMBIENT_IS_SET
#define PR_CAP_AMBIENT_IS_SET 1
#endif

#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE 2
#endif

#ifndef PR_CAP_AMBIENT_LOWER
#define PR_CAP_AMBIENT_LOWER 3
#endif

#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

int secure_noroot_set_and_locked(uint64_t mask);
int lock_securebits(uint64_t skip_mask, bool require_keep_caps);

unsigned int get_last_valid_cap(void);
int cap_ambient_supported(void);

int config_net_loopback(void);

int write_pid_to_path(pid_t pid, const char *path);
int write_proc_file(pid_t pid, const char *content, const char *basename);

int mkdir_p(const char *path, mode_t mode, bool isdir);

int get_mount_flags(const char *source, unsigned long *mnt_flags);

int setup_mount_destination(const char *source, const char *dest, uid_t uid,
			    uid_t gid, bool bind);

int lookup_user(const char *user, uid_t *uid, gid_t *gid);
int lookup_group(const char *group, gid_t *gid);

/* sys_set_no_new_privs: returns true if successful. */
bool sys_set_no_new_privs(void);
int seccomp_ret_log_available(void);
int seccomp_ret_kill_process_available(void);
bool seccomp_filter_flags_available(unsigned int flags);

/*
 * is_canonical_path: checks whether @path is a canonical path.
 * This means:
 * -Absolute.
 * -No symlinks.
 * -No /./, /../, or extra '/'.
 * -Single trailing '/' is OK.
 */
bool is_canonical_path(const char *path);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _SYSTEM_H_ */
