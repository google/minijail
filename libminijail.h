/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * The general pattern of use here:
 * 1) Construct a minijail with minijail_new()
 * 2) Apply the desired restrictions to it
 * 3) Enter it, which locks the current process inside it, or:
 * 3) Run a process inside it
 * 4) Destroy it.
 */

#ifndef _LIBMINIJAIL_H_
#define _LIBMINIJAIL_H_

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	MINIJAIL_ERR_PRELOAD = 252,
	MINIJAIL_ERR_JAIL = 253,
	MINIJAIL_ERR_INIT = 254,
};

struct minijail;

/* Allocates a new minijail with no restrictions. */
struct minijail *minijail_new(void);

/*
 * These functions add restrictions to the minijail. They are not applied until
 * minijail_enter() is called. See the documentation in minijail0.1 for
 * explanations in detail of what the restrictions do.
 */
void minijail_change_uid(struct minijail *j, uid_t uid);
void minijail_change_gid(struct minijail *j, gid_t gid);
/* Copies |list|. */
void minijail_set_supplementary_gids(struct minijail *j, size_t size,
				     const gid_t *list);
/* Stores user to change to and copies |user| for internal consistency. */
int minijail_change_user(struct minijail *j, const char *user);
/* Does not take ownership of |group|. */
int minijail_change_group(struct minijail *j, const char *group);
void minijail_use_seccomp(struct minijail *j);
void minijail_no_new_privs(struct minijail *j);
void minijail_use_seccomp_filter(struct minijail *j);
void minijail_parse_seccomp_filters(struct minijail *j, const char *path);
void minijail_log_seccomp_filter_failures(struct minijail *j);
void minijail_use_caps(struct minijail *j, uint64_t capmask);
void minijail_reset_signal_mask(struct minijail *j);
void minijail_namespace_vfs(struct minijail *j);
void minijail_namespace_enter_vfs(struct minijail *j, const char *ns_path);
void minijail_namespace_ipc(struct minijail *j);
void minijail_namespace_net(struct minijail *j);
void minijail_namespace_enter_net(struct minijail *j, const char *ns_path);
/*
 * Implies namespace_vfs and remount_proc_readonly.
 * WARNING: this is NOT THREAD SAFE. See the block comment in </libminijail.c>.
 */
void minijail_namespace_pids(struct minijail *j);
void minijail_namespace_user(struct minijail *j);
int minijail_uidmap(struct minijail *j, const char *uidmap);
int minijail_gidmap(struct minijail *j, const char *gidmap);
void minijail_remount_proc_readonly(struct minijail *j);
void minijail_run_as_init(struct minijail *j);
int minijail_write_pid_file(struct minijail *j, const char *path);
void minijail_inherit_usergroups(struct minijail *j);
void minijail_disable_ptrace(struct minijail *j);
/*
 * Changes the jailed process's syscall table to the alt_syscall table
 * named |table|.
 */
int minijail_use_alt_syscall(struct minijail *j, const char *table);

/*
 * Adds the jailed process to the cgroup given by |path|.  |path| should be the
 * full path to the cgroups "tasks" file.
 * Example: /sys/fs/cgroup/cpu/jailed_procs/tasks adds to the "jailed_procs" cpu
 * cgroup.
 */
int minijail_add_to_cgroup(struct minijail *j, const char *path);

/*
 * minijail_enter_chroot: enables chroot() restriction for @j
 * @j   minijail to apply restriction to
 * @dir directory to chroot() to. Owned by caller.
 *
 * Enters @dir, binding all bind mounts specified with minijail_bind() into
 * place. Requires @dir to contain all necessary directories for bind mounts
 * (i.e., if you have requested a bind mount at /etc, /etc must exist in @dir.)
 *
 * Returns 0 on success.
 */
int minijail_enter_chroot(struct minijail *j, const char *dir);
int minijail_enter_pivot_root(struct minijail *j, const char *dir);

/*
 * minijail_get_original_path: returns the path of a given file outside of the
 * chroot.
 * @j           minijail to obtain the path from.
 * @chroot_path path inside of the chroot() to.
 *
 * When executing a binary in a chroot or pivot_root, return path to the binary
 * outside of the chroot.
 *
 * Returns a string containing the path.  This must be freed by the caller.
 */
char *minijail_get_original_path(struct minijail *j, const char *chroot_path);

/*
 * minijail_mount_tmp: enables mounting of a tmpfs filesystem on /tmp.
 * As be rules of bind mounts, /tmp must exist in chroot.
 */
void minijail_mount_tmp(struct minijail *j);

/*
 * minijail_mount: when entering minijail @j, mounts @src at @dst with @flags
 * @j         minijail to bind inside
 * @src       source to bind
 * @dest      location to bind (inside chroot)
 * @type      type of filesystem
 * @flags     flags passed to mount
 *
 * This may be called multiple times; all bindings will be applied in the order
 * of minijail_mount() calls.
 */
int minijail_mount(struct minijail *j, const char *src, const char *dest,
		   const char *type, unsigned long flags);

/*
 * minijail_bind: bind-mounts @src into @j as @dest, optionally writeable
 * @j         minijail to bind inside
 * @src       source to bind
 * @dest      location to bind (inside chroot)
 * @writeable 1 if the bind mount should be writeable
 *
 * This may be called multiple times; all bindings will be applied in the order
 * of minijail_bind() calls.
 */
int minijail_bind(struct minijail *j, const char *src, const char *dest,
		  int writeable);

/*
 * Lock this process into the given minijail. Note that this procedure cannot fail,
 * since there is no way to undo privilege-dropping; therefore, if any part of
 * the privilege-drop fails, minijail_enter() will abort the entire process.
 *
 * Some restrictions cannot be enabled this way (pid namespaces) and attempting
 * to do so will cause an abort.
 */
void minijail_enter(const struct minijail *j);

/*
 * Run the specified command in the given minijail, execve(2)-style. This is
 * required if minijail_namespace_pids() was used.
 */
int minijail_run(struct minijail *j, const char *filename,
		 char *const argv[]);

/*
 * Run the specified command in the given minijail, execve(2)-style.
 * Used with static binaries, or on systems without support for LD_PRELOAD.
 */
int minijail_run_no_preload(struct minijail *j, const char *filename,
			    char *const argv[]);

/*
 * Run the specified command in the given minijail, execve(2)-style.
 * Update |*pchild_pid| with the pid of the child.
 */
int minijail_run_pid(struct minijail *j, const char *filename,
		     char *const argv[], pid_t *pchild_pid);

/*
 * Run the specified command in the given minijail, execve(2)-style.
 * Update |*pstdin_fd| with a fd that allows writing to the child's
 * standard input.
 */
int minijail_run_pipe(struct minijail *j, const char *filename,
		      char *const argv[], int *pstdin_fd);

/*
 * Run the specified command in the given minijail, execve(2)-style.
 * Update |*pchild_pid| with the pid of the child.
 * Update |*pstdin_fd| with a fd that allows writing to the child's
 * standard input.
 * Update |*pstdout_fd| with a fd that allows reading from the child's
 * standard output.
 * Update |*pstderr_fd| with a fd that allows reading from the child's
 * standard error.
 */
int minijail_run_pid_pipes(struct minijail *j, const char *filename,
			   char *const argv[], pid_t *pchild_pid,
			   int *pstdin_fd, int *pstdout_fd, int *pstderr_fd);

/*
 * Run the specified command in the given minijail, execve(2)-style.
 * Update |*pchild_pid| with the pid of the child.
 * Update |*pstdin_fd| with a fd that allows writing to the child's
 * standard input.
 * Update |*pstdout_fd| with a fd that allows reading from the child's
 * standard output.
 * Update |*pstderr_fd| with a fd that allows reading from the child's
 * standard error.
 * Used with static binaries, or on systems without support for LD_PRELOAD.
 */
int minijail_run_pid_pipes_no_preload(struct minijail *j, const char *filename,
				      char *const argv[], pid_t *pchild_pid,
				      int *pstdin_fd, int *pstdout_fd,
				      int *pstderr_fd);

/*
 * Kill the specified minijail. The minijail must have been created with pid
 * namespacing; if it was, all processes inside it are atomically killed.
 */
int minijail_kill(struct minijail *j);

/*
 * Wait for all processed in the specified minijail to exit. Returns the exit
 * status of the _first_ process spawned in the jail.
 */
int minijail_wait(struct minijail *j);

/*
 * Frees the given minijail. It does not matter if the process is inside the minijail or
 * not.
 */
void minijail_destroy(struct minijail *j);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* !_LIBMINIJAIL_H_ */
