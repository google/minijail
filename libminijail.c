/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <asm/unistd.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include "landlock_util.h"
#include "libminijail-private.h"
#include "libminijail.h"

#include "signal_handler.h"
#include "syscall_filter.h"
#include "syscall_wrapper.h"
#include "system.h"
#include "util.h"

/* Until these are reliably available in linux/prctl.h. */
#ifndef PR_ALT_SYSCALL
#define PR_ALT_SYSCALL 0x43724f53
#endif

/* New cgroup namespace might not be in linux-headers yet. */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#define MAX_CGROUPS 10 /* 10 different controllers supported by Linux. */

#define MAX_RLIMITS 32 /* Currently there are 15 supported by Linux. */

#define MAX_PRESERVED_FDS 128U

/* Keyctl commands. */
#define KEYCTL_JOIN_SESSION_KEYRING 1

/*
 * The userspace equivalent of MNT_USER_SETTABLE_MASK, which is the mask of all
 * flags that can be modified by MS_REMOUNT.
 */
#define MS_USER_SETTABLE_MASK                                                  \
	(MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_NODIRATIME |       \
	 MS_RELATIME | MS_RDONLY)

struct minijail_rlimit {
	int type;
	rlim_t cur;
	rlim_t max;
};

struct mountpoint {
	char *src;
	char *dest;
	char *type;
	char *data;
	int has_data;
	unsigned long flags;
	struct mountpoint *next;
};

struct minijail_remount {
	unsigned long remount_mode;
	char *mount_name;
	struct minijail_remount *next;
};

struct hook {
	minijail_hook_t hook;
	void *payload;
	minijail_hook_event_t event;
	struct hook *next;
};

struct fs_rule {
	char *path;
	uint64_t landlock_flags;
	struct fs_rule *next;
};

struct preserved_fd {
	int parent_fd;
	int child_fd;
};

/*
 * minijail struct: new fields should either be marshaled/unmarshaled or have a
 * comment explaining why that's unnecessary.
 */
struct minijail {
	/*
	 * WARNING: new bool flags should always be added to this struct,
	 * unless you’re certain they don’t need to remain after marshaling.
	 * If you add a flag here you need to make sure it's
	 * accounted for in minijail_pre{enter|exec}() below.
	 */
	struct {
		bool uid : 1;
		bool gid : 1;
		bool inherit_suppl_gids : 1;
		bool set_suppl_gids : 1;
		bool keep_suppl_gids : 1;
		bool use_caps : 1;
		bool capbset_drop : 1;
		bool set_ambient_caps : 1;
		bool vfs : 1;
		bool enter_vfs : 1;
		bool pids : 1;
		bool ipc : 1;
		bool uts : 1;
		bool net : 1;
		bool enter_net : 1;
		bool ns_cgroups : 1;
		bool userns : 1;
		bool disable_setgroups : 1;
		bool seccomp : 1;
		bool remount_proc_ro : 1;
		bool no_new_privs : 1;
		bool seccomp_filter : 1;
		bool seccomp_filter_tsync : 1;
		bool seccomp_filter_logging : 1;
		bool seccomp_filter_allow_speculation : 1;
		bool chroot : 1;
		bool pivot_root : 1;
		bool mount_dev : 1;
		bool mount_tmp : 1;
		bool do_init : 1;
		bool run_as_init : 1;
		bool pid_file : 1;
		bool cgroups : 1;
		bool alt_syscall : 1;
		bool reset_signal_mask : 1;
		bool reset_signal_handlers : 1;
		bool close_open_fds : 1;
		bool new_session_keyring : 1;
		bool forward_signals : 1;
		bool setsid : 1;
		bool using_minimalistic_mountns : 1;
		bool enable_profile_fs_restrictions : 1;
		bool enable_default_runtime : 1;
	} flags;
	uid_t uid;
	gid_t gid;
	gid_t usergid;
	char *user;
	size_t suppl_gid_count;
	gid_t *suppl_gid_list;
	uint64_t caps;
	uint64_t cap_bset;
	pid_t initpid;
	int mountns_fd;
	int netns_fd;
	char *chrootdir;
	char *pid_file_path;
	char *uidmap;
	char *gidmap;
	char *hostname;
	char *preload_path;
	/*
	 * Filename that will be executed, unless an ELF fd is used instead.
	 * This field is only used for logs and isn't included in marshaling.
	 */
	char *filename;
	size_t filter_len;
	struct sock_fprog *filter_prog;
	char *alt_syscall_table;
	struct mountpoint *mounts_head;
	struct mountpoint *mounts_tail;
	size_t mounts_count;
	unsigned long remount_mode;
	struct minijail_remount *remounts_head;
	struct minijail_remount *remounts_tail;
	size_t tmpfs_size;
	struct fs_rule *fs_rules_head;
	struct fs_rule *fs_rules_tail;
	size_t fs_rules_count;
	char *cgroups[MAX_CGROUPS];
	size_t cgroup_count;
	struct minijail_rlimit rlimits[MAX_RLIMITS];
	size_t rlimit_count;
	uint64_t securebits_skip_mask;
	struct hook *hooks_head;
	struct hook *hooks_tail;
	struct preserved_fd preserved_fds[MAX_PRESERVED_FDS];
	size_t preserved_fd_count;
	char *seccomp_policy_path;
};

static void run_hooks_or_die(const struct minijail *j,
			     minijail_hook_event_t event);

static bool seccomp_is_logging_allowed(const struct minijail *j)
{
	return seccomp_default_ret_log() || j->flags.seccomp_filter_logging;
}

static void free_mounts_list(struct minijail *j)
{
	while (j->mounts_head) {
		struct mountpoint *m = j->mounts_head;
		j->mounts_head = j->mounts_head->next;
		free(m->data);
		free(m->type);
		free(m->dest);
		free(m->src);
		free(m);
	}
	// No need to clear mounts_head as we know it's NULL after the loop.
	j->mounts_tail = NULL;
}

static void free_remounts_list(struct minijail *j)
{
	while (j->remounts_head) {
		struct minijail_remount *m = j->remounts_head;
		j->remounts_head = j->remounts_head->next;
		free(m->mount_name);
		free(m);
	}
	// No need to clear remounts_head as we know it's NULL after the loop.
	j->remounts_tail = NULL;
}

static void free_fs_rules_list(struct minijail *j)
{
	while (j->fs_rules_head) {
		struct fs_rule *r = j->fs_rules_head;
		j->fs_rules_head = j->fs_rules_head->next;
		free(r->path);
		free(r);
	}
	j->fs_rules_tail = NULL;
}

/*
 * Writes exactly n bytes from buf to file descriptor fd.
 * Returns 0 on success or a negative error code on error.
 */
static int write_exactly(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	while (n > 0) {
		const ssize_t written = write(fd, p, n);
		if (written < 0) {
			if (errno == EINTR)
				continue;

			return -errno;
		}

		p += written;
		n -= written;
	}

	return 0;
}

/* Closes *pfd and sets it to -1. */
static void close_and_reset(int *pfd)
{
	if (*pfd != -1)
		close(*pfd);
	*pfd = -1;
}

/*
 * Strip out flags meant for the parent.
 * We keep things that are not inherited across execve(2) (e.g. capabilities),
 * or are easier to set after execve(2) (e.g. seccomp filters).
 */
void minijail_preenter(struct minijail *j)
{
	j->flags.vfs = 0;
	j->flags.enter_vfs = 0;
	j->flags.ns_cgroups = 0;
	j->flags.net = 0;
	j->flags.uts = 0;
	j->flags.remount_proc_ro = 0;
	j->flags.pids = 0;
	j->flags.do_init = 0;
	j->flags.run_as_init = 0;
	j->flags.pid_file = 0;
	j->flags.cgroups = 0;
	j->flags.forward_signals = 0;
	j->flags.setsid = 0;
	j->remount_mode = 0;
	j->flags.using_minimalistic_mountns = 0;
	j->flags.enable_profile_fs_restrictions = 0;
	j->flags.enable_default_runtime = 0;
	free_remounts_list(j);
}

/* Adds a rule for a given path to apply once minijail is entered. */
int add_fs_restriction_path(struct minijail *j,
		const char *path,
		uint64_t landlock_flags)
{
	struct fs_rule *r = calloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;
	r->path = strdup(path);
	r->landlock_flags = landlock_flags;

	if (j->fs_rules_tail) {
		j->fs_rules_tail->next = r;
		j->fs_rules_tail = r;
	} else {
		j->fs_rules_head = r;
		j->fs_rules_tail = r;
	}

	j->fs_rules_count++;
	return 0;
}

bool mount_has_bind_flag(struct mountpoint *m) {
	return !!(m->flags & MS_BIND);
}

bool mount_has_readonly_flag(struct mountpoint *m) {
	return !!(m->flags & MS_RDONLY);
}

bool mount_events_allowed(struct mountpoint *m) {
	return !!(m->flags & MS_SHARED) || !!(m->flags & MS_SLAVE);
}

/*
 * Strip out flags meant for the child.
 * We keep things that are inherited across execve(2).
 */
void minijail_preexec(struct minijail *j)
{
	int vfs = j->flags.vfs;
	int enter_vfs = j->flags.enter_vfs;
	int ns_cgroups = j->flags.ns_cgroups;
	int net = j->flags.net;
	int uts = j->flags.uts;
	int remount_proc_ro = j->flags.remount_proc_ro;
	int userns = j->flags.userns;
	int using_minimalistic_mountns = j->flags.using_minimalistic_mountns;
	int enable_profile_fs_restrictions = j->flags.enable_profile_fs_restrictions;
	int enable_default_runtime = j->flags.enable_default_runtime;
	if (j->user)
		free(j->user);
	j->user = NULL;
	if (j->suppl_gid_list)
		free(j->suppl_gid_list);
	j->suppl_gid_list = NULL;
	if (j->preload_path)
		free(j->preload_path);
	j->preload_path = NULL;
	free_mounts_list(j);
	free_fs_rules_list(j);
	memset(&j->flags, 0, sizeof(j->flags));
	/* Now restore anything we meant to keep. */
	j->flags.vfs = vfs;
	j->flags.enter_vfs = enter_vfs;
	j->flags.ns_cgroups = ns_cgroups;
	j->flags.net = net;
	j->flags.uts = uts;
	j->flags.remount_proc_ro = remount_proc_ro;
	j->flags.userns = userns;
	j->flags.using_minimalistic_mountns = using_minimalistic_mountns;
	j->flags.enable_profile_fs_restrictions = enable_profile_fs_restrictions;
	j->flags.enable_default_runtime = enable_default_runtime;
	/* Note, |pids| will already have been used before this call. */
}

/* Minijail API. */

struct minijail API *minijail_new(void)
{
	struct minijail *j = calloc(1, sizeof(struct minijail));
	if (j) {
		j->remount_mode = MS_PRIVATE;
		j->flags.using_minimalistic_mountns = false;
		j->flags.enable_profile_fs_restrictions = true;
		j->flags.enable_default_runtime = true;
	}
	return j;
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

	if (j->flags.inherit_suppl_gids)
		die("cannot inherit *and* set supplementary groups");
	if (j->flags.keep_suppl_gids)
		die("cannot keep *and* set supplementary groups");

	if (size == 0) {
		/* Clear supplementary groups. */
		j->suppl_gid_list = NULL;
		j->suppl_gid_count = 0;
		j->flags.set_suppl_gids = 1;
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
	j->flags.set_suppl_gids = 1;
}

void API minijail_keep_supplementary_gids(struct minijail *j)
{
	j->flags.keep_suppl_gids = 1;
}

int API minijail_change_user(struct minijail *j, const char *user)
{
	uid_t uid;
	gid_t gid;
	int rc = lookup_user(user, &uid, &gid);
	if (rc)
		return rc;
	minijail_change_uid(j, uid);
	j->user = strdup(user);
	if (!j->user)
		return -ENOMEM;
	j->usergid = gid;
	return 0;
}

int API minijail_change_group(struct minijail *j, const char *group)
{
	gid_t gid;
	int rc = lookup_group(group, &gid);
	if (rc)
		return rc;
	minijail_change_gid(j, gid);
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

void API minijail_set_seccomp_filter_tsync(struct minijail *j)
{
	if (j->filter_len > 0 && j->filter_prog != NULL) {
		die("minijail_set_seccomp_filter_tsync() must be called "
		    "before minijail_parse_seccomp_filters()");
	}

	if (seccomp_is_logging_allowed(j) && !seccomp_ret_log_available()) {
		/*
		 * If SECCOMP_RET_LOG is not available, we don't want to use
		 * SECCOMP_RET_TRAP to both kill the entire process and report
		 * failing syscalls, since it will be brittle. Just bail.
		 */
		die("SECCOMP_RET_LOG not available, cannot use logging with "
		    "thread sync at the same time");
	}

	j->flags.seccomp_filter_tsync = 1;
}

void API minijail_set_seccomp_filter_allow_speculation(struct minijail *j)
{
	if (j->filter_len > 0 && j->filter_prog != NULL) {
		die("minijail_set_seccomp_filter_allow_speculation() must be "
		    "called before minijail_parse_seccomp_filters()");
	}

	j->flags.seccomp_filter_allow_speculation = 1;
}

void API minijail_log_seccomp_filter_failures(struct minijail *j)
{
	if (j->filter_len > 0 && j->filter_prog != NULL) {
		die("minijail_log_seccomp_filter_failures() must be called "
		    "before minijail_parse_seccomp_filters()");
	}

	if (j->flags.seccomp_filter_tsync && !seccomp_ret_log_available()) {
		/*
		 * If SECCOMP_RET_LOG is not available, we don't want to use
		 * SECCOMP_RET_TRAP to both kill the entire process and report
		 * failing syscalls, since it will be brittle. Just bail.
		 */
		die("SECCOMP_RET_LOG not available, cannot use thread sync "
		    "with logging at the same time");
	}

	if (debug_logging_allowed()) {
		j->flags.seccomp_filter_logging = 1;
	} else {
		warn("non-debug build: ignoring request to enable seccomp "
		     "logging");
	}
}

void API minijail_set_using_minimalistic_mountns(struct minijail *j)
{
	j->flags.using_minimalistic_mountns = true;
}

void API minijail_set_enable_default_runtime(struct minijail *j,
					     bool enable_default_runtime) {
	j->flags.enable_default_runtime = enable_default_runtime;
}

bool API minijail_get_enable_default_runtime(struct minijail *j) {
	return j->flags.enable_default_runtime;
}

void API minijail_set_enable_profile_fs_restrictions(struct minijail *j)
{
	j->flags.enable_profile_fs_restrictions = true;
}

void API minijail_add_minimalistic_mountns_fs_rules(struct minijail *j)
{
	struct mountpoint *m = j->mounts_head;
	bool landlock_enabled_by_profile = false;
	if (!j->flags.using_minimalistic_mountns ||
	    !j->flags.enable_profile_fs_restrictions)
		return;
	/*
	 * We only want to use Landlock if the profile only consists of -b
	 * mounts. If we find any -k mounts return.
	 */
	while (m) {
		if (!mount_has_bind_flag(m))
			return;
		m = m->next;
	}

	/* Apply Landlock rules. */
	m = j->mounts_head;
	while (m) {
		landlock_enabled_by_profile = true;
		minijail_add_fs_restriction_rx(j, m->dest);
		/*
		 * Allow rw if mounted as writable, or mount flags allow mount
		 * events.
		 */
		if (!mount_has_readonly_flag(m) || mount_events_allowed(m))
			minijail_add_fs_restriction_advanced_rw(j, m->dest);
		m = m->next;
	}
	if (landlock_enabled_by_profile) {
		minijail_enable_default_fs_restrictions(j);
		minijail_add_fs_restriction_edit(j, "/dev");
		minijail_add_fs_restriction_ro(j, "/proc");
		if (j->flags.vfs)
			minijail_add_fs_restriction_rw(j, "/tmp");
	}
}

void API minijail_enable_default_fs_restrictions(struct minijail *j)
{
	// Common library locations.
	minijail_add_fs_restriction_rx(j, "/lib");
	minijail_add_fs_restriction_rx(j, "/lib64");
	minijail_add_fs_restriction_rx(j, "/usr/lib");
	minijail_add_fs_restriction_rx(j, "/usr/lib64");
	// Common locations for services invoking Minijail.
	minijail_add_fs_restriction_rx(j, "/bin");
	minijail_add_fs_restriction_rx(j, "/sbin");
	minijail_add_fs_restriction_rx(j, "/usr/sbin");
	minijail_add_fs_restriction_rx(j, "/usr/bin");
}

void API minijail_use_caps(struct minijail *j, uint64_t capmask)
{
	/*
	 * 'minijail_use_caps' configures a runtime-capabilities-only
	 * environment, including a bounding set matching the thread's runtime
	 * (permitted|inheritable|effective) sets.
	 * Therefore, it will override any existing bounding set configurations
	 * since the latter would allow gaining extra runtime capabilities from
	 * file capabilities.
	 */
	if (j->flags.capbset_drop) {
		warn("overriding bounding set configuration");
		j->cap_bset = 0;
		j->flags.capbset_drop = 0;
	}
	j->caps = capmask;
	j->flags.use_caps = 1;
}

void API minijail_capbset_drop(struct minijail *j, uint64_t capmask)
{
	if (j->flags.use_caps) {
		/*
		 * 'minijail_use_caps' will have already configured a capability
		 * bounding set matching the (permitted|inheritable|effective)
		 * sets. Abort if the user tries to configure a separate
		 * bounding set. 'minijail_capbset_drop' and 'minijail_use_caps'
		 * are mutually exclusive.
		 */
		die("runtime capabilities already configured, can't drop "
		    "bounding set separately");
	}
	j->cap_bset = capmask;
	j->flags.capbset_drop = 1;
}

void API minijail_set_ambient_caps(struct minijail *j)
{
	j->flags.set_ambient_caps = 1;
}

void API minijail_reset_signal_mask(struct minijail *j)
{
	j->flags.reset_signal_mask = 1;
}

void API minijail_reset_signal_handlers(struct minijail *j)
{
	j->flags.reset_signal_handlers = 1;
}

void API minijail_namespace_vfs(struct minijail *j)
{
	j->flags.vfs = 1;
}

void API minijail_namespace_enter_vfs(struct minijail *j, const char *ns_path)
{
	/* Note: Do not use O_CLOEXEC here.  We'll close it after we use it. */
	int ns_fd = open(ns_path, O_RDONLY);
	if (ns_fd < 0) {
		pdie("failed to open namespace '%s'", ns_path);
	}
	j->mountns_fd = ns_fd;
	j->flags.enter_vfs = 1;
}

void API minijail_new_session_keyring(struct minijail *j)
{
	j->flags.new_session_keyring = 1;
}

void API minijail_skip_setting_securebits(struct minijail *j,
					  uint64_t securebits_skip_mask)
{
	j->securebits_skip_mask = securebits_skip_mask;
}

void API minijail_remount_mode(struct minijail *j, unsigned long mode)
{
	j->remount_mode = mode;
}

void API minijail_skip_remount_private(struct minijail *j)
{
	j->remount_mode = 0;
}

void API minijail_namespace_pids(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.remount_proc_ro = 1;
	j->flags.pids = 1;
	j->flags.do_init = 1;
}

void API minijail_namespace_pids_rw_proc(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.pids = 1;
	j->flags.do_init = 1;
}

void API minijail_namespace_ipc(struct minijail *j)
{
	j->flags.ipc = 1;
}

void API minijail_namespace_uts(struct minijail *j)
{
	j->flags.uts = 1;
}

int API minijail_namespace_set_hostname(struct minijail *j, const char *name)
{
	if (j->hostname)
		return -EINVAL;
	minijail_namespace_uts(j);
	j->hostname = strdup(name);
	if (!j->hostname)
		return -ENOMEM;
	return 0;
}

void API minijail_namespace_net(struct minijail *j)
{
	j->flags.net = 1;
}

void API minijail_namespace_enter_net(struct minijail *j, const char *ns_path)
{
	/* Note: Do not use O_CLOEXEC here.  We'll close it after we use it. */
	int ns_fd = open(ns_path, O_RDONLY);
	if (ns_fd < 0) {
		pdie("failed to open namespace '%s'", ns_path);
	}
	j->netns_fd = ns_fd;
	j->flags.enter_net = 1;
}

void API minijail_namespace_cgroups(struct minijail *j)
{
	j->flags.ns_cgroups = 1;
}

void API minijail_close_open_fds(struct minijail *j)
{
	j->flags.close_open_fds = 1;
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

void API minijail_namespace_user_disable_setgroups(struct minijail *j)
{
	j->flags.disable_setgroups = 1;
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
	j->flags.inherit_suppl_gids = 1;
}

void API minijail_run_as_init(struct minijail *j)
{
	/*
	 * Since the jailed program will become 'init' in the new PID namespace,
	 * Minijail does not need to fork an 'init' process.
	 */
	j->flags.run_as_init = 1;
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
		if (streq(b->dest, path_inside_chroot))
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
			return path_join(b->src, relative_path);
		}
		b = b->next;
	}

	/* If there is a chroot path, append |path_inside_chroot| to that. */
	if (j->chrootdir)
		return path_join(j->chrootdir, path_inside_chroot);

	/* No chroot, so the path outside is the same as it is inside. */
	return strdup(path_inside_chroot);
}

void API minijail_mount_dev(struct minijail *j)
{
	j->flags.mount_dev = 1;
}

void API minijail_mount_tmp(struct minijail *j)
{
	minijail_mount_tmp_size(j, 64 * 1024 * 1024);
}

void API minijail_mount_tmp_size(struct minijail *j, size_t size)
{
	j->tmpfs_size = size;
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

int API minijail_rlimit(struct minijail *j, int type, rlim_t cur, rlim_t max)
{
	size_t i;

	if (j->rlimit_count >= MAX_RLIMITS)
		return -ENOMEM;
	/* It's an error if the caller sets the same rlimit multiple times. */
	for (i = 0; i < j->rlimit_count; i++) {
		if (j->rlimits[i].type == type)
			return -EEXIST;
	}

	j->rlimits[j->rlimit_count].type = type;
	j->rlimits[j->rlimit_count].cur = cur;
	j->rlimits[j->rlimit_count].max = max;
	j->rlimit_count++;
	return 0;
}

int API minijail_forward_signals(struct minijail *j)
{
	j->flags.forward_signals = 1;
	return 0;
}

int API minijail_create_session(struct minijail *j)
{
	j->flags.setsid = 1;
	return 0;
}

int API minijail_add_fs_restriction_rx(struct minijail *j, const char *path)
{
	return !add_fs_restriction_path(j, path,
		ACCESS_FS_ROUGHLY_READ_EXECUTE);
}

int API minijail_add_fs_restriction_ro(struct minijail *j, const char *path)
{
	return !add_fs_restriction_path(j, path, ACCESS_FS_ROUGHLY_READ);
}

int API minijail_add_fs_restriction_rw(struct minijail *j, const char *path)
{
	return !add_fs_restriction_path(j, path,
		ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_BASIC_WRITE);
}

int API minijail_add_fs_restriction_advanced_rw(struct minijail *j,
						const char *path)
{
	return !add_fs_restriction_path(j, path,
		ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_FULL_WRITE);
}

int API minijail_add_fs_restriction_edit(struct minijail *j,
						const char *path)
{
	return !add_fs_restriction_path(j, path,
		ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_EDIT);
}

static bool is_valid_bind_path(const char *path)
{
	if (!block_symlinks_in_bindmount_paths()) {
		return true;
	}

	/*
	 * tokenize() will modify both the |prefixes| pointer and the contents
	 * of the string, so:
	 * -Copy |BINDMOUNT_ALLOWED_PREFIXES| since it lives in .rodata.
	 * -Save the original pointer for free()ing.
	 */
	char *prefixes = strdup(BINDMOUNT_ALLOWED_PREFIXES);
	attribute_cleanup_str char *orig_prefixes = prefixes;
	(void)orig_prefixes;

	char *prefix = NULL;
	bool found_prefix = false;
	if (!is_canonical_path(path)) {
		while ((prefix = tokenize(&prefixes, ",")) != NULL) {
			if (path_is_parent(prefix, path)) {
				found_prefix = true;
				break;
			}
		}
		if (!found_prefix) {
			/*
			 * If the path does not include one of the allowed
			 * prefixes, fail.
			 */
			warn("path '%s' is not a canonical path", path);
			return false;
		}
	}
	return true;
}

int API minijail_mount_with_data(struct minijail *j, const char *src,
				 const char *dest, const char *type,
				 unsigned long flags, const char *data)
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

	if (!data || !data[0]) {
		/*
		 * Set up secure defaults for certain filesystems.  Adding this
		 * fs-specific logic here kind of sucks, but considering how
		 * people use these in practice, it's probably OK.  If they want
		 * the kernel defaults, they can pass data="" instead of NULL.
		 */
		if (streq(type, "tmpfs")) {
			/* tmpfs defaults to mode=1777 and size=50%. */
			data = "mode=0755,size=10M";
		}
	}
	if (data) {
		m->data = strdup(data);
		if (!m->data)
			goto error;
		m->has_data = 1;
	}

	/* If they don't specify any flags, default to secure ones. */
	if (flags == 0)
		flags = MS_NODEV | MS_NOEXEC | MS_NOSUID;
	m->flags = flags;

	/*
	 * Unless asked to enter an existing namespace, force vfs namespacing
	 * so the mounts don't leak out into the containing vfs namespace.
	 * If Minijail is being asked to enter the root vfs namespace this will
	 * leak mounts, but it's unlikely that the user would ask to do that by
	 * mistake.
	 */
	if (!j->flags.enter_vfs)
		minijail_namespace_vfs(j);

	if (j->mounts_tail)
		j->mounts_tail->next = m;
	else
		j->mounts_head = m;
	j->mounts_tail = m;
	j->mounts_count++;

	return 0;

error:
	free(m->type);
	free(m->src);
	free(m->dest);
	free(m);
	return -ENOMEM;
}

int API minijail_mount(struct minijail *j, const char *src, const char *dest,
		       const char *type, unsigned long flags)
{
	return minijail_mount_with_data(j, src, dest, type, flags, NULL);
}

int API minijail_bind(struct minijail *j, const char *src, const char *dest,
		      int writeable)
{
	unsigned long flags = MS_BIND;

	/*
	 * Check for symlinks in bind-mount source paths to warn the user early.
	 * Minijail will perform one final check immediately before the mount()
	 * call.
	 */
	if (!is_valid_bind_path(src)) {
		warn("src '%s' is not a valid bind mount path", src);
		return -ELOOP;
	}

	/*
	 * Symlinks in |dest| are blocked by the ChromiumOS LSM:
	 * <kernel>/security/chromiumos/lsm.c#77
	 */

	if (!writeable)
		flags |= MS_RDONLY;

	/*
	 * |type| is ignored for bind mounts, use it to signal that this mount
	 * came from minijail_bind().
	 * TODO(b/238362528): Implement a better way to signal this.
	 */
	return minijail_mount(j, src, dest, "minijail_bind", flags);
}

int API minijail_add_remount(struct minijail *j, const char *mount_name,
			     unsigned long remount_mode)
{
	struct minijail_remount *m;

	if (*mount_name != '/')
		return -EINVAL;
	m = calloc(1, sizeof(*m));
	if (!m)
		return -ENOMEM;
	m->mount_name = strdup(mount_name);
	if (!m->mount_name) {
		free(m);
		return -ENOMEM;
	}

	m->remount_mode = remount_mode;

	if (j->remounts_tail)
		j->remounts_tail->next = m;
	else
		j->remounts_head = m;
	j->remounts_tail = m;

	return 0;
}

int API minijail_add_hook(struct minijail *j, minijail_hook_t hook,
			  void *payload, minijail_hook_event_t event)
{
	struct hook *c;

	if (hook == NULL)
		return -EINVAL;
	if (event >= MINIJAIL_HOOK_EVENT_MAX)
		return -EINVAL;
	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->hook = hook;
	c->payload = payload;
	c->event = event;

	if (j->hooks_tail)
		j->hooks_tail->next = c;
	else
		j->hooks_head = c;
	j->hooks_tail = c;

	return 0;
}

int API minijail_preserve_fd(struct minijail *j, int parent_fd, int child_fd)
{
	if (parent_fd < 0 || child_fd < 0)
		return -EINVAL;
	if (j->preserved_fd_count >= MAX_PRESERVED_FDS)
		return -ENOMEM;
	j->preserved_fds[j->preserved_fd_count].parent_fd = parent_fd;
	j->preserved_fds[j->preserved_fd_count].child_fd = child_fd;
	j->preserved_fd_count++;
	return 0;
}

int API minijail_set_preload_path(struct minijail *j, const char *preload_path)
{
	if (j->preload_path)
		return -EINVAL;
	j->preload_path = strdup(preload_path);
	if (!j->preload_path)
		return -ENOMEM;
	return 0;
}

static void clear_seccomp_options(struct minijail *j)
{
	j->flags.seccomp_filter = 0;
	j->flags.seccomp_filter_tsync = 0;
	j->flags.seccomp_filter_logging = 0;
	j->flags.seccomp_filter_allow_speculation = 0;
	j->filter_len = 0;
	j->filter_prog = NULL;
	j->flags.no_new_privs = 0;
	if (j->seccomp_policy_path) {
		free(j->seccomp_policy_path);
	}
	j->seccomp_policy_path = NULL;
}

static int seccomp_should_use_filters(struct minijail *j)
{
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL) == -1) {
		/*
		 * |errno| will be set to EINVAL when seccomp has not been
		 * compiled into the kernel. On certain platforms and kernel
		 * versions this is not a fatal failure. In that case, and only
		 * in that case, disable seccomp and skip loading the filters.
		 */
		if ((errno == EINVAL) && seccomp_can_softfail()) {
			warn("not loading seccomp filters, seccomp filter not "
			     "supported");
			clear_seccomp_options(j);
			return 0;
		}
		/*
		 * If |errno| != EINVAL or seccomp_can_softfail() is false,
		 * we can proceed. Worst case scenario minijail_enter() will
		 * abort() if seccomp fails.
		 */
	}
	if (j->flags.seccomp_filter_tsync) {
		/* Are the seccomp(2) syscall and the TSYNC option supported? */
		if (sys_seccomp(SECCOMP_SET_MODE_FILTER,
				SECCOMP_FILTER_FLAG_TSYNC, NULL) == -1) {
			int saved_errno = errno;
			if (saved_errno == ENOSYS && seccomp_can_softfail()) {
				warn("seccomp(2) syscall not supported");
				clear_seccomp_options(j);
				return 0;
			} else if (saved_errno == EINVAL &&
				   seccomp_can_softfail()) {
				warn(
				    "seccomp filter thread sync not supported");
				clear_seccomp_options(j);
				return 0;
			}
			/*
			 * Similar logic here. If seccomp_can_softfail() is
			 * false, or |errno| != ENOSYS, or |errno| != EINVAL,
			 * we can proceed. Worst case scenario minijail_enter()
			 * will abort() if seccomp or TSYNC fail.
			 */
		}
	}
	if (j->flags.seccomp_filter_allow_speculation) {
		/* Is the SPEC_ALLOW flag supported? */
		if (!seccomp_filter_flags_available(
			SECCOMP_FILTER_FLAG_SPEC_ALLOW)) {
			warn("allowing speculative execution on seccomp "
			     "processes not supported");
			j->flags.seccomp_filter_allow_speculation = 0;
		}
	}
	return 1;
}

static int set_seccomp_filters_internal(struct minijail *j,
					const struct sock_fprog *filter,
					bool owned)
{
	struct sock_fprog *fprog;

	if (owned) {
		/*
		 * If |owned| is true, it's OK to cast away the const-ness since
		 * we'll own the pointer going forward.
		 */
		fprog = (struct sock_fprog *)filter;
	} else {
		fprog = malloc(sizeof(struct sock_fprog));
		if (!fprog)
			return -ENOMEM;
		fprog->len = filter->len;
		fprog->filter = malloc(sizeof(struct sock_filter) * fprog->len);
		if (!fprog->filter) {
			free(fprog);
			return -ENOMEM;
		}
		memcpy(fprog->filter, filter->filter,
		       sizeof(struct sock_filter) * fprog->len);
	}

	if (j->filter_prog) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}

	j->filter_len = fprog->len;
	j->filter_prog = fprog;
	return 0;
}

static int parse_seccomp_filters(struct minijail *j, const char *filename,
				 FILE *policy_file)
{
	struct sock_fprog *fprog = malloc(sizeof(struct sock_fprog));
	if (!fprog)
		return -ENOMEM;

	struct filter_options filteropts;

	/*
	 * Figure out filter options.
	 * Allow logging?
	 */
	filteropts.allow_logging =
	    debug_logging_allowed() && seccomp_is_logging_allowed(j);

	/* What to do on a blocked system call? */
	if (filteropts.allow_logging) {
		if (seccomp_ret_log_available())
			filteropts.action = ACTION_RET_LOG;
		else
			filteropts.action = ACTION_RET_TRAP;
	} else {
		if (j->flags.seccomp_filter_tsync) {
			if (seccomp_ret_kill_process_available()) {
				filteropts.action = ACTION_RET_KILL_PROCESS;
			} else {
				filteropts.action = ACTION_RET_TRAP;
			}
		} else {
			filteropts.action = ACTION_RET_KILL;
		}
	}

	/*
	 * If SECCOMP_RET_LOG is not available, need to allow extra syscalls
	 * for logging.
	 */
	filteropts.allow_syscalls_for_logging =
	    filteropts.allow_logging && !seccomp_ret_log_available();

	/* Whether to fail on duplicate syscalls. */
	filteropts.allow_duplicate_syscalls = allow_duplicate_syscalls();

	if (compile_filter(filename, policy_file, fprog, &filteropts)) {
		free(fprog);
		return -1;
	}

	return set_seccomp_filters_internal(j, fprog, true /* owned */);
}

void API minijail_parse_seccomp_filters(struct minijail *j, const char *path)
{
	if (!seccomp_should_use_filters(j))
		return;

	attribute_cleanup_fp FILE *file = fopen(path, "re");
	if (!file) {
		pdie("failed to open seccomp filter file '%s'", path);
	}

	if (parse_seccomp_filters(j, path, file) != 0) {
		die("failed to compile seccomp filter BPF program in '%s'",
		    path);
	}
	if (j->seccomp_policy_path) {
		free(j->seccomp_policy_path);
	}
	j->seccomp_policy_path = strdup(path);
}

void API minijail_parse_seccomp_filters_from_fd(struct minijail *j, int fd)
{
	char *fd_path, *path;
	attribute_cleanup_fp FILE *file = NULL;

	if (!seccomp_should_use_filters(j))
		return;

	file = fdopen(fd, "r");
	if (!file) {
		pdie("failed to associate stream with fd %d", fd);
	}

	if (asprintf(&fd_path, "/proc/self/fd/%d", fd) == -1)
		pdie("failed to create path for fd %d", fd);
	path = realpath(fd_path, NULL);
	if (path == NULL)
		pwarn("failed to get path of fd %d", fd);
	free(fd_path);

	if (parse_seccomp_filters(j, path ? path : "<fd>", file) != 0) {
		die("failed to compile seccomp filter BPF program from fd %d",
		    fd);
	}
	if (j->seccomp_policy_path) {
		free(j->seccomp_policy_path);
	}
	j->seccomp_policy_path = path;
}

void API minijail_set_seccomp_filters(struct minijail *j,
				      const struct sock_fprog *filter)
{
	if (!seccomp_should_use_filters(j))
		return;

	if (seccomp_is_logging_allowed(j)) {
		die("minijail_log_seccomp_filter_failures() is incompatible "
		    "with minijail_set_seccomp_filters()");
	}

	/*
	 * set_seccomp_filters_internal() can only fail with ENOMEM.
	 * Furthermore, since we won't own the incoming filter, it will not be
	 * modified.
	 */
	if (set_seccomp_filters_internal(j, filter, false /* owned */) < 0) {
		die("failed to set seccomp filter");
	}
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

static void marshal_state_init(struct marshal_state *state, char *buf,
			       size_t available)
{
	state->available = available;
	state->buf = buf;
	state->total = 0;
}

static void marshal_append(struct marshal_state *state, const void *src,
			   size_t length)
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

static void marshal_append_string(struct marshal_state *state, const char *src)
{
	marshal_append(state, src, strlen(src) + 1);
}

static void marshal_mount(struct marshal_state *state,
			  const struct mountpoint *m)
{
	marshal_append(state, m->src, strlen(m->src) + 1);
	marshal_append(state, m->dest, strlen(m->dest) + 1);
	marshal_append(state, m->type, strlen(m->type) + 1);
	marshal_append(state, (char *)&m->has_data, sizeof(m->has_data));
	if (m->has_data)
		marshal_append(state, m->data, strlen(m->data) + 1);
	marshal_append(state, (char *)&m->flags, sizeof(m->flags));
}

static void marshal_fs_rule(struct marshal_state *state,
			    const struct fs_rule *r)
{
	marshal_append(state, r->path, strlen(r->path) + 1);
	marshal_append(state, (char *)&r->landlock_flags,
		       sizeof(r->landlock_flags));
}

static void minijail_marshal_helper(struct marshal_state *state,
				    const struct minijail *j)
{
	struct mountpoint *m = NULL;
	struct fs_rule *r = NULL;
	size_t i;

	marshal_append(state, (char *)j, sizeof(*j));
	if (j->user)
		marshal_append_string(state, j->user);
	if (j->suppl_gid_list) {
		marshal_append(state, j->suppl_gid_list,
			       j->suppl_gid_count * sizeof(gid_t));
	}
	if (j->chrootdir)
		marshal_append_string(state, j->chrootdir);
	if (j->hostname)
		marshal_append_string(state, j->hostname);
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
		marshal_mount(state, m);
	}
	for (i = 0; i < j->cgroup_count; ++i)
		marshal_append_string(state, j->cgroups[i]);
	for (r = j->fs_rules_head; r; r = r->next)
		marshal_fs_rule(state, r);
	if (j->seccomp_policy_path)
		marshal_append_string(state, j->seccomp_policy_path);
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

int minijail_unmarshal(struct minijail *j, char *serialized, size_t length)
{
	size_t i;
	size_t count;
	size_t fs_rules_count;
	int ret = -EINVAL;

	if (length < sizeof(*j))
		goto out;
	memcpy((void *)j, serialized, sizeof(*j));
	serialized += sizeof(*j);
	length -= sizeof(*j);

	/* Potentially stale pointers not used as signals. */
	j->preload_path = NULL;
	j->filename = NULL;
	j->pid_file_path = NULL;
	j->uidmap = NULL;
	j->gidmap = NULL;
	j->mounts_head = NULL;
	j->mounts_tail = NULL;
	j->remounts_head = NULL;
	j->remounts_tail = NULL;
	j->filter_prog = NULL;
	j->hooks_head = NULL;
	j->hooks_tail = NULL;
	j->fs_rules_head = NULL;
	j->fs_rules_tail = NULL;

	if (j->user) { /* stale pointer */
		char *user = consumestr(&serialized, &length);
		if (!user)
			goto clear_pointers;
		j->user = strdup(user);
		if (!j->user)
			goto clear_pointers;
	}

	if (j->suppl_gid_list) { /* stale pointer */
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

	if (j->chrootdir) { /* stale pointer */
		char *chrootdir = consumestr(&serialized, &length);
		if (!chrootdir)
			goto bad_chrootdir;
		j->chrootdir = strdup(chrootdir);
		if (!j->chrootdir)
			goto bad_chrootdir;
	}

	if (j->hostname) { /* stale pointer */
		char *hostname = consumestr(&serialized, &length);
		if (!hostname)
			goto bad_hostname;
		j->hostname = strdup(hostname);
		if (!j->hostname)
			goto bad_hostname;
	}

	if (j->alt_syscall_table) { /* stale pointer */
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
		int *has_data;
		const char *dest;
		const char *type;
		const char *data = NULL;
		const char *src = consumestr(&serialized, &length);
		if (!src)
			goto bad_mounts;
		dest = consumestr(&serialized, &length);
		if (!dest)
			goto bad_mounts;
		type = consumestr(&serialized, &length);
		if (!type)
			goto bad_mounts;
		has_data =
		    consumebytes(sizeof(*has_data), &serialized, &length);
		if (!has_data)
			goto bad_mounts;
		if (*has_data) {
			data = consumestr(&serialized, &length);
			if (!data)
				goto bad_mounts;
		}
		flags = consumebytes(sizeof(*flags), &serialized, &length);
		if (!flags)
			goto bad_mounts;
		if (minijail_mount_with_data(j, src, dest, type, *flags, data))
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

	/* Unmarshal fs_rules. */
	fs_rules_count = j->fs_rules_count;
	j->fs_rules_count = 0;
	for (i = 0; i < fs_rules_count; ++i) {
		const char *path = consumestr(&serialized, &length);
		uint64_t landlock_flags;
		void *landlock_flags_bytes =
		    consumebytes(sizeof(landlock_flags), &serialized, &length);

		if (!path)
			goto bad_fs_rules;
		memcpy(&landlock_flags, landlock_flags_bytes,
		       sizeof(landlock_flags));
		if (!landlock_flags)
			goto bad_fs_rules;
		if (add_fs_restriction_path(j, path, landlock_flags))
			goto bad_fs_rules;
	}

	if (j->seccomp_policy_path) { /* stale pointer */
		char *seccomp_policy_path = consumestr(&serialized, &length);
		if (!seccomp_policy_path)
			goto bad_cgroups;
		j->seccomp_policy_path = strdup(seccomp_policy_path);
		if (!j->seccomp_policy_path)
			goto bad_cgroups;
	}

	return 0;

	/*
	 * If more is added after j->seccomp_policy_path, then this is needed:
	 * if (j->seccomp_policy_path)
	 * 	free(j->seccomp_policy_path);
	 */

bad_cgroups:
	free_mounts_list(j);
	free_remounts_list(j);
	for (i = 0; i < j->cgroup_count; ++i)
		free(j->cgroups[i]);
bad_fs_rules:
	free_fs_rules_list(j);
bad_mounts:
	if (j->filter_prog && j->filter_prog->filter)
		free(j->filter_prog->filter);
bad_filter_prog_instrs:
	if (j->filter_prog)
		free(j->filter_prog);
bad_filters:
	if (j->alt_syscall_table)
		free(j->alt_syscall_table);
bad_syscall_table:
	if (j->hostname)
		free(j->hostname);
bad_hostname:
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
	j->hostname = NULL;
	j->alt_syscall_table = NULL;
	j->cgroup_count = 0;
	j->fs_rules_count = 0;
	j->seccomp_policy_path = NULL;
out:
	return ret;
}

struct dev_spec {
	const char *name;
	mode_t mode;
	dev_t major, minor;
};

// clang-format off
static const struct dev_spec device_nodes[] = {
    {
"null",
	S_IFCHR | 0666, 1, 3,
    },
    {
	"zero",
	S_IFCHR | 0666, 1, 5,
    },
    {
	"full",
	S_IFCHR | 0666, 1, 7,
    },
    {
	"urandom",
	S_IFCHR | 0444, 1, 9,
    },
    {
	"tty",
	S_IFCHR | 0666, 5, 0,
    },
};
// clang-format on

struct dev_sym_spec {
	const char *source, *dest;
};

static const struct dev_sym_spec device_symlinks[] = {
    {
	"ptmx",
	"pts/ptmx",
    },
    {
	"fd",
	"/proc/self/fd",
    },
    {
	"stdin",
	"fd/0",
    },
    {
	"stdout",
	"fd/1",
    },
    {
	"stderr",
	"fd/2",
    },
};

/*
 * Clean up the temporary dev path we had setup previously.  In case of errors,
 * we don't want to go leaking empty tempdirs.
 */
static void mount_dev_cleanup(char *dev_path)
{
	umount2(dev_path, MNT_DETACH);
	rmdir(dev_path);
	free(dev_path);
}

/*
 * Set up the pseudo /dev path at the temporary location.
 * See mount_dev_finalize for more details.
 */
static int mount_dev(char **dev_path_ret)
{
	int ret;
	attribute_cleanup_fd int dev_fd = -1;
	size_t i;
	mode_t mask;
	char *dev_path;

	/*
	 * Create a temp path for the /dev init.  We'll relocate this to the
	 * final location later on in the startup process.
	 */
	dev_path = *dev_path_ret = strdup("/tmp/minijail.dev.XXXXXX");
	if (dev_path == NULL || mkdtemp(dev_path) == NULL)
		pdie("could not create temp path for /dev");

	/* Set up the empty /dev mount point first. */
	ret = mount("minijail-devfs", dev_path, "tmpfs", MS_NOEXEC | MS_NOSUID,
		    "size=5M,mode=755");
	if (ret) {
		rmdir(dev_path);
		return ret;
	}

	/* We want to set the mode directly from the spec. */
	mask = umask(0);

	/* Get a handle to the temp dev path for *at funcs below. */
	dev_fd = open(dev_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
	if (dev_fd < 0) {
		ret = 1;
		goto done;
	}

	/* Create all the nodes in /dev. */
	for (i = 0; i < ARRAY_SIZE(device_nodes); ++i) {
		const struct dev_spec *ds = &device_nodes[i];
		ret = mknodat(dev_fd, ds->name, ds->mode,
			      makedev(ds->major, ds->minor));
		if (ret)
			goto done;
	}

	/* Create all the symlinks in /dev. */
	for (i = 0; i < ARRAY_SIZE(device_symlinks); ++i) {
		const struct dev_sym_spec *ds = &device_symlinks[i];
		ret = symlinkat(ds->dest, dev_fd, ds->source);
		if (ret)
			goto done;
	}

	/* Create empty dir for glibc shared mem APIs. */
	ret = mkdirat(dev_fd, "shm", 01777);
	if (ret)
		goto done;

	/* Restore old mask. */
done:
	umask(mask);

	if (ret)
		mount_dev_cleanup(dev_path);

	return ret;
}

/*
 * Relocate the temporary /dev mount to its final /dev place.
 * We have to do this two step process so people can bind mount extra
 * /dev paths like /dev/log.
 */
static int mount_dev_finalize(const struct minijail *j, char *dev_path)
{
	int ret = -1;
	char *dest = NULL;

	/* Unmount the /dev mount if possible. */
	if (umount2("/dev", MNT_DETACH))
		goto done;

	if (asprintf(&dest, "%s/dev", j->chrootdir ?: "") < 0)
		goto done;

	if (mount(dev_path, dest, NULL, MS_MOVE, NULL))
		goto done;

	ret = 0;
done:
	free(dest);
	mount_dev_cleanup(dev_path);

	return ret;
}

/*
 * mount_one: Applies mounts from @m for @j, recursing as needed.
 * @j Minijail these mounts are for
 * @m Head of list of mounts
 *
 * Returns 0 for success.
 */
static int mount_one(const struct minijail *j, struct mountpoint *m,
		     const char *dev_path)
{
	int ret;
	char *dest;
	bool do_remount = false;
	bool has_bind_flag = mount_has_bind_flag(m);
	bool has_remount_flag = !!(m->flags & MS_REMOUNT);
	unsigned long original_mnt_flags = 0;

	/* We assume |dest| has a leading "/". */
	if (dev_path && strncmp("/dev/", m->dest, 5) == 0) {
		/*
		 * Since the temp path is rooted at /dev, skip that dest part.
		 */
		if (asprintf(&dest, "%s%s", dev_path, m->dest + 4) < 0)
			return -ENOMEM;
	} else {
		if (asprintf(&dest, "%s%s", j->chrootdir ?: "", m->dest) < 0)
			return -ENOMEM;
	}

	ret = setup_mount_destination(m->src, dest, j->uid, j->gid,
				      has_bind_flag);
	if (ret) {
		warn("cannot create mount target '%s'", dest);
		goto error;
	}

	/*
	 * Remount bind mounts that:
	 * - Come from the minijail_bind() API, and
	 * - Add the 'ro' flag
	 * since 'bind' and other flags can't both be specified in the same
	 * mount(2) call.
	 * Callers using minijail_mount() to perform bind mounts are expected to
	 * know what they're doing and call minijail_mount() with MS_REMOUNT as
	 * needed.
	 * Therefore, if the caller is asking for a remount (using MS_REMOUNT),
	 * there is no need to do an extra remount here.
	 */
	if (has_bind_flag && strcmp(m->type, "minijail_bind") == 0 &&
	    !has_remount_flag) {
		/*
		 * Grab the mount flags of the source. These are used to figure
		 * out whether the bind mount needs to be remounted read-only.
		 */
		if (get_mount_flags(m->src, &original_mnt_flags)) {
			warn("cannot get mount flags for '%s'", m->src);
			goto error;
		}

		if ((m->flags & MS_RDONLY) !=
		    (original_mnt_flags & MS_RDONLY)) {
			do_remount = 1;
			/*
			 * Restrict the mount flags to those that are
			 * user-settable in a MS_REMOUNT request, but excluding
			 * MS_RDONLY. The user-requested mount flags will
			 * dictate whether the remount will have that flag or
			 * not.
			 */
			original_mnt_flags &=
			    (MS_USER_SETTABLE_MASK & ~MS_RDONLY);
		}
	}

	/*
	 * Do a final check for symlinks in |m->src|.
	 * |m->src| will only contain a valid path when purely bind-mounting
	 * (but not when remounting a bind mount).
	 *
	 * Short of having a version of mount(2) that can take fd's, this is the
	 * smallest we can make the TOCTOU window.
	 */
	if (has_bind_flag && !has_remount_flag && !is_valid_bind_path(m->src)) {
		warn("src '%s' is not a valid bind mount path", m->src);
		goto error;
	}

	ret = mount(m->src, dest, m->type, m->flags, m->data);
	if (ret) {
		pwarn("cannot mount '%s' as '%s' with flags %#lx", m->src, dest,
		      m->flags);
		goto error;
	}

	/* Remount *after* the initial mount. */
	if (do_remount) {
		ret =
		    mount(m->src, dest, NULL,
			  m->flags | original_mnt_flags | MS_REMOUNT, m->data);
		if (ret) {
			pwarn(
			    "cannot bind-remount '%s' as '%s' with flags %#lx",
			    m->src, dest,
			    m->flags | original_mnt_flags | MS_REMOUNT);
			goto error;
		}
	}

	free(dest);
	if (m->next)
		return mount_one(j, m->next, dev_path);
	return 0;

error:
	free(dest);
	return ret;
}

static void process_mounts_or_die(const struct minijail *j)
{
	/*
	 * We have to mount /dev first in case there are bind mounts from
	 * the original /dev into the new unique tmpfs one.
	 */
	char *dev_path = NULL;
	if (j->flags.mount_dev && mount_dev(&dev_path))
		pdie("mount_dev failed");

	if (j->mounts_head && mount_one(j, j->mounts_head, dev_path)) {
		warn("mount_one failed with /dev at '%s'", dev_path);

		if (dev_path)
			mount_dev_cleanup(dev_path);

		_exit(MINIJAIL_ERR_MOUNT);
	}

	/*
	 * Once all bind mounts have been processed, move the temp dev to
	 * its final /dev home.
	 */
	if (j->flags.mount_dev && mount_dev_finalize(j, dev_path))
		pdie("mount_dev_finalize failed");
}

static int enter_chroot(const struct minijail *j)
{
	run_hooks_or_die(j, MINIJAIL_HOOK_EVENT_PRE_CHROOT);

	if (chroot(j->chrootdir))
		return -errno;

	if (chdir("/"))
		return -errno;

	return 0;
}

static int enter_pivot_root(const struct minijail *j)
{
	attribute_cleanup_fd int oldroot = -1;
	attribute_cleanup_fd int newroot = -1;

	run_hooks_or_die(j, MINIJAIL_HOOK_EVENT_PRE_CHROOT);

	/*
	 * Keep the fd for both old and new root.
	 * It will be used in fchdir(2) later.
	 */
	oldroot = open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (oldroot < 0)
		pdie("failed to open / for fchdir");
	newroot = open(j->chrootdir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (newroot < 0)
		pdie("failed to open %s for fchdir", j->chrootdir);

	/*
	 * To ensure j->chrootdir is the root of a filesystem,
	 * do a self bind mount.
	 */
	if (mount(j->chrootdir, j->chrootdir, "bind", MS_BIND | MS_REC, ""))
		pdie("failed to bind mount '%s'", j->chrootdir);
	if (chdir(j->chrootdir))
		return -errno;
	if (syscall(SYS_pivot_root, ".", "."))
		pdie("pivot_root");

	/*
	 * Now the old root is mounted on top of the new root. Use fchdir(2) to
	 * change to the old root and unmount it.
	 */
	if (fchdir(oldroot))
		pdie("failed to fchdir to old /");

	/*
	 * If skip_remount_private was enabled for minijail_enter(),
	 * there could be a shared mount point under |oldroot|. In that case,
	 * mounts under this shared mount point will be unmounted below, and
	 * this unmounting will propagate to the original mount namespace
	 * (because the mount point is shared). To prevent this unexpected
	 * unmounting, remove these mounts from their peer groups by recursively
	 * remounting them as MS_PRIVATE.
	 */
	if (mount(NULL, ".", NULL, MS_REC | MS_PRIVATE, NULL))
		pdie("failed to mount(/, private) before umount(/)");
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

static int mount_tmp(const struct minijail *j)
{
	const char fmt[] = "size=%zu,mode=1777";
	/* Count for the user storing ULLONG_MAX literally + extra space. */
	char data[sizeof(fmt) + sizeof("18446744073709551615ULL")];
	int ret;

	ret = snprintf(data, sizeof(data), fmt, j->tmpfs_size);

	if (ret <= 0)
		pdie("tmpfs size spec error");
	else if ((size_t)ret >= sizeof(data))
		pdie("tmpfs size spec too large");

	unsigned long flags = MS_NODEV | MS_NOEXEC | MS_NOSUID;

	if (block_symlinks_in_noninit_mountns_tmp()) {
		flags |= MS_NOSYMFOLLOW;
	}

	return mount("none", "/tmp", "tmpfs", flags, data);
}

static int remount_proc_readonly(const struct minijail *j)
{
	const char *kProcPath = "/proc";
	const unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;
	/*
	 * Right now, we're holding a reference to our parent's old mount of
	 * /proc in our namespace, which means using MS_REMOUNT here would
	 * mutate our parent's mount as well, even though we're in a VFS
	 * namespace (!). Instead, remove their mount from our namespace lazily
	 * (MNT_DETACH) and make our own.
	 *
	 * However, we skip this in the user namespace case because it will
	 * invariably fail. Every mount namespace is "owned" by the
	 * user namespace of the process that creates it. Mount namespace A is
	 * "less privileged" than mount namespace B if A is created off of B,
	 * and B is owned by a different user namespace.
	 * When a less privileged mount namespace is created, the mounts used to
	 * initialize it (coming from the more privileged mount namespace) come
	 * as a unit, and are locked together. This means that code running in
	 * the new mount (and user) namespace cannot piecemeal unmount
	 * individual mounts inherited from a more privileged mount namespace.
	 * See https://man7.org/linux/man-pages/man7/mount_namespaces.7.html,
	 * "Restrictions on mount namespaces" for details.
	 *
	 * This happens in our use case because we first enter a new user
	 * namespace (on clone(2)) and then we unshare(2) a new mount namespace,
	 * which means the new mount namespace is less privileged than its
	 * parent mount namespace. This would also happen if we entered a new
	 * mount namespace on clone(2), since the user namespace is created
	 * first.
	 * In all other non-user-namespace cases the new mount namespace is
	 * similarly privileged as the parent mount namespace so unmounting a
	 * single mount is allowed.
	 *
	 * We still remount /proc as read-only in the user namespace case
	 * because while a process with CAP_SYS_ADMIN in the new user namespace
	 * can unmount the RO mount and get at the RW mount, an attacker with
	 * access only to a write primitive will not be able to modify /proc.
	 */
	if (!j->flags.userns && umount2(kProcPath, MNT_DETACH))
		return -errno;
	if (mount("proc", kProcPath, "proc", kSafeFlags | MS_RDONLY, ""))
		return -errno;
	return 0;
}

static void kill_child_and_die(const struct minijail *j, const char *msg)
{
	kill(j->initpid, SIGKILL);
	die("%s", msg);
}

static void write_pid_file_or_die(const struct minijail *j)
{
	if (write_pid_to_path(j->initpid, j->pid_file_path))
		kill_child_and_die(j, "failed to write pid file");
}

static void add_to_cgroups_or_die(const struct minijail *j)
{
	size_t i;

	for (i = 0; i < j->cgroup_count; ++i) {
		if (write_pid_to_path(j->initpid, j->cgroups[i]))
			kill_child_and_die(j, "failed to add to cgroups");
	}
}

static void set_rlimits_or_die(const struct minijail *j)
{
	size_t i;

	for (i = 0; i < j->rlimit_count; ++i) {
		struct rlimit limit;
		limit.rlim_cur = j->rlimits[i].cur;
		limit.rlim_max = j->rlimits[i].max;
		if (prlimit(j->initpid, j->rlimits[i].type, &limit, NULL))
			kill_child_and_die(j, "failed to set rlimit");
	}
}

static void write_ugid_maps_or_die(const struct minijail *j)
{
	if (j->uidmap && write_proc_file(j->initpid, j->uidmap, "uid_map") != 0)
		kill_child_and_die(j, "failed to write uid_map");
	if (j->gidmap && j->flags.disable_setgroups) {
		/*
		 * Older kernels might not have the /proc/<pid>/setgroups files.
		 */
		int ret = write_proc_file(j->initpid, "deny", "setgroups");
		if (ret != 0) {
			if (ret == -ENOENT) {
				/*
				 * See
				 * http://man7.org/linux/man-pages/man7/user_namespaces.7.html.
				 */
				warn("could not disable setgroups(2)");
			} else
				kill_child_and_die(
				    j, "failed to disable setgroups(2)");
		}
	}
	if (j->gidmap && write_proc_file(j->initpid, j->gidmap, "gid_map") != 0)
		kill_child_and_die(j, "failed to write gid_map");
}

static void enter_user_namespace(const struct minijail *j)
{
	int uid = j->flags.uid ? j->uid : 0;
	int gid = j->flags.gid ? j->gid : 0;
	if (j->gidmap && setresgid(gid, gid, gid)) {
		pdie("user_namespaces: setresgid(%d, %d, %d) failed", gid, gid,
		     gid);
	}
	if (j->uidmap && setresuid(uid, uid, uid)) {
		pdie("user_namespaces: setresuid(%d, %d, %d) failed", uid, uid,
		     uid);
	}
}

static void parent_setup_complete(int *pipe_fds)
{
	close_and_reset(&pipe_fds[0]);
	close_and_reset(&pipe_fds[1]);
}

/*
 * wait_for_parent_setup: Called by the child process to wait for any
 * further parent-side setup to complete before continuing.
 */
static void wait_for_parent_setup(int *pipe_fds)
{
	char buf;

	close_and_reset(&pipe_fds[1]);

	/* Wait for parent to complete setup and close the pipe. */
	if (read(pipe_fds[0], &buf, 1) != 0)
		die("failed to sync with parent");
	close_and_reset(&pipe_fds[0]);
}

static void drop_ugid(const struct minijail *j)
{
	if (j->flags.inherit_suppl_gids + j->flags.keep_suppl_gids +
		j->flags.set_suppl_gids >
	    1) {
		die("can only do one of inherit, keep, or set supplementary "
		    "groups");
	}

	if (j->flags.inherit_suppl_gids) {
		if (initgroups(j->user, j->usergid))
			pdie("initgroups(%s, %d) failed", j->user, j->usergid);
	} else if (j->flags.set_suppl_gids) {
		if (setgroups(j->suppl_gid_count, j->suppl_gid_list))
			pdie("setgroups(suppl_gids) failed");
	} else if (!j->flags.keep_suppl_gids && !j->flags.disable_setgroups) {
		/*
		 * Only attempt to clear supplementary groups if we are changing
		 * users or groups, and if the caller did not request to disable
		 * setgroups (used when entering a user namespace as a
		 * non-privileged user).
		 */
		if ((j->flags.uid || j->flags.gid) && setgroups(0, NULL))
			pdie("setgroups(0, NULL) failed");
	}

	if (j->flags.gid && setresgid(j->gid, j->gid, j->gid))
		pdie("setresgid(%d, %d, %d) failed", j->gid, j->gid, j->gid);

	if (j->flags.uid && setresuid(j->uid, j->uid, j->uid))
		pdie("setresuid(%d, %d, %d) failed", j->uid, j->uid, j->uid);
}

static void drop_capbset(uint64_t keep_mask, unsigned int last_valid_cap)
{
	const uint64_t one = 1;
	unsigned int i;
	for (i = 0; i < sizeof(keep_mask) * 8 && i <= last_valid_cap; ++i) {
		if (keep_mask & (one << i))
			continue;
		if (prctl(PR_CAPBSET_DROP, i))
			pdie("could not drop capability from bounding set");
	}
}

static void drop_caps(const struct minijail *j, unsigned int last_valid_cap)
{
	if (!j->flags.use_caps)
		return;

	cap_t caps = cap_get_proc();
	cap_value_t flag[1];
	const size_t ncaps = sizeof(j->caps) * 8;
	const uint64_t one = 1;
	unsigned int i;
	if (!caps)
		die("can't get process caps");
	if (cap_clear(caps))
		die("can't clear caps");

	for (i = 0; i < ncaps && i <= last_valid_cap; ++i) {
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
	 * Instead of dropping the bounding set first, do it here in case
	 * the caller had a more permissive bounding set which could
	 * have been used above to raise a capability that wasn't already
	 * present. This requires CAP_SETPCAP, so we raised/kept it above.
	 *
	 * However, if we're asked to skip setting *and* locking the
	 * SECURE_NOROOT securebit, also skip dropping the bounding set.
	 * If the caller wants to regain all capabilities when executing a
	 * set-user-ID-root program, allow them to do so. The default behavior
	 * (i.e. the behavior without |securebits_skip_mask| set) will still put
	 * the jailed process tree in a capabilities-only environment.
	 *
	 * We check the negated skip mask for SECURE_NOROOT and
	 * SECURE_NOROOT_LOCKED. If the bits are set in the negated mask they
	 * will *not* be skipped in lock_securebits(), and therefore we should
	 * drop the bounding set.
	 */
	if (secure_noroot_set_and_locked(~j->securebits_skip_mask)) {
		drop_capbset(j->caps, last_valid_cap);
	} else {
		warn("SECURE_NOROOT not set, not dropping bounding set");
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

	/*
	 * If ambient capabilities are supported, clear all capabilities first,
	 * then raise the requested ones.
	 */
	if (j->flags.set_ambient_caps) {
		if (!cap_ambient_supported()) {
			pdie("ambient capabilities not supported");
		}
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) !=
		    0) {
			pdie("can't clear ambient capabilities");
		}

		for (i = 0; i < ncaps && i <= last_valid_cap; ++i) {
			if (!(j->caps & (one << i)))
				continue;

			if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0,
				  0) != 0) {
				pdie("prctl(PR_CAP_AMBIENT, "
				     "PR_CAP_AMBIENT_RAISE, %u) failed",
				     i);
			}
		}
	}

	cap_free(caps);
}

/* Creates a ruleset for current inodes then calls landlock_restrict_self(). */
static void apply_landlock_restrictions(const struct minijail *j)
{
	struct fs_rule *r;
	attribute_cleanup_fd int ruleset_fd = -1;

	r = j->fs_rules_head;
	while (r) {
		if (ruleset_fd < 0) {
			struct minijail_landlock_ruleset_attr ruleset_attr = {
				.handled_access_fs = HANDLED_ACCESS_TYPES
			};
			ruleset_fd = landlock_create_ruleset(
				&ruleset_attr, sizeof(ruleset_attr), 0);
			if (ruleset_fd < 0) {
				const int err = errno;
				pwarn("failed to create a ruleset");
				switch (err) {
				case ENOSYS:
					pwarn("Landlock is not supported by the current kernel");
					break;
				case EOPNOTSUPP:
					pwarn("Landlock is currently disabled by kernel config");
					break;
				}
				return;
			}
		}
		populate_ruleset_internal(r->path, ruleset_fd, r->landlock_flags);
		r = r->next;
	}

	if (ruleset_fd >= 0) {
		if (j->filename != NULL) {
			info("applying Landlock to process %s", j->filename);
		}
		if (landlock_restrict_self(ruleset_fd, 0)) {
			pdie("failed to enforce ruleset");
		}
	}
}

static void set_no_new_privs(const struct minijail *j) {
	if (j->flags.no_new_privs) {
		if (!sys_set_no_new_privs()) {
			die("set_no_new_privs() failed");
		}
	}
}

static void set_seccomp_filter(const struct minijail *j)
{
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
		warn("running with (HW)ASan, not setting seccomp filter");
		return;
	}

	if (j->flags.seccomp_filter) {
		if (seccomp_is_logging_allowed(j)) {
			warn("logging seccomp filter failures");
			if (!seccomp_ret_log_available()) {
				/*
				 * If SECCOMP_RET_LOG is not available,
				 * install the SIGSYS handler first.
				 */
				if (install_sigsys_handler())
					pdie(
					    "failed to install SIGSYS handler");
			}
		} else if (j->flags.seccomp_filter_tsync) {
			/*
			 * If setting thread sync,
			 * reset the SIGSYS signal handler so that
			 * the entire thread group is killed.
			 */
			if (signal(SIGSYS, SIG_DFL) == SIG_ERR)
				pdie("failed to reset SIGSYS disposition");
		}
	}

	/*
	 * Install the syscall filter.
	 */
	if (j->flags.seccomp_filter) {
		if (j->flags.seccomp_filter_tsync ||
		    j->flags.seccomp_filter_allow_speculation) {
			int filter_flags =
			    (j->flags.seccomp_filter_tsync
				 ? SECCOMP_FILTER_FLAG_TSYNC
				 : 0) |
			    (j->flags.seccomp_filter_allow_speculation
				 ? SECCOMP_FILTER_FLAG_SPEC_ALLOW
				 : 0);
			if (sys_seccomp(SECCOMP_SET_MODE_FILTER, filter_flags,
					j->filter_prog)) {
				pdie("seccomp(tsync) failed");
			}
		} else {
			if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
				  j->filter_prog)) {
				pdie("prctl(seccomp_filter) failed");
			}
		}
	}
}

static pid_t forward_pid = -1;

static void forward_signal(int sig, siginfo_t *siginfo attribute_unused,
			   void *void_context attribute_unused)
{
	if (forward_pid != -1) {
		kill(forward_pid, sig);
	}
}

static void install_signal_handlers(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &forward_signal;
	act.sa_flags = SA_SIGINFO | SA_RESTART;

	/* Handle all signals, except SIGCHLD. */
	for (int sig = 1; sig < NSIG; sig++) {
		/*
		 * We don't care if we get EINVAL: that just means that we
		 * can't handle this signal, so let's skip it and continue.
		 */
		sigaction(sig, &act, NULL);
	}
	/* Reset SIGCHLD's handler. */
	signal(SIGCHLD, SIG_DFL);

	/* Handle real-time signals. */
	for (int sig = SIGRTMIN; sig <= SIGRTMAX; sig++) {
		sigaction(sig, &act, NULL);
	}
}

static const char *lookup_hook_name(minijail_hook_event_t event)
{
	switch (event) {
	case MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS:
		return "pre-drop-caps";
	case MINIJAIL_HOOK_EVENT_PRE_EXECVE:
		return "pre-execve";
	case MINIJAIL_HOOK_EVENT_PRE_CHROOT:
		return "pre-chroot";
	case MINIJAIL_HOOK_EVENT_MAX:
		/*
		 * Adding this in favor of a default case to force the
		 * compiler to error out if a new enum value is added.
		 */
		break;
	}
	return "unknown";
}

static void run_hooks_or_die(const struct minijail *j,
			     minijail_hook_event_t event)
{
	int rc;
	int hook_index = 0;
	for (struct hook *c = j->hooks_head; c; c = c->next) {
		if (c->event != event)
			continue;
		rc = c->hook(c->payload);
		if (rc != 0) {
			errno = -rc;
			pdie("%s hook (index %d) failed",
			     lookup_hook_name(event), hook_index);
		}
		/* Only increase the index within the same hook event type. */
		++hook_index;
	}
}

void API minijail_enter(const struct minijail *j)
{
	/*
	 * If we're dropping caps, get the last valid cap from /proc now,
	 * since /proc can be unmounted before drop_caps() is called.
	 */
	unsigned int last_valid_cap = 0;
	if (j->flags.capbset_drop || j->flags.use_caps)
		last_valid_cap = get_last_valid_cap();

	if (j->flags.pids)
		die("tried to enter a pid-namespaced jail;"
		    " try minijail_run()?");

	if (j->flags.inherit_suppl_gids && !j->user)
		die("cannot inherit supplementary groups without setting a "
		    "username");

	/*
	 * We can't recover from failures if we've dropped privileges partially,
	 * so we don't even try. If any of our operations fail, we abort() the
	 * entire process.
	 */
	if (j->flags.enter_vfs) {
		if (setns(j->mountns_fd, CLONE_NEWNS))
			pdie("setns(CLONE_NEWNS) failed");
		close(j->mountns_fd);
	}

	if (j->flags.vfs) {
		if (unshare(CLONE_NEWNS))
			pdie("unshare(CLONE_NEWNS) failed");
		/*
		 * By default, remount all filesystems as private, unless
		 * - Passed a specific remount mode, in which case remount with
		 *   that,
		 * - Asked not to remount at all, in which case skip the
		 *   mount(2) call.
		 * https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt
		 */
		if (j->remount_mode) {
			if (mount(NULL, "/", NULL, MS_REC | j->remount_mode,
				  NULL))
				pdie("mount(NULL, /, NULL, "
				     "MS_REC | j->remount_mode, NULL) failed");

			struct minijail_remount *temp = j->remounts_head;
			while (temp) {
				if (temp->remount_mode < j->remount_mode)
					die("cannot remount %s as stricter "
					    "than the root dir",
					    temp->mount_name);
				if (mount(NULL, temp->mount_name, NULL,
					  MS_REC | temp->remount_mode, NULL))
					pdie("mount(NULL, %s, NULL, "
					     "MS_REC | temp->remount_mode, "
					     "NULL) failed",
					     temp->mount_name);
				temp = temp->next;
			}
		}
	}

	if (j->flags.ipc && unshare(CLONE_NEWIPC)) {
		pdie("unshare(CLONE_NEWIPC) failed");
	}

	if (j->flags.uts) {
		if (unshare(CLONE_NEWUTS))
			pdie("unshare(CLONE_NEWUTS) failed");

		if (j->hostname &&
		    sethostname(j->hostname, strlen(j->hostname)))
			pdie("sethostname(%s) failed", j->hostname);
	}

	if (j->flags.enter_net) {
		if (setns(j->netns_fd, CLONE_NEWNET))
			pdie("setns(CLONE_NEWNET) failed");
		close(j->netns_fd);
	} else if (j->flags.net) {
		if (unshare(CLONE_NEWNET))
			pdie("unshare(CLONE_NEWNET) failed");
		config_net_loopback();
	}

	if (j->flags.ns_cgroups && unshare(CLONE_NEWCGROUP))
		pdie("unshare(CLONE_NEWCGROUP) failed");

	if (j->flags.new_session_keyring) {
		if (syscall(SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING, NULL) < 0)
			pdie("keyctl(KEYCTL_JOIN_SESSION_KEYRING) failed");
	}

	/* We have to process all the mounts before we chroot/pivot_root. */
	process_mounts_or_die(j);

	if (j->flags.chroot && enter_chroot(j))
		pdie("chroot");

	if (j->flags.pivot_root && enter_pivot_root(j))
		pdie("pivot_root");

	if (j->flags.mount_tmp && mount_tmp(j))
		pdie("mount_tmp");

	if (j->flags.remount_proc_ro && remount_proc_readonly(j))
		pdie("remount");

	run_hooks_or_die(j, MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS);

	/*
	 * If we're only dropping capabilities from the bounding set, but not
	 * from the thread's (permitted|inheritable|effective) sets, do it now.
	 */
	if (j->flags.capbset_drop) {
		drop_capbset(j->cap_bset, last_valid_cap);
	}

	/*
	 * POSIX capabilities are a bit tricky. We must set SECBIT_KEEP_CAPS
	 * before drop_ugid() below as the latter would otherwise drop all
	 * capabilities.
	 */
	if (j->flags.use_caps) {
		/*
		 * When using ambient capabilities, CAP_SET{GID,UID} can be
		 * inherited across execve(2), so SECBIT_KEEP_CAPS is not
		 * strictly needed.
		 */
		bool require_keep_caps = !j->flags.set_ambient_caps;
		if (lock_securebits(j->securebits_skip_mask,
				    require_keep_caps) < 0) {
			pdie("locking securebits failed");
		}
	}

	if (j->flags.no_new_privs) {
		/*
		 * If we're setting no_new_privs, we can drop privileges
		 * before setting seccomp filter. This way filter policies
		 * don't need to allow privilege-dropping syscalls.
		 */
		drop_ugid(j);
		drop_caps(j, last_valid_cap);

		/*
		 * Landlock is applied as late as possible. If no_new_privs is
		 * requested, then we need to set that first because the
		 * landlock_restrict_self() syscall has a seccomp(2) like check
		 * for that. See:
		 * https://elixir.bootlin.com/linux/v5.15.74/source/security/landlock/syscalls.c#L409
		 */
		set_no_new_privs(j);
		apply_landlock_restrictions(j);
		set_seccomp_filter(j);
	} else {
		apply_landlock_restrictions(j);

		/*
		 * If we're not setting no_new_privs,
		 * we need to set seccomp filter *before* dropping privileges.
		 * WARNING: this means that filter policies *must* allow
		 * setgroups()/setresgid()/setresuid() for dropping root and
		 * capget()/capset()/prctl() for dropping caps.
		 */
		set_seccomp_filter(j);
		drop_ugid(j);
		drop_caps(j, last_valid_cap);
	}

	/*
	 * Select the specified alternate syscall table.  The table must not
	 * block prctl(2) if we're using seccomp as well.
	 */
	if (j->flags.alt_syscall) {
		if (prctl(PR_ALT_SYSCALL, 1, j->alt_syscall_table))
			pdie("prctl(PR_ALT_SYSCALL) failed");
	}

	/*
	 * seccomp has to come last since it cuts off all the other
	 * privilege-dropping syscalls :)
	 */
	if (j->flags.seccomp && prctl(PR_SET_SECCOMP, 1)) {
		if ((errno == EINVAL) && seccomp_can_softfail()) {
			warn("seccomp not supported");
			return;
		}
		pdie("prctl(PR_SET_SECCOMP) failed");
	}
}

/* TODO(wad): will visibility affect this variable? */
static int init_exitstatus = 0;

static void init_term(int sig attribute_unused)
{
	_exit(init_exitstatus);
}

static void init(pid_t rootpid)
{
	pid_t pid;
	int status;
	/* So that we exit with the right status. */
	signal(SIGTERM, init_term);
	/* TODO(wad): self jail with seccomp filters here. */
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
	attribute_cleanup_str char *buf = NULL;
	int r;
	if (sizeof(sz) != bytes)
		return -EINVAL;
	if (sz > USHRT_MAX) /* arbitrary check */
		return -E2BIG;
	buf = malloc(sz);
	if (!buf)
		return -ENOMEM;
	bytes = read(fd, buf, sz);
	if (bytes != sz)
		return -EINVAL;
	r = minijail_unmarshal(j, buf, sz);
	return r;
}

int API minijail_to_fd(struct minijail *j, int fd)
{
	size_t sz = minijail_size(j);
	if (!sz)
		return -EINVAL;

	attribute_cleanup_str char *buf = malloc(sz);
	if (!buf)
		return -ENOMEM;

	int err = minijail_marshal(j, buf, sz);
	if (err)
		return err;

	/* Sends [size][minijail]. */
	err = write_exactly(fd, &sz, sizeof(sz));
	if (err)
		return err;

	return write_exactly(fd, buf, sz);
}

int API minijail_copy_jail(const struct minijail *from, struct minijail *out)
{
	size_t sz = minijail_size(from);
	if (!sz)
		return -EINVAL;

	attribute_cleanup_str char *buf = malloc(sz);
	if (!buf)
		return -ENOMEM;

	int err = minijail_marshal(from, buf, sz);
	if (err)
		return err;

	return minijail_unmarshal(out, buf, sz);
}

static int setup_preload(const struct minijail *j attribute_unused,
			 char ***child_env attribute_unused)
{
#if defined(__ANDROID__)
	/* Don't use LDPRELOAD on Android. */
	return 0;
#else
	const char *preload_path = j->preload_path ?: PRELOADPATH;
	char *newenv = NULL;
	int ret = 0;
	const char *oldenv = minijail_getenv(*child_env, kLdPreloadEnvVar);

	if (!oldenv)
		oldenv = "";

	/* Only insert a separating space if we have something to separate... */
	if (asprintf(&newenv, "%s%s%s", oldenv, oldenv[0] != '\0' ? " " : "",
		     preload_path) < 0) {
		return -1;
	}

	ret = minijail_setenv(child_env, kLdPreloadEnvVar, newenv, 1);
	free(newenv);
	return ret;
#endif
}

/*
 * This is for logging purposes and does not change the enforced seccomp
 * filter.
 */
static int setup_seccomp_policy_path(const struct minijail *j,
				     char ***child_env)
{
	return minijail_setenv(child_env, kSeccompPolicyPathEnvVar,
			       j->seccomp_policy_path ? j->seccomp_policy_path
						      : "NO-LABEL",
			       1 /* overwrite */);
}

static int setup_pipe(char ***child_env, int fds[2])
{
	int r = pipe(fds);
	char fd_buf[11];
	if (r)
		return r;
	r = snprintf(fd_buf, sizeof(fd_buf), "%d", fds[0]);
	if (r <= 0)
		return -EINVAL;
	return minijail_setenv(child_env, kFdEnvVar, fd_buf, 1);
}

static int close_open_fds(int *inheritable_fds, size_t size)
{
	const char *kFdPath = "/proc/self/fd";

	DIR *d = opendir(kFdPath);
	struct dirent *dir_entry;

	if (d == NULL)
		return -1;
	int dir_fd = dirfd(d);
	while ((dir_entry = readdir(d)) != NULL) {
		size_t i;
		char *end;
		bool should_close = true;
		const int fd = strtol(dir_entry->d_name, &end, 10);

		if ((*end) != '\0') {
			continue;
		}
		/*
		 * We might have set up some pipes that we want to share with
		 * the parent process, and should not be closed.
		 */
		for (i = 0; i < size; ++i) {
			if (fd == inheritable_fds[i]) {
				should_close = false;
				break;
			}
		}
		/* Also avoid closing the directory fd. */
		if (should_close && fd != dir_fd)
			close(fd);
	}
	closedir(d);
	return 0;
}

/* Return true if the specified file descriptor is already open. */
static int fd_is_open(int fd)
{
	return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

static_assert(FD_SETSIZE >= MAX_PRESERVED_FDS * 2 - 1,
	      "If true, ensure_no_fd_conflict will always find an unused fd.");

/* If parent_fd will be used by a child fd, move it to an unused fd. */
static int ensure_no_fd_conflict(const fd_set *child_fds, int child_fd,
				 int *parent_fd)
{
	if (!FD_ISSET(*parent_fd, child_fds)) {
		return 0;
	}

	/*
	 * If no other parent_fd matches the child_fd then use it instead of a
	 * temporary.
	 */
	int fd = child_fd;
	if (fd == -1 || fd_is_open(fd)) {
		fd = FD_SETSIZE - 1;
		while (FD_ISSET(fd, child_fds) || fd_is_open(fd)) {
			--fd;
			if (fd < 0) {
				die("failed to find an unused fd");
			}
		}
	}

	int ret = dup2(*parent_fd, fd);
	/*
	 * warn() opens a file descriptor so it needs to happen after dup2 to
	 * avoid unintended side effects. This can be avoided by reordering the
	 * mapping requests so that the source fds with overlap are mapped
	 * first (unless there are cycles).
	 */
	warn("mapped fd overlap: moving %d to %d", *parent_fd, fd);
	if (ret == -1) {
		return -1;
	}

	*parent_fd = fd;
	return 0;
}

/*
 * Populate child_fds_out with the set of file descriptors that will be replaced
 * by redirect_fds().
 *
 * NOTE: This creates temporaries for parent file descriptors that would
 * otherwise be overwritten during redirect_fds().
 */
static int get_child_fds(struct minijail *j, fd_set *child_fds_out)
{
	/* Relocate parent_fds that would be replaced by a child_fd. */
	for (size_t i = 0; i < j->preserved_fd_count; i++) {
		int child_fd = j->preserved_fds[i].child_fd;
		if (FD_ISSET(child_fd, child_fds_out)) {
			die("fd %d is mapped more than once", child_fd);
		}

		int *parent_fd = &j->preserved_fds[i].parent_fd;
		if (ensure_no_fd_conflict(child_fds_out, child_fd, parent_fd) ==
		    -1) {
			return -1;
		}

		FD_SET(child_fd, child_fds_out);
	}
	return 0;
}

/*
 * Structure holding resources and state created when running a minijail.
 */
struct minijail_run_state {
	pid_t child_pid;
	int pipe_fds[2];
	int stdin_fds[2];
	int stdout_fds[2];
	int stderr_fds[2];
	int child_sync_pipe_fds[2];
	char **child_env;
};

/*
 * Move pipe_fds if they conflict with a child_fd.
 */
static int avoid_pipe_conflicts(struct minijail_run_state *state,
				fd_set *child_fds_out)
{
	int *pipe_fds[] = {
	    state->pipe_fds,   state->child_sync_pipe_fds, state->stdin_fds,
	    state->stdout_fds, state->stderr_fds,
	};
	for (size_t i = 0; i < ARRAY_SIZE(pipe_fds); ++i) {
		if (pipe_fds[i][0] != -1 &&
		    ensure_no_fd_conflict(child_fds_out, -1, &pipe_fds[i][0]) ==
			-1) {
			return -1;
		}
		if (pipe_fds[i][1] != -1 &&
		    ensure_no_fd_conflict(child_fds_out, -1, &pipe_fds[i][1]) ==
			-1) {
			return -1;
		}
	}
	return 0;
}

/*
 * Redirect j->preserved_fds from the parent_fd to the child_fd.
 *
 * NOTE: This will clear FD_CLOEXEC since otherwise the child_fd would not be
 * inherited after the exec call.
 */
static int redirect_fds(struct minijail *j, fd_set *child_fds)
{
	for (size_t i = 0; i < j->preserved_fd_count; i++) {
		if (j->preserved_fds[i].parent_fd ==
		    j->preserved_fds[i].child_fd) {
			// Clear CLOEXEC if it is set so the FD will be
			// inherited by the child.
			int flags =
			    fcntl(j->preserved_fds[i].child_fd, F_GETFD);
			if (flags == -1 || (flags & FD_CLOEXEC) == 0) {
				continue;
			}

			// Currently FD_CLOEXEC is cleared without being
			// restored. It may make sense to track when this
			// happens and restore FD_CLOEXEC in the child process.
			flags &= ~FD_CLOEXEC;
			if (fcntl(j->preserved_fds[i].child_fd, F_SETFD,
				  flags) == -1) {
				pwarn("failed to clear CLOEXEC for %d",
				      j->preserved_fds[i].parent_fd);
			}
			continue;
		}
		if (dup2(j->preserved_fds[i].parent_fd,
			 j->preserved_fds[i].child_fd) == -1) {
			return -1;
		}
	}

	/*
	 * After all fds have been duped, we are now free to close all parent
	 * fds that are *not* child fds.
	 */
	for (size_t i = 0; i < j->preserved_fd_count; i++) {
		int parent_fd = j->preserved_fds[i].parent_fd;
		if (!FD_ISSET(parent_fd, child_fds)) {
			close(parent_fd);
		}
	}
	return 0;
}

static void minijail_free_run_state(struct minijail_run_state *state)
{
	state->child_pid = -1;

	int *fd_pairs[] = {state->pipe_fds, state->stdin_fds, state->stdout_fds,
			   state->stderr_fds, state->child_sync_pipe_fds};
	for (size_t i = 0; i < ARRAY_SIZE(fd_pairs); ++i) {
		close_and_reset(&fd_pairs[i][0]);
		close_and_reset(&fd_pairs[i][1]);
	}

	minijail_free_env(state->child_env);
	state->child_env = NULL;
}

/* Set up stdin/stdout/stderr file descriptors in the child. */
static void setup_child_std_fds(struct minijail *j,
				struct minijail_run_state *state)
{
	struct {
		const char *name;
		int from;
		int to;
	} fd_map[] = {
	    {"stdin", state->stdin_fds[0], STDIN_FILENO},
	    {"stdout", state->stdout_fds[1], STDOUT_FILENO},
	    {"stderr", state->stderr_fds[1], STDERR_FILENO},
	};

	for (size_t i = 0; i < ARRAY_SIZE(fd_map); ++i) {
		if (fd_map[i].from == -1 || fd_map[i].from == fd_map[i].to)
			continue;
		if (dup2(fd_map[i].from, fd_map[i].to) == -1)
			die("failed to set up %s pipe", fd_map[i].name);
	}

	/* Close temporary pipe file descriptors. */
	int *std_pipes[] = {state->stdin_fds, state->stdout_fds,
			    state->stderr_fds};
	for (size_t i = 0; i < ARRAY_SIZE(std_pipes); ++i) {
		close_and_reset(&std_pipes[i][0]);
		close_and_reset(&std_pipes[i][1]);
	}

	/*
	 * If any of stdin, stdout, or stderr are TTYs, or setsid flag is
	 * set, create a new session. This prevents the jailed process from
	 * using the TIOCSTI ioctl to push characters into the parent process
	 * terminal's input buffer, therefore escaping the jail.
	 *
	 * Since it has just forked, the child will not be a process group
	 * leader, and this call to setsid() should always succeed.
	 */
	if (j->flags.setsid || isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) ||
	    isatty(STDERR_FILENO)) {
		if (setsid() < 0) {
			pdie("setsid() failed");
		}

		if (isatty(STDIN_FILENO)) {
			if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) != 0) {
				pwarn("failed to set controlling terminal");
			}
		}
	}
}

/*
 * Structure that specifies how to start a minijail.
 *
 * filename - The program to exec in the child. Should be NULL if elf_fd is set.
 * elf_fd - A fd to be used with fexecve. Should be -1 if filename is set.
 *   NOTE: either filename or elf_fd is required if |exec_in_child| = 1.
 * argv - Arguments for the child program. Required if |exec_in_child| = 1.
 * envp - Environment for the child program. Available if |exec_in_child| = 1.
 * use_preload - If true use LD_PRELOAD.
 * exec_in_child - If true, run |filename|. Otherwise, the child will return to
 *     the caller.
 * pstdin_fd - Filled with stdin pipe if non-NULL.
 * pstdout_fd - Filled with stdout pipe if non-NULL.
 * pstderr_fd - Filled with stderr pipe if non-NULL.
 * pchild_pid - Filled with the pid of the child process if non-NULL.
 */
struct minijail_run_config {
	const char *filename;
	int elf_fd;
	char *const *argv;
	char *const *envp;
	int use_preload;
	int exec_in_child;
	int *pstdin_fd;
	int *pstdout_fd;
	int *pstderr_fd;
	pid_t *pchild_pid;
};

static int
minijail_run_config_internal(struct minijail *j,
			     const struct minijail_run_config *config);

int API minijail_run(struct minijail *j, const char *filename,
		     char *const argv[])
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = NULL,
	    .use_preload = true,
	    .exec_in_child = true,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_env(struct minijail *j, const char *filename,
			 char *const argv[], char *const envp[])
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = envp,
	    .use_preload = true,
	    .exec_in_child = true,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_pid(struct minijail *j, const char *filename,
			 char *const argv[], pid_t *pchild_pid)
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = NULL,
	    .use_preload = true,
	    .exec_in_child = true,
	    .pchild_pid = pchild_pid,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_pipe(struct minijail *j, const char *filename,
			  char *const argv[], int *pstdin_fd)
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = NULL,
	    .use_preload = true,
	    .exec_in_child = true,
	    .pstdin_fd = pstdin_fd,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_pid_pipes(struct minijail *j, const char *filename,
			       char *const argv[], pid_t *pchild_pid,
			       int *pstdin_fd, int *pstdout_fd, int *pstderr_fd)
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = NULL,
	    .use_preload = true,
	    .exec_in_child = true,
	    .pstdin_fd = pstdin_fd,
	    .pstdout_fd = pstdout_fd,
	    .pstderr_fd = pstderr_fd,
	    .pchild_pid = pchild_pid,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_env_pid_pipes(struct minijail *j, const char *filename,
				   char *const argv[], char *const envp[],
				   pid_t *pchild_pid, int *pstdin_fd,
				   int *pstdout_fd, int *pstderr_fd)
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = envp,
	    .use_preload = true,
	    .exec_in_child = true,
	    .pstdin_fd = pstdin_fd,
	    .pstdout_fd = pstdout_fd,
	    .pstderr_fd = pstderr_fd,
	    .pchild_pid = pchild_pid,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_fd_env_pid_pipes(struct minijail *j, int elf_fd,
				      char *const argv[], char *const envp[],
				      pid_t *pchild_pid, int *pstdin_fd,
				      int *pstdout_fd, int *pstderr_fd)
{
	struct minijail_run_config config = {
	    .filename = NULL,
	    .elf_fd = elf_fd,
	    .argv = argv,
	    .envp = envp,
	    .use_preload = true,
	    .exec_in_child = true,
	    .pstdin_fd = pstdin_fd,
	    .pstdout_fd = pstdout_fd,
	    .pstderr_fd = pstderr_fd,
	    .pchild_pid = pchild_pid,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_no_preload(struct minijail *j, const char *filename,
				char *const argv[])
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = NULL,
	    .use_preload = false,
	    .exec_in_child = true,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_pid_pipes_no_preload(struct minijail *j,
					  const char *filename,
					  char *const argv[], pid_t *pchild_pid,
					  int *pstdin_fd, int *pstdout_fd,
					  int *pstderr_fd)
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = NULL,
	    .use_preload = false,
	    .exec_in_child = true,
	    .pstdin_fd = pstdin_fd,
	    .pstdout_fd = pstdout_fd,
	    .pstderr_fd = pstderr_fd,
	    .pchild_pid = pchild_pid,
	};
	return minijail_run_config_internal(j, &config);
}

int API minijail_run_env_pid_pipes_no_preload(struct minijail *j,
					      const char *filename,
					      char *const argv[],
					      char *const envp[],
					      pid_t *pchild_pid, int *pstdin_fd,
					      int *pstdout_fd, int *pstderr_fd)
{
	struct minijail_run_config config = {
	    .filename = filename,
	    .elf_fd = -1,
	    .argv = argv,
	    .envp = envp,
	    .use_preload = false,
	    .exec_in_child = true,
	    .pstdin_fd = pstdin_fd,
	    .pstdout_fd = pstdout_fd,
	    .pstderr_fd = pstderr_fd,
	    .pchild_pid = pchild_pid,
	};
	return minijail_run_config_internal(j, &config);
}

pid_t API minijail_fork(struct minijail *j)
{
	struct minijail_run_config config = {
	    .elf_fd = -1,
	};
	return minijail_run_config_internal(j, &config);
}

static int minijail_run_internal(struct minijail *j,
				 const struct minijail_run_config *config,
				 struct minijail_run_state *state_out)
{
	int sync_child = 0;
	int ret;
	/* We need to remember this across the minijail_preexec() call. */
	int pid_namespace = j->flags.pids;
	/*
	 * Create an init process if we are entering a pid namespace, unless the
	 * user has explicitly opted out by calling minijail_run_as_init().
	 */
	int do_init = j->flags.do_init && !j->flags.run_as_init;
	int use_preload = config->use_preload;

	if (config->filename != NULL && config->elf_fd != -1) {
		die("filename and elf_fd cannot be set at the same time");
	}
	if (config->filename != NULL) {
		j->filename = strdup(config->filename);
	}

	/*
	 * Only copy the environment if we need to modify it. If this is done
	 * unconditionally, it triggers odd behavior in the ARC container.
	 */
	if (use_preload || j->seccomp_policy_path) {
		state_out->child_env =
		    minijail_copy_env(config->envp ? config->envp : environ);
		if (!state_out->child_env)
			return ENOMEM;
	}

	if (j->seccomp_policy_path &&
	    setup_seccomp_policy_path(j, &state_out->child_env))
		return -EFAULT;

	if (use_preload) {
		if (j->hooks_head != NULL)
			die("Minijail hooks are not supported with LD_PRELOAD");
		if (!config->exec_in_child)
			die("minijail_fork is not supported with LD_PRELOAD");

		/*
		 * Before we fork(2) and execve(2) the child process, we need
		 * to open a pipe(2) to send the minijail configuration over.
		 */
		if (setup_preload(j, &state_out->child_env) ||
		    setup_pipe(&state_out->child_env, state_out->pipe_fds))
			return -EFAULT;
	}

	if (!use_preload) {
		if (j->flags.use_caps && j->caps != 0 &&
		    !j->flags.set_ambient_caps) {
			die("non-empty, non-ambient capabilities are not "
			    "supported without LD_PRELOAD");
		}
	}

	/* Create pipes for stdin/stdout/stderr as requested by caller. */
	struct {
		bool requested;
		int *pipe_fds;
	} pipe_fd_req[] = {
	    {config->pstdin_fd != NULL, state_out->stdin_fds},
	    {config->pstdout_fd != NULL, state_out->stdout_fds},
	    {config->pstderr_fd != NULL, state_out->stderr_fds},
	};

	for (size_t i = 0; i < ARRAY_SIZE(pipe_fd_req); ++i) {
		if (pipe_fd_req[i].requested &&
		    pipe(pipe_fd_req[i].pipe_fds) == -1)
			return EFAULT;
	}

	/*
	 * If the parent process needs to configure the child's runtime
	 * environment after forking, create a pipe(2) to block the child until
	 * configuration is done.
	 */
	if (j->flags.forward_signals || j->flags.pid_file || j->flags.cgroups ||
	    j->rlimit_count || j->flags.userns) {
		sync_child = 1;
		if (pipe(state_out->child_sync_pipe_fds))
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
	 * its fork()ed child return in turn), but that process would be
	 * crippled with its libc locks potentially broken. We might try
	 * fork()ing in the parent before we clone() to ensure that we own all
	 * the locks, but then we have to have the forked child hanging around
	 * consuming resources (and possibly having file descriptors / shared
	 * memory regions / etc attached). We'd need to keep the child around to
	 * avoid having its children get reparented to init.
	 *
	 * TODO(ellyjones): figure out if the "forked child hanging around"
	 * problem is fixable or not. It would be nice if we worked in this
	 * case.
	 */
	pid_t child_pid;
	if (pid_namespace) {
		unsigned long clone_flags = CLONE_NEWPID | SIGCHLD;
		if (j->flags.userns)
			clone_flags |= CLONE_NEWUSER;

		child_pid = syscall(SYS_clone, clone_flags, NULL, 0L, 0L, 0L);

		if (child_pid < 0) {
			if (errno == EPERM)
				pdie("clone(CLONE_NEWPID | ...) failed with "
				     "EPERM; is this process missing "
				     "CAP_SYS_ADMIN?");
			pdie("clone(CLONE_NEWPID | ...) failed");
		}
	} else {
		child_pid = fork();

		if (child_pid < 0)
			pdie("fork failed");
	}

	state_out->child_pid = child_pid;
	if (child_pid) {
		j->initpid = child_pid;

		if (j->flags.forward_signals) {
			forward_pid = child_pid;
			install_signal_handlers();
		}

		if (j->flags.pid_file)
			write_pid_file_or_die(j);

		if (j->flags.cgroups)
			add_to_cgroups_or_die(j);

		if (j->rlimit_count)
			set_rlimits_or_die(j);

		if (j->flags.userns)
			write_ugid_maps_or_die(j);

		if (j->flags.enter_vfs)
			close(j->mountns_fd);

		if (j->flags.enter_net)
			close(j->netns_fd);

		if (sync_child)
			parent_setup_complete(state_out->child_sync_pipe_fds);

		if (use_preload) {
			/*
			 * Add SIGPIPE to the signal mask to avoid getting
			 * killed if the child process finishes or closes its
			 * end of the pipe prematurely.
			 *
			 * TODO(crbug.com/1022170): Use pthread_sigmask instead
			 * of sigprocmask if Minijail is used in multithreaded
			 * programs.
			 */
			sigset_t to_block, to_restore;
			if (sigemptyset(&to_block) < 0)
				pdie("sigemptyset failed");
			if (sigaddset(&to_block, SIGPIPE) < 0)
				pdie("sigaddset failed");
			if (sigprocmask(SIG_BLOCK, &to_block, &to_restore) < 0)
				pdie("sigprocmask failed");

			/* Send marshalled minijail. */
			close_and_reset(&state_out->pipe_fds[0]);
			ret = minijail_to_fd(j, state_out->pipe_fds[1]);
			close_and_reset(&state_out->pipe_fds[1]);

			/* Accept any pending SIGPIPE. */
			while (true) {
				const struct timespec zero_time = {0, 0};
				const int sig =
				    sigtimedwait(&to_block, NULL, &zero_time);
				if (sig < 0) {
					if (errno != EINTR)
						break;
				} else {
					if (sig != SIGPIPE)
						die("unexpected signal %d",
						    sig);
				}
			}

			/* Restore the signal mask to its original state. */
			if (sigprocmask(SIG_SETMASK, &to_restore, NULL) < 0)
				pdie("sigprocmask failed");

			if (ret) {
				warn("failed to send marshalled minijail: %s",
				     strerror(-ret));
				kill(j->initpid, SIGKILL);
			}
		}

		return 0;
	}

	/* Child process. */
	if (j->flags.reset_signal_mask) {
		sigset_t signal_mask;
		if (sigemptyset(&signal_mask) != 0)
			pdie("sigemptyset failed");
		if (sigprocmask(SIG_SETMASK, &signal_mask, NULL) != 0)
			pdie("sigprocmask failed");
	}

	if (j->flags.reset_signal_handlers) {
		int signum;
		for (signum = 0; signum <= SIGRTMAX; signum++) {
			/*
			 * Ignore EINVAL since some signal numbers in the range
			 * might not be valid.
			 */
			if (signal(signum, SIG_DFL) == SIG_ERR &&
			    errno != EINVAL) {
				pdie("failed to reset signal %d disposition",
				     signum);
			}
		}
	}

	if (j->flags.close_open_fds) {
		const size_t kMaxInheritableFdsSize = 11 + MAX_PRESERVED_FDS;
		int inheritable_fds[kMaxInheritableFdsSize];
		size_t size = 0;

		int *pipe_fds[] = {
		    state_out->pipe_fds,   state_out->child_sync_pipe_fds,
		    state_out->stdin_fds,  state_out->stdout_fds,
		    state_out->stderr_fds,
		};

		for (size_t i = 0; i < ARRAY_SIZE(pipe_fds); ++i) {
			if (pipe_fds[i][0] != -1) {
				inheritable_fds[size++] = pipe_fds[i][0];
			}
			if (pipe_fds[i][1] != -1) {
				inheritable_fds[size++] = pipe_fds[i][1];
			}
		}

		/*
		 * Preserve namespace file descriptors over the close_open_fds()
		 * call. These are closed in minijail_enter() so they won't leak
		 * into the child process.
		 */
		if (j->flags.enter_vfs)
			minijail_preserve_fd(j, j->mountns_fd, j->mountns_fd);
		if (j->flags.enter_net)
			minijail_preserve_fd(j, j->netns_fd, j->netns_fd);

		for (size_t i = 0; i < j->preserved_fd_count; i++) {
			/*
			 * Preserve all parent_fds. They will be dup2(2)-ed in
			 * the child later.
			 */
			inheritable_fds[size++] = j->preserved_fds[i].parent_fd;
		}

		if (config->elf_fd > -1) {
			inheritable_fds[size++] = config->elf_fd;
		}

		if (close_open_fds(inheritable_fds, size) < 0)
			die("failed to close open file descriptors");
	}

	/* The set of fds will be replaced. */
	fd_set child_fds;
	FD_ZERO(&child_fds);
	if (get_child_fds(j, &child_fds))
		die("failed to set up fd redirections");

	if (avoid_pipe_conflicts(state_out, &child_fds))
		die("failed to redirect conflicting pipes");

	/* The elf_fd needs to be mutable so use a stack copy from now on. */
	int elf_fd = config->elf_fd;
	if (elf_fd != -1 && ensure_no_fd_conflict(&child_fds, -1, &elf_fd))
		die("failed to redirect elf_fd");

	if (redirect_fds(j, &child_fds))
		die("failed to set up fd redirections");

	if (sync_child)
		wait_for_parent_setup(state_out->child_sync_pipe_fds);

	if (j->flags.userns)
		enter_user_namespace(j);

	setup_child_std_fds(j, state_out);

	/* If running an init program, let it decide when/how to mount /proc. */
	if (pid_namespace && !do_init)
		j->flags.remount_proc_ro = 0;

	if (use_preload) {
		/* Strip out flags that cannot be inherited across execve(2). */
		minijail_preexec(j);
	} else {
		/*
		 * If not using LD_PRELOAD, do all jailing before execve(2).
		 * Note that PID namespaces can only be entered on fork(2),
		 * so that flag is still cleared.
		 */
		j->flags.pids = 0;
	}

	/*
	 * Jail this process.
	 * If forking, return.
	 * If not, execve(2) the target.
	 */
	minijail_enter(j);

	if (config->exec_in_child && pid_namespace && do_init) {
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
		if (child_pid < 0) {
			_exit(child_pid);
		} else if (child_pid > 0) {
			minijail_free_run_state(state_out);

			/*
			 * Best effort. Don't bother checking the return value.
			 */
			prctl(PR_SET_NAME, "minijail-init");
			init(child_pid); /* Never returns. */
		}
		state_out->child_pid = child_pid;
	}

	run_hooks_or_die(j, MINIJAIL_HOOK_EVENT_PRE_EXECVE);

	if (!config->exec_in_child)
		return 0;

	/*
	 * We're going to execve(), so make sure any remaining resources are
	 * freed. Exceptions are:
	 *  1. The child environment. No need to worry about freeing it since
	 *     execve reinitializes the heap anyways.
	 *  2. The read side of the LD_PRELOAD pipe, which we need to hand down
	 *     into the target in which the preloaded code will read from it and
	 *     then close it.
	 */
	state_out->pipe_fds[0] = -1;
	char *const *child_env = state_out->child_env;
	state_out->child_env = NULL;
	minijail_free_run_state(state_out);

	/*
	 * If we aren't pid-namespaced, or the jailed program asked to be init:
	 *   calling process
	 *   -> execve()-ing process
	 * If we are:
	 *   calling process
	 *   -> init()-ing process
	 *      -> execve()-ing process
	 */
	if (!child_env)
		child_env = config->envp ? config->envp : environ;
	if (elf_fd > -1) {
		fexecve(elf_fd, config->argv, child_env);
		pwarn("fexecve(%d) failed", config->elf_fd);
	} else {
		execve(config->filename, config->argv, child_env);
		pwarn("execve(%s) failed", config->filename);
	}

	ret = (errno == ENOENT ? MINIJAIL_ERR_NO_COMMAND
			       : MINIJAIL_ERR_NO_ACCESS);
	_exit(ret);
}

static int
minijail_run_config_internal(struct minijail *j,
			     const struct minijail_run_config *config)
{
	struct minijail_run_state state = {
	    .child_pid = -1,
	    .pipe_fds = {-1, -1},
	    .stdin_fds = {-1, -1},
	    .stdout_fds = {-1, -1},
	    .stderr_fds = {-1, -1},
	    .child_sync_pipe_fds = {-1, -1},
	    .child_env = NULL,
	};
	int ret = minijail_run_internal(j, config, &state);

	if (ret == 0) {
		if (config->pchild_pid)
			*config->pchild_pid = state.child_pid;

		/* Grab stdin/stdout/stderr descriptors requested by caller. */
		struct {
			int *pfd;
			int *psrc;
		} fd_map[] = {
		    {config->pstdin_fd, &state.stdin_fds[1]},
		    {config->pstdout_fd, &state.stdout_fds[0]},
		    {config->pstderr_fd, &state.stderr_fds[0]},
		};

		for (size_t i = 0; i < ARRAY_SIZE(fd_map); ++i) {
			if (fd_map[i].pfd) {
				*fd_map[i].pfd = *fd_map[i].psrc;
				*fd_map[i].psrc = -1;
			}
		}

		if (!config->exec_in_child)
			ret = state.child_pid;
	}

	minijail_free_run_state(&state);

	return ret;
}

static int minijail_wait_internal(struct minijail *j, int expected_signal)
{
	if (j->initpid <= 0)
		return -ECHILD;

	int st;
	while (true) {
		const int ret = waitpid(j->initpid, &st, 0);
		if (ret >= 0)
			break;
		if (errno != EINTR)
			return -errno;
	}

	if (!WIFEXITED(st)) {
		int error_status = st;
		if (!WIFSIGNALED(st)) {
			return error_status;
		}

		int signum = WTERMSIG(st);
		/*
		 * We return MINIJAIL_ERR_JAIL if the process received
		 * SIGSYS, which happens when a syscall is blocked by
		 * seccomp filters.
		 * If not, we do what bash(1) does:
		 * $? = 128 + signum
		 */
		if (signum == SIGSYS) {
			warn("child process %d had a policy violation (%s)",
			     j->initpid,
			     j->seccomp_policy_path ? j->seccomp_policy_path
						    : "NO-LABEL");
			error_status = MINIJAIL_ERR_JAIL;
		} else {
			if (signum != expected_signal) {
				warn("child process %d received signal %d",
				     j->initpid, signum);
			}
			error_status = MINIJAIL_ERR_SIG_BASE + signum;
		}
		return error_status;
	}

	int exit_status = WEXITSTATUS(st);
	if (exit_status != 0)
		info("child process %d exited with status %d", j->initpid,
		     exit_status);

	return exit_status;
}

int API minijail_kill(struct minijail *j)
{
	if (j->initpid <= 0)
		return -ECHILD;

	if (kill(j->initpid, SIGTERM))
		return -errno;

	return minijail_wait_internal(j, SIGTERM);
}

int API minijail_wait(struct minijail *j)
{
	return minijail_wait_internal(j, 0);
}

void API minijail_destroy(struct minijail *j)
{
	size_t i;

	if (j->filter_prog) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}
	free_mounts_list(j);
	free_remounts_list(j);
	while (j->hooks_head) {
		struct hook *c = j->hooks_head;
		j->hooks_head = c->next;
		free(c);
	}
	j->hooks_tail = NULL;
	while (j->fs_rules_head) {
		struct fs_rule *r = j->fs_rules_head;
		j->fs_rules_head = r->next;
		free(r);
	}
	j->fs_rules_tail = NULL;
	if (j->user)
		free(j->user);
	if (j->suppl_gid_list)
		free(j->suppl_gid_list);
	if (j->chrootdir)
		free(j->chrootdir);
	if (j->pid_file_path)
		free(j->pid_file_path);
	if (j->uidmap)
		free(j->uidmap);
	if (j->gidmap)
		free(j->gidmap);
	if (j->hostname)
		free(j->hostname);
	if (j->preload_path)
		free(j->preload_path);
	if (j->filename)
		free(j->filename);
	if (j->alt_syscall_table)
		free(j->alt_syscall_table);
	for (i = 0; i < j->cgroup_count; ++i)
		free(j->cgroups[i]);
	if (j->seccomp_policy_path)
		free(j->seccomp_policy_path);
	free(j);
}

void API minijail_log_to_fd(int fd, int min_priority)
{
	init_logging(LOG_TO_FD, fd, min_priority);
}
