/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * Landlock system definitions.
 *
 * These definitions are based on <linux/landlock.h>. However, because we
 * can't guarantee that header will be available on all systems that need to
 * build Minijail, they are extracted here.
 */

#ifndef _LANDLOCK_H
#define _LANDLOCK_H

#include <linux/types.h>

/**
 * struct landlock_ruleset_attr - Ruleset definition
 *
 * Argument of sys_landlock_create_ruleset().  This structure can grow in
 * future versions.
 */
struct minijail_landlock_ruleset_attr {
	/**
	 * @handled_access_fs: Bitmask of actions (cf. `Filesystem flags`_)
	 * that is handled by this ruleset and should then be forbidden if no
	 * rule explicitly allow them.  This is needed for backward
	 * compatibility reasons.
	 */
	__u64 handled_access_fs;
};

/*
 * sys_landlock_create_ruleset() flags:
 *
 * - %LANDLOCK_CREATE_RULESET_VERSION: Get the highest supported Landlock ABI
 *   version.
 */
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION			(1U << 0)
#endif

/**
 * enum landlock_rule_type - Landlock rule type
 *
 * Argument of sys_landlock_add_rule().
 */
enum minijail_landlock_rule_type {
	/**
	 * @LANDLOCK_RULE_PATH_BENEATH: Type of a &struct
	 * landlock_path_beneath_attr .
	 */
	LANDLOCK_RULE_PATH_BENEATH = 1,
};

/**
 * struct landlock_path_beneath_attr - Path hierarchy definition
 *
 * Argument of sys_landlock_add_rule().
 */
struct minijail_landlock_path_beneath_attr {
	/**
	 * @allowed_access: Bitmask of allowed actions for this file hierarchy
	 * (cf. `Filesystem flags`_).
	 */
	__u64 allowed_access;
	/**
	 * @parent_fd: File descriptor, open with ``O_PATH``, which identifies
	 * the parent directory of a file hierarchy, or just a file.
	 */
	__s32 parent_fd;
	/*
	 * This struct is packed to avoid trailing reserved members.
	 * Cf. security/landlock/syscalls.c:build_check_abi()
	 */
}  __attribute__((__packed__));

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE			(1ULL << 0)
#endif

#ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
#define LANDLOCK_ACCESS_FS_WRITE_FILE			(1ULL << 1)
#endif

#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#define LANDLOCK_ACCESS_FS_READ_FILE			(1ULL << 2)
#endif

#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#define LANDLOCK_ACCESS_FS_READ_DIR			(1ULL << 3)
#endif

#ifndef LANDLOCK_ACCESS_FS_REMOVE_DIR
#define LANDLOCK_ACCESS_FS_REMOVE_DIR			(1ULL << 4)
#endif

#ifndef LANDLOCK_ACCESS_FS_REMOVE_FILE
#define LANDLOCK_ACCESS_FS_REMOVE_FILE			(1ULL << 5)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_CHAR
#define LANDLOCK_ACCESS_FS_MAKE_CHAR			(1ULL << 6)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_DIR
#define LANDLOCK_ACCESS_FS_MAKE_DIR			(1ULL << 7)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_REG
#define LANDLOCK_ACCESS_FS_MAKE_REG			(1ULL << 8)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_SOCK
#define LANDLOCK_ACCESS_FS_MAKE_SOCK			(1ULL << 9)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_FIFO
#define LANDLOCK_ACCESS_FS_MAKE_FIFO			(1ULL << 10)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_BLOCK
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK			(1ULL << 11)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_SYM
#define LANDLOCK_ACCESS_FS_MAKE_SYM			(1ULL << 12)
#endif

#endif /* _LANDLOCK_H */
