/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * Landlock functions and constants.
 */

#ifndef _LANDLOCK_UTIL_H_
#define _LANDLOCK_UTIL_H_

#include <asm/unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "landlock.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif

#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif

#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#define ACCESS_FS_ROUGHLY_READ                                                 \
	(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_READ_EXECUTE                                         \
	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |           \
	 LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_BASIC_WRITE                                          \
	(LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |       \
	 LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |        \
	 LANDLOCK_ACCESS_FS_MAKE_REG)

#define ACCESS_FS_ROUGHLY_EDIT                                                 \
	(LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |       \
	 LANDLOCK_ACCESS_FS_REMOVE_FILE)

#define ACCESS_FS_ROUGHLY_FULL_WRITE                                           \
	(LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |       \
	 LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |       \
	 LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |           \
	 LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |         \
	 LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM)

#define ACCESS_FILE                                                            \
	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |          \
	 LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |          \
	 LANDLOCK_ACCESS_FS_IOCTL_DEV)

#define HANDLED_ACCESS_TYPES                                                   \
	(ACCESS_FS_ROUGHLY_READ_EXECUTE | ACCESS_FS_ROUGHLY_FULL_WRITE)

#define LANDLOCK_ABI_FS_REFER_SUPPORTED	    2
#define LANDLOCK_ABI_FS_TRUNCATE_SUPPORTED  3
#define LANDLOCK_ABI_FS_IOCTL_DEV_SUPPORTED 5
#define LANDLOCK_ABI_DEFAULT		    2

/*
 * Performs Landlock create ruleset syscall.
 *
 * Returns the ruleset file descriptor on success, returns an error code
 * otherwise.
 */
extern int
landlock_create_ruleset(const struct minijail_landlock_ruleset_attr *const attr,
			const size_t size, const __u32 flags);

/* Performs Landlock add rule syscall. */
extern int landlock_add_rule(const int ruleset_fd,
			     const enum minijail_landlock_rule_type rule_type,
			     const void *const rule_attr, const __u32 flags);

/* Performs Landlock restrict self syscall. */
extern int landlock_restrict_self(const int ruleset_fd, const __u32 flags);

/* Returns the handled filesystem access mask for the given ABI version. */
extern uint64_t landlock_get_handled_fs_mask(const int abi);

/*
 * Returns the filesystem access mask for RW paths for the given ABI version.
 */
extern uint64_t landlock_get_rw_mask(const int abi);

/*
 * Returns the filesystem access mask for advanced RW paths for the given ABI
 * version.
 */
extern uint64_t landlock_get_advanced_rw_mask(const int abi);

/*
 * Returns the filesystem access mask for edit paths for the given ABI version.
 */
extern uint64_t landlock_get_edit_mask(const int abi);

/*
 * Populates the landlock ruleset for a path and any needed paths beneath.
 *
 * |allowed_access| should already be masked to only include flags supported by
 * the effective Landlock ABI. If |path| is not a directory, directory-only
 * flags will be filtered out using |ACCESS_FILE| (which contains all possible
 * file access rights, including those from newer ABI versions).
 */
extern bool populate_ruleset_internal(const char *const path,
				      const int ruleset_fd,
				      const uint64_t allowed_access);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _LANDLOCK_UTIL_H_ */
