/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* Define _GNU_SOURCE because we need O_PATH to resolve correctly. */
#define _GNU_SOURCE

#include "landlock_util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "util.h"

int landlock_create_ruleset(
    const struct minijail_landlock_ruleset_attr *const attr, const size_t size,
    const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

int landlock_add_rule(const int ruleset_fd,
		      const enum minijail_landlock_rule_type rule_type,
		      const void *const rule_attr, const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}

int landlock_restrict_self(const int ruleset_fd, const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

uint64_t landlock_get_handled_fs_mask(const int abi)
{
	static const uint64_t masks[] = {
	    [0] = 0,
	    [1] = HANDLED_ACCESS_TYPES,
	    [2] = HANDLED_ACCESS_TYPES | LANDLOCK_ACCESS_FS_REFER,
	    [3] = HANDLED_ACCESS_TYPES | LANDLOCK_ACCESS_FS_REFER |
		  LANDLOCK_ACCESS_FS_TRUNCATE,
	    [4] = HANDLED_ACCESS_TYPES | LANDLOCK_ACCESS_FS_REFER |
		  LANDLOCK_ACCESS_FS_TRUNCATE,
	    [5] = HANDLED_ACCESS_TYPES | LANDLOCK_ACCESS_FS_REFER |
		  LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV,
	};
	const size_t max_supported_abi = sizeof(masks) / sizeof(masks[0]) - 1;
	if (abi < 0) {
		return 0;
	}
	size_t index = MIN((size_t)abi, max_supported_abi);
	return masks[index];
}

uint64_t landlock_get_rw_mask(const int abi)
{
	uint64_t mask = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_BASIC_WRITE;
	if (abi >= LANDLOCK_ABI_FS_TRUNCATE_SUPPORTED) {
		mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
	}
	return mask;
}

uint64_t landlock_get_advanced_rw_mask(const int abi)
{
	uint64_t mask = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_FULL_WRITE;
	if (abi >= LANDLOCK_ABI_FS_REFER_SUPPORTED) {
		mask |= LANDLOCK_ACCESS_FS_REFER;
	}
	if (abi >= LANDLOCK_ABI_FS_TRUNCATE_SUPPORTED) {
		mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
	}
	if (abi >= LANDLOCK_ABI_FS_IOCTL_DEV_SUPPORTED) {
		mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
	}
	return mask;
}

uint64_t landlock_get_edit_mask(const int abi)
{
	uint64_t mask = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_EDIT;
	if (abi >= LANDLOCK_ABI_FS_TRUNCATE_SUPPORTED) {
		mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
	}
	return mask;
}

bool populate_ruleset_internal(const char *const path, const int ruleset_fd,
			       const uint64_t allowed_access)
{
	struct minijail_landlock_path_beneath_attr path_beneath = {
	    .parent_fd = -1,
	};
	struct stat statbuf;
	attribute_cleanup_fd int parent_fd = open(path, O_PATH | O_CLOEXEC);
	path_beneath.parent_fd = parent_fd;
	if (path_beneath.parent_fd < 0) {
		pwarn("Failed to open \"%s\"", path);
		return false;
	}
	if (fstat(path_beneath.parent_fd, &statbuf)) {
		return false;
	}
	path_beneath.allowed_access = allowed_access;
	if (!S_ISDIR(statbuf.st_mode)) {
		path_beneath.allowed_access &= ACCESS_FILE;
	}
	if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
			      &path_beneath, 0)) {
		pwarn("Failed to update ruleset \"%s\"", path);
		return false;
	}
	return true;
}
