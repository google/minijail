/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#if defined(__i386__) || defined(__x86_64__)
#include <asm/prctl.h>
#endif /* __i386__ || __x86_64__ */
#include <errno.h>
#include <fcntl.h>
#include <linux/fd.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/mman.h>
#include <linux/net.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/serial.h>
#include <linux/sockios.h>
#include <linux/termios.h>
#include <signal.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "arch.h"

/* These defines use C structures that are not defined in the same headers which
 * cause our CPP logic to fail w/undefined identifiers.  Remove them to avoid
 * build errors on such broken systems.
 */
#undef BLKTRACESETUP
#undef FS_IOC_FIEMAP

/* The old glibc bundled with the Android host toolchain is missing some ioctl
 * definitions used by minijail policy in crosvm and other projects. Locally
 * define them below.
 * This UAPI is taken from sanitized bionic headers.
 */

/* <linux/fs.h> */
#if !defined(FS_IOC_FSGETXATTR) && !defined(FS_IOC_FSSETXATTR)
struct fsxattr {
	__u32 fsx_xflags;
	__u32 fsx_extsize;
	__u32 fsx_nextents;
	__u32 fsx_projid;
	__u32 fsx_cowextsize;
	unsigned char fsx_pad[8];
};
#define FS_IOC_FSGETXATTR _IOR('X', 31, struct fsxattr)
#define FS_IOC_FSSETXATTR _IOW('X', 32, struct fsxattr)
#endif /* !FS_IOC_FSGETXATTR && !FS_IOC_FSSETXATTR */

/* <linux/fscrypt.h> */
#if !defined(FS_IOC_SET_ENCRYPTION_POLICY) &&                                  \
    !defined(FS_IOC_GET_ENCRYPTION_POLICY)
#define FSCRYPT_KEY_DESCRIPTOR_SIZE 8
struct fscrypt_policy_v1 {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
};
#define fscrypt_policy fscrypt_policy_v1
#define FS_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct fscrypt_policy)
#define FS_IOC_GET_ENCRYPTION_POLICY _IOW('f', 21, struct fscrypt_policy)
#endif /* !FS_IOC_SET_ENCRYPTION_POLICY && !FS_IOC_GET_ENCRYPTION_POLICY */
#if !defined(FS_IOC_GET_ENCRYPTION_POLICY_EX)
#define FS_IOC_GET_ENCRYPTION_POLICY_EX _IOWR('f', 22, __u8[9])
#endif
