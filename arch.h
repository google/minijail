/* arch.h
 * Copyright 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * ARCH_NR #define's.
 */

#ifndef ARCH_H
#define ARCH_H

#include <linux/audit.h>

/* clang-format off */
#if defined(__i386__)
#  define ARCH_NR AUDIT_ARCH_I386
#  define ARCH_NAME "x86"
#elif defined(__x86_64__)
#  define ARCH_NR AUDIT_ARCH_X86_64
#  define ARCH_NAME "x86_64"
#elif defined(__arm__)
/*
 * <linux/audit.h> includes <linux/elf-em.h>, which does not define EM_ARM.
 * <linux/elf.h> only includes <asm/elf.h> if we're in the kernel.
 */
#  ifndef EM_ARM
#    define EM_ARM 40
#  endif
#  define ARCH_NR AUDIT_ARCH_ARM
#  define ARCH_NAME "arm"
#elif defined(__aarch64__)
#  define ARCH_NR AUDIT_ARCH_AARCH64
#  define ARCH_NAME "arm64"
#elif defined(__hppa__)
#  define ARCH_NR AUDIT_ARCH_PARISC
#  define ARCH_NAME "parisc"
#elif defined(__ia64__)
#  define ARCH_NR AUDIT_ARCH_IA64
#  define ARCH_NAME "ia64"
#elif defined(__mips__)
#  if defined(__mips64)
#    if defined(__MIPSEB__)
#      define ARCH_NR AUDIT_ARCH_MIPS64
#      define ARCH_NAME "mips64"
#    else
#      define ARCH_NR AUDIT_ARCH_MIPSEL64
#      define ARCH_NAME "mipsel64"
#    endif
#  else
#    if defined(__MIPSEB__)
#      define ARCH_NR AUDIT_ARCH_MIPS
#      define ARCH_NAME "mips"
#    else
#      define ARCH_NR AUDIT_ARCH_MIPSEL
#      define ARCH_NAME "mipsel"
#    endif
#  endif
#elif defined(__powerpc64__)
#  define ARCH_NR AUDIT_ARCH_PPC64
#  define ARCH_NAME "ppc64"
#elif defined(__powerpc__)
#  define ARCH_NR AUDIT_ARCH_PPC
#  define ARCH_NAME "ppc"
#elif defined(__s390x__)
#  define ARCH_NR AUDIT_ARCH_S390X
#  define ARCH_NAME "s390x"
#elif defined(__s390__)
#  define ARCH_NR AUDIT_ARCH_S390
#  define ARCH_NAME "s390"
#elif defined(__sparc__)
#  if defined(__arch64__)
#    define AUDIT_ARCH_SPARC64
#    define ARCH_NAME "sparc64"
#  else
#    define AUDIT_ARCH_SPARC
#    define ARCH_NAME "sparc"
#  endif
#else
#  error "AUDIT_ARCH value unavailable"
#endif
/* clang-format on */

#endif /* ARCH_H */
