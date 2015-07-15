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

#if defined(__i386__)
#  define ARCH_NR AUDIT_ARCH_I386
#elif defined(__x86_64__)
#  define ARCH_NR AUDIT_ARCH_X86_64
#elif defined(__arm__)
/*
 * <linux/audit.h> includes <linux/elf-em.h>, which does not define EM_ARM.
 * <linux/elf.h> only includes <asm/elf.h> if we're in the kernel.
 */
#  ifndef EM_ARM
#    define EM_ARM 40
#  endif
#  define ARCH_NR AUDIT_ARCH_ARM
#elif defined(__aarch64__)
#  define ARCH_NR AUDIT_ARCH_AARCH64
#elif defined(__hppa__)
#  define ARCH_NR AUDIT_ARCH_PARISC
#elif defined(__ia64__)
#  define ARCH_NR AUDIT_ARCH_IA64
#elif defined(__mips__)
#  if defined(__mips64)
#    if defined(__MIPSEB__)
#      define ARCH_NR AUDIT_ARCH_MIPS64
#    else
#      define ARCH_NR AUDIT_ARCH_MIPSEL64
#    endif
#  else
#    if defined(__MIPSEB__)
#      define ARCH_NR AUDIT_ARCH_MIPS
#    else
#      define ARCH_NR AUDIT_ARCH_MIPSEL
#    endif
#  endif
#elif defined(__powerpc64__)
#  define ARCH_NR AUDIT_ARCH_PPC64
#elif defined(__powerpc__)
#  define ARCH_NR AUDIT_ARCH_PPC
#elif defined(__s390x__)
#  define ARCH_NR AUDIT_ARCH_S390X
#elif defined(__s390__)
#  define ARCH_NR AUDIT_ARCH_S390
#elif defined(__sparc__)
#  if defined(__arch64__)
#    define AUDIT_ARCH_SPARC64
#  else
#    define AUDIT_ARCH_SPARC
#  endif
#else
#  error "AUDIT_ARCH value unavailable"
#endif

#endif /* ARCH_H */
