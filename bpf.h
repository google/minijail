/* bpf.h
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Berkeley Packet Filter functions.
 */

#ifndef BPF_H
#define BPF_H

#include <asm/bitsperlong.h>   /* for __BITS_PER_LONG */
#include <endian.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <stddef.h>
#include <sys/user.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "arch.h"

#if __BITS_PER_LONG == 32 || defined(__ILP32__)
#define BITS32
#elif __BITS_PER_LONG == 64
#define BITS64
#endif

/* Constants for comparison operators. */
#define MIN_OPERATOR 128
enum {
	EQ = MIN_OPERATOR,
	NE,
	LT,
	LE,
	GT,
	GE,
	SET,
	IN
};

/*
 * BPF return values and data structures,
 * since they're not yet in the kernel.
 */
#define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	0x00030000U /* return SIGSYS */
#define SECCOMP_RET_ERRNO	0x00050000U /* return -1 and set errno */
#define SECCOMP_RET_LOG		0x7ffc0000U /* allow after logging */
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */

#define SECCOMP_RET_DATA	0x0000ffffU /* mask for return value */

struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

/* Size-dependent defines. */
#if defined(BITS32)
/*
 * On 32 bits, comparisons take 2 instructions: 1 for loading the argument,
 * 1 for the actual comparison.
 */
#define BPF_LOAD_ARG_LEN		1U
#define BPF_COMP_LEN			1U
#define BPF_SHORT_GT_GE_COMP_LEN	1U
#define BPF_GT_GE_COMP_LEN		1U
#define BPF_ARG_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_COMP_LEN)
#define BPF_ARG_SHORT_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_SHORT_GT_GE_COMP_LEN)
#define BPF_ARG_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_GT_GE_COMP_LEN)

#define bpf_comp_jeq bpf_comp_jeq32
#define bpf_comp_jgt bpf_comp_jgt32
#define bpf_comp_jge bpf_comp_jge32
#define bpf_comp_jset bpf_comp_jset32

#define LO_ARG(idx) offsetof(struct seccomp_data, args[(idx)])

#elif defined(BITS64)
/*
 * On 64 bits, comparisons take 7-8 instructions: 4 for loading the argument,
 * and 3-4 for the actual comparison.
 */
#define BPF_LOAD_ARG_LEN		4U
#define BPF_COMP_LEN			3U
#define BPF_SHORT_GT_GE_COMP_LEN	3U
#define BPF_GT_GE_COMP_LEN		4U
#define BPF_ARG_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_COMP_LEN)
#define BPF_ARG_SHORT_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_SHORT_GT_GE_COMP_LEN)
#define BPF_ARG_GT_GE_COMP_LEN (BPF_LOAD_ARG_LEN + BPF_GT_GE_COMP_LEN)

#define bpf_comp_jeq bpf_comp_jeq64
#define bpf_comp_jgt bpf_comp_jgt64
#define bpf_comp_jge bpf_comp_jge64
#define bpf_comp_jset bpf_comp_jset64

/* Ensure that we load the logically correct offset. */
#if defined(__LITTLE_ENDIAN__) || __BYTE_ORDER == __LITTLE_ENDIAN
#define LO_ARG(idx) offsetof(struct seccomp_data, args[(idx)])
#define HI_ARG(idx) offsetof(struct seccomp_data, args[(idx)]) + sizeof(__u32)
#else
#error "Unsupported endianness"
#endif

#else
#error "Unknown bit width"

#endif

/* Common jump targets. */
#define NEXT 0
#define SKIP 1
#define SKIPN(_n) (_n)

/* Support for labels in BPF programs. */
#define JUMP_JT 0xff
#define JUMP_JF 0xff
#define LABEL_JT 0xfe
#define LABEL_JF 0xfe

#define MAX_BPF_LABEL_LEN 32

#define BPF_LABELS_MAX 512U	/* Each syscall could have an argument block. */
struct bpf_labels {
	size_t count;
	struct __bpf_label {
		const char *label;
		unsigned int location;
	} labels[BPF_LABELS_MAX];
};

/* BPF instruction manipulation functions and macros. */
static inline size_t set_bpf_instr(struct sock_filter *instr,
				   unsigned short code, unsigned int k,
				   unsigned char jt, unsigned char jf)
{
	instr->code = code;
	instr->k = k;
	instr->jt = jt;
	instr->jf = jf;
	return 1U;
}

#define set_bpf_stmt(_block, _code, _k) \
	set_bpf_instr((_block), (_code), (_k), 0, 0)

#define set_bpf_jump(_block, _code, _k, _jt, _jf) \
	set_bpf_instr((_block), (_code), (_k), (_jt), (_jf))

#define set_bpf_lbl(_block, _lbl_id) \
	set_bpf_jump((_block), BPF_JMP+BPF_JA, (_lbl_id), \
			LABEL_JT, LABEL_JF)

#define set_bpf_jump_lbl(_block, _lbl_id) \
	set_bpf_jump((_block), BPF_JMP+BPF_JA, (_lbl_id), \
			JUMP_JT, JUMP_JF)

#define set_bpf_ret_kill(_block) \
	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define set_bpf_ret_trap(_block) \
	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_TRAP)

#define set_bpf_ret_errno(_block, _errno) \
	set_bpf_stmt((_block), BPF_RET+BPF_K, \
		SECCOMP_RET_ERRNO | ((_errno) & SECCOMP_RET_DATA))

#define set_bpf_ret_log(_block) \
	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_LOG)

#define set_bpf_ret_allow(_block) \
	set_bpf_stmt((_block), BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define bpf_load_syscall_nr(_filter) \
	set_bpf_stmt((_filter), BPF_LD+BPF_W+BPF_ABS, syscall_nr)

/* BPF label functions. */
int bpf_resolve_jumps(struct bpf_labels *labels,
		struct sock_filter *filter, size_t count);
int bpf_label_id(struct bpf_labels *labels, const char *label);
void free_label_strings(struct bpf_labels *labels);

/* BPF helper functions. */
size_t bpf_load_arg(struct sock_filter *filter, int argidx);
size_t bpf_comp_jeq(struct sock_filter *filter, unsigned long c,
		    unsigned char jt, unsigned char jf);
size_t bpf_comp_jgt(struct sock_filter *filter, unsigned long c,
		    unsigned char jt, unsigned char jf);
size_t bpf_comp_jge(struct sock_filter *filter, unsigned long c,
		    unsigned char jt, unsigned char jf);
size_t bpf_comp_jset(struct sock_filter *filter, unsigned long mask,
		     unsigned char jt, unsigned char jf);
size_t bpf_comp_jin(struct sock_filter *filter, unsigned long mask,
		    unsigned char jt, unsigned char jf);

/* Functions called by syscall_filter.c */
#define ARCH_VALIDATION_LEN 3U
#define ALLOW_SYSCALL_LEN 2U

size_t bpf_arg_comp(struct sock_filter **pfilter,
		int op, int argidx, unsigned long c, unsigned int label_id);
size_t bpf_validate_arch(struct sock_filter *filter);
size_t bpf_allow_syscall(struct sock_filter *filter, int nr);
size_t bpf_allow_syscall_args(struct sock_filter *filter,
		int nr, unsigned int id);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* BPF_H */
