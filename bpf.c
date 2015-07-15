/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"

/* Architecture validation. */
size_t bpf_validate_arch(struct sock_filter *filter)
{
	struct sock_filter *curr_block = filter;
	set_bpf_stmt(curr_block++, BPF_LD+BPF_W+BPF_ABS, arch_nr);
	set_bpf_jump(curr_block++,
			BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, SKIP, NEXT);
	set_bpf_ret_kill(curr_block++);
	return curr_block - filter;
}

/* Syscall number eval functions. */
size_t bpf_allow_syscall(struct sock_filter *filter, int nr)
{
	struct sock_filter *curr_block = filter;
	set_bpf_jump(curr_block++, BPF_JMP+BPF_JEQ+BPF_K, nr, NEXT, SKIP);
	set_bpf_stmt(curr_block++, BPF_RET+BPF_K, SECCOMP_RET_ALLOW);
	return curr_block - filter;
}

size_t bpf_allow_syscall_args(struct sock_filter *filter,
		int nr, unsigned int id)
{
	struct sock_filter *curr_block = filter;
	set_bpf_jump(curr_block++, BPF_JMP+BPF_JEQ+BPF_K, nr, NEXT, SKIP);
	set_bpf_jump_lbl(curr_block++, id);
	return curr_block - filter;
}

/* Size-aware arg loaders. */
#if defined(BITS32)
size_t bpf_load_arg(struct sock_filter *filter, int argidx)
{
	set_bpf_stmt(filter, BPF_LD+BPF_W+BPF_ABS, LO_ARG(argidx));
	return 1U;
}
#elif defined(BITS64)
size_t bpf_load_arg(struct sock_filter *filter, int argidx)
{
	struct sock_filter *curr_block = filter;
	set_bpf_stmt(curr_block++, BPF_LD+BPF_W+BPF_ABS, LO_ARG(argidx));
	set_bpf_stmt(curr_block++, BPF_ST, 0); /* lo -> M[0] */
	set_bpf_stmt(curr_block++, BPF_LD+BPF_W+BPF_ABS, HI_ARG(argidx));
	set_bpf_stmt(curr_block++, BPF_ST, 1); /* hi -> M[1] */
	return curr_block - filter;
}
#endif

/* Size-aware equality comparison. */
size_t bpf_comp_jeq32(struct sock_filter *filter, unsigned long c,
		unsigned char jt, unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	set_bpf_jump(filter, BPF_JMP+BPF_JEQ+BPF_K, lo, jt, jf);
	return 1U;
}

/*
 * On 64 bits, we have to do two 32-bit comparisons.
 * We jump true when *both* comparisons are true.
 */
#if defined(BITS64)
size_t bpf_comp_jeq64(struct sock_filter *filter, uint64_t c,
		unsigned char jt, unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	unsigned int hi = (unsigned int)(c >> 32);

	struct sock_filter *curr_block = filter;

	/* bpf_load_arg leaves |hi| in A */
	curr_block += bpf_comp_jeq32(curr_block, hi, NEXT, SKIPN(2) + jf);
	set_bpf_stmt(curr_block++, BPF_LD+BPF_MEM, 0); /* swap in |lo| */
	curr_block += bpf_comp_jeq32(curr_block, lo, jt, jf);

	return curr_block - filter;
}
#endif

/* Size-aware bitwise AND. */
size_t bpf_comp_jset32(struct sock_filter *filter, unsigned long mask,
		unsigned char jt, unsigned char jf)
{
	unsigned int mask_lo = (unsigned int)(mask & 0xFFFFFFFF);
	set_bpf_jump(filter, BPF_JMP+BPF_JSET+BPF_K, mask_lo, jt, jf);
	return 1U;
}

/*
 * On 64 bits, we have to do two 32-bit bitwise ANDs.
 * We jump true when *either* bitwise AND is true (non-zero).
 */
#if defined(BITS64)
size_t bpf_comp_jset64(struct sock_filter *filter, uint64_t mask,
		unsigned char jt, unsigned char jf)
{
	unsigned int mask_lo = (unsigned int)(mask & 0xFFFFFFFF);
	unsigned int mask_hi = (unsigned int)(mask >> 32);

	struct sock_filter *curr_block = filter;

	/* bpf_load_arg leaves |hi| in A */
	curr_block += bpf_comp_jset32(curr_block, mask_hi, SKIPN(2) + jt, NEXT);
	set_bpf_stmt(curr_block++, BPF_LD+BPF_MEM, 0); /* swap in |lo| */
	curr_block += bpf_comp_jset32(curr_block, mask_lo, jt, jf);

	return curr_block - filter;
}
#endif

size_t bpf_arg_comp(struct sock_filter **pfilter,
		int op, int argidx, unsigned long c, unsigned int label_id)
{
	struct sock_filter *filter = calloc(BPF_ARG_COMP_LEN + 1,
			sizeof(struct sock_filter));
	struct sock_filter *curr_block = filter;
	size_t (*comp_function)(struct sock_filter *filter, unsigned long k,
				unsigned char jt, unsigned char jf);
	int flip = 0;

	/* Load arg */
	curr_block += bpf_load_arg(curr_block, argidx);

	/* Jump type */
	switch (op) {
	case EQ:
		comp_function = bpf_comp_jeq;
		flip = 0;
		break;
	case NE:
		comp_function = bpf_comp_jeq;
		flip = 1;
		break;
	case SET:
		comp_function = bpf_comp_jset;
		flip = 0;
		break;
	default:
		*pfilter = NULL;
		return 0;
	}

	/*
	 * It's easier for the rest of the code to have the true branch
	 * skip and the false branch fall through.
	 */
	unsigned char jt = flip ? NEXT : SKIP;
	unsigned char jf = flip ? SKIP : NEXT;
	curr_block += comp_function(curr_block, c, jt, jf);
	curr_block += set_bpf_jump_lbl(curr_block, label_id);

	*pfilter = filter;
	return curr_block - filter;
}

void dump_bpf_filter(struct sock_filter *filter, unsigned short len)
{
	int i = 0;

	printf("len == %d\n", len);
	printf("filter:\n");
	for (i = 0; i < len; i++) {
		printf("%d: \t{ code=%#x, jt=%u, jf=%u, k=%#x \t}\n",
			i, filter[i].code, filter[i].jt, filter[i].jf, filter[i].k);
	}
}

void dump_bpf_prog(struct sock_fprog *fprog)
{
	struct sock_filter *filter = fprog->filter;
	unsigned short len = fprog->len;
	dump_bpf_filter(filter, len);
}

int bpf_resolve_jumps(struct bpf_labels *labels,
		struct sock_filter *filter, size_t count)
{
	struct sock_filter *begin = filter;
	__u8 insn = count - 1;

	if (count < 1)
		return -1;
	/*
	 * Walk it once, backwards, to build the label table and do fixups.
	 * Since backward jumps are disallowed by BPF, this is easy.
	 */
	for (filter += insn; filter >= begin; --insn, --filter) {
		if (filter->code != (BPF_JMP+BPF_JA))
			continue;
		switch ((filter->jt<<8)|filter->jf) {
		case (JUMP_JT<<8)|JUMP_JF:
			if (labels->labels[filter->k].location == 0xffffffff) {
				fprintf(stderr, "Unresolved label: '%s'\n",
					labels->labels[filter->k].label);
				return 1;
			}
			filter->k = labels->labels[filter->k].location -
					(insn + 1);
			filter->jt = 0;
			filter->jf = 0;
			continue;
		case (LABEL_JT<<8)|LABEL_JF:
			if (labels->labels[filter->k].location != 0xffffffff) {
				fprintf(stderr, "Duplicate label use: '%s'\n",
					labels->labels[filter->k].label);
				return 1;
			}
			labels->labels[filter->k].location = insn;
			filter->k = 0; /* fall through */
			filter->jt = 0;
			filter->jf = 0;
			continue;
		}
	}
	return 0;
}

/* Simple lookup table for labels. */
int bpf_label_id(struct bpf_labels *labels, const char *label)
{
	struct __bpf_label *begin = labels->labels, *end;
	int id;
	if (labels->count == 0) {
		begin->label = strndup(label, MAX_BPF_LABEL_LEN);
		if (!begin->label) {
			return -1;
		}
		begin->location = 0xffffffff;
		labels->count++;
		return 0;
	}
	end = begin + labels->count;
	for (id = 0; begin < end; ++begin, ++id) {
		if (!strcmp(label, begin->label))
			return id;
	}
	begin->label = strndup(label, MAX_BPF_LABEL_LEN);
	if (!begin->label) {
		return -1;
	}
	begin->location = 0xffffffff;
	labels->count++;
	return id;
}

/* Free label strings. */
void free_label_strings(struct bpf_labels *labels)
{
	if (labels->count == 0)
		return;

	struct __bpf_label *begin = labels->labels, *end;

	end = begin + labels->count;
	for (; begin < end; ++begin) {
		if (begin->label)
			free((void*)(begin->label));
	}
}
