/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "util.h"

/* Architecture validation. */
size_t bpf_validate_arch(struct sock_filter *filter)
{
	struct sock_filter *curr_block = filter;
	set_bpf_stmt(curr_block++, BPF_LD + BPF_W + BPF_ABS, arch_nr);
	set_bpf_jump(curr_block++, BPF_JMP + BPF_JEQ + BPF_K, MINIJAIL_ARCH_NR,
		     SKIP, NEXT);
	set_bpf_ret_kill(curr_block++);
	return curr_block - filter;
}

/* Syscall number eval functions. */
size_t bpf_allow_syscall(struct sock_filter *filter, int nr)
{
	struct sock_filter *curr_block = filter;
	set_bpf_jump(curr_block++, BPF_JMP + BPF_JEQ + BPF_K, nr, NEXT, SKIP);
	set_bpf_stmt(curr_block++, BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
	return curr_block - filter;
}

size_t bpf_allow_syscall_args(struct sock_filter *filter, int nr,
			      unsigned int id)
{
	struct sock_filter *curr_block = filter;
	set_bpf_jump(curr_block++, BPF_JMP + BPF_JEQ + BPF_K, nr, NEXT, SKIP);
	set_bpf_jump_lbl(curr_block++, id);
	return curr_block - filter;
}

/* Size-aware arg loaders. */
#if defined(BITS32)
size_t bpf_load_arg(struct sock_filter *filter, int argidx)
{
	set_bpf_stmt(filter, BPF_LD + BPF_W + BPF_ABS, LO_ARG(argidx));
	return 1U;
}
#elif defined(BITS64)
size_t bpf_load_arg(struct sock_filter *filter, int argidx)
{
	struct sock_filter *curr_block = filter;
	set_bpf_stmt(curr_block++, BPF_LD + BPF_W + BPF_ABS, LO_ARG(argidx));
	set_bpf_stmt(curr_block++, BPF_ST, 0); /* lo -> M[0] */
	set_bpf_stmt(curr_block++, BPF_LD + BPF_W + BPF_ABS, HI_ARG(argidx));
	set_bpf_stmt(curr_block++, BPF_ST, 1); /* hi -> M[1] */
	return curr_block - filter;
}
#endif

/* Size-aware comparisons. */
size_t bpf_comp_jeq32(struct sock_filter *filter, unsigned long c,
		      unsigned char jt, unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	set_bpf_jump(filter, BPF_JMP + BPF_JEQ + BPF_K, lo, jt, jf);
	return 1U;
}

/*
 * On 64 bits, we have to do two 32-bit comparisons.
 * We jump true when *both* comparisons are true.
 */
#if defined(BITS64)
size_t bpf_comp_jeq64(struct sock_filter *filter, uint64_t c, unsigned char jt,
		      unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	unsigned int hi = (unsigned int)(c >> 32);

	struct sock_filter *curr_block = filter;

	/* bpf_load_arg leaves |hi| in A */
	curr_block += bpf_comp_jeq32(curr_block, hi, NEXT, SKIPN(2) + jf);
	set_bpf_stmt(curr_block++, BPF_LD + BPF_MEM, 0); /* swap in |lo| */
	curr_block += bpf_comp_jeq32(curr_block, lo, jt, jf);

	return curr_block - filter;
}
#endif

size_t bpf_comp_jgt32(struct sock_filter *filter, unsigned long c,
		      unsigned char jt, unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	set_bpf_jump(filter, BPF_JMP + BPF_JGT + BPF_K, lo, jt, jf);
	return 1U;
}

size_t bpf_comp_jge32(struct sock_filter *filter, unsigned long c,
		      unsigned char jt, unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	set_bpf_jump(filter, BPF_JMP + BPF_JGE + BPF_K, lo, jt, jf);
	return 1U;
}

/*
 * On 64 bits, we have to do two/three 32-bit comparisons.
 * We jump true when the |hi| comparison is true *or* |hi| is equal and the
 * |lo| comparison is true.
 */
#if defined(BITS64)
size_t bpf_comp_jgt64(struct sock_filter *filter, uint64_t c, unsigned char jt,
		      unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	unsigned int hi = (unsigned int)(c >> 32);

	struct sock_filter *curr_block = filter;

	/* bpf_load_arg leaves |hi| in A. */
	if (hi == 0) {
		curr_block +=
		    bpf_comp_jgt32(curr_block, hi, SKIPN(2) + jt, NEXT);
	} else {
		curr_block +=
		    bpf_comp_jgt32(curr_block, hi, SKIPN(3) + jt, NEXT);
		curr_block +=
		    bpf_comp_jeq32(curr_block, hi, NEXT, SKIPN(2) + jf);
	}
	set_bpf_stmt(curr_block++, BPF_LD + BPF_MEM, 0); /* swap in |lo| */
	curr_block += bpf_comp_jgt32(curr_block, lo, jt, jf);

	return curr_block - filter;
}

size_t bpf_comp_jge64(struct sock_filter *filter, uint64_t c, unsigned char jt,
		      unsigned char jf)
{
	unsigned int lo = (unsigned int)(c & 0xFFFFFFFF);
	unsigned int hi = (unsigned int)(c >> 32);

	struct sock_filter *curr_block = filter;

	/* bpf_load_arg leaves |hi| in A. */
	if (hi == 0) {
		curr_block +=
		    bpf_comp_jgt32(curr_block, hi, SKIPN(2) + jt, NEXT);
	} else {
		curr_block +=
		    bpf_comp_jgt32(curr_block, hi, SKIPN(3) + jt, NEXT);
		curr_block +=
		    bpf_comp_jeq32(curr_block, hi, NEXT, SKIPN(2) + jf);
	}
	set_bpf_stmt(curr_block++, BPF_LD + BPF_MEM, 0); /* swap in |lo| */
	curr_block += bpf_comp_jge32(curr_block, lo, jt, jf);

	return curr_block - filter;
}
#endif

/* Size-aware bitwise AND. */
size_t bpf_comp_jset32(struct sock_filter *filter, unsigned long mask,
		       unsigned char jt, unsigned char jf)
{
	unsigned int mask_lo = (unsigned int)(mask & 0xFFFFFFFF);
	set_bpf_jump(filter, BPF_JMP + BPF_JSET + BPF_K, mask_lo, jt, jf);
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
	set_bpf_stmt(curr_block++, BPF_LD + BPF_MEM, 0); /* swap in |lo| */
	curr_block += bpf_comp_jset32(curr_block, mask_lo, jt, jf);

	return curr_block - filter;
}
#endif

size_t bpf_comp_jin(struct sock_filter *filter, unsigned long mask,
		    unsigned char jt, unsigned char jf)
{
	unsigned long negative_mask = ~mask;
	/*
	 * The mask is negated, so the comparison will be true when the argument
	 * includes a flag that wasn't listed in the original (non-negated)
	 * mask. This would be the failure case, so we switch |jt| and |jf|.
	 */
	return bpf_comp_jset(filter, negative_mask, jf, jt);
}

static size_t bpf_arg_comp_len(int op, unsigned long c attribute_unused)
{
	/* The comparisons that use gt/ge internally may have extra opcodes. */
	switch (op) {
	case LT:
	case LE:
	case GT:
	case GE:
#if defined(BITS64)
		/*
		 * |c| can only have a high 32-bit part when running on 64 bits.
		 */
		if ((c >> 32) == 0)
			return BPF_ARG_SHORT_GT_GE_COMP_LEN + 1;
#endif
		return BPF_ARG_GT_GE_COMP_LEN + 1;
	default:
		return BPF_ARG_COMP_LEN + 1;
	}
}

size_t bpf_arg_comp(struct sock_filter **pfilter, int op, int argidx,
		    unsigned long c, unsigned int label_id)
{
	size_t filter_len = bpf_arg_comp_len(op, c);
	struct sock_filter *filter =
	    calloc(filter_len, sizeof(struct sock_filter));
	struct sock_filter *curr_block = filter;
	size_t (*comp_function)(struct sock_filter * filter, unsigned long k,
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
	case LT:
		comp_function = bpf_comp_jge;
		flip = 1;
		break;
	case LE:
		comp_function = bpf_comp_jgt;
		flip = 1;
		break;
	case GT:
		comp_function = bpf_comp_jgt;
		flip = 0;
		break;
	case GE:
		comp_function = bpf_comp_jge;
		flip = 0;
		break;
	case SET:
		comp_function = bpf_comp_jset;
		flip = 0;
		break;
	case IN:
		comp_function = bpf_comp_jin;
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

int bpf_resolve_jumps(struct bpf_labels *labels, struct sock_filter *filter,
		      size_t len)
{
	struct sock_filter *instr;
	size_t i, offset;

	if (len > BPF_MAXINSNS)
		return -1;

	/*
	 * Walk it once, backwards, to build the label table and do fixups.
	 * Since backward jumps are disallowed by BPF, this is easy.
	 */
	for (i = 0; i < len; i++) {
		offset = len - i - 1;
		instr = &filter[offset];
		if (instr->code != (BPF_JMP + BPF_JA))
			continue;
		switch ((instr->jt << 8) | instr->jf) {
		case (JUMP_JT << 8) | JUMP_JF:
			if (instr->k >= labels->count) {
				warn("nonexistent label id: %u", instr->k);
				return -1;
			}
			if (labels->labels[instr->k].location == 0xffffffff) {
				warn("unresolved label: '%s'",
				     labels->labels[instr->k].label);
				return -1;
			}
			instr->k =
			    labels->labels[instr->k].location - (offset + 1);
			instr->jt = 0;
			instr->jf = 0;
			continue;
		case (LABEL_JT << 8) | LABEL_JF:
			if (labels->labels[instr->k].location != 0xffffffff) {
				warn("duplicate label: '%s'",
				     labels->labels[instr->k].label);
				return -1;
			}
			labels->labels[instr->k].location = offset;
			instr->k = 0; /* Fall through. */
			instr->jt = 0;
			instr->jf = 0;
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
		if (!strcmp(label, begin->label)) {
			return id;
		}
	}

	/* The label wasn't found. Insert it only if there's space. */
	if (labels->count == BPF_LABELS_MAX) {
		return -1;
	}
	begin->label = strndup(label, MAX_BPF_LABEL_LEN);
	if (!begin->label) {
		return -1;
	}
	begin->location = 0xffffffff;
	labels->count++;
	return id;
}

void free_label_strings(struct bpf_labels *labels)
{
	if (labels->count == 0)
		return;

	struct __bpf_label *begin = labels->labels, *end;

	end = begin + labels->count;
	for (; begin < end; ++begin) {
		if (begin->label)
			free((void *)(begin->label));
	}

	labels->count = 0;
}
