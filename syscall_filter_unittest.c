/* syscall_filter_unittest.c
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test syscall filtering.
 */

#include <errno.h>

#include "test_harness.h"

#include "bpf.h"
#include "syscall_filter.h"

/* BPF testing macros. */
#define EXPECT_EQ_BLOCK(_block, _code, _k, _jt, _jf)	\
do {	\
	EXPECT_EQ((_block)->code, _code);		\
	EXPECT_EQ((_block)->k, (unsigned int)(_k));	\
	EXPECT_EQ((_block)->jt, _jt);			\
	EXPECT_EQ((_block)->jf, _jf);			\
} while (0)

#define EXPECT_EQ_STMT(_block, _code, _k) \
	EXPECT_EQ_BLOCK(_block, _code, _k, 0, 0)

#define EXPECT_COMP(_block) \
do {	\
	EXPECT_EQ((_block)->len, BPF_ARG_COMP_LEN + 1);			\
	EXPECT_EQ((_block)->instrs->code, BPF_LD+BPF_W+BPF_ABS);	\
} while (0)

#define EXPECT_LBL(_block) \
	do {	\
	EXPECT_EQ((_block)->code, BPF_JMP+BPF_JA);	\
	EXPECT_EQ((_block)->jt, LABEL_JT);		\
	EXPECT_EQ((_block)->jf, LABEL_JF);		\
} while (0)

#define EXPECT_JUMP_LBL(_block) \
do {	\
	EXPECT_EQ((_block)->code, BPF_JMP+BPF_JA);	\
	EXPECT_EQ((_block)->jt, JUMP_JT);		\
	EXPECT_EQ((_block)->jf, JUMP_JF);		\
} while (0)

#define EXPECT_GROUP_END(_block) \
do {	\
	EXPECT_EQ((_block)->len, 2U);			\
	EXPECT_JUMP_LBL(&(_block)->instrs[0]);		\
	EXPECT_LBL(&(_block)->instrs[1]);		\
} while (0)

#define EXPECT_KILL(_block) \
do {	\
	EXPECT_EQ((_block)->len, 1U);				\
	EXPECT_EQ_STMT(_block->instrs,				\
			BPF_RET+BPF_K, SECCOMP_RET_KILL);	\
} while (0)

#define EXPECT_ALLOW(_block) \
do {	\
	EXPECT_EQ((_block)->len, 2U);				\
	EXPECT_LBL(&(_block)->instrs[0]);			\
	EXPECT_EQ_STMT(&(_block)->instrs[1],			\
			BPF_RET+BPF_K, SECCOMP_RET_ALLOW);	\
} while (0)

FIXTURE(bpf) {};

FIXTURE_SETUP(bpf) {}
FIXTURE_TEARDOWN(bpf) {}

TEST_F(bpf, set_bpf_instr) {
	struct sock_filter instr;
	unsigned char code = BPF_LD+BPF_W+BPF_ABS;
	unsigned int k = 4;
	unsigned char jt = 1, jf = 2;

	size_t len = set_bpf_instr(&instr, code, k, jt, jf);

	EXPECT_EQ(len, 1U);
	EXPECT_EQ_BLOCK(&instr, code, k, jt, jf);
}

TEST_F(bpf, bpf_load_arg) {
	struct sock_filter load_arg[BPF_LOAD_ARG_LEN];
	int argidx = 1;
	size_t len = bpf_load_arg(load_arg, argidx);

	EXPECT_EQ(len, BPF_LOAD_ARG_LEN);
	EXPECT_EQ_STMT(&load_arg[0], BPF_LD+BPF_W+BPF_ABS, LO_ARG(argidx));
	EXPECT_EQ_STMT(&load_arg[1], BPF_ST, 0);
	EXPECT_EQ_STMT(&load_arg[2], BPF_LD+BPF_W+BPF_ABS, HI_ARG(argidx));
	EXPECT_EQ_STMT(&load_arg[3], BPF_ST, 1);
}

TEST_F(bpf, bpf_comp_jeq) {
	struct sock_filter comp_jeq[BPF_COMP_LEN];
	unsigned long c = 1;
	unsigned char jt = 1;
	unsigned char jf = 2;

	size_t len = bpf_comp_jeq64(comp_jeq, c, jt, jf);

	EXPECT_EQ(len, BPF_COMP_LEN);
	EXPECT_EQ_BLOCK(&comp_jeq[0],
			BPF_JMP+BPF_JEQ+BPF_K, 0, 0, jf + 2);
	EXPECT_EQ_STMT(&comp_jeq[1], BPF_LD+BPF_MEM, 0);
	EXPECT_EQ_BLOCK(&comp_jeq[2],
			BPF_JMP+BPF_JEQ+BPF_K, c, jt, jf);
}

TEST_F(bpf, bpf_arg_comp) {
	struct sock_filter *arg_comp;
	int op = EQ;
	int argidx = 1;
	unsigned long c = 3;
	unsigned int label_id = 0;

	size_t len = bpf_arg_comp(&arg_comp, op, argidx, c, label_id);

	EXPECT_EQ(len, BPF_ARG_COMP_LEN + 1);
	EXPECT_EQ_STMT(&arg_comp[0],
			BPF_LD+BPF_W+BPF_ABS, LO_ARG(argidx));
	EXPECT_EQ_STMT(&arg_comp[1], BPF_ST, 0);
	EXPECT_EQ_STMT(&arg_comp[2],
			BPF_LD+BPF_W+BPF_ABS, HI_ARG(argidx));
	EXPECT_EQ_STMT(&arg_comp[3], BPF_ST, 1);

	EXPECT_EQ_BLOCK(&arg_comp[4],
			BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 2);
	EXPECT_EQ_STMT(&arg_comp[5], BPF_LD+BPF_MEM, 0);
	EXPECT_EQ_BLOCK(&arg_comp[6],
			BPF_JMP+BPF_JEQ+BPF_K, c, 1, 0);
	EXPECT_JUMP_LBL(&arg_comp[7]);

	free(arg_comp);
}

FIXTURE(arg_filter) {
	struct bpf_labels labels;
};

FIXTURE_SETUP(arg_filter) {}
FIXTURE_TEARDOWN(arg_filter) {}

TEST_F(arg_filter, arg0_equals) {
	const char *fragment = "arg0 == 0";
	int nr = 1;
	unsigned int id = 0;
	struct filter_block *block =
		compile_section(nr, fragment, id, &self->labels);

	ASSERT_NE(block, NULL);
	EXPECT_EQ(block->total_len, 14U);

	/* First block is a label. */
	struct filter_block *curr_block = block;
	ASSERT_NE(curr_block, NULL);
	EXPECT_EQ(block->len, 1U);
	EXPECT_LBL(curr_block->instrs);

	/* Second block is a comparison. */
	curr_block = block->next;
	EXPECT_COMP(curr_block);

	/* Third block is a jump and a label (end of AND group). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_GROUP_END(curr_block);

	/* Fourth block is SECCOMP_RET_KILL */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_KILL(curr_block);

	/* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_ALLOW(curr_block);

	EXPECT_EQ(curr_block->next, NULL);

	free_block_list(block);
	free_label_strings(&self->labels);
}

TEST_F(arg_filter, and_or) {
	const char *fragment = "arg0 == 0 && arg1 == 0 || arg0 == 1";
	int nr = 1;
	unsigned int id = 0;

	struct filter_block *block =
		compile_section(nr, fragment, id, &self->labels);
	ASSERT_NE(block, NULL);
	EXPECT_EQ(block->total_len, 32U);

	/* First block is a label. */
	struct filter_block *curr_block = block;
	ASSERT_NE(curr_block, NULL);
	EXPECT_EQ(block->len, 1U);
	EXPECT_LBL(curr_block->instrs);

	/* Second block is a comparison ("arg0 == 0"). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_COMP(curr_block);

	/* Third block is a comparison ("arg1 == 0"). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_COMP(curr_block);

	/* Fourth block is a jump and a label (end of AND group). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_GROUP_END(curr_block);

	/* Fifth block is a comparison ("arg0 == 1"). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_COMP(curr_block);

	/* Sixth block is a jump and a label (end of AND group). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_GROUP_END(curr_block);

	/* Seventh block is SECCOMP_RET_KILL */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_KILL(curr_block);

	/* Eigth block is "SUCCESS" label and SECCOMP_RET_ALLOW */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_ALLOW(curr_block);

	EXPECT_EQ(curr_block->next, NULL);

	free_block_list(block);
	free_label_strings(&self->labels);
}

TEST_F(arg_filter, ret_errno) {
	const char *fragment = "arg0 == 0 || arg0 == 1; return 1";
	int nr = 1;
	unsigned int id = 0;

	struct filter_block *block =
		compile_section(nr, fragment, id, &self->labels);
	ASSERT_NE(block, NULL);
	EXPECT_EQ(block->total_len, 24U);

	/* First block is a label. */
	struct filter_block *curr_block = block;
	ASSERT_NE(curr_block, NULL);
	EXPECT_EQ(block->len, 1U);
	EXPECT_LBL(curr_block->instrs);

	/* Second block is a comparison ("arg0 == 0"). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_COMP(curr_block);

	/* Third block is a jump and a label (end of AND group). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_GROUP_END(curr_block);

	/* Fourth block is a comparison ("arg0 == 1"). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_COMP(curr_block);

	/* Fifth block is a jump and a label (end of AND group). */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_GROUP_END(curr_block);

	/* Sixth block is SECCOMP_RET_ERRNO */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_EQ(curr_block->len, 1U);
	EXPECT_EQ_STMT(curr_block->instrs,
			BPF_RET+BPF_K,
			SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));

	/* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_ALLOW(curr_block);

	EXPECT_EQ(curr_block->next, NULL);

	free_block_list(block);
	free_label_strings(&self->labels);
}

TEST_F(arg_filter, invalid) {
	const char *fragment = "argnn == 0";
	int nr = 1;
	unsigned int id = 0;

	struct filter_block *block =
			compile_section(nr, fragment, id, &self->labels);
	ASSERT_EQ(block, NULL);

	fragment = "arg0 == 0 && arg1 == 1; return errno";
	block = compile_section(nr, fragment, id, &self->labels);
	ASSERT_EQ(block, NULL);
}

TEST_HARNESS_MAIN
