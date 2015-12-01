/* syscall_filter_unittest.c
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test syscall filtering.
 */

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>	/* For O_WRONLY */

#include "test_harness.h"

#include "bpf.h"
#include "syscall_filter.h"

#include "util.h"

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

#define EXPECT_ARCH_VALIDATION(_filter) \
do {	\
	EXPECT_EQ_STMT(&(_filter)[0], BPF_LD+BPF_W+BPF_ABS, arch_nr);	\
	EXPECT_EQ_BLOCK(&(_filter)[1],					\
			BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, SKIP, NEXT);	\
	EXPECT_EQ_STMT(&(_filter)[2], BPF_RET+BPF_K, SECCOMP_RET_KILL);	\
} while (0)

#define EXPECT_ALLOW_SYSCALL(_filter, _nr) \
do {	\
	EXPECT_EQ_BLOCK(&(_filter)[0],					\
			BPF_JMP+BPF_JEQ+BPF_K, (_nr), NEXT, SKIP);	\
	EXPECT_EQ_STMT(&(_filter)[1],					\
			BPF_RET+BPF_K, SECCOMP_RET_ALLOW);		\
} while (0)

#define EXPECT_ALLOW_SYSCALL_ARGS(_filter, _nr, _id, _jt, _jf) \
do {	\
	EXPECT_EQ_BLOCK(&(_filter)[0],					\
			BPF_JMP+BPF_JEQ+BPF_K, (_nr), NEXT, SKIP);	\
	EXPECT_EQ_BLOCK(&(_filter)[1],					\
			BPF_JMP+BPF_JA, (_id), (_jt), (_jf));		\
} while (0)


FIXTURE(bpf) {};

FIXTURE_SETUP(bpf) {}
FIXTURE_TEARDOWN(bpf) {}

/* Test that setting one BPF instruction works. */
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

#if defined(BITS32)
	EXPECT_EQ_STMT(&load_arg[0], BPF_LD+BPF_W+BPF_ABS, LO_ARG(argidx));
#elif defined(BITS64)
	EXPECT_EQ_STMT(&load_arg[0], BPF_LD+BPF_W+BPF_ABS, LO_ARG(argidx));
	EXPECT_EQ_STMT(&load_arg[1], BPF_ST, 0);
	EXPECT_EQ_STMT(&load_arg[2], BPF_LD+BPF_W+BPF_ABS, HI_ARG(argidx));
	EXPECT_EQ_STMT(&load_arg[3], BPF_ST, 1);
#endif
}

TEST_F(bpf, bpf_comp_jeq) {
	struct sock_filter comp_jeq[BPF_COMP_LEN];
	unsigned long c = 1;
	unsigned char jt = 1;
	unsigned char jf = 2;

	size_t len = bpf_comp_jeq(comp_jeq, c, jt, jf);

	EXPECT_EQ(len, BPF_COMP_LEN);

#if defined(BITS32)
	EXPECT_EQ_BLOCK(&comp_jeq[0],
			BPF_JMP+BPF_JEQ+BPF_K, c, jt, jf);
#elif defined(BITS64)
	EXPECT_EQ_BLOCK(&comp_jeq[0],
			BPF_JMP+BPF_JEQ+BPF_K, 0, 0, jf + 2);
	EXPECT_EQ_STMT(&comp_jeq[1], BPF_LD+BPF_MEM, 0);
	EXPECT_EQ_BLOCK(&comp_jeq[2],
			BPF_JMP+BPF_JEQ+BPF_K, c, jt, jf);
#endif
}

TEST_F(bpf, bpf_comp_jset) {
	struct sock_filter comp_jset[BPF_COMP_LEN];
	unsigned long mask = O_WRONLY;
	unsigned char jt = 1;
	unsigned char jf = 2;

	size_t len = bpf_comp_jset(comp_jset, mask, jt, jf);

	EXPECT_EQ(len, BPF_COMP_LEN);

#if defined(BITS32)
	EXPECT_EQ_BLOCK(&comp_jset[0],
			BPF_JMP+BPF_JSET+BPF_K, mask, jt, jf);
#elif defined(BITS64)
	EXPECT_EQ_BLOCK(&comp_jset[0],
			BPF_JMP+BPF_JSET+BPF_K, 0, jt + 2, 0);
	EXPECT_EQ_STMT(&comp_jset[1], BPF_LD+BPF_MEM, 0);
	EXPECT_EQ_BLOCK(&comp_jset[2],
			BPF_JMP+BPF_JSET+BPF_K, mask, jt, jf);
#endif
}

TEST_F(bpf, bpf_arg_comp) {
	struct sock_filter *arg_comp;
	int op = EQ;
	int argidx = 1;
	unsigned long c = 3;
	unsigned int label_id = 0;

	size_t len = bpf_arg_comp(&arg_comp, op, argidx, c, label_id);

	EXPECT_EQ(len, BPF_ARG_COMP_LEN + 1);

#if defined(BITS32)
	EXPECT_EQ_STMT(&arg_comp[0],
			BPF_LD+BPF_W+BPF_ABS, LO_ARG(argidx));
	EXPECT_EQ_BLOCK(&arg_comp[1],
			BPF_JMP+BPF_JEQ+BPF_K, c, 1, 0);
	EXPECT_JUMP_LBL(&arg_comp[2]);
#elif defined(BITS64)
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
#endif
	free(arg_comp);
}

TEST_F(bpf, bpf_validate_arch) {
	struct sock_filter validate_arch[ARCH_VALIDATION_LEN];

	size_t len = bpf_validate_arch(validate_arch);

	EXPECT_EQ(len, ARCH_VALIDATION_LEN);
	EXPECT_ARCH_VALIDATION(validate_arch);
}

TEST_F(bpf, bpf_allow_syscall) {
	struct sock_filter allow_syscall[ALLOW_SYSCALL_LEN];
	int nr = 1;

	size_t len = bpf_allow_syscall(allow_syscall, nr);

	EXPECT_EQ(len, ALLOW_SYSCALL_LEN);
	EXPECT_ALLOW_SYSCALL(allow_syscall, nr);
}

TEST_F(bpf, bpf_allow_syscall_args) {
	struct sock_filter allow_syscall[ALLOW_SYSCALL_LEN];
	int nr = 1;
	unsigned int id = 1024;

	size_t len = bpf_allow_syscall_args(allow_syscall, nr, id);

	EXPECT_EQ(len, ALLOW_SYSCALL_LEN);
	EXPECT_ALLOW_SYSCALL_ARGS(allow_syscall, nr, id, JUMP_JT, JUMP_JF);
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
	size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
	EXPECT_EQ(block->total_len, exp_total_len);

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

TEST_F(arg_filter, arg0_mask) {
	const char *fragment = "arg1 & O_RDWR";
	int nr = 1;
	unsigned int id = 0;
	struct filter_block *block =
		compile_section(nr, fragment, id, &self->labels);

	ASSERT_NE(block, NULL);
	size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
	EXPECT_EQ(block->total_len, exp_total_len);

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

TEST_F(arg_filter, arg0_eq_mask) {
	const char *fragment = "arg1 == O_WRONLY|O_CREAT";
	int nr = 1;
	unsigned int id = 0;
	struct filter_block *block =
		compile_section(nr, fragment, id, &self->labels);

	ASSERT_NE(block, NULL);
	size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
	EXPECT_EQ(block->total_len, exp_total_len);

	/* First block is a label. */
	struct filter_block *curr_block = block;
	ASSERT_NE(curr_block, NULL);
	EXPECT_EQ(block->len, 1U);
	EXPECT_LBL(curr_block->instrs);

	/* Second block is a comparison. */
	curr_block = block->next;
	EXPECT_COMP(curr_block);
	EXPECT_EQ(curr_block->instrs[BPF_ARG_COMP_LEN  - 1].k,
		(unsigned int)(O_WRONLY | O_CREAT));

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
	size_t exp_total_len = 1 + 3 * (BPF_ARG_COMP_LEN + 1) + 2 + 2 + 1 + 2;
	EXPECT_EQ(block->total_len, exp_total_len);

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
	size_t exp_total_len = 1 + 2 * (BPF_ARG_COMP_LEN + 1) + 2 + 2 + 1 + 2;
	EXPECT_EQ(block->total_len, exp_total_len);

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

TEST_F(arg_filter, unconditional_errno) {
	const char *fragment = "return 1";
	int nr = 1;
	unsigned int id = 0;

	struct filter_block *block =
		compile_section(nr, fragment, id, &self->labels);
	ASSERT_NE(block, NULL);
	size_t exp_total_len = 2;
	EXPECT_EQ(block->total_len, exp_total_len);

	/* First block is a label. */
	struct filter_block *curr_block = block;
	ASSERT_NE(curr_block, NULL);
	EXPECT_EQ(block->len, 1U);
	EXPECT_LBL(curr_block->instrs);

	/* Second block is SECCOMP_RET_ERRNO */
	curr_block = curr_block->next;
	EXPECT_NE(curr_block, NULL);
	EXPECT_EQ(curr_block->len, 1U);
	EXPECT_EQ_STMT(curr_block->instrs,
			BPF_RET+BPF_K,
			SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));

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

FIXTURE(filter) {};

/*
 * When compiling for Android, disable tests that require data files.
 * TODO(b/259497279): Re-enable this.
 */
#if !defined(__ANDROID__)
FIXTURE_SETUP(filter) {}
FIXTURE_TEARDOWN(filter) {}

TEST_F(filter, seccomp_mode1) {
	struct sock_fprog actual;
	FILE *policy = fopen("test/seccomp.policy", "r");
	int res = compile_filter(policy, &actual, NO_LOGGING);

	/*
	 * Checks return value, filter length, and that the filter
	 * validates arch, loads syscall number, and
	 * only allows expected syscalls.
	 */
	ASSERT_EQ(res, 0);
	EXPECT_EQ(actual.len, 13);
	EXPECT_ARCH_VALIDATION(actual.filter);
	EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
			BPF_LD+BPF_W+BPF_ABS, syscall_nr);
	EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1,
			__NR_read);
	EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3,
			__NR_write);
	EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
			__NR_rt_sigreturn);
	EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7,
			__NR_exit);
	EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET+BPF_K,
			SECCOMP_RET_KILL);

	free(actual.filter);
	fclose(policy);
}

TEST_F(filter, seccomp_read_write) {
	struct sock_fprog actual;
	FILE *policy = fopen("test/stdin_stdout.policy", "r");
	int res = compile_filter(policy, &actual, NO_LOGGING);

	/*
	 * Checks return value, filter length, and that the filter
	 * validates arch, loads syscall number, and
	 * only allows expected syscalls, jumping to correct arg filter
	 * offsets.
	 */
	ASSERT_EQ(res, 0);
	size_t exp_total_len = 27 + 3 * (BPF_ARG_COMP_LEN + 1);
	EXPECT_EQ(actual.len, exp_total_len);

	EXPECT_ARCH_VALIDATION(actual.filter);
	EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
			BPF_LD+BPF_W+BPF_ABS, syscall_nr);
	EXPECT_ALLOW_SYSCALL_ARGS(actual.filter + ARCH_VALIDATION_LEN + 1,
			__NR_read, 7, 0, 0);
	EXPECT_ALLOW_SYSCALL_ARGS(actual.filter + ARCH_VALIDATION_LEN + 3,
			__NR_write, 12 + BPF_ARG_COMP_LEN, 0, 0);
	EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
			__NR_rt_sigreturn);
	EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7,
			__NR_exit);
	EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9, BPF_RET+BPF_K,
			SECCOMP_RET_KILL);

	free(actual.filter);
	fclose(policy);
}

TEST_F(filter, invalid) {
	struct sock_fprog actual;

	FILE *policy = fopen("test/invalid_syscall_name.policy", "r");
	int res = compile_filter(policy, &actual, NO_LOGGING);
	ASSERT_NE(res, 0);
	fclose(policy);

	policy = fopen("test/invalid_arg_filter.policy", "r");
	res = compile_filter(policy, &actual, NO_LOGGING);
	ASSERT_NE(res, 0);
	fclose(policy);
}

TEST_F(filter, nonexistent) {
	struct sock_fprog actual;

	FILE *policy = fopen("test/nonexistent-file.policy", "r");
	int res = compile_filter(policy, &actual, NO_LOGGING);
	ASSERT_NE(res, 0);
}

TEST_F(filter, log) {
	struct sock_fprog actual;

	FILE *policy = fopen("test/seccomp.policy", "r");
	int res = compile_filter(policy, &actual, USE_LOGGING);

	size_t i;
	size_t index = 0;
	/*
	 * Checks return value, filter length, and that the filter
	 * validates arch, loads syscall number, only allows expected syscalls,
	 * and returns TRAP on failure.
	 * NOTE(jorgelo): the filter is longer since we add the syscalls needed
	 * for logging.
	 */
	ASSERT_EQ(res, 0);
	EXPECT_EQ(actual.len, 13 + 2 * log_syscalls_len);
	EXPECT_ARCH_VALIDATION(actual.filter);
	EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
			BPF_LD+BPF_W+BPF_ABS, syscall_nr);

	index = ARCH_VALIDATION_LEN + 1;
	for (i = 0; i < log_syscalls_len; i++)
		EXPECT_ALLOW_SYSCALL(actual.filter + (index + 2 * i),
				     lookup_syscall(log_syscalls[i]));

	index += 2 * log_syscalls_len;

	EXPECT_ALLOW_SYSCALL(actual.filter + index, __NR_read);
	EXPECT_ALLOW_SYSCALL(actual.filter + index + 2, __NR_write);
	EXPECT_ALLOW_SYSCALL(actual.filter + index + 4, __NR_rt_sigreturn);
	EXPECT_ALLOW_SYSCALL(actual.filter + index + 6, __NR_exit);
	EXPECT_EQ_STMT(actual.filter + index + 8, BPF_RET+BPF_K,
			SECCOMP_RET_TRAP);

	free(actual.filter);
	fclose(policy);
}
#endif	/* __ANDROID__ */

TEST_HARNESS_MAIN
