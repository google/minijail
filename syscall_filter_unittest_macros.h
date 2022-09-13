/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef SYSCALL_FILTER_UNITTEST_MACROS_H
#define SYSCALL_FILTER_UNITTEST_MACROS_H

#include "bpf.h"

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

#define EXPECT_GT_GE_COMP(_block) \
do {	\
	EXPECT_EQ((_block)->len, BPF_ARG_GT_GE_COMP_LEN + 1);		\
	EXPECT_EQ((_block)->instrs->code, BPF_LD+BPF_W+BPF_ABS);	\
} while (0)

#define EXPECT_SHORT_GT_GE_COMP(_block) \
do {	\
	EXPECT_EQ((_block)->len, BPF_ARG_SHORT_GT_GE_COMP_LEN + 1);	\
	EXPECT_EQ((_block)->instrs->code, BPF_LD+BPF_W+BPF_ABS);	\
} while (0)

#define EXPECT_LBL(_block) \
do {	\
	EXPECT_TRUE((_block)->code == (BPF_JMP+BPF_JA));	\
	EXPECT_TRUE((_block)->jt == LABEL_JT);			\
	EXPECT_TRUE((_block)->jf == LABEL_JF);			\
} while (0)

#define EXPECT_ACTUAL_LBL(_block, _id) \
do {	\
	EXPECT_TRUE((_block)->code == (BPF_JMP+BPF_JA));	\
	EXPECT_TRUE((_block)->k == (_id));			\
	EXPECT_TRUE((_block)->jt == LABEL_JT);			\
	EXPECT_TRUE((_block)->jf == LABEL_JF);			\
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
	EXPECT_EQ_STMT((_block)->instrs,			\
			BPF_RET+BPF_K, SECCOMP_RET_KILL);	\
} while (0)

#define EXPECT_TRAP(_block) \
do {	\
	EXPECT_EQ((_block)->len, 1U);				\
	EXPECT_EQ_STMT((_block)->instrs,			\
			BPF_RET+BPF_K, SECCOMP_RET_TRAP);	\
} while (0)

#define EXPECT_LOG(_block) \
do {	\
	EXPECT_EQ((_block)->len, 1U);				\
	EXPECT_EQ_STMT((_block)->instrs,			\
			BPF_RET+BPF_K, SECCOMP_RET_LOG);	\
} while (0)

#define EXPECT_ALLOW(_block) \
do {	\
	EXPECT_EQ((_block)->len, 2U);				\
	EXPECT_LBL(&(_block)->instrs[0]);			\
	EXPECT_EQ_STMT(&(_block)->instrs[1],			\
			BPF_RET+BPF_K, SECCOMP_RET_ALLOW);	\
} while (0)

#define EXPECT_ARCH_VALIDATION(_filter)                                        \
	do {                                                                   \
		EXPECT_EQ_STMT(&(_filter)[0], BPF_LD + BPF_W + BPF_ABS,        \
			       arch_nr);                                       \
		EXPECT_EQ_BLOCK(&(_filter)[1], BPF_JMP + BPF_JEQ + BPF_K,      \
				MINIJAIL_ARCH_NR, SKIP, NEXT);                 \
		EXPECT_EQ_STMT(&(_filter)[2], BPF_RET + BPF_K,                 \
			       SECCOMP_RET_KILL);                              \
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

#endif	// SYSCALL_FILTER_UNITTEST_MACROS_H
