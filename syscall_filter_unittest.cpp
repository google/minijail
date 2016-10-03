// syscall_filter_unittest.cpp
// Copyright (C) 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Test syscall filtering using gtest.

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h> /* For O_WRONLY. */

#include <gtest/gtest.h>

#include "bpf.h"
#include "syscall_filter.h"
#include "syscall_filter_unittest_macros.h"
#include "util.h"

/* Test that setting one BPF instruction works. */
TEST(bpf, set_bpf_instr) {
  struct sock_filter instr;
  unsigned char code = BPF_LD + BPF_W + BPF_ABS;
  unsigned int k = 4;
  unsigned char jt = 1, jf = 2;

  size_t len = set_bpf_instr(&instr, code, k, jt, jf);

  EXPECT_EQ(len, 1U);
  EXPECT_EQ_BLOCK(&instr, code, k, jt, jf);
}

TEST(bpf, bpf_load_arg) {
  struct sock_filter load_arg[BPF_LOAD_ARG_LEN];
  int argidx = 1;
  size_t len = bpf_load_arg(load_arg, argidx);

  EXPECT_EQ(len, BPF_LOAD_ARG_LEN);

#if defined(BITS32)
  EXPECT_EQ_STMT(&load_arg[0], BPF_LD + BPF_W + BPF_ABS, LO_ARG(argidx));
#elif defined(BITS64)
  EXPECT_EQ_STMT(&load_arg[0], BPF_LD + BPF_W + BPF_ABS, LO_ARG(argidx));
  EXPECT_EQ_STMT(&load_arg[1], BPF_ST, 0);
  EXPECT_EQ_STMT(&load_arg[2], BPF_LD + BPF_W + BPF_ABS, HI_ARG(argidx));
  EXPECT_EQ_STMT(&load_arg[3], BPF_ST, 1);
#endif
}

TEST(bpf, bpf_comp_jeq) {
  struct sock_filter comp_jeq[BPF_COMP_LEN];
  unsigned long c = 1;
  unsigned char jt = 1;
  unsigned char jf = 2;

  size_t len = bpf_comp_jeq(comp_jeq, c, jt, jf);

  EXPECT_EQ(len, BPF_COMP_LEN);

#if defined(BITS32)
  EXPECT_EQ_BLOCK(&comp_jeq[0], BPF_JMP + BPF_JEQ + BPF_K, c, jt, jf);
#elif defined(BITS64)
  EXPECT_EQ_BLOCK(&comp_jeq[0], BPF_JMP + BPF_JEQ + BPF_K, 0, 0, jf + 2);
  EXPECT_EQ_STMT(&comp_jeq[1], BPF_LD + BPF_MEM, 0);
  EXPECT_EQ_BLOCK(&comp_jeq[2], BPF_JMP + BPF_JEQ + BPF_K, c, jt, jf);
#endif
}

TEST(bpf, bpf_comp_jset) {
  struct sock_filter comp_jset[BPF_COMP_LEN];
  unsigned long mask = O_WRONLY;
  unsigned char jt = 1;
  unsigned char jf = 2;

  size_t len = bpf_comp_jset(comp_jset, mask, jt, jf);

  EXPECT_EQ(len, BPF_COMP_LEN);

#if defined(BITS32)
  EXPECT_EQ_BLOCK(&comp_jset[0], BPF_JMP + BPF_JSET + BPF_K, mask, jt, jf);
#elif defined(BITS64)
  EXPECT_EQ_BLOCK(&comp_jset[0], BPF_JMP + BPF_JSET + BPF_K, 0, jt + 2, 0);
  EXPECT_EQ_STMT(&comp_jset[1], BPF_LD + BPF_MEM, 0);
  EXPECT_EQ_BLOCK(&comp_jset[2], BPF_JMP + BPF_JSET + BPF_K, mask, jt, jf);
#endif
}

TEST(bpf, bpf_arg_comp) {
  struct sock_filter *arg_comp;
  int op = EQ;
  int argidx = 1;
  unsigned long c = 3;
  unsigned int label_id = 0;

  size_t len = bpf_arg_comp(&arg_comp, op, argidx, c, label_id);

  EXPECT_EQ(len, BPF_ARG_COMP_LEN + 1);

#if defined(BITS32)
  EXPECT_EQ_STMT(&arg_comp[0], BPF_LD + BPF_W + BPF_ABS, LO_ARG(argidx));
  EXPECT_EQ_BLOCK(&arg_comp[1], BPF_JMP + BPF_JEQ + BPF_K, c, 1, 0);
  EXPECT_JUMP_LBL(&arg_comp[2]);
#elif defined(BITS64)
  EXPECT_EQ_STMT(&arg_comp[0], BPF_LD + BPF_W + BPF_ABS, LO_ARG(argidx));
  EXPECT_EQ_STMT(&arg_comp[1], BPF_ST, 0);
  EXPECT_EQ_STMT(&arg_comp[2], BPF_LD + BPF_W + BPF_ABS, HI_ARG(argidx));
  EXPECT_EQ_STMT(&arg_comp[3], BPF_ST, 1);

  EXPECT_EQ_BLOCK(&arg_comp[4], BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 2);
  EXPECT_EQ_STMT(&arg_comp[5], BPF_LD + BPF_MEM, 0);
  EXPECT_EQ_BLOCK(&arg_comp[6], BPF_JMP + BPF_JEQ + BPF_K, c, 1, 0);
  EXPECT_JUMP_LBL(&arg_comp[7]);
#endif
  free(arg_comp);
}

TEST(bpf, bpf_validate_arch) {
  struct sock_filter validate_arch[ARCH_VALIDATION_LEN];

  size_t len = bpf_validate_arch(validate_arch);

  EXPECT_EQ(len, ARCH_VALIDATION_LEN);
  EXPECT_ARCH_VALIDATION(validate_arch);
}

TEST(bpf, bpf_allow_syscall) {
  struct sock_filter allow_syscall[ALLOW_SYSCALL_LEN];
  int nr = 1;

  size_t len = bpf_allow_syscall(allow_syscall, nr);

  EXPECT_EQ(len, ALLOW_SYSCALL_LEN);
  EXPECT_ALLOW_SYSCALL(allow_syscall, nr);
}

TEST(bpf, bpf_allow_syscall_args) {
  struct sock_filter allow_syscall[ALLOW_SYSCALL_LEN];
  int nr = 1;
  unsigned int id = 1024;

  size_t len = bpf_allow_syscall_args(allow_syscall, nr, id);

  EXPECT_EQ(len, ALLOW_SYSCALL_LEN);
  EXPECT_ALLOW_SYSCALL_ARGS(allow_syscall, nr, id, JUMP_JT, JUMP_JF);
}

class ArgFilterTest : public ::testing::Test {
 protected:
  virtual void TearDown() { free_label_strings(&labels_); }
  struct bpf_labels labels_;
};

TEST_F(ArgFilterTest, arg0_equals) {
  const char *fragment = "arg0 == 0";
  int nr = 1;
  unsigned int id = 0;
  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);

  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = block->next;
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, arg0_mask) {
  const char *fragment = "arg1 & O_RDWR";
  int nr = 1;
  unsigned int id = 0;
  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);

  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = block->next;
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, arg0_eq_mask) {
  const char *fragment = "arg1 == O_WRONLY|O_CREAT";
  int nr = 1;
  unsigned int id = 0;

  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);

  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);
  EXPECT_EQ(curr_block->instrs[BPF_ARG_COMP_LEN - 1].k,
            (unsigned int)(O_WRONLY | O_CREAT));

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, and_or) {
  const char *fragment = "arg0 == 0 && arg1 == 0 || arg0 == 1";
  int nr = 1;
  unsigned int id = 0;

  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);
  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + 3 * (BPF_ARG_COMP_LEN + 1) + 2 + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Third block is a comparison ("arg1 == 0"). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Fourth block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Fifth block is a comparison ("arg0 == 1"). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Sixth block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Seventh block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_KILL(curr_block);

  /* Eigth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, ret_errno) {
  const char *fragment = "arg0 == 0 || arg0 == 1; return 1";
  int nr = 1;
  unsigned int id = 0;

  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);
  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + 2 * (BPF_ARG_COMP_LEN + 1) + 2 + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is a comparison ("arg0 == 1"). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Fifth block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Sixth block is SECCOMP_RET_ERRNO. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_EQ_STMT(curr_block->instrs,
                 BPF_RET + BPF_K,
                 SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));

  /* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, unconditional_errno) {
  const char *fragment = "return 1";
  int nr = 1;
  unsigned int id = 0;

  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);
  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is SECCOMP_RET_ERRNO. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_EQ_STMT(curr_block->instrs,
                 BPF_RET + BPF_K,
                 SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, invalid) {
  const char *fragment = "argnn == 0";
  int nr = 1;
  unsigned int id = 0;

  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);
  ASSERT_TRUE(block == NULL);

  fragment = "arg0 == 0 && arg1 == 1; return errno";
  block = compile_section(nr, fragment, id, &labels_, NO_LOGGING);
  ASSERT_TRUE(block == NULL);
}

TEST_F(ArgFilterTest, log_no_ret_error) {
  const char *fragment = "arg0 == 0";
  int nr = 1;
  unsigned int id = 0;
  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, USE_LOGGING);

  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_TRAP, with no errno. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_TRAP(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, log_bad_ret_error) {
  const char *fragment = "arg0 == 0; return";
  int nr = 1;
  unsigned int id = 0;

  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, NO_LOGGING);
  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /*
   * Sixth block is NOT SECCOMP_RET_ERRNO, it should be SECCOMP_RET_KILL.
   */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_KILL(curr_block);

  /* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

TEST_F(ArgFilterTest, no_log_bad_ret_error) {
  const char *fragment = "arg0 == 0; return";
  int nr = 1;
  unsigned int id = 0;

  struct filter_block *block =
      compile_section(nr, fragment, id, &labels_, USE_LOGGING);
  ASSERT_TRUE(block != NULL);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_EQ(block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_GROUP_END(curr_block);

  /*
   * Sixth block is *not* SECCOMP_RET_ERRNO, it should be
   * SECCOMP_RET_TRAP.
   */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_TRAP(curr_block);

  /* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_TRUE(curr_block != NULL);
  EXPECT_ALLOW(curr_block);

  EXPECT_TRUE(curr_block->next == NULL);

  free_block_list(block);
}

FILE *write_policy_to_pipe(const char *policy, size_t len) {
  int pipefd[2];
  if (pipe(pipefd) == -1) {
    pwarn("pipe(pipefd) failed");
    return NULL;
  }

  size_t i = 0;
  unsigned int attempts = 0;
  ssize_t ret;
  while (i < len) {
    ret = write(pipefd[1], &policy[i], len - i);
    if (ret == -1) {
      close(pipefd[0]);
      close(pipefd[1]);
      return NULL;
    }

    /* If we write 0 bytes three times in a row, fail. */
    if (ret == 0) {
      if (++attempts >= 3) {
        close(pipefd[0]);
        close(pipefd[1]);
        warn("write() returned 0 three times in a row");
        return NULL;
      }
      continue;
    }

    attempts = 0;
    i += (size_t)ret;
  }

  close(pipefd[1]);
  return fdopen(pipefd[0], "r");
}

TEST(FilterTest, seccomp_mode1) {
  struct sock_fprog actual;
  const char *policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE *policy_file = write_policy_to_pipe(policy, strlen(policy));
  ASSERT_TRUE(policy_file != NULL);

  int res = compile_filter(policy_file, &actual, USE_RET_KILL, NO_LOGGING);
  fclose(policy_file);

  /*
   * Checks return value, filter length, and that the filter
   * validates arch, loads syscall number, and
   * only allows expected syscalls.
   */
  ASSERT_EQ(res, 0);
  EXPECT_EQ(actual.len, 13);
  EXPECT_ARCH_VALIDATION(actual.filter);
  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN,
                 BPF_LD + BPF_W + BPF_ABS,
                 syscall_nr);
  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read);
  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 3, __NR_write);
  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
                       __NR_rt_sigreturn);
  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9,
                 BPF_RET + BPF_K,
                 SECCOMP_RET_KILL);

  free(actual.filter);
}

TEST(FilterTest, seccomp_mode1_trap) {
  struct sock_fprog actual;
  const char *policy =
    "read: 1\n"
    "write: 1\n"
    "rt_sigreturn: 1\n"
    "exit: 1\n";

  FILE *policy_file = write_policy_to_pipe(policy, strlen(policy));
  ASSERT_TRUE(policy_file != NULL);

  int res = compile_filter(policy_file, &actual, USE_RET_TRAP, NO_LOGGING);
  fclose(policy_file);

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
      SECCOMP_RET_TRAP);

  free(actual.filter);
}

TEST(FilterTest, seccomp_read_write) {
  struct sock_fprog actual;
  const char *policy =
      "read: arg0 == 0\n"
      "write: arg0 == 1 || arg0 == 2\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE *policy_file = write_policy_to_pipe(policy, strlen(policy));
  ASSERT_TRUE(policy_file != NULL);

  int res = compile_filter(policy_file, &actual, USE_RET_KILL, NO_LOGGING);
  fclose(policy_file);

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
                 BPF_LD + BPF_W + BPF_ABS,
                 syscall_nr);
  EXPECT_ALLOW_SYSCALL_ARGS(
      actual.filter + ARCH_VALIDATION_LEN + 1, __NR_read, 7, 0, 0);
  EXPECT_ALLOW_SYSCALL_ARGS(actual.filter + ARCH_VALIDATION_LEN + 3,
                            __NR_write,
                            12 + BPF_ARG_COMP_LEN,
                            0,
                            0);
  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 5,
                       __NR_rt_sigreturn);
  EXPECT_ALLOW_SYSCALL(actual.filter + ARCH_VALIDATION_LEN + 7, __NR_exit);
  EXPECT_EQ_STMT(actual.filter + ARCH_VALIDATION_LEN + 9,
                 BPF_RET + BPF_K,
                 SECCOMP_RET_KILL);

  free(actual.filter);
}

TEST(FilterTest, invalid_name) {
  struct sock_fprog actual;
  const char *policy = "notasyscall: 1\n";

  FILE *policy_file = write_policy_to_pipe(policy, strlen(policy));
  ASSERT_TRUE(policy_file != NULL);

  int res = compile_filter(policy_file, &actual, 0, NO_LOGGING);
  fclose(policy_file);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, invalid_arg) {
  struct sock_fprog actual;
  const char *policy = "open: argnn ==\n";

  FILE *policy_file = write_policy_to_pipe(policy, strlen(policy));
  ASSERT_TRUE(policy_file != NULL);

  int res = compile_filter(policy_file, &actual, 0, NO_LOGGING);
  fclose(policy_file);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, nonexistent) {
  struct sock_fprog actual;
  int res = compile_filter(NULL, &actual, 0, NO_LOGGING);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, log) {
  struct sock_fprog actual;
  const char *policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE *policy_file = write_policy_to_pipe(policy, strlen(policy));
  ASSERT_TRUE(policy_file != NULL);

  int res = compile_filter(policy_file, &actual, USE_RET_TRAP, USE_LOGGING);
  fclose(policy_file);

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
                 BPF_LD + BPF_W + BPF_ABS,
                 syscall_nr);

  index = ARCH_VALIDATION_LEN + 1;
  for (i = 0; i < log_syscalls_len; i++)
    EXPECT_ALLOW_SYSCALL(actual.filter + (index + 2 * i),
                         lookup_syscall(log_syscalls[i]));

  index += 2 * log_syscalls_len;

  EXPECT_ALLOW_SYSCALL(actual.filter + index, __NR_read);
  EXPECT_ALLOW_SYSCALL(actual.filter + index + 2, __NR_write);
  EXPECT_ALLOW_SYSCALL(actual.filter + index + 4, __NR_rt_sigreturn);
  EXPECT_ALLOW_SYSCALL(actual.filter + index + 6, __NR_exit);
  EXPECT_EQ_STMT(actual.filter + index + 8, BPF_RET + BPF_K, SECCOMP_RET_TRAP);

  free(actual.filter);
}

TEST(FilterTest, allow_log_but_kill) {
  struct sock_fprog actual;
  const char *policy =
    "read: 1\n"
    "write: 1\n"
    "rt_sigreturn: 1\n"
    "exit: 1\n";

  FILE *policy_file = write_policy_to_pipe(policy, strlen(policy));
  ASSERT_TRUE(policy_file != NULL);

  int res = compile_filter(policy_file, &actual, USE_RET_KILL, USE_LOGGING);
  fclose(policy_file);

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
      SECCOMP_RET_KILL);

  free(actual.filter);
}
