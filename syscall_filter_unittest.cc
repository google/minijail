/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test syscall filtering using gtest.
 */

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h> /* For O_WRONLY. */

#include <gtest/gtest.h>
#include <string>

#include "bpf.h"
#include "syscall_filter.h"
#include "syscall_filter_unittest_macros.h"
#include "test_util.h"
#include "util.h"

namespace {

// Simple C++ -> C wrappers to simplify test code.

enum ret_trap {
  USE_RET_KILL = 0,
  USE_RET_TRAP = 1,
};

enum use_logging {
  NO_LOGGING          = 0,
  USE_SIGSYS_LOGGING  = 1,
  USE_RET_LOG_LOGGING = 2,
};

int test_compile_filter(
    const std::string& filename,
    FILE* policy_file,
    struct sock_fprog* prog,
    enum block_action action = ACTION_RET_KILL,
    enum use_logging allow_logging = NO_LOGGING,
    bool allow_dup_syscalls = true) {
  struct filter_options filteropts {
    .action = action,
    .allow_logging = allow_logging != NO_LOGGING,
    .allow_syscalls_for_logging = allow_logging == USE_SIGSYS_LOGGING,
    .allow_duplicate_syscalls = allow_dup_syscalls,
  };
  return compile_filter(filename.c_str(), policy_file, prog, &filteropts);
}

int test_compile_file(
    std::string filename,
    FILE* policy_file,
    struct filter_block* head,
    struct filter_block** arg_blocks,
    struct bpf_labels* labels,
    enum block_action action = ACTION_RET_KILL,
    enum use_logging allow_logging = NO_LOGGING,
    unsigned int include_level = 0,
    bool allow_dup_syscalls = false) {
  struct filter_options filteropts {
    .action = action,
    .allow_logging = allow_logging != NO_LOGGING,
    .allow_syscalls_for_logging = allow_logging == USE_SIGSYS_LOGGING,
    .allow_duplicate_syscalls = allow_dup_syscalls,
  };
  size_t num_syscalls = get_num_syscalls();
  struct parser_state **previous_syscalls =
      (struct parser_state **)calloc(num_syscalls,
                                     sizeof(struct parser_state *));
  int res = compile_file(filename.c_str(), policy_file, head, arg_blocks,
                         labels, &filteropts, previous_syscalls,
                         include_level);
  free_previous_syscalls(previous_syscalls);
  return res;
}

struct filter_block* test_compile_policy_line(
    struct parser_state* state,
    int nr,
    const std::string& policy_line,
    unsigned int label_id,
    struct bpf_labels* labels,
    enum block_action action = ACTION_RET_KILL) {
  return compile_policy_line(state, nr, policy_line.c_str(), label_id,
           labels, action);
}

}  // namespace

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
  const int argidx = 1;
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
  unsigned long mask = (1UL << (sizeof(unsigned long) * 8 - 1)) | O_WRONLY;
  unsigned char jt = 1;
  unsigned char jf = 2;

  size_t len = bpf_comp_jset(comp_jset, mask, jt, jf);

  EXPECT_EQ(len, BPF_COMP_LEN);

#if defined(BITS32)
  EXPECT_EQ_BLOCK(&comp_jset[0], BPF_JMP + BPF_JSET + BPF_K, mask, jt, jf);
#elif defined(BITS64)
  EXPECT_EQ_BLOCK(
      &comp_jset[0], BPF_JMP + BPF_JSET + BPF_K, 0x80000000, jt + 2, 0);
  EXPECT_EQ_STMT(&comp_jset[1], BPF_LD + BPF_MEM, 0);
  EXPECT_EQ_BLOCK(&comp_jset[2], BPF_JMP + BPF_JSET + BPF_K, O_WRONLY, jt, jf);
#endif
}

TEST(bpf, bpf_comp_jin) {
  struct sock_filter comp_jin[BPF_COMP_LEN];
  unsigned long mask = (1UL << (sizeof(unsigned long) * 8 - 1)) | O_WRONLY;
  unsigned char jt = 10;
  unsigned char jf = 20;

  size_t len = bpf_comp_jin(comp_jin, mask, jt, jf);

  EXPECT_EQ(len, BPF_COMP_LEN);

#if defined(BITS32)
  EXPECT_EQ_BLOCK(&comp_jin[0], BPF_JMP + BPF_JSET + BPF_K, ~mask, jf, jt);
#elif defined(BITS64)
  EXPECT_EQ_BLOCK(
      &comp_jin[0], BPF_JMP + BPF_JSET + BPF_K, 0x7FFFFFFF, jf + 2, 0);
  EXPECT_EQ_STMT(&comp_jin[1], BPF_LD + BPF_MEM, 0);
  EXPECT_EQ_BLOCK(&comp_jin[2], BPF_JMP + BPF_JSET + BPF_K, ~O_WRONLY, jf, jt);
#endif
}

TEST(bpf, bpf_arg_comp) {
  struct sock_filter *arg_comp;
  int op = EQ;
  const int argidx = 1;
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

class BpfLabelTest : public ::testing::Test {
 protected:
  virtual void SetUp() { labels_.count = 0; }
  virtual void TearDown() { free_label_strings(&labels_); }
  struct bpf_labels labels_;
};

TEST_F(BpfLabelTest, zero_length_filter) {
  int res = bpf_resolve_jumps(&labels_, nullptr, 0);

  EXPECT_EQ(res, 0);
  EXPECT_EQ(labels_.count, 0U);
}

TEST_F(BpfLabelTest, single_label) {
  struct sock_filter test_label[1];

  int id = bpf_label_id(&labels_, "test");
  set_bpf_lbl(test_label, id);
  int res = bpf_resolve_jumps(&labels_, test_label, 1);

  EXPECT_EQ(res, 0);
  EXPECT_EQ(labels_.count, 1U);
}

TEST_F(BpfLabelTest, repeated_label) {
  struct sock_filter test_label[2];

  int id = bpf_label_id(&labels_, "test");
  set_bpf_lbl(&test_label[0], id);
  set_bpf_lbl(&test_label[1], id);
  int res = bpf_resolve_jumps(&labels_, test_label, 2);

  EXPECT_EQ(res, -1);
}

TEST_F(BpfLabelTest, jump_with_no_label) {
  struct sock_filter test_jump[1];

  set_bpf_jump_lbl(test_jump, 14831);
  int res = bpf_resolve_jumps(&labels_, test_jump, 1);

  EXPECT_EQ(res, -1);
}

TEST_F(BpfLabelTest, jump_to_valid_label) {
  struct sock_filter test_jump[2];

  int id = bpf_label_id(&labels_, "test");
  set_bpf_jump_lbl(&test_jump[0], id);
  set_bpf_lbl(&test_jump[1], id);

  int res = bpf_resolve_jumps(&labels_, test_jump, 2);
  EXPECT_EQ(res, 0);
  EXPECT_EQ(labels_.count, 1U);
}

TEST_F(BpfLabelTest, jump_to_invalid_label) {
  struct sock_filter test_jump[2];

  int id = bpf_label_id(&labels_, "test");
  set_bpf_jump_lbl(&test_jump[0], id + 1);
  set_bpf_lbl(&test_jump[1], id);

  int res = bpf_resolve_jumps(&labels_, test_jump, 2);
  EXPECT_EQ(res, -1);
}

TEST_F(BpfLabelTest, jump_to_unresolved_label) {
  struct sock_filter test_jump[2];

  int id = bpf_label_id(&labels_, "test");
  /* Notice the order of the instructions is reversed. */
  set_bpf_lbl(&test_jump[0], id);
  set_bpf_jump_lbl(&test_jump[1], id);

  int res = bpf_resolve_jumps(&labels_, test_jump, 2);
  EXPECT_EQ(res, -1);
}

TEST_F(BpfLabelTest, too_many_labels) {
  unsigned int i;
  char label[20];

  for (i = 0; i < BPF_LABELS_MAX; i++) {
    snprintf(label, 20, "test%u", i);
    (void) bpf_label_id(&labels_, label);
  }
  int id = bpf_label_id(&labels_, "test");

  /* Insertion failed... */
  EXPECT_EQ(id, -1);
  /* ... because the label lookup table is full. */
  EXPECT_EQ(labels_.count, BPF_LABELS_MAX);
}

class ArgFilterTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    labels_.count = 0;
    state_.filename = "policy";
    state_.line_number = 1;
  }
  virtual void TearDown() { free_label_strings(&labels_); }
  struct bpf_labels labels_;
  int nr_ = 1;
  unsigned int id_ = 0;
  struct parser_state state_;
};

TEST_F(ArgFilterTest, empty_atom) {
  std::string fragment = "";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, whitespace_atom) {
  std::string fragment = "\t    ";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, no_comparison) {
  std::string fragment = "arg0";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, no_constant) {
  std::string fragment = "arg0 ==";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, arg0_equals) {
  std::string fragment = "arg0 == 0";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);

  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, arg0_equals_trap) {
  std::string fragment = "arg0 == 0";

  struct filter_block* block = test_compile_policy_line(
      &state_, nr_, fragment, id_, &labels_, ACTION_RET_TRAP);

  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block* curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_TRAP. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_TRAP(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, arg0_equals_log) {
  std::string fragment = "arg0 == 0";

  struct filter_block* block = test_compile_policy_line(
      &state_, nr_, fragment, id_, &labels_, ACTION_RET_LOG);

  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block* curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_LOG. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_LOG(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, arg0_short_gt_ge_comparisons) {
  for (const std::string fragment :
       {"arg1 < 0xff", "arg1 <= 0xff", "arg1 > 0xff", "arg1 >= 0xff"}) {
    struct filter_block* block =
        test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);

    ASSERT_NE(block, nullptr);
    size_t exp_total_len = 1 + (BPF_ARG_SHORT_GT_GE_COMP_LEN + 1) + 2 + 1 + 2;
    EXPECT_EQ(block->total_len, exp_total_len);

    // First block is a label.
    struct filter_block* curr_block = block;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_EQ(curr_block->len, 1U);
    EXPECT_LBL(curr_block->instrs);

    // Second block is a short gt/ge comparison.
    curr_block = curr_block->next;
    EXPECT_SHORT_GT_GE_COMP(curr_block);

    // Third block is a jump and a label (end of AND group).
    curr_block = curr_block->next;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_GROUP_END(curr_block);

    // Fourth block is SECCOMP_RET_KILL.
    curr_block = curr_block->next;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_KILL(curr_block);

    // Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW.
    curr_block = curr_block->next;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_ALLOW(curr_block);

    EXPECT_EQ(curr_block->next, nullptr);

    free_block_list(block);
  }
}

#if defined(BITS64)
TEST_F(ArgFilterTest, arg0_long_gt_ge_comparisons) {
  for (const std::string fragment :
       {"arg1 < 0xbadc0ffee0ddf00d", "arg1 <= 0xbadc0ffee0ddf00d",
        "arg1 > 0xbadc0ffee0ddf00d", "arg1 >= 0xbadc0ffee0ddf00d"}) {
    struct filter_block* block =
        test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);

    ASSERT_NE(block, nullptr);
    size_t exp_total_len = 1 + (BPF_ARG_GT_GE_COMP_LEN + 1) + 2 + 1 + 2;
    EXPECT_EQ(block->total_len, exp_total_len);

    // First block is a label.
    struct filter_block* curr_block = block;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_EQ(curr_block->len, 1U);
    EXPECT_LBL(curr_block->instrs);

    // Second block is a gt/ge comparison.
    curr_block = curr_block->next;
    EXPECT_GT_GE_COMP(curr_block);

    // Third block is a jump and a label (end of AND group).
    curr_block = curr_block->next;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_GROUP_END(curr_block);

    // Fourth block is SECCOMP_RET_KILL.
    curr_block = curr_block->next;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_KILL(curr_block);

    // Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW.
    curr_block = curr_block->next;
    ASSERT_NE(curr_block, nullptr);
    EXPECT_ALLOW(curr_block);

    EXPECT_EQ(curr_block->next, nullptr);

    free_block_list(block);
  }
}
#endif

TEST_F(ArgFilterTest, arg0_mask) {
  std::string fragment = "arg1 & O_RDWR";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);

  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, arg0_flag_set_inclusion) {
  std::string fragment = "arg0 in O_RDONLY|O_CREAT";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);

  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, arg0_eq_mask) {
  std::string fragment = "arg1 == O_WRONLY|O_CREAT";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);

  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);
  EXPECT_EQ(curr_block->instrs[BPF_ARG_COMP_LEN - 1].k,
            (unsigned int)(O_WRONLY | O_CREAT));

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, and_or) {
  std::string fragment = "arg0 == 0 && arg1 == 0 || arg0 == 1";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + 3 * (BPF_ARG_COMP_LEN + 1) + 2 + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Third block is a comparison ("arg1 == 0"). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Fourth block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fifth block is a comparison ("arg0 == 1"). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Sixth block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Seventh block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_KILL(curr_block);

  /* Eigth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, ret_errno) {
  std::string fragment = "arg0 == 0 || arg0 == 1; return 1";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + 2 * (BPF_ARG_COMP_LEN + 1) + 2 + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is a comparison ("arg0 == 1"). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Fifth block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Sixth block is SECCOMP_RET_ERRNO. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_EQ_STMT(curr_block->instrs,
                 BPF_RET + BPF_K,
                 SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));

  /* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, unconditional_errno) {
  std::string fragment = "return 1";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is SECCOMP_RET_ERRNO. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_EQ_STMT(curr_block->instrs,
                 BPF_RET + BPF_K,
                 SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA));

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, invalid_arg_token) {
  std::string fragment = "org0 == 0";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, invalid_arg_number) {
  std::string fragment = "argnn == 0";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, extra_chars_in_arg_token) {
  std::string fragment = "arg0n == 0";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, invalid_operator) {
  std::string fragment = "arg0 invalidop 0";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, invalid_constant) {
  std::string fragment = "arg0 == INVALIDCONSTANT";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, extra_tokens) {
  std::string fragment = "arg0 == 0 EXTRATOKEN";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, invalid_errno) {
  std::string fragment = "arg0 == 0 && arg1 == 1; return errno";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_EQ(block, nullptr);
}

TEST_F(ArgFilterTest, log_no_ret_error) {
  std::string fragment = "arg0 == 0";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_,
                               ACTION_RET_TRAP);

  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_TRAP, with no errno. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_TRAP(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, log_bad_ret_error) {
  std::string fragment = "arg0 == 0; return";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_);
  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /*
   * Sixth block is NOT SECCOMP_RET_ERRNO, it should be SECCOMP_RET_KILL.
   */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_KILL(curr_block);

  /* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

TEST_F(ArgFilterTest, no_log_bad_ret_error) {
  std::string fragment = "arg0 == 0; return";

  struct filter_block* block =
      test_compile_policy_line(&state_, nr_, fragment, id_, &labels_,
                               ACTION_RET_TRAP);
  ASSERT_NE(block, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(block->total_len, exp_total_len);

  /* First block is a label. */
  struct filter_block *curr_block = block;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_LBL(curr_block->instrs);

  /* Second block is a comparison ("arg0 == 0"). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /*
   * Sixth block is *not* SECCOMP_RET_ERRNO, it should be
   * SECCOMP_RET_TRAP.
   */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_TRAP(curr_block);

  /* Seventh block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);

  free_block_list(block);
}

namespace {

class FileTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    labels_.count = 0;
    head_ = new_filter_block();
    arg_blocks_ = nullptr;
  }
  virtual void TearDown() {
    free_label_strings(&labels_);
    free_block_list(head_);
    free_block_list(arg_blocks_);
  }
  struct bpf_labels labels_;
  struct filter_block *head_;
  struct filter_block *arg_blocks_;
};

}  // namespace

TEST_F(FileTest, malformed_policy) {
  std::string policy =
      "malformed";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
                              &labels_);
  fclose(policy_file);

  /*
   * Policy is malformed, but process should not crash.
   */
  ASSERT_EQ(res, -1);
}

TEST_F(FileTest, double_free_on_compile_error) {
  std::string policy =
      "read:arg0 == 0\n"
      "write:0";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
                              &labels_);
  fclose(policy_file);

  /*
   * Policy is malformed, but process should not crash.
   */
  ASSERT_EQ(res, -1);
}

TEST_F(FileTest, invalid_return) {
  std::string policy =
      "read:arg0 == 0; ;";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
                              &labels_);
  fclose(policy_file);

  /*
   * Policy is malformed, but process should not crash.
   */
  ASSERT_EQ(res, -1);
}

TEST_F(FileTest, seccomp_mode1) {
  std::string policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
                              &labels_);
  fclose(policy_file);

  /*
   * Checks return value and that the blocks only allow expected syscalls.
   */
  ASSERT_EQ(res, 0);
  struct filter_block *curr_block = head_;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_read);
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_write);
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_rt_sigreturn);
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_exit);

  EXPECT_EQ(curr_block->next, nullptr);
}

TEST_F(FileTest, seccomp_read) {
  std::string policy =
      "read: arg0 == 0\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  const int LABEL_ID = 0;

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
                              &labels_);
  fclose(policy_file);

  /*
   * Checks return value, that the blocks only allow expected syscalls, and that
   * labels between |head_| and |arg_blocks_| match.
   */
  ASSERT_EQ(res, 0);
  struct filter_block *curr_block = head_;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL_ARGS(curr_block->instrs,
                            __NR_read,
                            LABEL_ID,
                            JUMP_JT,
                            JUMP_JF);
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_write);
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_rt_sigreturn);
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_exit);

  ASSERT_NE(arg_blocks_, nullptr);
  size_t exp_total_len = 1 + (BPF_ARG_COMP_LEN + 1) + 2 + 1 + 2;
  EXPECT_EQ(arg_blocks_->total_len, exp_total_len);

  /* First block is a label. */
  curr_block = arg_blocks_;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_EQ(curr_block->len, 1U);
  EXPECT_ACTUAL_LBL(curr_block->instrs, LABEL_ID);

  /* Second block is a comparison. */
  curr_block = curr_block->next;
  EXPECT_COMP(curr_block);

  /* Third block is a jump and a label (end of AND group). */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_GROUP_END(curr_block);

  /* Fourth block is SECCOMP_RET_KILL. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_KILL(curr_block);

  /* Fifth block is "SUCCESS" label and SECCOMP_RET_ALLOW. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW(curr_block);

  EXPECT_EQ(curr_block->next, nullptr);
}

TEST_F(FileTest, multiline) {
  std::string policy =
      "read:\\\n1\n"
      "openat:arg0 \\\nin\\\n   \\\n5";

  const int LABEL_ID = 0;

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_file("policy", policy_file, head_, &arg_blocks_,
                              &labels_);
  fclose(policy_file);

  /*
   * Policy should be valid.
   */
  ASSERT_EQ(res, 0);

  /* First block is the read. */
  struct filter_block *curr_block = head_;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL(curr_block->instrs, __NR_read);

  /* Second block is the open. */
  curr_block = curr_block->next;
  ASSERT_NE(curr_block, nullptr);
  EXPECT_ALLOW_SYSCALL_ARGS(curr_block->instrs,
                            __NR_openat,
                            LABEL_ID,
                            JUMP_JT,
                            JUMP_JF);

  EXPECT_EQ(curr_block->next, nullptr);
}

TEST(FilterTest, seccomp_mode1) {
  struct sock_fprog actual;
  std::string policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
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

TEST(FilterTest, seccomp_mode1_with_check) {
  struct sock_fprog actual;
  std::string policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual,
                                ACTION_RET_KILL, NO_LOGGING, false
                                /* allow duplicate syscalls */);
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

/*
 * This fails even with allow_duplicate_syscalls set to true because the
 * creation of labels for the arguments causes conflicts which cause the
 * compile_filter function to fail.
 */
TEST(FilterTest, duplicate_read_with_args) {
  struct sock_fprog actual;
  std::string policy =
      "read: arg0 == 0\n"
      "read: arg1 == 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  ASSERT_EQ(res, -1);
}

/*
 * This does not fail because only one instance of read defines an argument.
 */
TEST(FilterTest, duplicate_read_with_one_arg) {
  struct sock_fprog actual;
  std::string policy =
      "read: arg0 == 0\n"
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  /* TODO: Don't know how to generate a correct value to validate the filter
   * that is generated. */
  ASSERT_EQ(res, 0);
  free(actual.filter);
}

TEST(FilterTest, seccomp_mode1_trap) {
  struct sock_fprog actual;
  std::string policy =
    "read: 1\n"
    "write: 1\n"
    "rt_sigreturn: 1\n"
    "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res =
      test_compile_filter("policy", policy_file, &actual, ACTION_RET_TRAP);
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

TEST(FilterTest, seccomp_mode1_log) {
  struct sock_fprog actual;
  std::string policy =
    "read: 1\n"
    "write: 1\n"
    "rt_sigreturn: 1\n"
    "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_LOG,
                                USE_RET_LOG_LOGGING);
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
      SECCOMP_RET_LOG);

  free(actual.filter);
}

TEST(FilterTest, seccomp_mode1_log_fails) {
  struct sock_fprog actual;
  std::string policy =
    "read: 1\n"
    "write: 1\n"
    "rt_sigreturn: 1\n"
    "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_LOG,
                                NO_LOGGING);
  fclose(policy_file);

  /*
   * ACTION_RET_LOG should never be used without allowing logging.
   */
  ASSERT_EQ(res, -1);
}

TEST(FilterTest, seccomp_mode1_ret_kill_process) {
  struct sock_fprog actual;
  std::string policy =
    "read: 1\n"
    "write: 1\n"
    "rt_sigreturn: 1\n"
    "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_KILL_PROCESS,
                                NO_LOGGING);
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
      SECCOMP_RET_KILL_PROCESS);

  free(actual.filter);
}

TEST(FilterTest, seccomp_read_write) {
  struct sock_fprog actual;
  std::string policy =
      "read: arg0 == 0\n"
      "write: arg0 == 1 || arg0 == 2\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
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

TEST(FilterTest, misplaced_whitespace) {
  struct sock_fprog actual;
  std::string policy = "read :1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  /* Checks return value and filter length. */
  ASSERT_EQ(res, 0);
  EXPECT_EQ(actual.len,
            ARCH_VALIDATION_LEN + 1 /* load syscall nr */ + ALLOW_SYSCALL_LEN +
                1 /* ret kill */);
  free(actual.filter);
}

TEST(FilterTest, missing_atom) {
  struct sock_fprog actual;
  std::string policy = "open:\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, whitespace_atom) {
  struct sock_fprog actual;
  std::string policy = "open:\t    \n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, invalid_name) {
  struct sock_fprog actual;
  std::string policy = "notasyscall: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, invalid_arg) {
  struct sock_fprog actual;
  std::string policy = "open: argnn ==\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, invalid_tokens) {
  struct sock_fprog actual;
  std::string policy = "read: arg0 == 1 |||| arg0 == 2\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, nonexistent) {
  struct sock_fprog actual;
  int res = test_compile_filter("policy", nullptr, &actual);
  ASSERT_NE(res, 0);
}

TEST(FilterTest, log) {
  struct sock_fprog actual;
  std::string policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_TRAP,
                                USE_SIGSYS_LOGGING);
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
                         lookup_syscall(log_syscalls[i], NULL));

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
  std::string policy =
    "read: 1\n"
    "write: 1\n"
    "rt_sigreturn: 1\n"
    "exit: 1\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual, ACTION_RET_KILL,
                                USE_SIGSYS_LOGGING);
  fclose(policy_file);

  size_t i;
  size_t index = 0;
  /*
   * Checks return value, filter length, and that the filter
   * validates arch, loads syscall number, only allows expected syscalls,
   * and kills on failure.
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
                         lookup_syscall(log_syscalls[i], NULL));

  index += 2 * log_syscalls_len;

  EXPECT_ALLOW_SYSCALL(actual.filter + index, __NR_read);
  EXPECT_ALLOW_SYSCALL(actual.filter + index + 2, __NR_write);
  EXPECT_ALLOW_SYSCALL(actual.filter + index + 4, __NR_rt_sigreturn);
  EXPECT_ALLOW_SYSCALL(actual.filter + index + 6, __NR_exit);
  EXPECT_EQ_STMT(actual.filter + index + 8, BPF_RET+BPF_K,
      SECCOMP_RET_KILL);

  free(actual.filter);
}

TEST(FilterTest, frequency) {
  struct sock_fprog actual;
  std::string frequency = "@frequency ./path/is/ignored.frequency\n";

  FILE* policy_file = write_to_pipe(frequency);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_EQ(res, 0);

  free(actual.filter);
}

TEST(FilterTest, include_invalid_token) {
  struct sock_fprog actual;
  std::string invalid_token = "@unclude ./test/seccomp.policy\n";

  FILE* policy_file = write_to_pipe(invalid_token);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_no_space) {
  struct sock_fprog actual;
  std::string no_space = "@includetest/seccomp.policy\n";

  FILE* policy_file = write_to_pipe(no_space);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_double_token) {
  struct sock_fprog actual;
  std::string double_token = "@includeinclude ./test/seccomp.policy\n";

  FILE* policy_file = write_to_pipe(double_token);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_no_file) {
  struct sock_fprog actual;
  std::string no_file = "@include\n";

  FILE* policy_file = write_to_pipe(no_file);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_space_no_file) {
  struct sock_fprog actual;
  std::string space_no_file = "@include \n";

  FILE* policy_file = write_to_pipe(space_no_file);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_implicit_relative_path) {
  struct sock_fprog actual;
  std::string implicit_relative_path = "@include test/seccomp.policy\n";

  FILE* policy_file = write_to_pipe(implicit_relative_path);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_extra_text) {
  struct sock_fprog actual;
  std::string extra_text = "@include /some/file: sneaky comment\n";

  FILE* policy_file = write_to_pipe(extra_text);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_split_filename) {
  struct sock_fprog actual;
  std::string split_filename = "@include /some/file:colon.policy\n";

  FILE* policy_file = write_to_pipe(split_filename);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);
  EXPECT_NE(res, 0);
}

TEST(FilterTest, include_nonexistent_file) {
  struct sock_fprog actual;
  std::string include_policy = "@include ./nonexistent.policy\n";

  FILE* policy_file = write_to_pipe(include_policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  ASSERT_NE(res, 0);
}

// TODO(jorgelo): Android unit tests don't currently support data files.
// Re-enable by creating a temporary policy file at runtime.
#if !defined(__ANDROID__)

TEST(FilterTest, include) {
  struct sock_fprog compiled_plain;
  struct sock_fprog compiled_with_include;

  std::string policy_plain =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n";

  FILE* file_plain = write_to_pipe(policy_plain);
  ASSERT_NE(file_plain, nullptr);
  int res_plain = test_compile_filter("policy", file_plain, &compiled_plain,
                                      ACTION_RET_KILL);
  fclose(file_plain);

  std::string policy_with_include =
      "@include " + source_path("test/seccomp.policy") + "\n";

  FILE* file_with_include = write_to_pipe(policy_with_include);
  ASSERT_NE(file_with_include, nullptr);
  int res_with_include = test_compile_filter(
      "policy", file_with_include, &compiled_with_include, ACTION_RET_KILL);
  fclose(file_with_include);

  /*
   * Checks that filter length is the same for a plain policy and an equivalent
   * policy with an @include statement. Also checks that the filter generated
   * from the policy with an @include statement is exactly the same as one
   * generated from a plain policy.
   */
  ASSERT_EQ(res_plain, 0);
  ASSERT_EQ(res_with_include, 0);

  EXPECT_EQ(compiled_plain.len, 13);
  EXPECT_EQ(compiled_with_include.len, 13);

  EXPECT_ARCH_VALIDATION(compiled_with_include.filter);
  EXPECT_EQ_STMT(compiled_with_include.filter + ARCH_VALIDATION_LEN,
                 BPF_LD + BPF_W + BPF_ABS,
                 syscall_nr);
  EXPECT_ALLOW_SYSCALL(compiled_with_include.filter + ARCH_VALIDATION_LEN + 1,
                       __NR_read);
  EXPECT_ALLOW_SYSCALL(compiled_with_include.filter + ARCH_VALIDATION_LEN + 3,
                       __NR_write);
  EXPECT_ALLOW_SYSCALL(compiled_with_include.filter + ARCH_VALIDATION_LEN + 5,
                       __NR_rt_sigreturn);
  EXPECT_ALLOW_SYSCALL(compiled_with_include.filter + ARCH_VALIDATION_LEN + 7,
                       __NR_exit);
  EXPECT_EQ_STMT(compiled_with_include.filter + ARCH_VALIDATION_LEN + 9,
                 BPF_RET + BPF_K,
                 SECCOMP_RET_KILL);

  free(compiled_plain.filter);
  free(compiled_with_include.filter);
}

TEST(FilterTest, include_same_syscalls) {
  struct sock_fprog actual;
  std::string policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n"
      "@include " + source_path("test/seccomp.policy") + "\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  ASSERT_EQ(res, 0);
  EXPECT_EQ(actual.len,
            ARCH_VALIDATION_LEN + 1 /* load syscall nr */ +
                2 * 8 /* check syscalls twice */ + 1 /* filter return */);
  free(actual.filter);
}

TEST(FilterTest, include_same_syscalls_with_check) {
  struct sock_fprog actual;
  std::string policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n"
      "@include " + source_path("test/seccomp.policy") + "\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual,
                                ACTION_RET_KILL, NO_LOGGING, false
                                /* allow duplicate syscalls */);
  fclose(policy_file);

  ASSERT_EQ(res, -1);
}

TEST(FilterTest, include_two) {
  struct sock_fprog actual;
  std::string policy =
      "@include " + source_path("test/seccomp.policy") + "\n" +
      "@include " + source_path("test/seccomp.policy") + "\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  ASSERT_EQ(res, 0);
  EXPECT_EQ(actual.len,
            ARCH_VALIDATION_LEN + 1 /* load syscall nr */ +
                2 * 8 /* check syscalls twice */ + 1 /* filter return */);
  free(actual.filter);
}

TEST(FilterTest, include_invalid_policy) {
  struct sock_fprog actual;
  std::string policy =
      "read: 1\n"
      "write: 1\n"
      "rt_sigreturn: 1\n"
      "exit: 1\n"
      "@include ./test/invalid_syscall_name.policy\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  /* Ensure the included (invalid) policy file exists. */
  FILE* included_file = fopen(
      source_path("test/invalid_syscall_name.policy").c_str(), "re");
  ASSERT_NE(included_file, nullptr);
  fclose(included_file);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  ASSERT_NE(res, 0);
}

TEST(FilterTest, include_nested) {
  struct sock_fprog actual;
  std::string policy = "@include ./test/nested.policy\n";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);

  /* Ensure the policy file exists. */
  FILE* included_file = fopen(source_path("test/nested.policy").c_str(), "re");
  ASSERT_NE(included_file, nullptr);
  fclose(included_file);

  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  ASSERT_NE(res, 0);
}

#endif  // !__ANDROID__

TEST(FilterTest, error_cleanup_leak) {
  struct sock_fprog actual;
  std::string policy =
      "read:&&\n"
      "read:&&";

  FILE* policy_file = write_to_pipe(policy);
  ASSERT_NE(policy_file, nullptr);
  int res = test_compile_filter("policy", policy_file, &actual);
  fclose(policy_file);

  /*
   * Policy is malformed, but process should not leak.
   */
  ASSERT_EQ(res, -1);
}
