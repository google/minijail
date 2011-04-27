// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tests for minijail::Options
#include "options.h"

#include "mock_env.h"
#include "mock_options.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace chromeos {

using ::testing::_;  // wildcard mock matcher
using ::testing::AtLeast;  // Times modifier
using ::testing::Invoke;  // Allow concrete call redirection
using ::testing::DefaultValue;  // allow for easy default return value change
using ::testing::Return;  // mock Return action

class OptionsDepsTest : public ::testing::Test {
 public:
  OptionsDepsTest() : options_(new minijail::MockOptions) { }
  ~OptionsDepsTest() { }
  void SetUp() {
    ON_CALL(*options_, FixUpDependencies())
      .WillByDefault(Invoke(options_.get(),
                            &minijail::MockOptions::OptionsFixUpDependencies));
  }
 protected:
  scoped_ptr<minijail::MockOptions> options_;
};

TEST_F(OptionsDepsTest, NothingToCorrect) {
  // Since all options default to false, this should just work.
  minijail::Options options;
  EXPECT_TRUE(options.FixUpDependencies());
}

TEST_F(OptionsDepsTest, MountsWithoutVfs) {
  EXPECT_CALL(*(options_.get()), FixUpDependencies())
      .Times(1);
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .WillOnce(Return(false));
  // Set up the case in need of correction
  EXPECT_CALL(*options_, add_readonly_mounts())
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, namespace_vfs())
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, set_namespace_vfs(true))  // Proof of correction
    .Times(1);
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, MountsWithVfs) {
  EXPECT_CALL(*(options_.get()), FixUpDependencies())
      .Times(1);
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .WillOnce(Return(false));
  // Setup case which should be untouched
  EXPECT_CALL(*options_, add_readonly_mounts())
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, namespace_vfs())
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, set_namespace_vfs(_))  // Proof of correction
    .Times(0);
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, NoMounts) {
  EXPECT_CALL(*(options_.get()), FixUpDependencies())
      .Times(1);
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .WillOnce(Return(false));
  // Setup case which should be untouched
  EXPECT_CALL(*options_, add_readonly_mounts())
    .WillOnce(Return(false));
  // VFS check should never be run since the conditional short circuits
  EXPECT_CALL(*options_, namespace_vfs())
    .Times(0);
  EXPECT_CALL(*options_, set_namespace_vfs(_))
    .Times(0);
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, BothSyscallEnforcements) {
  EXPECT_CALL(*(options_.get()), FixUpDependencies())
      .Times(1);
  // Case which fails
  EXPECT_CALL(*options_, add_readonly_mounts())
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, enforce_syscalls_by_source())
    .WillOnce(Return(true));
  EXPECT_FALSE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, SyscallBenchmarkOnly) {
  EXPECT_CALL(*(options_.get()), FixUpDependencies())
      .Times(1);
  EXPECT_CALL(*options_, add_readonly_mounts())
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, enforce_syscalls_by_source())
    .WillOnce(Return(false));
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, SyscallNoBenchmark) {
  EXPECT_CALL(*(options_.get()), FixUpDependencies())
      .Times(1);
  EXPECT_CALL(*options_, add_readonly_mounts())
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, enforce_syscalls_by_source())
    .Times(0);
  EXPECT_TRUE(options_->FixUpDependencies());
}







}  // namespace chromeos
