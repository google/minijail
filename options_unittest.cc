// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tests for minijail::Options
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
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, MountsWithoutVfs) {
  // Set up the case in need of correction
  EXPECT_CALL(*options_, add_readonly_mounts())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, namespace_vfs())
    .Times(1)
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, set_namespace_vfs(true))  // Proof of correction
    .Times(1);
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, MountsWithVfs) {
  // Setup case which should be untouched
  EXPECT_CALL(*options_, add_readonly_mounts())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, namespace_vfs())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, set_namespace_vfs(_))  // Proof of correction
    .Times(0);
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, NoMounts) {
  // Setup case which should be untouched
  EXPECT_CALL(*options_, add_readonly_mounts())
    .Times(1)
    .WillOnce(Return(false));
  // VFS check should never be run since the conditional short circuits
  EXPECT_CALL(*options_, namespace_vfs())
    .Times(0);
  EXPECT_CALL(*options_, set_namespace_vfs(_))
    .Times(0);
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, BothSyscallEnforcements) {
  // Case which fails
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, enforce_syscalls_by_source())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_FALSE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, SyscallBenchmarkOnly) {
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, enforce_syscalls_by_source())
    .Times(1)
    .WillOnce(Return(false));
  EXPECT_TRUE(options_->FixUpDependencies());
}

TEST_F(OptionsDepsTest, SyscallNoBenchmark) {
  EXPECT_CALL(*options_, enforce_syscalls_benchmark())
    .Times(1)
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, enforce_syscalls_by_source())
    .Times(0);
  EXPECT_TRUE(options_->FixUpDependencies());
}







}  // namespace chromeos
