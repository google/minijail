// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Tests for MiniJail
#include "mock_env.h"
#include "mock_options.h"
#include "minijail.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace chromeos {

using ::testing::_;  // wildcard mock matcher
using ::testing::AtLeast;  // Times modifier
using ::testing::DefaultValue;  // allow for easy default return value change
using ::testing::Return;  // mock Return action

class MiniJailTest : public ::testing::Test {
 public:
  static const char kDummyPath[];
  void SetUp() {
    env_.reset(new minijail::MockEnv);
    options_.reset(new minijail::MockOptions);
    // Setup options to return the mock env
    EXPECT_CALL(*options_, env())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(env_.get()));
  }
  void TearDown() {
  }
 protected:
  scoped_ptr<minijail::MockEnv> env_;
  scoped_ptr<minijail::MockOptions> options_;
};

const char MiniJailTest::kDummyPath[] = "/path/to/target/binary";

TEST_F(MiniJailTest, RunGetsPath) {
  MiniJail jail;
  jail.Initialize(options_.get());

  // This will be a relative no-op since all the options are defaulting
  // to false.
  EXPECT_TRUE(jail.Jail());
  // Ensure the pre-configured dummy path is propagated via Run().
  EXPECT_CALL(*env_, Run(kDummyPath, NULL, NULL))
    .Times(1)
    .WillOnce(Return(true));
  // Setup executable_path to return a dummy
  EXPECT_CALL(*options_, executable_path())
    .Times(2)
    .WillRepeatedly(Return(kDummyPath));
  EXPECT_TRUE(jail.Run());
}

TEST_F(MiniJailTest, DefaultTrueEnvAndOptions) {
  // Make all default mock calls return true
  DefaultValue<bool>::Set(true);
  MiniJail jail;
  jail.Initialize(options_.get());
  EXPECT_TRUE(jail.Jail());
  // Setup executable_path to return a dummy
  EXPECT_CALL(*options_, executable_path())
    .Times(2)
    .WillRepeatedly(Return(kDummyPath));
  EXPECT_TRUE(jail.Run());
  DefaultValue<bool>::Clear();
}

TEST_F(MiniJailTest, NamespaceFlagsPidOnly) {
  MiniJail jail;
  jail.Initialize(options_.get());

  EXPECT_CALL(*options_, namespace_pid())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, namespace_vfs())
    .Times(2)
    .WillOnce(Return(false))
    .WillOnce(Return(false));
  EXPECT_CALL(*env_, EnterNamespace(CLONE_NEWPID))
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_TRUE(jail.Jail());
}

TEST_F(MiniJailTest, NamespaceFlagsVfsOnly) {
  MiniJail jail;
  jail.Initialize(options_.get());

  EXPECT_CALL(*options_, namespace_pid())
    .Times(1)
    .WillOnce(Return(false));
  EXPECT_CALL(*options_, namespace_vfs())
    .Times(2)
    .WillOnce(Return(true))
    .WillOnce(Return(true));
  EXPECT_CALL(*env_, EnterNamespace(CLONE_NEWNS))
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_TRUE(jail.Jail());
}

TEST_F(MiniJailTest, NamespaceFlagsAll) {
  MiniJail jail;
  jail.Initialize(options_.get());

  EXPECT_CALL(*options_, namespace_pid())
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_CALL(*options_, namespace_vfs())
    .Times(2)
    .WillOnce(Return(true))
    .WillOnce(Return(true));
  EXPECT_CALL(*env_, EnterNamespace(CLONE_NEWNS|CLONE_NEWPID))
    .Times(1)
    .WillOnce(Return(true));
  EXPECT_TRUE(jail.Jail());  // all works on first call
}

// TODO(wad) finish up test cases for each conditional


}  // namespace chromeos
