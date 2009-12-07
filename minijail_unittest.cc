// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Tests for MiniJail
#include "env.h"
#include "minijail.h"
#include <gtest/gtest.h>

namespace chromeos {

// TODO: pull in gmock to make this non-crazy for testing.
class TrueEnv : public minijail::Env {
 public:
  TrueEnv() { }
  ~TrueEnv() { }
  bool DisableTracing() const { return true; }
  bool KeepRootCapabilities() const { return true; }
  bool DisableDefaultRootPrivileges() const { return true; }
  bool ChangeUser(uid_t uid, gid_t gid) const { return true; }
  bool SanitizeBoundingSet(uint64 capmask) const { return true; }
  bool EnterNamespace(int namespaces) const { return true; }
  bool FilterSyscallsBySource() const { return true; }
  bool Mount() const { return true; }
  bool SanitizeCapabilities(uint64 eff_capmask) const { return true; }
  bool Run(const char *path,
           char * const *argv,
           char * const *envp) const { return true; }
};

class MiniJailTest : public ::testing::Test { };

TEST(MiniJailTest, TrueJail) {
  TrueEnv *env = new TrueEnv;
  MiniJailOptions options;
  options.set_env(env);  // takes ownership
  options.set_executable_path("/no/where");
  MiniJail jail;
  jail.Initialize(&options);
  // This does basically nothing since the options default to false.
  // Only ChangeUser is actually called.
  EXPECT_TRUE(jail.Jail());
  EXPECT_TRUE(jail.Run());
}

}  // namespace chromeos
