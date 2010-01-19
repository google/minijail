// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Options mock class
#ifndef __CHROMEOS_OPTIONS_MOCK_OPTIONS_H
#define __CHROMEOS_OPTIONS_MOCK_OPTIONS_H

#include "options.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace chromeos {
namespace minijail {

class MockOptions : public Options {
 public:
  MockOptions() { }
  ~MockOptions() { }
  MOCK_CONST_METHOD0(env, const Env *());
  MOCK_METHOD1(set_env, void(Env *));
  MOCK_METHOD1(set_executable_path, void(const char*));
  MOCK_CONST_METHOD0(executable_path, const char *());
  MOCK_METHOD2(set_arguments, void(char * const *, int));
  MOCK_CONST_METHOD0(arguments, char * const *());
  MOCK_CONST_METHOD0(argument_count, int());
  MOCK_METHOD1(set_environment, void(char * const *));
  MOCK_CONST_METHOD0(environment, char * const *());

  MOCK_METHOD1(set_add_readonly_mounts, void(bool));
  MOCK_METHOD1(set_disable_tracing, void(bool));
  MOCK_METHOD1(set_enforce_syscalls_benchmark, void(bool));
  MOCK_METHOD1(set_enforce_syscalls_by_source, void(bool));
  MOCK_METHOD1(set_gid, void(gid_t));
  MOCK_METHOD1(set_namespace_vfs, void(bool));
  MOCK_METHOD1(set_namespace_pid, void(bool));
  MOCK_METHOD1(set_sanitize_environment, void(bool));
  MOCK_METHOD1(set_uid, void(uid_t));
  MOCK_METHOD1(set_use_capabilities, void(bool));

  MOCK_CONST_METHOD0(add_readonly_mounts, bool());
  MOCK_CONST_METHOD0(disable_tracing, bool());
  MOCK_CONST_METHOD0(enforce_syscalls_benchmark, bool());
  MOCK_CONST_METHOD0(enforce_syscalls_by_source, bool());
  MOCK_CONST_METHOD0(gid, gid_t());
  MOCK_CONST_METHOD0(namespace_vfs, bool());
  MOCK_CONST_METHOD0(namespace_pid, bool());
  MOCK_CONST_METHOD0(sanitize_environment, bool());
  MOCK_CONST_METHOD0(uid, uid_t());
  MOCK_CONST_METHOD0(use_capabilities, bool());

  MOCK_CONST_METHOD0(change_uid, bool());
  MOCK_CONST_METHOD0(change_gid, bool());
  MOCK_METHOD0(FixUpDependencies, bool());

  // Concrete call to the parent class fo easy self-testing of the
  // default implementation. To use:
  //   EXPECT_CALL(*mockopt, FixUpDependencies())
  //     .WillOnce(Invoke(mockopt, &MockOptions::OptionsFixUpDependencies));
  bool OptionsFixUpDependencies() { return Options::FixUpDependencies(); }
};

}  // namespace minijail
}  // namespace chromeos

#endif  // __CHROMEOS_OPTIONS_MOCK_OPTIONS_H
