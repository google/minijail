// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Env mock class
#ifndef __CHROMEOS_MINIJAIL_MOCK_ENV_H
#define __CHROMEOS_MINIJAIL_MOCK_ENV_H

#include "env.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace chromeos {
namespace minijail {

class MockEnv : public Env {
 public:
  MockEnv() { }
  ~MockEnv() { }
  MOCK_CONST_METHOD2(ChangeUser, bool(uid_t, gid_t));
  MOCK_CONST_METHOD0(DisableDefaultRootPrivileges, bool());
  MOCK_CONST_METHOD0(DisableTracing, bool());
  MOCK_CONST_METHOD1(EnterNamespace, bool(int));
  MOCK_CONST_METHOD0(FilterSyscallsBenchmarkOnly, bool());
  MOCK_CONST_METHOD0(FilterSyscallsBySource, bool());
  MOCK_CONST_METHOD0(KeepRootCapabilities, bool());
  MOCK_CONST_METHOD0(Mount, bool());
  MOCK_CONST_METHOD1(SanitizeBoundingSet, bool(uint64));
  MOCK_CONST_METHOD1(SanitizeCapabilities, bool(uint64));
  MOCK_CONST_METHOD3(Run, bool(const char *, char * const *, char * const *));
};

}  // namespace minijail
}  // namespace chromeos

#endif  // __CHROMEOS_MINIJAIL_MOCK_ENV_H
