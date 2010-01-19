// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Interface mock class
#ifndef __CHROMEOS_INTERFACE_MOCK_INTERFACE_H
#define __CHROMEOS_INTERFACE_MOCK_INTERFACE_H

#include "interface.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace chromeos {
namespace minijail {

class MockInterface : public Interface {
 public:
  MockInterface() { }
  ~MockInterface() { }
  MOCK_METHOD1(Initialize, bool(const Options *));
  MOCK_CONST_METHOD0(options, const Options *());
  MOCK_METHOD1(set_options, void(const Options *));
  MOCK_METHOD0(name, const char *());
  MOCK_CONST_METHOD0(Jail, bool());
  MOCK_CONST_METHOD0(Run, bool());
};

}  // namespace minijail
}  // namespace chromeos

#endif  // __CHROMEOS_INTERFACE_MOCK_INTERFACE_H
