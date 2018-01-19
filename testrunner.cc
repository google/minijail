/* Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Main entrypoint for gtest.
 * Redirects logging to stderr to avoid syslog logspam.
 */

#include <stdio.h>

#include <gtest/gtest.h>

#include "util.h"

namespace {

class Environment : public ::testing::Environment {
 public:
  ~Environment() override = default;

  void SetUp() override {
    init_logging(LOG_TO_FD, STDERR_FILENO, LOG_INFO);
  }
};

}  // namespace

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  ::testing::AddGlobalTestEnvironment(new Environment());
  return RUN_ALL_TESTS();
}
