// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Default Interface implementation

#include "minijail/env.h"
#include "minijail/options.h"
#include "minijail/interface.h"

namespace chromeos {
namespace minijail {

bool Interface::Run() const {
  LOG_IF(FATAL, !options()->executable_path()) << "No executable path given.";
  return options()->env()->Run(options()->executable_path(),
                               options()->arguments(),
                               options()->environment());
}

}  // namespace minijail
}  // namespace chromeos
