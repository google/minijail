// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Default implementation of the Options interface.

#include "minijail/options.h"

#include <base/basictypes.h>
#include <base/logging.h>
#include <base/scoped_ptr.h>

namespace chromeos {

namespace minijail {

bool Options::FixUpDependencies() {
  if (add_readonly_mounts() && !namespace_vfs()) {
    DLOG(INFO) << "add_readonly_mounts(true) implies "
               << "namespace_vfs(true): correcting.";
    set_namespace_vfs(true);
  }
  if (enforce_syscalls_benchmark() && enforce_syscalls_by_source()) {
    LOG(ERROR) << "enforce_syscalls_benchmark(true) and "
               << "enforce_syscalls_by_source(true) cannot both be set.";
    return false;
  }
  return true;
}

}  // namespace minijail
}  // namespace chromeos
