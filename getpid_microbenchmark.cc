// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Microbenchmark of getpid()
#include "microbenchmark/microbenchmark.h"

#include <syscall.h>
namespace chromeos {
namespace benchmarks {

static void GetPid(bool scaffold_only) {
  if (!scaffold_only) syscall(__NR_getpid);
}
CHROMEOS_MICROBENCHMARK(GetPid, 1000000);

}  // namespace benchmarks
}  // namespace chromeos
