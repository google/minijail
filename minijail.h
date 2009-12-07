// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Implements a simple jail that uses CommandLine heavily instead of
// the Options class.  It should act as a simple reference implementation
// for all functionality.

#ifndef __CHROMEOS_MINIJAIL_MINIJAIL_H
#define __CHROMEOS_MINIJAIL_MINIJAIL_H

#include <string>

#include <base/basictypes.h>
#include <base/logging.h>
#include <base/scoped_ptr.h>

#include "minijail/env.h"
#include "minijail/options.h"
#include "minijail/interface.h"

namespace chromeos {


class MiniJailOptions : public minijail::Options {
 public:
  MiniJailOptions() { }
  ~MiniJailOptions() { }
  // We can set some defaults here if desired.
 private:
  DISALLOW_COPY_AND_ASSIGN(MiniJailOptions);
};

class MiniJail : public minijail::Interface {
 public:
  MiniJail() { }
  ~MiniJail() { }
  const char *name() { return "MiniJail"; }
  bool Jail() const;
 private:
  DISALLOW_COPY_AND_ASSIGN(MiniJail);
};

}  // namespace chromeos

#endif  // __CHROMEOS_MINIJAIL_MINIJAIL
