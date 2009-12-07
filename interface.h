// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Abstract interface for implementing minijails

#ifndef __CHROMEOS_MINIJAIL_INTERFACE_H
#define __CHROMEOS_MINIJAIL_INTERFACE_H

#include <base/basictypes.h>
#include <base/scoped_ptr.h>

namespace chromeos {
namespace minijail {

class Options;

class Interface {
 public:
  Interface() : options_(NULL) { }  // new default
  virtual ~Interface() { }
  virtual bool Initialize(const Options *options)
    { set_options(options); return true; }
  virtual const Options *options() const { return options_; }
  virtual void set_options(const Options *options) { options_ = options; }

  // To be overriden.
  virtual const char *name() { return "minijail::Interface"; }
  //  Implements the jail logic
  virtual bool Jail() const = 0;
  // Performs the execution step.  It isn't required to return.
  virtual bool Run() const;

 private:
  const Options *options_;

  DISALLOW_COPY_AND_ASSIGN(Interface);
};

}  // namespace minijail
}  // namespace chromeos

#endif  // __CHROMEOS_MINIJAIL_INTERFACE_H
