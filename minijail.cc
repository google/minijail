// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Implements MiniJail jailing logic.

#include "minijail.h"

#include <errno.h>

namespace chromeos {

bool MiniJail::Jail() const {
  // XXX This is a very early implementation of the jailing logic.
  // XXX Many features are missing or will be made more tunable.
  const minijail::Options *opts = options();
  if (!opts) {
    LOG(ERROR) << "No Options given. Initialize must be called first "
               << "with a valid Option pointer.";
    return false;
  }
  const minijail::Env *env = opts->env();

  int namespaces = 0;
  if (opts->namespace_pid())
    namespaces |= CLONE_NEWPID;
  if (opts->namespace_vfs())
    namespaces |= CLONE_NEWNS;
  if (namespaces && !env->EnterNamespace(namespaces)) {
    return false;
  }

  if (opts->namespace_vfs() && opts->add_readonly_mounts()) {
    if (!env->Mount()) {  // TODO(wad) add flags
      return false;
    }
  }

  if (opts->use_capabilities()) {
    if (!env->KeepRootCapabilities()) {
      return false;
    }
    if (!env->DisableDefaultRootPrivileges()) {
      return false;
    }
  }

  if (opts->disable_tracing()) {
    if (!env->DisableTracing()) {
      return false;
    }
  }

  uid_t uid = getuid();
  if (opts->change_uid()) {
    uid = opts->uid();
  }
  gid_t gid = getgid();
  if (opts->change_gid()) {
    gid = opts->gid();
  }
  // TODO(wad) separate group and user changes
  if (opts->change_uid() || opts->change_gid()) {
    DLOG(INFO) << "Attempting to change user and/or groups...";
    if (!env->ChangeUser(uid, gid)) {
      return false;
    }
  }

  if (opts->enforce_syscalls_by_source()) {
    if (!env->FilterSyscallsBySource()) {
      return false;
    }
  } else if (opts->enforce_syscalls_benchmark()) {
    if (!env->FilterSyscallsBenchmarkOnly()) {
      return false;
    }
  }

  if (opts->use_capabilities()) {
    // TODO(wad) use helpers to read caps from flags
    if (!env->SanitizeCapabilities(0)) {
      return false;
    }
    if (!env->SanitizeBoundingSet(0)) {
      return false;
    }
  }
  return true;
}

}  // namespace chromeos
