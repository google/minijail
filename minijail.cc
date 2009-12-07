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
  // Dumb forced exit on failure.
  LOG_IF(FATAL, !env->EnterNamespace(namespaces));

  if (opts->namespace_vfs() && opts->add_readonly_mounts())
    LOG_IF(FATAL, !env->Mount()); // TODO(wad) add flags

  if (opts->use_capabilities()) {
    LOG_IF(FATAL, !env->KeepRootCapabilities());
    LOG_IF(FATAL, !env->DisableDefaultRootPrivileges());
  }

  if (opts->disable_tracing())
    LOG_IF(FATAL, !env->DisableTracing());

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
    LOG_IF(FATAL, !env->ChangeUser(uid, gid));
  }

  if (opts->enforce_syscalls_by_source()) {
    LOG_IF(FATAL, !env->FilterSyscallsBySource());
  } else if (opts->enforce_syscalls_benchmark()) {
    LOG_IF(FATAL, !env->FilterSyscallsBenchmarkOnly());
  }

  if (opts->use_capabilities()) {
    // TODO(wad) use helpers to read caps from flags
    LOG_IF(FATAL, !env->SanitizeCapabilities(0));
    LOG_IF(FATAL, !env->SanitizeBoundingSet(0));
  }
  return true;
}

}  // namespace chromeos
