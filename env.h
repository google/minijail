// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Provide a interfacefor supplying system interface functionality at a
// behavioral level.
//
// TODO(wad) Support LinuxSUIDSandox, net namespaces, jail profiles, etc.

#ifndef __CHROMEOS_MINIJAIL_ENV_H
#define __CHROMEOS_MINIJAIL_ENV_H

#include <base/basictypes.h>
#include <base/scoped_ptr.h>

namespace chromeos {
namespace minijail {

class Env {
 public:
  Env() { }
  virtual ~Env() { }
  virtual bool ChangeUser(uid_t uid, gid_t gid) const;
  virtual bool DisableDefaultRootPrivileges() const;
  virtual bool DisableTracing() const;
  virtual bool EnterNamespace(int namespaces) const;
  virtual bool FilterSyscallsBenchmarkOnly() const;
  virtual bool FilterSyscallsBySource() const;
  // virtual bool ExportXAuthority(int appgroup, bool trusted) const;
  virtual bool KeepRootCapabilities() const;
  // bool do_delayed_chroot;
  // bool enter_net_namespace();
  // TODO(wad) add flags: ro_proc, custom /dev, ...
  virtual bool Mount() const;
  virtual bool SanitizeBoundingSet(uint64 capmask) const;
  // /dev/input/*
  // /dev/video*
  // /dev/*audio*
  // bool ShimUserDevices();
  //bool add_to_cgroup(const char *cgroup_name);
  virtual bool SanitizeCapabilities(uint64 eff_capmask) const;

  virtual bool Run(const char *path,
                   char * const *argv,
                   char * const *envp) const;
 private:
  DISALLOW_COPY_AND_ASSIGN(Env);
};

}  // namespace minijail
}  // namespace chromeos

#endif  // __CHROMEOS_MINIJAIL_ENV_H
