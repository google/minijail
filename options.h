// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Options abstract class for minijails.
#ifndef __CHROMEOS_MINIJAIL_OPTIONS_H
#define __CHROMEOS_MINIJAIL_OPTIONS_H

#include <base/basictypes.h>
#include <base/logging.h>
#include <base/scoped_ptr.h>

#include "minijail/env.h"

namespace chromeos {
namespace minijail {

class Options {
 public:
  Options() : env_(new Env),
              executable_path_(NULL),
              argument_count_(0),
              arguments_(NULL),
              environment_(NULL),
              add_readonly_mounts_(false),
              change_gid_(false),
              change_uid_(false),
              disable_tracing_(false),
              enforce_syscalls_benchmark_(false),
              enforce_syscalls_by_source_(false),
              gid_(0),
              namespace_vfs_(false),
              namespace_pid_(false),
              sanitize_environment_(false),
              uid_(0),
              use_capabilities_(false) { }

  virtual ~Options() { }

  // Takes ownership of an Env pointer
  virtual const Env *env() const { return env_.get(); }
  virtual void set_env(Env *env) { env_.reset(env); }

  //// Methods for configuring the binary to be run.

  // Sets the path to the executable when Run() is called in the jail.
  // Pointer ownership is not taken.
  virtual void set_executable_path(const char *exe) { executable_path_ = exe; }
  virtual const char *executable_path() const { return executable_path_; }
  // Sets an array of arguments to use for running the executable.
  // Pointer ownership is not taken.
  virtual void set_arguments(char * const *argv, int count)
    { arguments_ = argv; argument_count_ = count; }
  virtual char * const *arguments() const { return arguments_; }
  virtual int argument_count() const { return argument_count_; }
  // Sets the baseline environment for the executable.
  // Pointer ownership is not taken.
  virtual void set_environment(char * const *envp) { environment_ = envp; }
  virtual char * const *environment() const { return environment_; }

  //// Methods for configuring the jail.

  // Determines if a read-only /proc will be mounted.
  // This option requires namespace_vfs_ = true.
  // If enabled, this option forcibly enables namespace_vfs_.
  virtual void set_add_readonly_mounts(bool val) { add_readonly_mounts_ = val; }
  virtual bool add_readonly_mounts() const { return add_readonly_mounts_; }
  // Disables cross-process tracing and core dumps.  This may cause problems
  // when generating crash dumps.  Options around that are TBD.
  virtual void set_disable_tracing(bool val) { disable_tracing_ = val; }
  virtual bool disable_tracing() const { return disable_tracing_; }
  // Enable no-op syscall filtering for raw benchmarking.
  virtual void set_enforce_syscalls_benchmark(bool val)
    { enforce_syscalls_benchmark_ = val; }
  virtual bool enforce_syscalls_benchmark() const
    { return enforce_syscalls_benchmark_; }
  // Enable kernel enforcement that all system calls originate from
  // read-only memory areas.
  virtual void set_enforce_syscalls_by_source(bool val)
    { enforce_syscalls_by_source_ = val; }
  virtual bool enforce_syscalls_by_source() const
    { return enforce_syscalls_by_source_; }
  // The value passed with this is numeric GID to transition to.
  // Calling this implies a gid change will be attempted.
  // TODO(wad) All supplementary groups are dropped.
  virtual void set_gid(gid_t val) { gid_ = val; change_gid_ = true; }
  virtual gid_t gid() const { return gid_; }
  // Sets VFS namespacing.  This is needed to have a custom
  // filesystem view (read-only mounts, etc).
  virtual void set_namespace_vfs(bool val) { namespace_vfs_ = val; }
  virtual bool namespace_vfs() const { return namespace_vfs_; }
  // Enable PID namespacing.  This will result in the process being
  // executed to be PID 1 in their own process tree.  The process will
  // not have visibility into other running processes (except via
  // /proc if not remounted).
  // TODO(wad) add init-like functionality and start the first process as pid 2.
  virtual void set_namespace_pid(bool val) { namespace_pid_ = val; }
  virtual bool namespace_pid() const { return namespace_pid_; }
  // Enables environment variable scrubbing.
  virtual void set_sanitize_environment(bool val)
    { sanitize_environment_ = val; }
  virtual bool sanitize_environment() const
    { return sanitize_environment_; }
  // The value passed with this is the numeric UID to transition to.
  virtual void set_uid(uid_t val) { uid_ = val; change_uid_ = true; }
  virtual uid_t uid() const { return uid_; }
  // Enables the use and sanitization of POSIX capabilities.
  // Without kKeepCapabilities, all capabilities save CAP_SETPCAP are
  // removed from the effective, inherited, permitted and bounding sets.
  virtual void set_use_capabilities(bool val) { use_capabilities_ = val; }
  virtual bool use_capabilities() const { return use_capabilities_; }

#if 0
  TODO(wad): additional functionality:
  virtual void set_cgroup_dir(const string& val) { cgroup_dir_ = val; }
  virtual const string& cgroup_dir() const { return cgroup_dir_; }

  virtual void set_supplemental_groups(std::vector<std::string>& val)
    { supplemental_groups_ = val; }
  virtual const std::vector<std::string> *supplemental_groups() const
    { return supplemental_groups_; }

  virtual void set_bounding_set(uint64 val) { bounding_set_ = val; }
  virtual uint64 bounding_set() const { return bounding_set_; }

  virtual void set_use_delayed_chroot(bool val) { use_delayed_chroot_ = val; }
  virtual bool use_delayed_chroot() const { return use_delayed_chroot_; }

  virtual void set_memory_limit(int64 val) { memory_limit_ = val; }
  virtual int64 memory_limit() const { return memory_limit_; }

  virtual void set_cpu_limit(int64 val) { cpu_limit_ = val; }
  virtual int64 cpu_limit() const { return cpu_limit_; }

  virtual void set_open_file_limit(int32 val) { open_file_limit_ = val; }
  virtual int32 open_file_limit() const { return open_file_limit_; }

  TODO(wad) other rlimits

  virtual void set_chroot(const std::string val) { chroot_ = val; }
  virtual const std::string chroot() const { return chroot_; }

  virtual void set_install_device_shims(bool val)
    { install_device_shims_ = val; }
  virtual bool install_device_shims() const { return install_device_shims_; }
#endif

  //// Helper methods
  // Indicate if the uid was set.
  virtual bool change_uid() const { return change_uid_; }
  // Indicate if the gid was set.
  virtual bool change_gid() const { return change_uid_; }
  // Ensures that all inter-dependent options are properly set.
  virtual bool FixUpDependencies();


 private:
  scoped_ptr<Env> env_;
  const char *executable_path_;
  int argument_count_;
  char * const *arguments_;
  char * const *environment_;

  bool add_readonly_mounts_;
  bool change_gid_;
  bool change_uid_;
  bool disable_tracing_;
  bool enforce_syscalls_benchmark_;
  bool enforce_syscalls_by_source_;
  gid_t gid_;
  bool namespace_vfs_;
  bool namespace_pid_;
  bool sanitize_environment_;
  uid_t uid_;
  bool use_capabilities_;

  DISALLOW_COPY_AND_ASSIGN(Options);
};

}  // namespace minijail
}  // namespace chromeos

#endif  // __CHROMEOS_MINIJAIL_OPTIONS_H
