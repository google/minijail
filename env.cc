// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Default implementation of the Env interface.

#include "minijail/env.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/logging.h>

// prctl constants that are still missing in the headers.
#define PR_GET_KEEPCAPS    7
#define PR_SET_KEEPCAPS    8
#define PR_CAPBSET_READ   23
#define PR_CAPBSET_DROP   24
#define PR_GET_SECUREBITS 27
#define PR_SET_SECUREBITS 28

namespace chromeos {

namespace minijail {

bool Env::DisableTracing() const {
  DLOG(INFO) << "Disabling DUMPABLE...";
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
    PLOG(FATAL) << "Failed to set PR_SET_KEEPCAPS";
  }
  if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)) {
    LOG(FATAL) << "PR_SET_DUMPABLE could not be set";
  }
  DLOG(INFO) << "Success";
  return true;
}

bool Env::KeepRootCapabilities() const {
  DLOG(INFO) << "Enabling KEEPCAPS...";
  if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
    PLOG(FATAL) << "Failed to set PR_SET_KEEPCAPS";
   }
  if (prctl(PR_GET_KEEPCAPS, 0) != 1) {
    LOG(FATAL) << "PR_GET_KEEPCAPS could not be set";
  }

  DLOG(INFO) << "Success.";
  return true;
}

bool Env::DisableDefaultRootPrivileges() const {
  DLOG(INFO) << "Enabling SECURE_ALL...";
  // From: kernel/include/linux/securebits.h:
  // http://git.chromium.org/cgi-bin/gitweb.cgi?p=kernel.git;a=blob;f=include/linux/securebits.h
  const int kSecureBitsAllLocked = 0x3f;
  if (prctl(PR_SET_SECUREBITS, kSecureBitsAllLocked)) {
    PLOG(FATAL) << "Failed to set PR_SET_SECUREBITS";
  }
  DLOG(INFO) << "Success.";
  return true;
}

bool Env::ChangeUser(uid_t uid, gid_t gid) const {
  // TODO(wad) support supplemental groups
  DLOG(INFO) << "Dropping root...";
  if (setgroups(0, NULL)) {
    PLOG(FATAL) << "Failed to drop supplementary groups";
  }
  if (setresgid(gid, gid, gid)) {
    PLOG(FATAL) << "Failed to change to gid " << gid;
  }
  if (setresuid(uid, uid, uid)) {
    PLOG(FATAL) << "Failed to change to uid " << uid;
  }
  DLOG(INFO) << "Success.";
  return true;
}

// At present, the total number of capabilities is less than 32. We
// will just pack them into a bitmask to save on effort.
bool Env::SanitizeBoundingSet(uint64 cap_mask) const {
  unsigned int cap;
  DLOG(INFO) << "Cleaning the bounding set...";
  // XXX: we read until prctl complains but that may not
  // match CAP_LAST_CAP.  We'll just drop the excess if it turns up.
  // We mustn´t drop CAP_SETPCAP on the way though.
  static const uint32 kBitsInAByte = 8;
  static const uint32 kMaxCaps = sizeof(cap_mask) * kBitsInAByte;
  for (cap = 0; cap < kMaxCaps && prctl(PR_CAPBSET_READ, cap) >= 0; ++cap) {
    if (cap == CAP_SETPCAP) {
      continue;
    }
    if (cap_mask & (1ULL << (cap))) {
      DLOG(INFO) << "Leaving cap " << cap << " in bounding set";
      continue;
    }
    if (prctl(PR_CAPBSET_DROP, cap)) {
      PLOG(FATAL) << "Failed to clean the bounding set of cap " << cap;
    }
  }
  DLOG(INFO) << "Success.";
  return true;
}

bool Env::SanitizeCapabilities(uint64 effective_capmask) const {
  DLOG(INFO) << "Dropping capabilities...";
  unsigned int cap;
  cap_t caps = cap_get_proc();
  cap_value_t raise_flag[1];
  if (!caps) {
    PLOG(FATAL) << "cap_get_proc failed";
  }
  if (cap_clear_flag(caps, CAP_INHERITABLE)) {
     PLOG(FATAL) << "Failed to clear all inheritable caps";
  }
  if (cap_clear_flag(caps, CAP_EFFECTIVE)) {
     PLOG(FATAL) << "Failed to clear all effective caps";
  }
  if (cap_clear_flag(caps, CAP_PERMITTED)) {
     PLOG(FATAL) << "Failed to clear all permitted caps";
  }
  for (cap = 0; cap < sizeof(effective_capmask)*8; ++cap) {
    // In a secure_noroot jail, cap_setpcap is safe.
    if (cap == CAP_SETPCAP ||
        effective_capmask & (1 << cap)) {
      raise_flag[0] = cap;
      DLOG(INFO) << "Adding cap " << cap << "=eip";
      if (cap_set_flag(caps, CAP_EFFECTIVE, 1, raise_flag, CAP_SET)) {
        PLOG(FATAL) << "Failed to add cap " << cap << " to the effective set";
      }
      if (cap_set_flag(caps, CAP_PERMITTED, 1, raise_flag, CAP_SET)) {
        PLOG(FATAL) << "Failed to add cap " << cap << " to the permitted set";
      }
      if (cap_set_flag(caps, CAP_INHERITABLE, 1, raise_flag, CAP_SET)) {
        PLOG(FATAL) << "Failed to add cap " << cap << " to the inherite set";
      }
    }
  }
  if (cap_set_proc(caps)) {
     PLOG(FATAL) << "Failed to apply cleaned capset";
  }
  cap_free(caps);
  DLOG(INFO) << "Success.";
  return true;
}

bool Env::FilterSyscallsBySource() const {
  DLOG(INFO) << "Calling seccomp(2)";
  if (prctl(PR_SET_SECCOMP, 2)) {
    PLOG(FATAL) << "Failed to enabled seccomp(2)";
  }
  DLOG(INFO) << "System calls now filtered by source";
  return true;
}

bool Env::FilterSyscallsBenchmarkOnly() const {
  DLOG(INFO) << "Calling seccomp(3)";
  if (prctl(PR_SET_SECCOMP, 3)) {
    PLOG(FATAL) << "Failed to enabled seccomp(3)";
  }
  DLOG(INFO) << "System calls now nop filtered";
  return true;
}

bool Env::EnterNamespace(int namespaces) const {
  if (namespaces == 0) {
    DLOG(INFO) << "No namespacing to be done.";
    return true;
  }
  DLOG(INFO) << "Entering namespaces " << namespaces;
  // TODO(wad) support namespace args
  const pid_t pid = syscall(
      __NR_clone, namespaces | CLONE_VFORK | SIGCHLD, 0, 0, 0);
  if (pid == -1) {
    PLOG(FATAL) << "Could not use PID namespacing";
    return false;
  }
  if (pid) {
    // Kill the original process without atexit handlers.
    DLOG(INFO) << "original process death:" << pid;
    _exit(0);
  }
  DLOG(INFO) << "Success: " << getpid();
  return true;
}

bool Env::Mount() const {
  DLOG(INFO) << "Attempting to mount /proc RO.";
  if (mount("proc",
            "/proc",
            "proc",
            MS_NODEV|MS_NOEXEC|MS_NOSUID|MS_RDONLY,
            "")) {
    PLOG(FATAL) << "Failed to mount a local /proc";
  }
  DLOG(INFO) << "Success.";
  return true;
}

bool Env::Run(const char *path, char * const *argv, char * const *envp) const {
  // TODO(wad) log-pid option
  DLOG(INFO) << "Executing: " << path << " with args: ";
  for (char * const* arg = argv; *arg; ++arg) {
    DLOG(INFO) << "-> " << *arg;
  }
  execve(path, argv, envp);
  PLOG(FATAL) << "failed to execute " << path;
  return false;
}

}  // namespace minijail
}  // namespace chromeos
