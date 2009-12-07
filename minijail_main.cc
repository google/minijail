// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Some portions Copyright (c) 2009 The Chromium Authors.
//
// Driver program for applying a minijail from the commandline to
// a process and its children (depending on the feature).

#include "minijail/minijail.h"

#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <iostream>
#include <new>
#include <string>
#include <vector>

#include <base/basictypes.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/string_util.h>

namespace switches {
static const char kAddReadonlyMounts[] = "add-readonly-mounts";
static const char kDisableTracing[] = "disable-tracing";
static const char kEnforceSyscallsBenchmark[] = "enforce-syscall-benchmark";
static const char kEnforceSyscallsBySource[] = "enforce-syscall-by-source";
static const char kGid[] = "gid";
static const char kNamespaceVfs[] = "namespace-vfs";
static const char kNamespacePid[] = "namespace-pid";
static const char kSanitizeEnvironment[] = "sanitize-environment";
static const char kUid[] = "uid";
static const char kUseCapabilities[] = "use-capabilities";
static const char kHelp[] = "help";

static const char kHelpMessage[] = "Available Switches:\n"
"  --add-readonly-mounts\n"
"    Mounts a read-only /proc. (implies namespace-vfs)\n"
"    (TODO other read-only/special mounts)\n"
"  --disable-tracing\n"
"    Disables ptrace() and core dumps.\n"
"    This may break debugging helpers\n"
"  --enforce-syscall-benchmark-source\n"
"    Runs system call filtering in a pass-through capacity only for\n"
"    benchmarking\n"
"  --enforce-syscall-by-source\n"
"    Enables kernel enforcement that system calls originate from read-only\n"
"    memory areas\n"
"  --gid [number]\n"
"    Numeric gid to transition to prior to execution.\n"
"   (TODO: Supplemental groups will be cleared.)\n"
"  --namespace-vfs\n"
"    Enables a process-tree specific VFS view.\n"
"  --namespace-pid\n"
"    Makes the executed process into procss id 1 in its own process view.\n"
"    With --add-readonly-mounts, other processes will not be visible\n"
"  --sanitize-environment\n"
"    Scrubs the environment clean of potentially dangerous values.\n"
"    (Note, this is a blacklist and not a whitelist so it may need attention)\n"
"  --uid [number]\n"
"    Numeric uid to transition to prior to execution.\n"
"  --use-capabilities\n"
"    Restricts all root-level capabilities to CAP_SETPCAP and enables\n"
"    SECURE_NOROOT.\n"
"  -- /path/to/program [arg1 [arg2 [ . . . ] ] ]\n"
"    Supplies the required program to execute and its arguments.\n"
"    At present, an empty environment will be passed.\n"
"\n";

}  // namespace switches

static void ProcessSwitches(CommandLine *cl,
                            chromeos::MiniJailOptions *jail_opts) {
  if (cl->HasSwitch(switches::kHelp)) {
    std::cerr << switches::kHelpMessage;
    exit(0);
  }

  // Configure the jail options
  jail_opts->set_namespace_pid(cl->HasSwitch(switches::kNamespacePid));
  jail_opts->set_namespace_vfs(cl->HasSwitch(switches::kNamespaceVfs));
  jail_opts->set_add_readonly_mounts(
    cl->HasSwitch(switches::kAddReadonlyMounts));
  jail_opts->set_disable_tracing(cl->HasSwitch(switches::kDisableTracing));
  jail_opts->set_enforce_syscalls_by_source(
    cl->HasSwitch(switches::kEnforceSyscallsBySource));
  jail_opts->set_use_capabilities(cl->HasSwitch(switches::kUseCapabilities));
  jail_opts->set_sanitize_environment(
    cl->HasSwitch(switches::kSanitizeEnvironment));

  std::string uid_string = cl->GetSwitchValueASCII(switches::kUid);
  if (!uid_string.empty()) {
    errno = 0;
    uid_t uid = static_cast<uid_t>(strtol(uid_string.c_str(), NULL, 0));
    PLOG_IF(WARNING, errno) << "failed to parse uid";
    jail_opts->set_uid(uid);
  }

  std::string gid_string = cl->GetSwitchValueASCII(switches::kGid);
  if (!gid_string.empty()) {
    errno = 0;
    gid_t gid = static_cast<gid_t>(strtol(gid_string.c_str(), NULL, 0));
    PLOG_IF(WARNING, errno) << "failed to parse gid";
    jail_opts->set_gid(gid);
  }

  if (!jail_opts->FixUpDependencies()) {
    LOG(FATAL) << "Irreconcilable jail options given. Aborting.";
  }

  // Grab the loose args to use as the command line.
  // We have to wstring->argv[][] manually. Ugh.
  std::vector<std::wstring> loose_wide_args = cl->GetLooseValues();
  std::vector<std::string> loose_args(loose_wide_args.size());
  char const* *jailed_argv = new char const*[loose_wide_args.size() + 1];
  std::vector<std::wstring>::const_iterator arg_it = loose_wide_args.begin();
  char const* *ja = jailed_argv;
  for (; arg_it != loose_wide_args.end(); ++arg_it) {
    std::string arg = WideToASCII(*arg_it);
    loose_args.push_back(arg);
    // XXX: clean up this leak even though it doesn't matter.
    *ja++ = strdup(arg.c_str());
  }
  *ja = 0;

  jail_opts->set_executable_path(jailed_argv[0]);
  jail_opts->set_arguments(const_cast<char * const*>(jailed_argv),
                           loose_args.size());
  // XXX We just leak this since we're going to exec anyhow.
  // delete jailed_argv;
}

int main(int argc, char *argv[], char **envp) {
  CommandLine::Init(argc, argv);
  logging::InitLogging(NULL,
                       logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
                       logging::DONT_LOCK_LOG_FILE,
                       logging::APPEND_TO_OLD_LOG_FILE);

  chromeos::MiniJailOptions jail_opts;
  CommandLine *cl = CommandLine::ForCurrentProcess();
  ProcessSwitches(cl, &jail_opts);
  jail_opts.set_environment(envp);

  LOG_IF(FATAL, !jail_opts.executable_path()) << "No executable given";

  chromeos::MiniJail jail;
  jail.Initialize(&jail_opts);
  bool ok = jail.Jail() && jail.Run();
  return !ok;
}

