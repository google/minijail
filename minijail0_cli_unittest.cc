/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test the minijail0 CLI using gtest.
 *
 * Note: We don't verify that the minijail struct was set correctly from these
 * flags as only libminijail.c knows that definition.  If we wanted to improve
 * this test, we'd have to pull that struct into a common (internal) header.
 */

#include <stdio.h>
#include <stdlib.h>

#include <gtest/gtest.h>

#include "libminijail.h"
#include "minijail0_cli.h"

namespace {

constexpr char kValidUser[] = "nobody";
constexpr char kValidUid[] = "100";
constexpr char kValidGroup[] = "users";
constexpr char kValidGid[] = "100";

class CliTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Most tests do not care about this logic.  For the few that do, make
    // them opt into it so they can validate specifically.
    elftype_ = ELFDYNAMIC;
  }
  virtual void TearDown() {}

  // We use a vector of strings rather than const char * pointers because we
  // need the backing memory to be writable.  The CLI might mutate the strings
  // as it parses things (which is normally permissible with argv).
  int parse_args_(const std::vector<std::string>& argv,
                  int* exit_immediately,
                  ElfType* elftype) {
    // Make sure we reset the getopts state when scanning a new argv.  Setting
    // this to 0 is a GNU extension, but AOSP/BSD also checks this (as an alias
    // to their "optreset").
    optind = 0;

    // We create & destroy this for every parse_args call because some API
    // calls can dupe memory which confuses LSAN.  https://crbug.com/844615
    struct minijail *j = minijail_new();

    std::vector<const char *> pargv;
    pargv.push_back("minijail0");
    for (const std::string& arg : argv)
      pargv.push_back(arg.c_str());

    // We grab stdout from parse_args itself as it might dump things we don't
    // usually care about like help output.
    testing::internal::CaptureStdout();

    const char* preload_path = PRELOADPATH;
    int ret =
        parse_args(j, pargv.size(), const_cast<char* const*>(pargv.data()),
                   exit_immediately, elftype, &preload_path);
    testing::internal::GetCapturedStdout();

    minijail_destroy(j);

    return ret;
  }

  int parse_args_(const std::vector<std::string>& argv) {
    return parse_args_(argv, &exit_immediately_, &elftype_);
  }

  ElfType elftype_;
  int exit_immediately_;
};

}  // namespace

// Should exit non-zero when there's no arguments.
TEST_F(CliTest, no_args) {
  std::vector<std::string> argv = {};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Should exit zero when we asked for help.
TEST_F(CliTest, help) {
  std::vector<std::string> argv = {"-h"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(0), "");

  argv = {"--help"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(0), "");

  argv = {"-H"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(0), "");
}

// Just a simple program to run.
TEST_F(CliTest, valid_program) {
  std::vector<std::string> argv = {"/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));
}

// Valid calls to the change user option.
TEST_F(CliTest, valid_set_user) {
  std::vector<std::string> argv = {"-u", "", "/bin/sh"};

  argv[1] = kValidUser;
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = kValidUid;
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the change user option.
TEST_F(CliTest, invalid_set_user) {
  std::vector<std::string> argv = {"-u", "", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "j;lX:J*Pj;oijfs;jdlkjC;j";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "1000x";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Supplying -u more than once is bad.
  argv = {"-u", kValidUser, "-u", kValidUid, "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1),
              "-u provided multiple times");
}

// Valid calls to the change group option.
TEST_F(CliTest, valid_set_group) {
  std::vector<std::string> argv = {"-g", "", "/bin/sh"};

  argv[1] = kValidGroup;
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = kValidGid;
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the change group option.
TEST_F(CliTest, invalid_set_group) {
  std::vector<std::string> argv = {"-g", "", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "j;lX:J*Pj;oijfs;jdlkjC;j";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "1000x";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Supplying -g more than once is bad.
  argv = {"-g", kValidGroup, "-g", kValidGid, "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1),
              "-g provided multiple times");
}

// Valid calls to the add-suppl-group option.
TEST_F(CliTest, valid_add_supp_group) {
  std::vector<std::string> argv = {"--add-suppl-group", "", "/bin/sh"};

  argv[1] = kValidGroup;
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = kValidGid;
  ASSERT_TRUE(parse_args_(argv));

  std::vector<std::string> argv2 = {"--add-suppl-group", "",
                                    "--add-suppl-group", "", "/bin/sh"};
  argv[1] = kValidGroup;
  argv[2] = kValidGid;
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the add-suppl-group option.
TEST_F(CliTest, invalid_add_supp_group) {
  std::vector<std::string> argv = {"--add-suppl-group", "", "/bin/sh"};

  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "j;lX:J*Pj;oijfs;jdlkjC;j";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "1000x";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the skip securebits option.
TEST_F(CliTest, valid_skip_securebits) {
  // An empty string is the same as 0.
  std::vector<std::string> argv = {"-B", "", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "0xAB";
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "1234";
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the skip securebits option.
TEST_F(CliTest, invalid_skip_securebits) {
  std::vector<std::string> argv = {"-B", "", "/bin/sh"};

  argv[1] = "xja";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the caps option.
TEST_F(CliTest, valid_caps) {
  // An empty string is the same as 0.
  std::vector<std::string> argv = {"-c", "", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "0xAB";
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "1234";
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the caps option.
TEST_F(CliTest, invalid_caps) {
  std::vector<std::string> argv = {"-c", "", "/bin/sh"};

  argv[1] = "xja";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the logging option.
TEST_F(CliTest, valid_logging) {
  std::vector<std::string> argv = {"--logging", "", "/bin/sh"};

  // This should list all valid logging targets.
  const std::vector<std::string> profiles = {
    "stderr",
    "syslog",
  };

  for (const auto profile : profiles) {
    argv[1] = profile;
    ASSERT_TRUE(parse_args_(argv));
  }
}

// Invalid calls to the logging option.
TEST_F(CliTest, invalid_logging) {
  std::vector<std::string> argv = {"--logging", "", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "stdout";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the rlimit option.
TEST_F(CliTest, valid_rlimit) {
  std::vector<std::string> argv = {"-R", "", "/bin/sh"};

  argv[1] = "0,1,2";
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "0,0x100,4";
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "1,1,unlimited";
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "2,unlimited,2";
  ASSERT_TRUE(parse_args_(argv));

  argv[1] = "RLIMIT_AS,unlimited,unlimited";
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the rlimit option.
TEST_F(CliTest, invalid_rlimit) {
  std::vector<std::string> argv = {"-R", "", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Missing cur & max.
  argv[1] = "0";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Missing max.
  argv[1] = "0,0";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Too many options.
  argv[1] = "0,0,0,0";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Non-numeric limits
  argv[1] = "0,0,invalid-limit";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Invalid number.
  argv[1] = "0,0,0j";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Invalid hex number.
  argv[1] = "0,0x1jf,0";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Invalid rlimit constant.
  argv[1] = "RLIMIT_GOGOOGOG,0,0";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the profile option.
TEST_F(CliTest, valid_profile) {
  std::vector<std::string> argv = {"--profile", "", "/bin/sh"};

  // This should list all valid profiles.
  const std::vector<std::string> profiles = {
    "minimalistic-mountns",
    "minimalistic-mountns-nodev",
  };

  for (const auto profile : profiles) {
    argv[1] = profile;
    ASSERT_TRUE(parse_args_(argv));
  }
}

// Invalid calls to the profile option.
TEST_F(CliTest, invalid_profile) {
  std::vector<std::string> argv = {"--profile", "", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  argv[1] = "random-unknown-profile";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the chroot option.
TEST_F(CliTest, valid_chroot) {
  std::vector<std::string> argv = {"-C", "/", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));
}

// Valid calls to the pivot root option.
TEST_F(CliTest, valid_pivot_root) {
  std::vector<std::string> argv = {"-P", "/", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));
}

// We cannot handle multiple options with chroot/profile/pivot root.
TEST_F(CliTest, conflicting_roots) {
  std::vector<std::string> argv;

  // Chroot & pivot root.
  argv = {"-C", "/", "-P", "/", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Chroot & minimalistic-mountns profile.
  argv = {"-C", "/", "--profile", "minimalistic-mountns", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Pivot root & minimalistic-mountns profile.
  argv = {"-P", "/", "--profile", "minimalistic-mountns", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the uidmap option.
TEST_F(CliTest, valid_uidmap) {
  std::vector<std::string> argv = {"-m", "/bin/sh"};
  // Use a default map (no option from user).
  ASSERT_TRUE(parse_args_(argv));

  // Use a single map.
  argv = {"-m0 0 1", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));

  // Multiple maps.
  argv = {"-m0 0 1,100 100 1", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));
}

// Valid calls to the gidmap option.
TEST_F(CliTest, valid_gidmap) {
  std::vector<std::string> argv = {"-M", "/bin/sh"};
  // Use a default map (no option from user).
  ASSERT_TRUE(parse_args_(argv));

  // Use a single map.
  argv = {"-M0 0 1", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));

  // Multiple maps.
  argv = {"-M0 0 1,100 100 1", "/bin/sh"};
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the uidmap/gidmap options.
// Note: Can't really test these as all validation is delayed/left to the
// runtime kernel.  Minijail will simply write verbatim what the user gave
// it to the corresponding /proc/.../[ug]id_map.

// Valid calls to the binding option.
TEST_F(CliTest, valid_binding) {
  std::vector<std::string> argv = {"-v", "-b", "", "/bin/sh"};

  // Dest & writable are optional.
  argv[1] = "/";
  ASSERT_TRUE(parse_args_(argv));

  // Writable is optional.
  argv[1] = "/,/";
  ASSERT_TRUE(parse_args_(argv));

  // Writable is an integer.
  argv[1] = "/,/,0";
  ASSERT_TRUE(parse_args_(argv));
  argv[1] = "/,/,1";
  ASSERT_TRUE(parse_args_(argv));

  // Dest is optional.
  argv[1] = "/,,0";
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the binding option.
TEST_F(CliTest, invalid_binding) {
  std::vector<std::string> argv = {"-v", "-b", "", "/bin/sh"};

  // Missing source.
  argv[2] = "";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Too many args.
  argv[2] = "/,/,0,what";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Missing mount namespace/etc...
  argv = {"-b", "/", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Bad value for <writable>.
  argv = {"-b", "/,,writable", "/bin/sh"};
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the mount option.
TEST_F(CliTest, valid_mount) {
  std::vector<std::string> argv = {"-v", "-k", "", "/bin/sh"};

  // Flags & data are optional.
  argv[2] = "none,/,none";
  ASSERT_TRUE(parse_args_(argv));

  // Data is optional.
  argv[2] = "none,/,none,0xe";
  ASSERT_TRUE(parse_args_(argv));

  // Flags are optional.
  argv[2] = "none,/,none,,mode=755";
  ASSERT_TRUE(parse_args_(argv));

  // Multiple data options to the kernel.
  argv[2] = "none,/,none,0xe,mode=755,uid=0,gid=10";
  ASSERT_TRUE(parse_args_(argv));

  // Single MS constant.
  argv[2] = "none,/,none,MS_NODEV,mode=755";
  ASSERT_TRUE(parse_args_(argv));

  // Multiple MS constants.
  argv[2] = "none,/,none,MS_NODEV|MS_NOEXEC,mode=755";
  ASSERT_TRUE(parse_args_(argv));

  // Mixed constant & number.
  argv[2] = "none,/,none,MS_NODEV|0xf,mode=755";
  ASSERT_TRUE(parse_args_(argv));
}

// Invalid calls to the mount option.
TEST_F(CliTest, invalid_mount) {
  std::vector<std::string> argv = {"-v", "-k", "", "/bin/sh"};

  // Missing source.
  argv[2] = "";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Missing dest.
  argv[2] = "none";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Missing type.
  argv[2] = "none,/";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");

  // Unknown MS constant.
  argv[2] = "none,/,none,MS_WHOOPS";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}

// Valid calls to the remount mode option.
TEST_F(CliTest, valid_remount_mode) {
  std::vector<std::string> argv = {"-v", "", "/bin/sh"};

  // Mode is optional.
  argv[1] = "-K";
  ASSERT_TRUE(parse_args_(argv));

  // This should list all valid modes.
  const std::vector<std::string> modes = {
    "shared",
    "private",
    "slave",
    "unbindable",
  };

  for (const auto& mode : modes) {
    argv[1] = "-K" + mode;
    ASSERT_TRUE(parse_args_(argv));
  }
}

// Invalid calls to the remount mode option.
TEST_F(CliTest, invalid_remount_mode) {
  std::vector<std::string> argv = {"-v", "", "/bin/sh"};

  // Unknown mode.
  argv[1] = "-Kfoo";
  ASSERT_EXIT(parse_args_(argv), testing::ExitedWithCode(1), "");
}
