/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test system.[ch] module code using gtest.
 */

#include <ftw.h>
#include <limits.h>
#include <linux/securebits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>

#include "system.h"
#include "unittest_util.h"

namespace {

// A random path that really really should not exist on the host.
constexpr const char kNoSuchDir[] = "/.x/..x/...x/path/should/not/exist/";

// A random file that should exist on both Linux and Android.
constexpr const char kValidFile[] = "/etc/hosts";

// A random directory that should exist.
constexpr const char kValidDir[] = "/";

// A random character device that should exist.
constexpr const char kValidCharDev[] = "/dev/null";

}  // namespace

TEST(secure_noroot_set_and_locked, zero_mask) {
  ASSERT_EQ(secure_noroot_set_and_locked(0), 0);
}

TEST(secure_noroot_set_and_locked, set) {
  ASSERT_EQ(secure_noroot_set_and_locked(issecure_mask(SECURE_NOROOT) |
                                         issecure_mask(SECURE_NOROOT_LOCKED)),
            1);
}

TEST(secure_noroot_set_and_locked, not_set) {
  ASSERT_EQ(secure_noroot_set_and_locked(issecure_mask(SECURE_KEEP_CAPS) |
                                         issecure_mask(SECURE_NOROOT_LOCKED)),
            0);
}

// Sanity check for the cap range.
TEST(get_last_valid_cap, basic) {
  unsigned int cap = get_last_valid_cap();

  // We pick 35 as it's been that since at least v3.0.
  // If this test is run on older kernels, it might fail.
  EXPECT_GE(cap, 35u);

  // Pick a really large number that we probably won't hit for a long time.
  // It helps that caps are bitfields.
  EXPECT_LT(cap, 128u);
}

// Might be useful to figure out the return value, but for now,
// just make sure it doesn't crash?
TEST(cap_ambient_supported, smoke) {
  cap_ambient_supported();
}

// An invalid path should return an error.
TEST(write_pid_to_path, bad_path) {
  EXPECT_NE(0, write_pid_to_path(0, kNoSuchDir));
}

// Make sure we can write a pid to the file.
TEST(write_pid_to_path, basic) {
  TemporaryFile tmp;
  ASSERT_TRUE(tmp.is_valid());

  EXPECT_EQ(0, write_pid_to_path(1234, tmp.path.c_str()));
  FILE *fp = fopen(tmp.path.c_str(), "re");
  EXPECT_NE(nullptr, fp);
  char data[6] = {};
  EXPECT_EQ(5u, fread(data, 1, sizeof(data), fp));
  fclose(fp);
  EXPECT_STREQ(data, "1234\n");
}

// If the destination exists, there's nothing to do.
// Also check trailing slash handling.
TEST(mkdir_p, dest_exists) {
  EXPECT_EQ(0, mkdir_p("/", 0, true));
  EXPECT_EQ(0, mkdir_p("///", 0, true));
  EXPECT_EQ(0, mkdir_p("/proc", 0, true));
  EXPECT_EQ(0, mkdir_p("/proc/", 0, true));
  EXPECT_EQ(0, mkdir_p("/dev", 0, true));
  EXPECT_EQ(0, mkdir_p("/dev/", 0, true));
}

// Create a directory tree that doesn't exist.
TEST(mkdir_p, create_tree) {
  TemporaryDir dir;
  ASSERT_TRUE(dir.is_valid());

  // Run `mkdir -p <path>/a/b/c`.
  std::string path_a = dir.path + "/a";
  std::string path_a_b = path_a + "/b";
  std::string path_a_b_c = path_a_b + "/c";

  // First try creating it as a file.
  EXPECT_EQ(0, mkdir_p(path_a_b_c.c_str(), 0700, false));

  // Make sure the final path doesn't exist yet.
  struct stat st;
  EXPECT_EQ(0, stat(path_a_b.c_str(), &st));
  EXPECT_EQ(true, S_ISDIR(st.st_mode));
  EXPECT_EQ(-1, stat(path_a_b_c.c_str(), &st));

  // Then create it as a complete dir.
  EXPECT_EQ(0, mkdir_p(path_a_b_c.c_str(), 0700, true));

  // Make sure the final dir actually exists.
  EXPECT_EQ(0, stat(path_a_b_c.c_str(), &st));
  EXPECT_EQ(true, S_ISDIR(st.st_mode));
}

// Return success on NULL pointer.
TEST(get_mount_flags, null_ptr) {
  ASSERT_EQ(0, get_mount_flags("/proc", nullptr));
}

// Successfully obtain mount flags.
TEST(get_mount_flags, mount_flags) {
  struct statvfs stvfs_buf;
  ASSERT_EQ(0, statvfs("/proc", &stvfs_buf));

  TemporaryDir dir;
  ASSERT_TRUE(dir.is_valid());

  unsigned long mount_flags = -1;
  ASSERT_EQ(0, get_mount_flags("/proc", &mount_flags));
  EXPECT_EQ(stvfs_buf.f_flag, mount_flags);

  // Same thing holds for children of a mount.
  mount_flags = -1;
  ASSERT_EQ(0, get_mount_flags("/proc/self", &mount_flags));
  EXPECT_EQ(stvfs_buf.f_flag, mount_flags);
}

// Non-existent paths fail with the proper errno value.
TEST(get_mount_flags, nonexistent_path) {
  unsigned long mount_flags = -1;
  ASSERT_EQ(-ENOENT, get_mount_flags("/does/not/exist", &mount_flags));
}

// If the destination exists, there's nothing to do.
TEST(setup_mount_destination, dest_exists) {
  // Pick some paths that should always exist.  We pass in invalid pointers
  // for other args so we crash if the dest check doesn't short circuit.
  EXPECT_EQ(0, setup_mount_destination(nullptr, kValidDir, 0, 0, false));
  EXPECT_EQ(0, setup_mount_destination(nullptr, "/proc", 0, 0, true));
  EXPECT_EQ(0, setup_mount_destination(nullptr, "/dev", 0, 0, false));
}

// When given a bind mount where the source is relative, reject it.
TEST(setup_mount_destination, reject_relative_bind) {
  // Pick a destination we know doesn't exist.
  EXPECT_NE(0, setup_mount_destination("foo", kNoSuchDir, 0, 0, true));
}

// A mount of a pseudo filesystem should make the destination dir.
TEST(setup_mount_destination, create_pseudo_fs) {
  TemporaryDir dir;
  ASSERT_TRUE(dir.is_valid());

  // Passing -1 for user ID/group ID tells chown to make no changes.
  std::string no_chmod = dir.path + "/no_chmod";
  EXPECT_EQ(0, setup_mount_destination("none", no_chmod.c_str(), -1, -1,
                                       false));
  // We check it's a directory by deleting it as such.
  EXPECT_EQ(0, rmdir(no_chmod.c_str()));

  // Confirm that a bad user ID/group ID fails the function as expected.
  // On Android, Bionic manages user IDs directly: there is no /etc/passwd file.
  // This results in most user IDs being valid. Instead of trying to find an
  // invalid user ID, just skip this check.
  if (!is_android()) {
    std::string with_chmod = dir.path + "/with_chmod";
    EXPECT_NE(0, setup_mount_destination("none", with_chmod.c_str(),
                                         UINT_MAX / 2, UINT_MAX / 2, false));
  }
}

// If the source path does not exist, we should error out.
TEST(setup_mount_destination, missing_source) {
  // The missing dest path is so we can exercise the source logic.
  EXPECT_NE(0, setup_mount_destination(kNoSuchDir, kNoSuchDir, 0, 0, false));
  EXPECT_NE(0, setup_mount_destination(kNoSuchDir, kNoSuchDir, 0, 0, true));
}

// A bind mount of a directory should create the destination dir.
TEST(setup_mount_destination, create_bind_dir) {
  TemporaryDir dir;
  ASSERT_TRUE(dir.is_valid());

  // Passing -1 for user ID/group ID tells chown to make no changes.
  std::string child_dir = dir.path + "/child_dir";
  EXPECT_EQ(0, setup_mount_destination(kValidDir, child_dir.c_str(), -1, -1,
                                       true));
  // We check it's a directory by deleting it as such.
  EXPECT_EQ(0, rmdir(child_dir.c_str()));
}

// A bind mount of a file should create the destination file.
TEST(setup_mount_destination, create_bind_file) {
  TemporaryDir dir;
  ASSERT_TRUE(dir.is_valid());

  // Passing -1 for user ID/group ID tells chown to make no changes.
  std::string child_file = dir.path + "/child_file";
  EXPECT_EQ(0, setup_mount_destination(kValidFile, child_file.c_str(), -1, -1,
                                       true));
  // We check it's a file by deleting it as such.
  EXPECT_EQ(0, unlink(child_file.c_str()));
}

// A mount of a character device should create the destination char.
TEST(setup_mount_destination, create_char_dev) {
  TemporaryDir dir;
  ASSERT_TRUE(dir.is_valid());

  // Passing -1 for user ID/group ID tells chown to make no changes.
  std::string child_dev = dir.path + "/child_dev";
  EXPECT_EQ(0, setup_mount_destination(kValidCharDev, child_dev.c_str(), -1, -1,
                                       false));
  // We check it's a directory by deleting it as such.
  EXPECT_EQ(0, rmdir(child_dev.c_str()));
}

TEST(seccomp_actions_available, smoke) {
  seccomp_ret_log_available();
  seccomp_ret_kill_process_available();
}

TEST(set_no_new_privs, basic) {
  EXPECT_TRUE(sys_set_no_new_privs());
}

TEST(is_canonical_path, basic) {
  EXPECT_FALSE(is_canonical_path("/proc/self"));
  EXPECT_FALSE(is_canonical_path("relative"));
  EXPECT_FALSE(is_canonical_path("/proc/./1"));
  EXPECT_FALSE(is_canonical_path("/proc/../proc/1"));

  EXPECT_TRUE(is_canonical_path("/"));
  EXPECT_TRUE(is_canonical_path("/proc"));
  EXPECT_TRUE(is_canonical_path("/proc/1"));
}

TEST(is_canonical_path, trailing_slash) {
  EXPECT_TRUE(is_canonical_path("/proc/1/"));
  EXPECT_FALSE(is_canonical_path("/proc/1//"));
}
