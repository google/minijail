/* Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test system.[ch] module code using gtest.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "system.h"

namespace {

// A random path that really really should not exist on the host.
const char kNoSuchDir[] = "/.x/..x/...x/path/should/not/exist/";

// A random file that should exist.
const char kValidFile[] = "/etc/passwd";

// A random directory that should exist.
const char kValidDir[] = "/";

// A random character device that should exist.
const char kValidCharDev[] = "/dev/null";

// Return a temp filename in the cwd that this test can manipulate.
// It will not exist when it returns, and the user has to free the memory.
char *get_temp_path() {
  char *path = strdup("minijail.tests.XXXXXX");
  if (!path)
    return nullptr;

  // Just create the temp path.
  int fd = mkstemp(path);
  if (fd < 0)
    return nullptr;
  close(fd);
  unlink(path);

  return path;
}

}  // namespace

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

// Invalid indexes should return errors, not crash.
TEST(setup_pipe_end, bad_index) {
  EXPECT_LT(setup_pipe_end(nullptr, 2), 0);
  EXPECT_LT(setup_pipe_end(nullptr, 3), 0);
  EXPECT_LT(setup_pipe_end(nullptr, 4), 0);
}

// Verify getting the first fd works.
TEST(setup_pipe_end, index0) {
  int fds[2];
  EXPECT_EQ(0, pipe(fds));
  // This should close fds[1] and return fds[0].
  EXPECT_EQ(fds[0], setup_pipe_end(fds, 0));
  // Use close() to verify open/close state.
  EXPECT_EQ(-1, close(fds[1]));
  EXPECT_EQ(0, close(fds[0]));
}

// Verify getting the second fd works.
TEST(setup_pipe_end, index1) {
  int fds[2];
  EXPECT_EQ(0, pipe(fds));
  // This should close fds[0] and return fds[1].
  EXPECT_EQ(fds[1], setup_pipe_end(fds, 1));
  // Use close() to verify open/close state.
  EXPECT_EQ(-1, close(fds[0]));
  EXPECT_EQ(0, close(fds[1]));
}

// Invalid indexes should return errors, not crash.
TEST(setup_and_dupe_pipe_end, bad_index) {
  EXPECT_LT(setup_and_dupe_pipe_end(nullptr, 2, -1), 0);
  EXPECT_LT(setup_and_dupe_pipe_end(nullptr, 3, -1), 0);
  EXPECT_LT(setup_and_dupe_pipe_end(nullptr, 4, -1), 0);
}

// An invalid path should return an error.
TEST(write_pid_to_path, bad_path) {
  EXPECT_NE(0, write_pid_to_path(0, kNoSuchDir));
}

// Make sure we can write a pid to the file.
TEST(write_pid_to_path, basic) {
  char *path = get_temp_path();
  ASSERT_NE(nullptr, path);

  EXPECT_EQ(0, write_pid_to_path(1234, path));
  FILE *fp = fopen(path, "re");
  unlink(path);
  EXPECT_NE(nullptr, fp);
  char data[6] = {};
  EXPECT_EQ(5u, fread(data, 1, sizeof(data), fp));
  fclose(fp);
  EXPECT_EQ(0, strcmp(data, "1234\n"));

  free(path);
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
  char *path = get_temp_path();
  ASSERT_NE(nullptr, path);
  unlink(path);

  // Run `mkdir -p <path>/a/b/c`.
  char *path_a, *path_a_b, *path_a_b_c;
  ASSERT_NE(-1, asprintf(&path_a, "%s/a", path));
  ASSERT_NE(-1, asprintf(&path_a_b, "%s/b", path_a));
  ASSERT_NE(-1, asprintf(&path_a_b_c, "%s/c", path_a_b));

  // First try creating it as a file.
  EXPECT_EQ(0, mkdir_p(path_a_b_c, 0700, false));

  // Make sure the final path doesn't exist yet.
  struct stat st;
  EXPECT_EQ(0, stat(path_a_b, &st));
  EXPECT_EQ(true, S_ISDIR(st.st_mode));
  EXPECT_EQ(-1, stat(path_a_b_c, &st));

  // Then create it as a complete dir.
  EXPECT_EQ(0, mkdir_p(path_a_b_c, 0700, true));

  // Make sure the final dir actually exists.
  EXPECT_EQ(0, stat(path_a_b_c, &st));
  EXPECT_EQ(true, S_ISDIR(st.st_mode));

  // Clean up.
  ASSERT_EQ(0, rmdir(path_a_b_c));
  ASSERT_EQ(0, rmdir(path_a_b));
  ASSERT_EQ(0, rmdir(path_a));
  ASSERT_EQ(0, rmdir(path));

  free(path_a_b_c);
  free(path_a_b);
  free(path_a);
  free(path);
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
  char *path = get_temp_path();
  ASSERT_NE(nullptr, path);

  // Passing -1 for uid/gid tells chown to make no changes.
  EXPECT_EQ(0, setup_mount_destination("none", path, -1, -1, false));
  // We check it's a directory by deleting it as such.
  EXPECT_EQ(0, rmdir(path));

  free(path);
}

// If the source path does not exist, we should error out.
TEST(setup_mount_destination, missing_source) {
  // The missing dest path is so we can exercise the source logic.
  EXPECT_NE(0, setup_mount_destination(kNoSuchDir, kNoSuchDir, 0, 0, false));
  EXPECT_NE(0, setup_mount_destination(kNoSuchDir, kNoSuchDir, 0, 0, true));
}

// A bind mount of a directory should create the destination dir.
TEST(setup_mount_destination, create_bind_dir) {
  char *path = get_temp_path();
  ASSERT_NE(nullptr, path);

  // Passing -1 for uid/gid tells chown to make no changes.
  EXPECT_EQ(0, setup_mount_destination(kValidDir, path, -1, -1, true));
  // We check it's a directory by deleting it as such.
  EXPECT_EQ(0, rmdir(path));

  free(path);
}

// A bind mount of a file should create the destination file.
TEST(setup_mount_destination, create_bind_file) {
  char *path = get_temp_path();
  ASSERT_NE(nullptr, path);

  // Passing -1 for uid/gid tells chown to make no changes.
  EXPECT_EQ(0, setup_mount_destination(kValidFile, path, -1, -1, true));
  // We check it's a file by deleting it as such.
  EXPECT_EQ(0, unlink(path));

  free(path);
}

// A mount of a character device should create the destination char.
TEST(setup_mount_destination, create_char_dev) {
  char *path = get_temp_path();
  ASSERT_NE(nullptr, path);

  // Passing -1 for uid/gid tells chown to make no changes.
  EXPECT_EQ(0, setup_mount_destination(kValidCharDev, path, -1, -1, false));
  // We check it's a directory by deleting it as such.
  EXPECT_EQ(0, rmdir(path));

  free(path);
}
