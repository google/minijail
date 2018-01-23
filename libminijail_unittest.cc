/* Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test platform independent logic of Minijail using gtest.
 */

#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "libminijail.h"
#include "libminijail-private.h"
#include "util.h"

namespace {

#if defined(__ANDROID__)
# define ROOT_PREFIX "/system"
#else
# define ROOT_PREFIX ""
#endif

const char kShellPath[] = ROOT_PREFIX "/bin/sh";
const char kCatPath[] = ROOT_PREFIX "/bin/cat";

}  // namespace

/* Prototypes needed only by test. */
size_t minijail_get_tmpfs_size(const struct minijail *);

/* Silence unused variable warnings. */
TEST(silence, silence_unused) {
  EXPECT_STREQ(kLdPreloadEnvVar, kLdPreloadEnvVar);
  EXPECT_STREQ(kFdEnvVar, kFdEnvVar);
  EXPECT_STRNE(kFdEnvVar, kLdPreloadEnvVar);
}

TEST(consumebytes, zero) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  EXPECT_NE(nullptr, consumebytes(0, &pos, &len));
  EXPECT_EQ(&buf[0], pos);
  EXPECT_EQ(sizeof(buf), len);
}

TEST(consumebytes, exact) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  char *end = &buf[sizeof(buf)];
  EXPECT_NE(nullptr, consumebytes(len, &pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(end, pos);
}

TEST(consumebytes, half) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  char *end = &buf[sizeof(buf) / 2];
  EXPECT_NE(nullptr, consumebytes(len / 2, &pos, &len));
  EXPECT_EQ(sizeof(buf) / 2, len);
  EXPECT_EQ(end, pos);
}

TEST(consumebytes, toolong) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  EXPECT_EQ(nullptr, consumebytes(len + 1, &pos, &len));
  EXPECT_EQ(sizeof(buf), len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr, zero) {
  char buf[1024];
  size_t len = 0;
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  EXPECT_EQ(nullptr, consumestr(&pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr, nonul) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  EXPECT_EQ(nullptr, consumestr(&pos, &len));
  EXPECT_EQ(sizeof(buf), len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr, full) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  buf[sizeof(buf)-1] = '\0';
  EXPECT_EQ((void *)buf, consumestr(&pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(&buf[sizeof(buf)], pos);
}

TEST(consumestr, trailing_nul) {
  char buf[1024];
  size_t len = sizeof(buf) - 1;
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  buf[sizeof(buf)-1] = '\0';
  EXPECT_EQ(nullptr, consumestr(&pos, &len));
  EXPECT_EQ(sizeof(buf) - 1, len);
  EXPECT_EQ(&buf[0], pos);
}

class MarshalTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    m_ = minijail_new();
    j_ = minijail_new();
    size_ = minijail_size(m_);
  }
  virtual void TearDown() {
    minijail_destroy(m_);
    minijail_destroy(j_);
  }

  char buf_[4096];
  struct minijail *m_;
  struct minijail *j_;
  size_t size_;
};

TEST_F(MarshalTest, empty) {
  ASSERT_EQ(0, minijail_marshal(m_, buf_, sizeof(buf_)));
  EXPECT_EQ(0, minijail_unmarshal(j_, buf_, size_));
}

TEST_F(MarshalTest, 0xff) {
  memset(buf_, 0xff, sizeof(buf_));
  /* Should fail on the first consumestr since a NUL will never be found. */
  EXPECT_EQ(-EINVAL, minijail_unmarshal(j_, buf_, sizeof(buf_)));
}

TEST(Test, minijail_run_pid_pipes_no_preload) {
  pid_t pid;
  int child_stdin, child_stdout, child_stderr;
  int mj_run_ret;
  ssize_t write_ret, read_ret;
  const size_t buf_len = 128;
  char buf[buf_len];
  int status;
  char teststr[] = "test\n";
  size_t teststr_len = strlen(teststr);
  char *argv[4];

  struct minijail *j = minijail_new();

  argv[0] = (char*)kCatPath;
  argv[1] = NULL;
  mj_run_ret = minijail_run_pid_pipes_no_preload(j, argv[0], argv,
                                                 &pid,
                                                 &child_stdin, &child_stdout,
                                                 NULL);
  EXPECT_EQ(mj_run_ret, 0);

  write_ret = write(child_stdin, teststr, teststr_len);
  EXPECT_EQ(write_ret, (int)teststr_len);

  read_ret = read(child_stdout, buf, 8);
  EXPECT_EQ(read_ret, (int)teststr_len);
  buf[teststr_len] = 0;
  EXPECT_EQ(strcmp(buf, teststr), 0);

  EXPECT_EQ(kill(pid, SIGTERM), 0);
  waitpid(pid, &status, 0);
  ASSERT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGTERM);

  argv[0] = (char*)kShellPath;
  argv[1] = "-c";
  argv[2] = "echo test >&2";
  argv[3] = NULL;
  mj_run_ret = minijail_run_pid_pipes_no_preload(j, argv[0], argv, &pid,
                                                 &child_stdin, &child_stdout,
                                                 &child_stderr);
  EXPECT_EQ(mj_run_ret, 0);

  read_ret = read(child_stderr, buf, buf_len);
  EXPECT_GE(read_ret, (int)teststr_len);

  waitpid(pid, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  minijail_destroy(j);
}

TEST(Test, test_minijail_no_fd_leaks) {
  pid_t pid;
  int child_stdout;
  int mj_run_ret;
  ssize_t read_ret;
  const size_t buf_len = 128;
  char buf[buf_len];
  char script[buf_len];
  int status;
  char *argv[4];

  int dev_null = open("/dev/null", O_RDONLY);
  ASSERT_NE(dev_null, -1);
  snprintf(script,
           sizeof(script),
           "[ -e /proc/self/fd/%d ] && echo yes || echo no",
           dev_null);

  struct minijail *j = minijail_new();

  argv[0] = (char*)kShellPath;
  argv[1] = "-c";
  argv[2] = script;
  argv[3] = NULL;
  mj_run_ret = minijail_run_pid_pipes_no_preload(
      j, argv[0], argv, &pid, NULL, &child_stdout, NULL);
  EXPECT_EQ(mj_run_ret, 0);

  read_ret = read(child_stdout, buf, buf_len);
  EXPECT_GE(read_ret, 0);
  buf[read_ret] = '\0';
  EXPECT_STREQ(buf, "yes\n");

  waitpid(pid, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  minijail_close_open_fds(j);
  mj_run_ret = minijail_run_pid_pipes_no_preload(
      j, argv[0], argv, &pid, NULL, &child_stdout, NULL);
  EXPECT_EQ(mj_run_ret, 0);

  read_ret = read(child_stdout, buf, buf_len);
  EXPECT_GE(read_ret, 0);
  buf[read_ret] = '\0';
  EXPECT_STREQ(buf, "no\n");

  waitpid(pid, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  minijail_destroy(j);

  close(dev_null);
}

TEST(Test, test_minijail_fork) {
  pid_t mj_fork_ret;
  int status;
  int pipe_fds[2];
  ssize_t pid_size = sizeof(mj_fork_ret);

  struct minijail *j = minijail_new();

  ASSERT_EQ(pipe(pipe_fds), 0);

  mj_fork_ret = minijail_fork(j);
  ASSERT_GE(mj_fork_ret, 0);
  if (mj_fork_ret == 0) {
    pid_t pid_in_parent;
    // Wait for the parent to tell us the pid in the parent namespace.
    EXPECT_EQ(read(pipe_fds[0], &pid_in_parent, pid_size), pid_size);
    EXPECT_EQ(pid_in_parent, getpid());
    exit(0);
  }

  EXPECT_EQ(write(pipe_fds[1], &mj_fork_ret, pid_size), pid_size);
  waitpid(mj_fork_ret, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  minijail_destroy(j);
}

static int early_exit(void* payload) {
  exit(static_cast<int>(reinterpret_cast<intptr_t>(payload)));
}

TEST(Test, test_minijail_callback) {
  pid_t pid;
  int mj_run_ret;
  int status;
  char *argv[2];
  int exit_code = 42;

  struct minijail *j = minijail_new();

  status =
      minijail_add_hook(j, &early_exit, reinterpret_cast<void *>(exit_code),
			MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS);
  EXPECT_EQ(status, 0);

  argv[0] = (char*)kCatPath;
  argv[1] = NULL;
  mj_run_ret = minijail_run_pid_pipes_no_preload(j, argv[0], argv, &pid, NULL,
						 NULL, NULL);
  EXPECT_EQ(mj_run_ret, 0);

  status = minijail_wait(j);
  EXPECT_EQ(status, exit_code);

  minijail_destroy(j);
}

TEST(Test, test_minijail_preserve_fd) {
  int mj_run_ret;
  int status;
  char *argv[2];
  char teststr[] = "test\n";
  size_t teststr_len = strlen(teststr);
  int read_pipe[2];
  int write_pipe[2];
  char buf[1024];

  struct minijail *j = minijail_new();

  status = pipe(read_pipe);
  ASSERT_EQ(status, 0);
  status = pipe(write_pipe);
  ASSERT_EQ(status, 0);

  status = minijail_preserve_fd(j, write_pipe[0], STDIN_FILENO);
  ASSERT_EQ(status, 0);
  status = minijail_preserve_fd(j, read_pipe[1], STDOUT_FILENO);
  ASSERT_EQ(status, 0);
  minijail_close_open_fds(j);

  argv[0] = (char*)kCatPath;
  argv[1] = NULL;
  mj_run_ret = minijail_run_no_preload(j, argv[0], argv);
  EXPECT_EQ(mj_run_ret, 0);

  close(write_pipe[0]);
  status = write(write_pipe[1], teststr, teststr_len);
  EXPECT_EQ(status, (int)teststr_len);
  close(write_pipe[1]);

  close(read_pipe[1]);
  status = read(read_pipe[0], buf, 8);
  EXPECT_EQ(status, (int)teststr_len);
  buf[teststr_len] = 0;
  EXPECT_EQ(strcmp(buf, teststr), 0);

  status = minijail_wait(j);
  EXPECT_EQ(status, 0);

  minijail_destroy(j);
}

namespace {

// Tests that require userns access.
// Android unit tests don't currently support entering user namespaces as
// unprivileged users due to having an older kernel.  Chrome OS unit tests
// don't support it either due to being in a chroot environment (see man 2
// clone for more information about failure modes with the CLONE_NEWUSER flag).
class NamespaceTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    userns_supported_ = UsernsSupported();
  }

  // Whether userns is supported.
  static bool userns_supported_;

  static bool UsernsSupported() {
    pid_t pid = fork();
    if (pid == -1)
      pdie("could not fork");

    if (pid == 0)
      _exit(unshare(CLONE_NEWUSER) == 0 ? 0 : 1);

    int status;
    if (waitpid(pid, &status, 0) < 0)
      pdie("could not wait");

    if (!WIFEXITED(status))
      die("child did not exit properly: %#x", status);

    bool ret = WEXITSTATUS(status) == 0;
    if (!ret)
      warn("Skipping userns related tests");
    return ret;
  }
};

bool NamespaceTest::userns_supported_;

}  // namespace

TEST_F(NamespaceTest, test_tmpfs_userns) {
  int mj_run_ret;
  int status;
  char *argv[4];
  char uidmap[128], gidmap[128];
  constexpr uid_t kTargetUid = 1000;  // Any non-zero value will do.
  constexpr gid_t kTargetGid = 1000;

  if (!userns_supported_) {
    SUCCEED();
    return;
  }

  struct minijail *j = minijail_new();

  minijail_namespace_pids(j);
  minijail_namespace_vfs(j);
  minijail_mount_tmp(j);
  minijail_run_as_init(j);

  // Perform userns mapping.
  minijail_namespace_user(j);
  snprintf(uidmap, sizeof(uidmap), "%d %d 1", kTargetUid, getuid());
  snprintf(gidmap, sizeof(gidmap), "%d %d 1", kTargetGid, getgid());
  minijail_change_uid(j, kTargetUid);
  minijail_change_gid(j, kTargetGid);
  minijail_uidmap(j, uidmap);
  minijail_gidmap(j, gidmap);
  minijail_namespace_user_disable_setgroups(j);

  argv[0] = (char*)kShellPath;
  argv[1] = "-c";
  argv[2] = "exec touch /tmp/foo";
  argv[3] = NULL;
  mj_run_ret = minijail_run_no_preload(j, argv[0], argv);
  EXPECT_EQ(mj_run_ret, 0);

  status = minijail_wait(j);
  EXPECT_EQ(status, 0);

  minijail_destroy(j);
}

TEST(Test, parse_size) {
  size_t size;

  ASSERT_EQ(0, parse_size(&size, "42"));
  ASSERT_EQ(42U, size);

  ASSERT_EQ(0, parse_size(&size, "16K"));
  ASSERT_EQ(16384U, size);

  ASSERT_EQ(0, parse_size(&size, "1M"));
  ASSERT_EQ(1024U * 1024, size);

  uint64_t gigabyte = 1024ULL * 1024 * 1024;
  ASSERT_EQ(0, parse_size(&size, "3G"));
  ASSERT_EQ(3U, size / gigabyte);
  ASSERT_EQ(0U, size % gigabyte);

  ASSERT_EQ(0, parse_size(&size, "4294967294"));
  ASSERT_EQ(3U, size / gigabyte);
  ASSERT_EQ(gigabyte - 2, size % gigabyte);

#if __WORDSIZE == 64
  uint64_t exabyte = gigabyte * 1024 * 1024 * 1024;
  ASSERT_EQ(0, parse_size(&size, "9E"));
  ASSERT_EQ(9U, size / exabyte);
  ASSERT_EQ(0U, size % exabyte);

  ASSERT_EQ(0, parse_size(&size, "15E"));
  ASSERT_EQ(15U, size / exabyte);
  ASSERT_EQ(0U, size % exabyte);

  ASSERT_EQ(0, parse_size(&size, "18446744073709551614"));
  ASSERT_EQ(15U, size / exabyte);
  ASSERT_EQ(exabyte - 2, size % exabyte);

  ASSERT_EQ(-ERANGE, parse_size(&size, "16E"));
  ASSERT_EQ(-ERANGE, parse_size(&size, "19E"));
  ASSERT_EQ(-EINVAL, parse_size(&size, "7GTPE"));
#elif __WORDSIZE == 32
  ASSERT_EQ(-ERANGE, parse_size(&size, "5G"));
  ASSERT_EQ(-ERANGE, parse_size(&size, "9G"));
  ASSERT_EQ(-ERANGE, parse_size(&size, "9E"));
  ASSERT_EQ(-ERANGE, parse_size(&size, "7GTPE"));
#endif

  ASSERT_EQ(-EINVAL, parse_size(&size, ""));
  ASSERT_EQ(-EINVAL, parse_size(&size, "14u"));
  ASSERT_EQ(-EINVAL, parse_size(&size, "14.2G"));
  ASSERT_EQ(-EINVAL, parse_size(&size, "-1G"));
  ASSERT_EQ(-EINVAL, parse_size(&size, "; /bin/rm -- "));
}
