/* Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test platform independent logic of Minijail using gtest.
 */

#include <errno.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <set>
#include <string>

#include "libminijail-private.h"
#include "libminijail.h"
#include "scoped_minijail.h"
#include "util.h"

namespace {

#if defined(__ANDROID__)
# define ROOT_PREFIX "/system"
#else
# define ROOT_PREFIX ""
#endif

constexpr char kShellPath[] = ROOT_PREFIX "/bin/sh";
constexpr char kCatPath[] = ROOT_PREFIX "/bin/cat";
constexpr char kPreloadPath[] = "./libminijailpreload.so";
constexpr size_t kBufferSize = 128;

std::set<pid_t> GetProcessSubtreePids(pid_t root_pid) {
  std::set<pid_t> pids{root_pid};
  bool progress = false;

  do {
    progress = false;
    DIR* d = opendir("/proc");
    if (!d)
      pdie("opendir(\"/proc\")");

    struct dirent* dir_entry;
    while ((dir_entry = readdir(d)) != nullptr) {
      if (dir_entry->d_type != DT_DIR)
        continue;
      char* end;
      const int pid = strtol(dir_entry->d_name, &end, 10);
      if (*end != '\0')
        continue;
      std::string path = "/proc/" + std::to_string(pid) + "/stat";

      FILE* f = fopen(path.c_str(), "re");
      if (!f)
        pdie("fopen(%s)", path.c_str());
      pid_t ppid;
      int ret = fscanf(f, "%*d (%*[^)]) %*c %d", &ppid);
      fclose(f);
      if (ret != 1) {
        continue;
      }
      if (pids.find(ppid) == pids.end())
        continue;
      progress |= pids.insert(pid).second;
    }
    closedir(d);
  } while (progress);
  return pids;
}

std::map<std::string, std::string> GetNamespaces(
    pid_t pid,
    const std::vector<std::string>& namespace_names) {
  std::map<std::string, std::string> namespaces;
  char buf[kBufferSize];
  for (const auto& namespace_name : namespace_names) {
    std::string path = "/proc/" + std::to_string(pid) + "/ns/" + namespace_name;
    ssize_t len = readlink(path.c_str(), buf, sizeof(buf));
    if (len == -1)
      pdie("readlink(\"%s\")", path.c_str());
    namespaces.emplace(namespace_name, std::string(buf, len));
  }
  return namespaces;
}

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

TEST(KillTest, running_process) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "sleep 1000", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_kill(j.get()), 128 + SIGTERM);
  EXPECT_EQ(minijail_kill(j.get()), -ESRCH);
}

TEST(KillTest, process_already_awaited) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "sleep 1; exit 42", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), 42);
  EXPECT_EQ(minijail_kill(j.get()), -ESRCH);
}

TEST(KillTest, process_already_finished_but_not_awaited) {
  int fds[2];
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "exit 42", nullptr};
  ASSERT_EQ(pipe(fds), 0);
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  ASSERT_EQ(close(fds[1]), 0);
  // Wait for process to finish.
  char buf[PIPE_BUF];
  EXPECT_EQ(read(fds[0], buf, PIPE_BUF), 0);
  EXPECT_EQ(minijail_kill(j.get()), 42);
  EXPECT_EQ(minijail_wait(j.get()), -ECHILD);
}

TEST(KillTest, process_not_started) {
  const ScopedMinijail j(minijail_new());
  EXPECT_EQ(minijail_kill(j.get()), -ECHILD);
}

TEST(WaitTest, return_zero) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "exit 0", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), 0);
}

TEST(WaitTest, return_max) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "exit 255", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), 255);
}

TEST(WaitTest, return_modulo) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "exit 256", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), 0);
}

TEST(WaitTest, killed_by_sigkill) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "kill -KILL $$; sleep 1000", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), MINIJAIL_ERR_SIG_BASE  + SIGKILL);
}

TEST(WaitTest, killed_by_sigsys) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "kill -SYS $$; sleep 1000", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), MINIJAIL_ERR_JAIL);
}

TEST(WaitTest, command_not_found) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"whatever", nullptr};
  EXPECT_EQ(minijail_run(j.get(), "command that cannot be found", argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), MINIJAIL_ERR_NO_COMMAND);
}

TEST(WaitTest, command_not_run) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"whatever", nullptr};
  EXPECT_EQ(minijail_run(j.get(), "/dev/null", argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), MINIJAIL_ERR_NO_ACCESS);
}

TEST(WaitTest, no_process) {
  const ScopedMinijail j(minijail_new());
  EXPECT_EQ(minijail_wait(j.get()), -ECHILD);
}

TEST(WaitTest, can_wait_only_once) {
  const ScopedMinijail j(minijail_new());
  char* const argv[] = {"sh", "-c", "exit 0", nullptr};
  EXPECT_EQ(minijail_run(j.get(), kShellPath, argv), 0);
  EXPECT_EQ(minijail_wait(j.get()), 0);
  EXPECT_EQ(minijail_wait(j.get()), -ECHILD);
}

TEST(Test, close_original_pipes_after_dup2) {
  // Pipe used by child process to signal that it continued after reading from
  // stdin.
  int to_wait[2];
  ASSERT_EQ(pipe(to_wait), 0);

  const ScopedMinijail j(minijail_new());
  char* program;
  ASSERT_GT(asprintf(&program, R"(
      echo Hi >&1;
      echo There >&2;
      exec 1>&-;
      exec 2>&-;
      read line1;
      read line2;
      echo "$line1$line2 and Goodbye" >&%d;
      exit 42;
    )", to_wait[1]), 0);
  char* const argv[] = {"sh", "-c", program, nullptr};

  int in = -1;
  int out = -1;
  int err = -1;
  EXPECT_EQ(minijail_run_pid_pipes_no_preload(j.get(), kShellPath, argv,
                                              nullptr, &in, &out, &err),
            0);
  free(program);

  EXPECT_GT(in, 0);
  EXPECT_GT(out, 0);
  EXPECT_GT(err, 0);

  char buf[PIPE_BUF];
  ssize_t n;

  // Check that stdout and stderr pipes work.
  n = read(out, buf, PIPE_BUF);
  ASSERT_GT(n, 0);
  EXPECT_EQ(std::string(buf, n), "Hi\n");

  n = read(err, buf, PIPE_BUF);
  ASSERT_GT(n, 0);
  EXPECT_EQ(std::string(buf, n), "There\n");

  // Check that the write ends of stdout and stderr pipes got closed by the
  // child process. If the child process kept other file descriptors connected
  // to stdout and stderr, then the parent process wouldn't be able to detect
  // that all write ends of these pipes are closed and it would block here.
  EXPECT_EQ(read(out, buf, PIPE_BUF), 0);
  EXPECT_EQ(read(err, buf, PIPE_BUF), 0);

  // Check that stdin pipe works.
  const std::string s = "Greetings\n";
  EXPECT_EQ(write(in, s.data(), s.size()), s.size());

  // Close write end of pipe connected to child's stdin. If there was another
  // file descriptor connected to this write end, then the child wouldn't be
  // able to detect that this write end is closed and it would block.
  ASSERT_EQ(close(in), 0);

  // Check that child process continued and ended.
  n = read(to_wait[0], buf, PIPE_BUF);
  ASSERT_GT(n, 0);
  EXPECT_EQ(std::string(buf, n), "Greetings and Goodbye\n");
  EXPECT_EQ(minijail_wait(j.get()), 42);
}

TEST(Test, minijail_run_env_pid_pipes) {
  // TODO(crbug.com/895875): The preload library interferes with ASan since they
  // both need to use LD_PRELOAD.
  if (running_with_asan()) {
    SUCCEED();
    return;
  }

  ScopedMinijail j(minijail_new());
  minijail_set_preload_path(j.get(), kPreloadPath);

  char *argv[4];
  argv[0] = const_cast<char*>(kCatPath);
  argv[1] = NULL;

  pid_t pid;
  int child_stdin, child_stdout;
  int mj_run_ret = minijail_run_pid_pipes(
      j.get(), argv[0], argv, &pid, &child_stdin, &child_stdout, NULL);
  EXPECT_EQ(mj_run_ret, 0);

  char teststr[] = "test\n";
  const size_t teststr_len = strlen(teststr);
  ssize_t write_ret = write(child_stdin, teststr, teststr_len);
  EXPECT_EQ(write_ret, static_cast<ssize_t>(teststr_len));

  char buf[kBufferSize] = {};
  ssize_t read_ret = read(child_stdout, buf, sizeof(buf) - 1);
  EXPECT_EQ(read_ret, static_cast<ssize_t>(teststr_len));
  EXPECT_STREQ(buf, teststr);

  int status;
  EXPECT_EQ(kill(pid, SIGTERM), 0);
  EXPECT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGTERM);

  argv[0] = const_cast<char*>(kShellPath);
  argv[1] = "-c";
  argv[2] = "echo \"${TEST_PARENT+set}|${TEST_VAR}\" >&2";
  argv[3] = nullptr;

  char *envp[2];
  envp[0] = "TEST_VAR=test";
  envp[1] = NULL;

  // Set a canary env var in the parent that should not be present in the child.
  ASSERT_EQ(setenv("TEST_PARENT", "test", 1 /*overwrite*/), 0);

  int child_stderr;
  mj_run_ret =
      minijail_run_env_pid_pipes(j.get(), argv[0], argv, envp, &pid,
                                 &child_stdin, &child_stdout, &child_stderr);
  EXPECT_EQ(mj_run_ret, 0);

  memset(buf, 0, sizeof(buf));
  read_ret = read(child_stderr, buf, sizeof(buf) - 1);
  EXPECT_GE(read_ret, 0);
  EXPECT_STREQ(buf, "|test\n");

  EXPECT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(Test, minijail_run_env_pid_pipes_no_preload) {
  ScopedMinijail j(minijail_new());

  char *argv[4];
  argv[0] = const_cast<char*>(kCatPath);
  argv[1] = NULL;

  pid_t pid;
  int child_stdin, child_stdout;
  int mj_run_ret = minijail_run_pid_pipes(
      j.get(), argv[0], argv, &pid, &child_stdin, &child_stdout, NULL);
  EXPECT_EQ(mj_run_ret, 0);

  char teststr[] = "test\n";
  const size_t teststr_len = strlen(teststr);
  ssize_t write_ret = write(child_stdin, teststr, teststr_len);
  EXPECT_EQ(write_ret, static_cast<ssize_t>(teststr_len));

  char buf[kBufferSize] = {};
  ssize_t read_ret = read(child_stdout, buf, 8);
  EXPECT_EQ(read_ret, static_cast<ssize_t>(teststr_len));
  EXPECT_STREQ(buf, teststr);

  int status;
  EXPECT_EQ(kill(pid, SIGTERM), 0);
  EXPECT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGTERM);

  argv[0] = const_cast<char*>(kShellPath);
  argv[1] = "-c";
  argv[2] = "echo \"${TEST_PARENT+set}|${TEST_VAR}\" >&2";
  argv[3] = nullptr;

  char *envp[2];
  envp[0] = "TEST_VAR=test";
  envp[1] = NULL;

  // Set a canary env var in the parent that should not be present in the child.
  ASSERT_EQ(setenv("TEST_PARENT", "test", 1 /*overwrite*/), 0);

  int child_stderr;
  mj_run_ret =
      minijail_run_env_pid_pipes(j.get(), argv[0], argv, envp, &pid,
                                 &child_stdin, &child_stdout, &child_stderr);
  EXPECT_EQ(mj_run_ret, 0);

  memset(buf, 0, sizeof(buf));
  read_ret = read(child_stderr, buf, sizeof(buf));
  EXPECT_GE(read_ret, 0);
  EXPECT_STREQ(buf, "|test\n");

  EXPECT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(Test, test_minijail_no_fd_leaks) {
  pid_t pid;
  int child_stdout;
  int mj_run_ret;
  ssize_t read_ret;
  char buf[kBufferSize];
  char script[kBufferSize];
  int status;
  char *argv[4];

  int dev_null = open("/dev/null", O_RDONLY);
  ASSERT_NE(dev_null, -1);
  snprintf(script,
           sizeof(script),
           "[ -e /proc/self/fd/%d ] && echo yes || echo no",
           dev_null);

  struct minijail *j = minijail_new();

  argv[0] = const_cast<char*>(kShellPath);
  argv[1] = "-c";
  argv[2] = script;
  argv[3] = NULL;
  mj_run_ret = minijail_run_pid_pipes_no_preload(
      j, argv[0], argv, &pid, NULL, &child_stdout, NULL);
  EXPECT_EQ(mj_run_ret, 0);

  read_ret = read(child_stdout, buf, sizeof(buf));
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

  read_ret = read(child_stdout, buf, sizeof(buf));
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

  ScopedMinijail j(minijail_new());

  ASSERT_EQ(pipe(pipe_fds), 0);

  mj_fork_ret = minijail_fork(j.get());
  ASSERT_GE(mj_fork_ret, 0);
  if (mj_fork_ret == 0) {
    pid_t pid_in_parent;
    // Wait for the parent to tell us the pid in the parent namespace.
    ASSERT_EQ(read(pipe_fds[0], &pid_in_parent, pid_size), pid_size);
    ASSERT_EQ(pid_in_parent, getpid());
    exit(0);
  }

  EXPECT_EQ(write(pipe_fds[1], &mj_fork_ret, pid_size), pid_size);
  waitpid(mj_fork_ret, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
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

  argv[0] = const_cast<char*>(kCatPath);
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

  argv[0] = const_cast<char*>(kCatPath);
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

TEST(Test, test_minijail_reset_signal_mask) {
  struct minijail *j = minijail_new();

  sigset_t original_signal_mask;
  {
    sigset_t signal_mask;
    ASSERT_EQ(0, sigemptyset(&signal_mask));
    ASSERT_EQ(0, sigaddset(&signal_mask, SIGUSR1));
    ASSERT_EQ(0, sigprocmask(SIG_SETMASK, &signal_mask, &original_signal_mask));
  }

  minijail_reset_signal_mask(j);

  pid_t mj_fork_ret = minijail_fork(j);
  ASSERT_GE(mj_fork_ret, 0);
  if (mj_fork_ret == 0) {
    sigset_t signal_mask;
    ASSERT_EQ(0, sigprocmask(SIG_SETMASK, NULL, &signal_mask));
    ASSERT_EQ(0, sigismember(&signal_mask, SIGUSR1));
    minijail_destroy(j);
    exit(0);
  }

  ASSERT_EQ(0, sigprocmask(SIG_SETMASK, &original_signal_mask, NULL));

  int status;
  waitpid(mj_fork_ret, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  minijail_destroy(j);
}

TEST(Test, test_minijail_reset_signal_handlers) {
  struct minijail *j = minijail_new();

  ASSERT_EQ(SIG_DFL, signal(SIGUSR1, SIG_DFL));
  ASSERT_EQ(SIG_DFL, signal(SIGUSR1, SIG_IGN));
  ASSERT_EQ(SIG_IGN, signal(SIGUSR1, SIG_IGN));

  minijail_reset_signal_handlers(j);

  pid_t mj_fork_ret = minijail_fork(j);
  ASSERT_GE(mj_fork_ret, 0);
  if (mj_fork_ret == 0) {
    ASSERT_EQ(SIG_DFL, signal(SIGUSR1, SIG_DFL));
    minijail_destroy(j);
    exit(0);
  }

  ASSERT_NE(SIG_ERR, signal(SIGUSR1, SIG_DFL));

  int status;
  waitpid(mj_fork_ret, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

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
  char uidmap[kBufferSize], gidmap[kBufferSize];
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

  argv[0] = const_cast<char*>(kShellPath);
  argv[1] = "-c";
  argv[2] = "exec touch /tmp/foo";
  argv[3] = NULL;
  mj_run_ret = minijail_run_no_preload(j, argv[0], argv);
  EXPECT_EQ(mj_run_ret, 0);

  status = minijail_wait(j);
  EXPECT_EQ(status, 0);

  minijail_destroy(j);
}

TEST_F(NamespaceTest, test_namespaces) {
  constexpr char teststr[] = "test\n";

  // TODO(crbug.com/895875): The preload library interferes with ASan since they
  // both need to use LD_PRELOAD.
  if (!userns_supported_ || running_with_asan()) {
    SUCCEED();
    return;
  }

  std::string uidmap = "0 " + std::to_string(getuid()) + " 1";
  std::string gidmap = "0 " + std::to_string(getgid()) + " 1";

  const std::vector<std::string> namespace_names = {"pid", "mnt",    "user",
                                                    "net", "cgroup", "uts"};
  // Grab the set of namespaces outside the container.
  std::map<std::string, std::string> init_namespaces =
      GetNamespaces(getpid(), namespace_names);
  std::function<void(struct minijail*)> test_functions[] = {
      [](struct minijail* j attribute_unused) {},
      [](struct minijail* j) {
        minijail_mount(j, "/", "/", "", MS_BIND | MS_REC | MS_RDONLY);
        minijail_enter_pivot_root(j, "/tmp");
      },
      [](struct minijail* j) { minijail_enter_chroot(j, "/"); },
  };

  // This test is run with and without the preload library.
  for (const auto& run_function :
       {minijail_run_pid_pipes, minijail_run_pid_pipes_no_preload}) {
    for (const auto& test_function : test_functions) {
      ScopedMinijail j(minijail_new());
      minijail_set_preload_path(j.get(), kPreloadPath);

      // Enter all the namespaces we can.
      minijail_namespace_cgroups(j.get());
      minijail_namespace_net(j.get());
      minijail_namespace_pids(j.get());
      minijail_namespace_user(j.get());
      minijail_namespace_vfs(j.get());
      minijail_namespace_uts(j.get());

      // Set up the user namespace.
      minijail_uidmap(j.get(), uidmap.c_str());
      minijail_gidmap(j.get(), gidmap.c_str());
      minijail_namespace_user_disable_setgroups(j.get());

      minijail_close_open_fds(j.get());
      test_function(j.get());

      char* const argv[] = {const_cast<char*>(kCatPath), nullptr};
      pid_t container_pid;
      int child_stdin, child_stdout;
      int mj_run_ret =
          run_function(j.get(), argv[0], argv,
                       &container_pid, &child_stdin, &child_stdout, nullptr);
      EXPECT_EQ(mj_run_ret, 0);

      // Send some data to stdin and read it back to ensure that the child
      // process is running.
      const size_t teststr_len = strlen(teststr);
      ssize_t write_ret = write(child_stdin, teststr, teststr_len);
      EXPECT_EQ(write_ret, static_cast<ssize_t>(teststr_len));

      char buf[kBufferSize];
      ssize_t read_ret = read(child_stdout, buf, 8);
      EXPECT_EQ(read_ret, static_cast<ssize_t>(teststr_len));
      buf[teststr_len] = 0;
      EXPECT_EQ(strcmp(buf, teststr), 0);

      // Grab the set of namespaces in every container process. They must not
      // match the ones in the init namespace, and they must all match each
      // other.
      std::map<std::string, std::string> container_namespaces =
          GetNamespaces(container_pid, namespace_names);
      EXPECT_NE(container_namespaces, init_namespaces);
      for (pid_t pid : GetProcessSubtreePids(container_pid))
        EXPECT_EQ(container_namespaces, GetNamespaces(pid, namespace_names));

      EXPECT_EQ(0, close(child_stdin));

      int status = minijail_wait(j.get());
      EXPECT_EQ(status, 0);
    }
  }
}

TEST_F(NamespaceTest, test_enter_ns) {
  char uidmap[kBufferSize], gidmap[kBufferSize];

  if (!userns_supported_) {
    SUCCEED();
    return;
  }

  // We first create a child in a new userns so we have privs to run more tests.
  // We can't combine the steps as the kernel disallows many resource sharing
  // from outside the userns.
  struct minijail *j = minijail_new();

  minijail_namespace_vfs(j);
  minijail_namespace_pids(j);
  minijail_run_as_init(j);

  // Perform userns mapping.
  minijail_namespace_user(j);
  snprintf(uidmap, sizeof(uidmap), "0 %d 1", getuid());
  snprintf(gidmap, sizeof(gidmap), "0 %d 1", getgid());
  minijail_uidmap(j, uidmap);
  minijail_gidmap(j, gidmap);
  minijail_namespace_user_disable_setgroups(j);

  pid_t pid = minijail_fork(j);
  if (pid == 0) {
    // Child.
    minijail_destroy(j);

    // Create new namespaces inside this userns which we may enter.
    j = minijail_new();
    minijail_namespace_net(j);
    minijail_namespace_vfs(j);
    pid = minijail_fork(j);
    if (pid == 0) {
      // Child.
      minijail_destroy(j);

      // Finally enter those namespaces.
      j = minijail_new();

      // We need to get the absolute path because entering a new mntns will
      // implicitly chdir(/) for us.
      char *path = realpath(kPreloadPath, nullptr);
      ASSERT_NE(nullptr, path);
      minijail_set_preload_path(j, path);

      minijail_namespace_net(j);
      minijail_namespace_vfs(j);

      minijail_namespace_enter_net(j, "/proc/self/ns/net");
      minijail_namespace_enter_vfs(j, "/proc/self/ns/mnt");

      char *argv[] = {"/bin/true", nullptr};
      EXPECT_EQ(0, minijail_run(j, argv[0], argv));
      EXPECT_EQ(0, minijail_wait(j));
      minijail_destroy(j);
      exit(0);
    } else {
      ASSERT_GT(pid, 0);
      EXPECT_EQ(0, minijail_wait(j));
      minijail_destroy(j);
      exit(0);
    }
  } else {
    ASSERT_GT(pid, 0);
    EXPECT_EQ(0, minijail_wait(j));
    minijail_destroy(j);
  }
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

void TestCreateSession(bool create_session) {
  int status;
  int pipe_fds[2];
  pid_t child_pid;
  pid_t parent_sid = getsid(0);
  ssize_t pid_size = sizeof(pid_t);

  ScopedMinijail j(minijail_new());
  // stdin/stdout/stderr might be attached to TTYs. Close them to avoid creating
  // a new session because of that.
  minijail_close_open_fds(j.get());

  if (create_session)
    minijail_create_session(j.get());

  ASSERT_EQ(pipe(pipe_fds), 0);
  minijail_preserve_fd(j.get(), pipe_fds[0], pipe_fds[0]);

  child_pid = minijail_fork(j.get());
  ASSERT_GE(child_pid, 0);
  if (child_pid == 0) {
    pid_t sid_in_parent;
    ASSERT_EQ(read(pipe_fds[0], &sid_in_parent, pid_size), pid_size);
    if (create_session)
      ASSERT_NE(sid_in_parent, getsid(0));
    else
      ASSERT_EQ(sid_in_parent, getsid(0));
    exit(0);
  }

  EXPECT_EQ(write(pipe_fds[1], &parent_sid, pid_size), pid_size);
  waitpid(child_pid, &status, 0);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(Test, default_no_new_session) {
  TestCreateSession(/*create_session=*/false);
}

TEST(Test, create_new_session) {
  TestCreateSession(/*create_session=*/true);
}
