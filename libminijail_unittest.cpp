// libminijail_unittest.cpp
// Copyright (C) 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Test platform independent logic of Minijail using gtest.

#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <gtest/gtest.h>

#include "libminijail.h"
#include "libminijail-private.h"
#include "util.h"

/* Prototypes needed only by test. */
void *consumebytes(size_t length, char **buf, size_t *buflength);
char *consumestr(char **buf, size_t *buflength);

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
  EXPECT_TRUE(NULL != consumebytes(0, &pos, &len));
  EXPECT_EQ(&buf[0], pos);
  EXPECT_EQ(sizeof(buf), len);
}

TEST(consumebytes, exact) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  char *end = &buf[sizeof(buf)];
  EXPECT_TRUE(NULL != consumebytes(len, &pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(end, pos);
}

TEST(consumebytes, half) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  char *end = &buf[sizeof(buf) / 2];
  EXPECT_TRUE(NULL != consumebytes(len / 2, &pos, &len));
  EXPECT_EQ(sizeof(buf) / 2, len);
  EXPECT_EQ(end, pos);
}

TEST(consumebytes, toolong) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  EXPECT_TRUE(NULL == consumebytes(len + 1, &pos, &len));
  EXPECT_EQ(sizeof(buf), len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr, zero) {
  char buf[1024];
  size_t len = 0;
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  EXPECT_EQ(NULL, consumestr(&pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr, nonul) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  EXPECT_EQ(NULL, consumestr(&pos, &len));
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
  EXPECT_EQ(NULL, consumestr(&pos, &len));
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
#if defined(__ANDROID__)
  char filename[] = "/system/bin/cat";
#else
  char filename[] = "/bin/cat";
#endif
  char teststr[] = "test\n";
  size_t teststr_len = strlen(teststr);
  char *argv[4];

  struct minijail *j = minijail_new();

  argv[0] = filename;
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

#if defined(__ANDROID__)
  argv[0] = "/system/bin/sh";
#else
  argv[0] = "/bin/sh";
#endif
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
