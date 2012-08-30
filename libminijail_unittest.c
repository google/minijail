/* libminijail_unittest.c
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test platform independent logic of minijail.
 */

#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "test_harness.h"

#include "libminijail.h"
#include "libminijail-private.h"

/* Prototypes needed only by test. */
void *consumebytes(size_t length, char **buf, size_t *buflength);
char *consumestr(char **buf, size_t *buflength);

/* Silence unused variable warnings. */
TEST(silence_unused) {
  EXPECT_STREQ(kLdPreloadEnvVar, kLdPreloadEnvVar);
  EXPECT_STREQ(kFdEnvVar, kFdEnvVar);
  EXPECT_STRNE(kFdEnvVar, kLdPreloadEnvVar);
}

TEST(consumebytes_zero) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  EXPECT_NE(NULL, consumebytes(0, &pos, &len));
  EXPECT_EQ(&buf[0], pos);
  EXPECT_EQ(sizeof(buf), len);
}

TEST(consumebytes_exact) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  char *end = &buf[sizeof(buf)];
  EXPECT_NE(NULL, consumebytes(len, &pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(end, pos);
}

TEST(consumebytes_half) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  char *end = &buf[sizeof(buf) / 2];
  EXPECT_NE(NULL, consumebytes(len / 2, &pos, &len));
  EXPECT_EQ(sizeof(buf) / 2, len);
  EXPECT_EQ(end, pos);
}

TEST(consumebytes_toolong) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  /* One past the end since it consumes the whole buffer. */
  EXPECT_EQ(NULL, consumebytes(len + 1, &pos, &len));
  EXPECT_EQ(sizeof(buf), len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr_zero) {
  char buf[1024];
  size_t len = 0;
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  EXPECT_EQ(NULL, consumestr(&pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr_nonul) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  EXPECT_EQ(NULL, consumestr(&pos, &len));
  EXPECT_EQ(sizeof(buf), len);
  EXPECT_EQ(&buf[0], pos);
}

TEST(consumestr_full) {
  char buf[1024];
  size_t len = sizeof(buf);
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  buf[sizeof(buf)-1] = '\0';
  EXPECT_EQ((void *)buf, consumestr(&pos, &len));
  EXPECT_EQ((size_t)0, len);
  EXPECT_EQ(&buf[sizeof(buf)], pos);
}

TEST(consumestr_trailing_nul) {
  char buf[1024];
  size_t len = sizeof(buf) - 1;
  char *pos = &buf[0];
  memset(buf, 0xff, sizeof(buf));
  buf[sizeof(buf)-1] = '\0';
  EXPECT_EQ(NULL, consumestr(&pos, &len));
  EXPECT_EQ(sizeof(buf) - 1, len);
  EXPECT_EQ(&buf[0], pos);
}

FIXTURE(marshal) {
  char buf[4096];
  struct minijail *m;
  struct minijail *j;
  size_t size;
};

FIXTURE_SETUP(marshal) {
  self->m = minijail_new();
  self->j = minijail_new();
  ASSERT_TRUE(self->m && self->j) TH_LOG("allocation failed");
  self->size = minijail_size(self->m);
  ASSERT_GT(sizeof(self->buf), self->size) {
    TH_LOG("static buffer too small for test");
  }
}

FIXTURE_TEARDOWN(marshal) {
  minijail_destroy(self->m);
  minijail_destroy(self->j);
}

TEST_F(marshal, empty) {
  ASSERT_EQ(0, minijail_marshal(self->m, self->buf, sizeof(self->buf)));
  EXPECT_EQ(0, minijail_unmarshal(self->j, self->buf, self->size));
}

TEST_F(marshal, 0xff) {
  memset(self->buf, 0xff, sizeof(self->buf));
  /* Should fail on the first consumestr since a NUL will never be found. */
  EXPECT_EQ(-EINVAL, minijail_unmarshal(self->j, self->buf, sizeof(self->buf)));
}

TEST(test_minijail_run_pid_pipe) {
  pid_t pid;
  int child_stdin;
  int mj_run_ret;
  int write_ret;
  int status;

  struct minijail *j = minijail_new();
  mj_run_ret = minijail_run_pid_pipe(j, "test/read_stdin",
                                     NULL, &pid, &child_stdin);
  EXPECT_EQ(mj_run_ret, 0);
  write_ret = write(child_stdin, "test\n", strlen("test\n"));
  EXPECT_GT(write_ret, -1);

  waitpid(pid, &status, 0);

  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  minijail_destroy(j);
}

TEST_HARNESS_MAIN
