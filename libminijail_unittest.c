/* libminijail_unittest.c
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test platform independent logic of minijail.
 */

#include "test_harness.h"

#include "libminijail.h"
#include "libminijail-private.h"

/* Silence unused variable warnings. */
TEST(silence_unused) {
  EXPECT_STREQ(kLdPreloadEnvVar, kLdPreloadEnvVar);
  EXPECT_STREQ(kFdEnvVar, kFdEnvVar);
  EXPECT_STRNE(kFdEnvVar, kLdPreloadEnvVar);
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
  /* It should parse, but the results will be a ... surprise. */
  EXPECT_EQ(0, minijail_unmarshal(self->j, self->buf, sizeof(self->buf)));
}

TEST_F(marshal, short) {
  ASSERT_EQ(0, minijail_marshal(self->m, self->buf, sizeof(self->buf)));
  EXPECT_NE(0, minijail_unmarshal(self->j, self->buf, self->size / 2));
}

TEST_HARNESS_MAIN
