/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test util.[ch] module code using gtest.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "util.h"

namespace {

std::string dump_env(const char *const *env) {
  std::string result;
  for (; *env; ++env) {
    result += *env;
    result += "\n";
  }

  return result;
}

}  // namespace

// Sanity check for the strip func.
TEST(strip, basic) {
  char str[] = " foo\t";
  ASSERT_EQ("foo", std::string(strip(str)));
}

// Make sure we don't crash with various "null"-like inputs.
TEST(tokenize, null_stringp) {
  ASSERT_EQ(nullptr, tokenize(nullptr, nullptr));
  ASSERT_EQ(nullptr, tokenize(nullptr, ""));
  ASSERT_EQ(nullptr, tokenize(nullptr, ","));

  char *p = nullptr;
  ASSERT_EQ(nullptr, tokenize(&p, nullptr));
}

// Make sure we don't crash with various "null"-like inputs.
TEST(tokenize, null_delim) {
  char str[] = "a,b,c";
  char *p = str;
  ASSERT_EQ(str, tokenize(&p, nullptr));
  ASSERT_EQ(nullptr, p);
  ASSERT_EQ(str, std::string("a,b,c"));

  p = str;
  ASSERT_EQ(str, tokenize(&p, ""));
  ASSERT_EQ(nullptr, p);
  ASSERT_EQ(str, std::string("a,b,c"));
}

// Sanity check for the tokenize func.
TEST(tokenize, basic) {
  char str[] = "a,b,c";
  char *p = str;
  ASSERT_EQ("a", std::string(tokenize(&p, ",")));
  ASSERT_EQ("b", std::string(tokenize(&p, ",")));
  ASSERT_EQ("c", std::string(tokenize(&p, ",")));
  ASSERT_EQ(nullptr, p);
  ASSERT_EQ(nullptr, tokenize(&p, ","));
}

// Check edge case with an empty string.
TEST(tokenize, empty_string) {
  char str[] = "";
  char *p = str;
  ASSERT_EQ("", std::string(tokenize(&p, ",")));
  ASSERT_EQ(nullptr, p);
  ASSERT_EQ(nullptr, tokenize(&p, ","));
}

// Check behavior with empty tokens at the start/middle/end.
TEST(tokenize, empty_tokens) {
  char str[] = ",,a,b,,,c,,";
  char *p = str;
  ASSERT_EQ("", std::string(tokenize(&p, ",")));
  ASSERT_EQ("", std::string(tokenize(&p, ",")));
  ASSERT_EQ("a", std::string(tokenize(&p, ",")));
  ASSERT_EQ("b", std::string(tokenize(&p, ",")));
  ASSERT_EQ("", std::string(tokenize(&p, ",")));
  ASSERT_EQ("", std::string(tokenize(&p, ",")));
  ASSERT_EQ("c", std::string(tokenize(&p, ",")));
  ASSERT_EQ("", std::string(tokenize(&p, ",")));
  ASSERT_EQ("", std::string(tokenize(&p, ",")));
  ASSERT_EQ(nullptr, p);
  ASSERT_EQ(nullptr, tokenize(&p, ","));
}

// Check environment manipulation functions.
TEST(environment, copy_and_modify) {
  minijail_free_env(nullptr);

  char **env = minijail_copy_env(nullptr);
  EXPECT_EQ("", dump_env(env));
  minijail_free_env(env);

  const char *const kConstEnv[] = {
    "val1=1",
    "val2=2",
    "dup=1",
    "dup=2",
    "empty=",
    nullptr,
  };

  // libc unfortunately uses char* const[] as the type for the environment, and
  // we match that. It's actually missing a const-ness of the chars making up
  // the environment strings, but we need that to initialize the |kEnv|
  // constant. Hence, do a cast here to force things into alignment...
  char* const* kEnv = const_cast<char* const*>(kConstEnv);

  env = minijail_copy_env(kEnv);
  EXPECT_EQ("val1=1\nval2=2\ndup=1\ndup=2\nempty=\n", dump_env(env));
  minijail_free_env(env);

  env = minijail_copy_env(kEnv);
  EXPECT_EQ("val1=1\nval2=2\ndup=1\ndup=2\nempty=\n", dump_env(env));

  EXPECT_EQ(EINVAL, minijail_setenv(nullptr, "val1", "3", 1));
  char **env_ret = nullptr;
  EXPECT_EQ(EINVAL, minijail_setenv(&env_ret, "val1", "3", 1));

  env_ret = env;
  EXPECT_EQ(EINVAL, minijail_setenv(&env_ret, nullptr, "3", 1));
  EXPECT_EQ(env, env_ret);
  EXPECT_EQ(EINVAL, minijail_setenv(&env_ret, "", "3", 1));
  EXPECT_EQ(env, env_ret);
  EXPECT_EQ(EINVAL, minijail_setenv(&env_ret, "", nullptr, 1));
  EXPECT_EQ(env, env_ret);

  EXPECT_EQ(0, minijail_setenv(&env, "val1", "3", 0));
  EXPECT_EQ("val1=1\nval2=2\ndup=1\ndup=2\nempty=\n", dump_env(env));
  EXPECT_EQ(0, minijail_setenv(&env, "val1", "3", 1));
  EXPECT_EQ("val1=3\nval2=2\ndup=1\ndup=2\nempty=\n", dump_env(env));
  EXPECT_EQ(0, minijail_setenv(&env, "val2", "4", 1));
  EXPECT_EQ("val1=3\nval2=4\ndup=1\ndup=2\nempty=\n", dump_env(env));
  EXPECT_EQ(0, minijail_setenv(&env, "dup", "5", 1));
  EXPECT_EQ("val1=3\nval2=4\ndup=5\ndup=2\nempty=\n", dump_env(env));
  EXPECT_EQ(0, minijail_setenv(&env, "empty", "6", 1));
  EXPECT_EQ("val1=3\nval2=4\ndup=5\ndup=2\nempty=6\n", dump_env(env));
  EXPECT_EQ(0, minijail_setenv(&env, "empty", "", 1));
  EXPECT_EQ("val1=3\nval2=4\ndup=5\ndup=2\nempty=\n", dump_env(env));
  EXPECT_EQ(0, minijail_setenv(&env, "new1", "7", 0));
  EXPECT_EQ("val1=3\nval2=4\ndup=5\ndup=2\nempty=\nnew1=7\n", dump_env(env));
  EXPECT_EQ(0, minijail_setenv(&env, "new2", "8", 1));
  EXPECT_EQ("val1=3\nval2=4\ndup=5\ndup=2\nempty=\nnew1=7\nnew2=8\n",
            dump_env(env));

  minijail_free_env(env);
}
