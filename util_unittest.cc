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

#include "bpf.h"
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

TEST(parse_single_constant, formats) {
  char *end;
  long int c = 0;
  std::string constant;

  // Check base 10 works.
  constant = "1234";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(1234, c);

  // Check base 16 works.
  constant = "0x1234";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(0x1234, c);

  // Check base 8 works.
  constant = "01234";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(01234, c);
}

TEST(parse_constant, unsigned) {
  char *end;
  long int c = 0;
  std::string constant;

#if defined(BITS32)
  constant = "0x80000000";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(0x80000000U, static_cast<unsigned long int>(c));

#elif defined(BITS64)
  constant = "0x8000000000000000";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(0x8000000000000000UL, static_cast<unsigned long int>(c));

#else
# error "unknown bits!"
#endif
}

TEST(parse_constant, unsigned_toobig) {
  char *end;
  long int c = 0;
  std::string constant;

#if defined(BITS32)
  constant = "0x100000000";  // Too big for 32-bit unsigned long int.
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  // Error case should return 0.
  EXPECT_EQ(0, c);

#elif defined(BITS64)
  constant = "0x10000000000000000";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  // Error case should return 0.
  EXPECT_EQ(0, c);

#else
# error "unknown bits!"
#endif
}

TEST(parse_constant, signed) {
  char *end;
  long int c = 0;
  std::string constant = "-1";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(-1, c);
}

TEST(parse_constant, signed_toonegative) {
  char *end;
  long int c = 0;
  std::string constant;

#if defined(BITS32)
  constant = "-0x80000001";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  // Error case should return 0.
  EXPECT_EQ(0, c);

#elif defined(BITS64)
  constant = "-0x8000000000000001";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  // Error case should return 0.
  EXPECT_EQ(0, c);

#else
# error "unknown bits!"
#endif
}

TEST(parse_constant, complements) {
  char* end;
  long int c = 0;
  std::string constant;

#if defined(BITS32)
  constant = "~0x005AF0FF|~0xFFA50FFF";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(c, 0xFFFFFF00);
  constant = "0x0F|~(0x005AF000|0x00A50FFF)|0xF0";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(c, 0xFF0000FF);

#elif defined(BITS64)
  constant = "~0x00005A5AF0F0FFFF|~0xFFFFA5A50F0FFFFF";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(c, 0xFFFFFFFFFFFF0000UL);
  constant = "0x00FF|~(0x00005A5AF0F00000|0x0000A5A50F0FFFFF)|0xFF00";
  c = parse_constant(const_cast<char*>(constant.data()), &end);
  EXPECT_EQ(c, 0xFFFF00000000FFFFUL);

#else
# error "unknown bits!"
#endif
}

TEST(parse_constant, parenthesized_expresions) {
  char* end;

  const std::vector<const char*> bad_expressions = {
      "(1", "1)", "(1)1", "|(1)", "(1)|", "()",
      "(",  "((", "(()",  "(()1", "1(0)",
  };
  for (const auto* expression : bad_expressions) {
    std::string mutable_expression = expression;
    long int c =
        parse_constant(const_cast<char*>(mutable_expression.data()), &end);
    EXPECT_EQ(reinterpret_cast<const void*>(end),
              reinterpret_cast<const void*>(mutable_expression.data()));
    // Error case should return 0.
    EXPECT_EQ(c, 0) << "For expression: \"" << expression << "\"";
  }

  const std::vector<const char*> good_expressions = {
      "(3)", "(1)|2", "1|(2)", "(1)|(2)", "((3))", "0|(1|2)", "(0|1|2)",
  };
  for (const auto* expression : good_expressions) {
    std::string mutable_expression = expression;
    long int c =
        parse_constant(const_cast<char*>(mutable_expression.data()), &end);
    EXPECT_EQ(c, 3) << "For expression: \"" << expression << "\"";
  }
}

TEST(parse_size, complete) {
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
