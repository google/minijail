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
