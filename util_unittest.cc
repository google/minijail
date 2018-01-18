// util_unittest.cpp
// Copyright (C) 2018 The Android Open Source Project
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
// Test system.[ch] module code using gtest.

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
