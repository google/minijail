/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test config_parser.c using gtest.
 */

#include <gtest/gtest.h>
#include <string>

#include "config_parser.h"
#include "test_util.h"
#include "util.h"

namespace {

class ConfigFileTest : public ::testing::Test {
protected:
  virtual void SetUp() {
    list_ = new_config_entry_list();
    ASSERT_NE(list_, nullptr);
  }
  virtual void TearDown() { free_config_entry_list(list_); }
  struct config_entry_list *list_;
};

} // namespace

TEST(ParsingConfigTest, valid_config_line) {
  ScopedConfigEntry entry(
      (config_entry *)calloc(1, sizeof(struct config_entry)));
  const std::vector<std::string> valid_conf_lines = {
      "mount=none",
      "valueless_key"
      "binding = none",
      "  xyz = abc  ",
  };

  for (const auto& conf_line : valid_conf_lines) {
    ASSERT_TRUE(parse_config_line(conf_line.c_str(), entry.get()));
    clear_config_entry(entry.get());
  }
}

TEST(ParsingConfigTest, invalid_config_line) {
  ScopedConfigEntry entry(
      (config_entry *)calloc(1, sizeof(struct config_entry)));
  const std::vector<std::string> invalid_conf_lines = {
      "= none",
      "",
      "empty_arg=",
      "empty_arg=   ",
  };

  for (const auto& conf_line : invalid_conf_lines) {
    ASSERT_FALSE(parse_config_line(conf_line.c_str(), entry.get()));
  }
}

TEST_F(ConfigFileTest, malformed_config_line) {
  std::string config = "% minijail-config-file v0\n"
                       "=malformed";
  ScopedFILE config_file(write_to_pipe(config));
  ASSERT_NE(config_file.get(), nullptr);

  bool res = parse_config_file(config_file.get(), list_);

  // Policy is malformed, but process should not crash.
  ASSERT_FALSE(res);
  ASSERT_EQ(list_->num_entries, 0);
}

TEST_F(ConfigFileTest, bad_directive) {
  std::string config = "% bad-directive\n"
                       "# comments";
  ScopedFILE config_file(write_to_pipe(config));
  ASSERT_NE(config_file.get(), nullptr);

  bool res = parse_config_file(config_file.get(), list_);

  // Policy is malformed, but process should not crash.
  ASSERT_FALSE(res);
  ASSERT_EQ(list_->num_entries, 0);
}

TEST_F(ConfigFileTest, wellformed_single_line) {
  std::string config = "% minijail-config-file v0\n"
                       "# Comments \n"
                       "\n"
                       "uts\n"
                       "mount= xyz\n"
                       "binding = none,/tmp";
  ScopedFILE config_file(write_to_pipe(config));
  ASSERT_NE(config_file.get(), nullptr);

  bool res = parse_config_file(config_file.get(), list_);

  ASSERT_TRUE(res);
  ASSERT_EQ(list_->num_entries, 3);
  struct config_entry *first_entry = list_->entries;
  struct config_entry *second_entry = list_->entries + 1;
  struct config_entry *third_entry = list_->entries + 2;
  ASSERT_EQ(std::string(first_entry->key), "uts");
  ASSERT_EQ(first_entry->value, nullptr);
  ASSERT_EQ(std::string(second_entry->key), "mount");
  ASSERT_EQ(std::string(second_entry->value), "xyz");
  ASSERT_EQ(std::string(third_entry->key), "binding");
  ASSERT_EQ(std::string(third_entry->value), "none,/tmp");
}

TEST_F(ConfigFileTest, wellformed_multi_line) {
  std::string config = "% minijail-config-file v0\n"
                       "# Comments \n"
                       "\n"
                       "mount = \\\n"
                       "none\n"
                       "binding = none,\\\n"
                       "/tmp";
  ScopedFILE config_file(write_to_pipe(config));
  ASSERT_NE(config_file.get(), nullptr);

  int res = parse_config_file(config_file.get(), list_);

  ASSERT_TRUE(res);
  ASSERT_EQ(list_->num_entries, 2);
  struct config_entry *first_entry = list_->entries;
  struct config_entry *second_entry = list_->entries + 1;
  ASSERT_EQ(std::string(first_entry->key), "mount");
  ASSERT_EQ(std::string(first_entry->value), "none");
  ASSERT_EQ(std::string(second_entry->key), "binding");
  ASSERT_EQ(std::string(second_entry->value), "none, /tmp");
}
