/* unittest_util.h
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Utility functions for unit tests.
 */

#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

namespace {

constexpr bool is_android_constexpr() {
#if defined(__ANDROID__)
  return true;
#else
  return false;
#endif
}

// Returns a template path that can be used as an argument to mkstemp / mkdtemp.
constexpr const char* temp_path_pattern() {
  if (is_android_constexpr())
    return "/data/local/tmp/minijail.tests.XXXXXX";
  else
    return "minijail.tests.XXXXXX";
}

// Recursively deletes the subtree rooted at |path|.
bool rmdir_recursive(const std::string& path) {
  auto callback = [](const char* child, const struct stat*, int file_type,
                     struct FTW*) -> int {
    if (file_type == FTW_DP) {
      if (rmdir(child) == -1) {
        fprintf(stderr, "rmdir(%s): %s\n", child, strerror(errno));
        return -1;
      }
    } else if (file_type == FTW_F) {
      if (unlink(child) == -1) {
        fprintf(stderr, "unlink(%s): %s\n", child, strerror(errno));
        return -1;
      }
    }
    return 0;
  };

  return nftw(path.c_str(), callback, 128, FTW_DEPTH) == 0;
}

}  // namespace

// Creates a temporary directory that will be cleaned up upon leaving scope.
class TemporaryDir {
 public:
  TemporaryDir() : path(temp_path_pattern()) {
    if (mkdtemp(const_cast<char*>(path.c_str())) == nullptr)
      path.clear();
  }
  ~TemporaryDir() {
    if (!is_valid())
      return;
    rmdir_recursive(path.c_str());
  }

  bool is_valid() const { return !path.empty(); }

  std::string path;

 private:
  TemporaryDir(const TemporaryDir&) = delete;
  TemporaryDir& operator=(const TemporaryDir&) = delete;
};

// Creates a named temporary file that will be cleaned up upon leaving scope.
class TemporaryFile {
 public:
  TemporaryFile() : path(temp_path_pattern()) {
    int fd = mkstemp(const_cast<char*>(path.c_str()));
    if (fd == -1) {
      path.clear();
      return;
    }
    close(fd);
  }
  ~TemporaryFile() {
    if (!is_valid())
      return;
    unlink(path.c_str());
  }

  bool is_valid() const { return !path.empty(); }

  std::string path;

 private:
  TemporaryFile(const TemporaryFile&) = delete;
  TemporaryFile& operator=(const TemporaryFile&) = delete;
};
