/* test_util.h
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Utility functions in testing.
 */

#ifndef _TEST_UTIL_H_
#define _TEST_UTIL_H_

#include <stdio.h>

#include <memory>
#include <string>

#include "config_parser.h"

namespace mj {

namespace internal {

// Functor for |ScopedFILE| (below).
struct ScopedFILECloser {
  inline void operator()(FILE *x) const {
    if (x) {
      fclose(x);
    }
  }
};

// Functor for |ScopedConfigEntry| (below).
struct ScopedConfigEntryDeleter {
  inline void operator()(config_entry *entry) const {
    if (entry) {
      free(entry);
    }
  }
};

} // namespace internal

} // namespace mj

using ScopedFILE = std::unique_ptr<FILE, mj::internal::ScopedFILECloser>;
using ScopedConfigEntry =
    std::unique_ptr<config_entry, mj::internal::ScopedConfigEntryDeleter>;

/*
 * write_to_pipe: write a string as the file content into a pipe based
 * file handle. This is particularly useful when testing with temporary data
 * files, without dealing with complexities such as relative file path, file
 * permission and etc. However, a pipe has limited capacity so write_to_pipe
 * will hang when a big enough string is written. This is for use in testing
 * only.
 *
 * Returns a FILE* that contains @content.
 */

FILE *write_to_pipe(const std::string& content);

/*
 * source_path: return the path to a test fixture located in the current
 * source tree. This uses the `SRC` environment variable as the root of the
 * tree, falling back to the current directory.
 */
std::string source_path(const std::string& file);

#endif /* _TEST_UTIL_H_ */
