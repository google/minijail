/* test_util.h
 * Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Utility functions in testing.
 */

#ifndef _TEST_UTIL_H_
#define _TEST_UTIL_H_

#include <string>

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

FILE *write_to_pipe(std::string content);

#endif /* _TEST_UTIL_H_ */
