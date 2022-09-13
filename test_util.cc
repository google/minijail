/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "test_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

#define MAX_PIPE_CAPACITY (4096)

FILE *write_to_pipe(const std::string& content)
{
	int pipefd[2];
	if (pipe(pipefd) == -1) {
		die("pipe(pipefd) failed");
	}

	size_t len = content.length();
	if (len > MAX_PIPE_CAPACITY)
		die("write_to_pipe cannot handle >4KB content.");
	size_t i = 0;
	unsigned int attempts = 0;
	ssize_t ret;
	while (i < len) {
		ret = write(pipefd[1], content.c_str() + i, len - i);
		if (ret == -1) {
			close(pipefd[0]);
			close(pipefd[1]);
			return NULL;
		}

		/* If we write 0 bytes three times in a row, fail. */
		if (ret == 0) {
			if (++attempts >= 3) {
				close(pipefd[0]);
				close(pipefd[1]);
				warn("write() returned 0 three times in a row");
				return NULL;
			}
			continue;
		}

		attempts = 0;
		i += (size_t)ret;
	}

	close(pipefd[1]);
	return fdopen(pipefd[0], "r");
}

std::string source_path(const std::string& file) {
	std::string srcdir = getenv("SRC") ? : ".";
	return srcdir + "/" + file;
}
