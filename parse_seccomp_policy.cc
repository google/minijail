/* Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>

#include "bpf.h"
#include "syscall_filter.h"
#include "util.h"

/* TODO(jorgelo): Use libseccomp disassembler here. */
int main(int argc, char **argv) {
	init_logging(LOG_TO_FD, STDERR_FILENO, LOG_INFO);

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <policy file>\n", argv[0]);
		return 1;
	}

	FILE *f = fopen(argv[1], "r");
	if (!f) {
		pdie("fopen(%s) failed", argv[1]);
	}

	struct sock_fprog fp;
	int res = compile_filter(argv[1], f, &fp, 0, 0);
	if (res != 0) {
		die("compile_filter failed");
	}
	dump_bpf_prog(&fp);

	free(fp.filter);
	fclose(f);
	return 0;
}
