// parse_seccomp_policy.cc
// Copyright (C) 2016 The Android Open Source Project
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

#include <stdio.h>

#include "bpf.h"
#include "syscall_filter.h"
#include "util.h"

/* TODO(jorgelo): Use libseccomp disassembler here. */
int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <policy file>\n", argv[0]);
		return 1;
	}

	FILE *f = fopen(argv[1], "r");
	if (!f) {
		pdie("fopen(%s) failed", argv[1]);
	}

	struct sock_fprog fp;
	int res = compile_filter(f, &fp, 0, 0);
	if (res != 0) {
		die("compile_filter failed");
	}
	dump_bpf_prog(&fp);

	free(fp.filter);
	fclose(f);
	return 0;
}
