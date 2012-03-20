/* syscall_filter.h
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Syscall filter functions.
 */

#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include "bpf.h"

#define MAX_POLICY_LINE_LEN 1024

struct filter_block {
	struct sock_filter *instrs;
	size_t len;

	struct filter_block *next;
	struct filter_block *last;
	size_t total_len;
};

struct filter_block *compile_section(int syscall_nr, const char *policy_line,
		unsigned int label_id, struct bpf_labels *labels);
void free_block_list(struct filter_block *head);

#endif /* SYSCALL_FILTER_H */
