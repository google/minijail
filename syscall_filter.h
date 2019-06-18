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

#ifdef __cplusplus
extern "C" {
#endif

struct filter_block {
	struct sock_filter *instrs;
	size_t len;

	struct filter_block *next;
	struct filter_block *last;
	size_t total_len;
};

struct parser_state {
	const char *filename;
	size_t line_number;
};

enum block_action { ACTION_RET_KILL = 0, ACTION_RET_TRAP, ACTION_RET_LOG };

struct filter_options {
	enum block_action action;
	int allow_logging;
	int allow_syscalls_for_logging;
};

struct bpf_labels;

struct filter_block *compile_policy_line(struct parser_state *state, int nr,
					 const char *policy_line,
					 unsigned int label_id,
					 struct bpf_labels *labels,
					 enum block_action action);

int compile_file(const char *filename, FILE *policy_file,
		 struct filter_block *head, struct filter_block **arg_blocks,
		 struct bpf_labels *labels,
		 const struct filter_options *filteropts,
		 unsigned int include_level);

int compile_filter(const char *filename, FILE *policy_file,
		   struct sock_fprog *prog,
		   const struct filter_options *filteropts);

struct filter_block *new_filter_block(void);
int flatten_block_list(struct filter_block *head, struct sock_filter *filter,
		       size_t index, size_t cap);
void free_block_list(struct filter_block *head);

int seccomp_can_softfail(void);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* SYSCALL_FILTER_H */
