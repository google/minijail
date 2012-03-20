/* parser.c
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Syscall filter syntax parser.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "syscall_filter.h"

#define error(_msg, ...) do {	\
	fprintf(stderr, "minijail: error: " _msg, ## __VA_ARGS__);	\
	abort();							\
} while (0)

int str_to_op(const char *op_str)
{
	if (!strcmp(op_str, "==")) {
		return EQ;
	} else if (!strcmp(op_str, "!=")) {
		return NE;
	} else {
		return 0;
	}
}

#define ONE_INSTR	1
#define TWO_INSTRS	2

struct sock_filter *new_instr_buf(size_t count)
{
	struct sock_filter *buf = calloc(count, sizeof(struct sock_filter));
	if (!buf)
		error("could not allocate BPF instruction buffer");

	return buf;
}

void append_filter_block(struct filter_block *head,
		struct sock_filter *instrs, size_t len)
{
	struct filter_block *new_last;

	/*
	 * If |head| has no filter assigned yet,
	 * we don't create a new node.
	 */
	if (head->instrs == NULL) {
		new_last = head;
	} else {
		new_last = calloc(1, sizeof(struct filter_block));
		if (!new_last)
			error("could not allocate BPF filter block");

		if (head->next != NULL) {
			head->last->next = new_last;
			head->last = new_last;
		} else {
			head->last = head->next = new_last;
		}
		head->total_len += len;
	}

	new_last->instrs = instrs;
	new_last->total_len = new_last->len = len;
	new_last->last = new_last->next = NULL;
}

void append_ret_kill(struct filter_block *head)
{
	struct sock_filter *filter = new_instr_buf(ONE_INSTR);
	set_bpf_ret_kill(filter);
	append_filter_block(head, filter, ONE_INSTR);
}

void append_ret_errno(struct filter_block *head, int errno_val)
{
	struct sock_filter *filter = new_instr_buf(ONE_INSTR);
	set_bpf_ret_errno(filter, errno_val);
	append_filter_block(head, filter, ONE_INSTR);
}

unsigned int get_label_id(struct bpf_labels *labels, const char *label_str)
{
	int label_id = bpf_label_id(labels, label_str);
	if (label_id < 0)
		error("could not allocate BPF label string");
	return label_id;
}

unsigned int group_end_lbl(struct bpf_labels *labels, int nr, int idx)
{
	char lbl_str[MAX_BPF_LABEL_LEN];
	snprintf(lbl_str, MAX_BPF_LABEL_LEN, "%d_%d_end", nr, idx);
	return get_label_id(labels, lbl_str);
}

unsigned int success_lbl(struct bpf_labels *labels, int nr)
{
	char lbl_str[MAX_BPF_LABEL_LEN];
	snprintf(lbl_str, MAX_BPF_LABEL_LEN, "%d_success", nr);
	return get_label_id(labels, lbl_str);
}

struct filter_block *compile_section(int syscall_nr, const char *policy_line,
		unsigned int entry_lbl_id, struct bpf_labels *labels)
{
	/*
	 * |policy_line| should be an expression of the form:
	 * "arg0 == 3 && arg1 == 5 || arg0 == 0x8"
	 *
	 * This is, an expression in DNF (disjunctive normal form);
	 * a disjunction ('||') of one or more conjunctions ('&&')
	 * of one or more atoms.
	 *
	 * Atoms are of the form "arg{DNUM} OP NUM"
	 * where:
	 *   - DNUM is a decimal number.
	 *   - OP is a comparison operator (== or != for now).
	 *   - NUM is a decimal or hexadecimal number.
	 *
	 * When the syscall arguments make the expression true,
	 * the syscall is allowed. If not, the process is killed.
	 *
	 * To avoid killing the process, a policy line can include an
	 * optional "return <errno>" clause:
	 *
	 * "arg0 == 3 && arg1 == 5 || arg0 == 0x8; return {NUM}"
	 *
	 * In this case, the syscall will return -1 and |errno| will
	 * be set to NUM.
	 */

	size_t len = 0;
	int group_idx = 0;

	/* Checks for overly long policy lines. */
	if (strlen(policy_line) >= MAX_POLICY_LINE_LEN)
		return NULL;

	/* strtok() modifies its first argument, so let's make a copy. */
	char *line = strndup(policy_line, MAX_POLICY_LINE_LEN);
	if (!line)
		return NULL;

	/* Splits the optional "return <errno>" part. */
	char *arg_filter = strtok(line, ";");
	char *ret_errno = strtok(NULL, ";");

	/*
	 * We build the argument filter as a collection of smaller
	 * "filter blocks" linked together in a singly-linked list.
	 */
	struct filter_block *head = calloc(1, sizeof(struct filter_block));
	if (!head)
		return NULL;

	head->instrs = NULL;
	head->last = head->next = NULL;

	/*
	 * Argument filters begin with a label where the main filter
	 * will jump after checking the syscall number.
	 */
	struct sock_filter *entry_label = new_instr_buf(ONE_INSTR);
	set_bpf_lbl(entry_label, entry_lbl_id);
	append_filter_block(head, entry_label, ONE_INSTR);

	/*
	 * Splits the policy line by '||' into conjunctions and each conjunction
	 * by '&&' into atoms.
	 */
	char *arg_filter_str;
	char *arg_filter_ptr;
	for (arg_filter_str = arg_filter; ; arg_filter_str = NULL) {
		char *group = strtok_r(arg_filter_str, "||", &arg_filter_ptr);

		if (group == NULL)
			break;

		char *group_str;
		char *group_ptr;
		for (group_str = group; ; group_str = NULL) {
			char *comp = strtok_r(group_str, "&&", &group_ptr);

			if (comp == NULL)
				break;

			/* Splits each atom. */
			char *comp_ptr;
			char *argidx_str = strtok_r(comp, " ", &comp_ptr);
			char *operator_str = strtok_r(NULL, " ", &comp_ptr);
			char *constant_str = strtok_r(NULL, " ", &comp_ptr);

			if (argidx_str == NULL ||
			    operator_str == NULL ||
			    constant_str == NULL)
				return NULL;

			int op = str_to_op(operator_str);

			if (op < MIN_OPERATOR)
				return NULL;

			if (strncmp(argidx_str, "arg", 3)) {
				return NULL;
			}

			char *argidx_ptr;
			long int argidx = strtol(
					argidx_str + 3, &argidx_ptr, 10);
			/*
			 * Checks to see if an actual argument index
			 * was parsed.
			 */
			if (argidx_ptr == argidx_str + 3) {
				return NULL;
			}

			long int c = strtol(constant_str, NULL, 0);
			unsigned int id = group_end_lbl(
					labels, syscall_nr, group_idx);

			/*
			 * Builds a BPF comparison between a syscall argument
			 * and a constant.
			 * The comparison lives inside an AND statement.
			 * If the comparison succeeds, we continue
			 * to the next comparison.
			 * If this comparison fails, the whole AND statement
			 * will fail, so we jump to the end of this AND statement.
			 */
			struct sock_filter *comp_block;
			len = bpf_arg_comp(&comp_block,
					op, argidx, c, id);
			if (len == 0)
				return NULL;

			append_filter_block(head, comp_block, len);
		}
		/*
		 * If the AND statement succeeds, we're done,
		 * so jump to SUCCESS line.
		 */
		unsigned int id = success_lbl(labels, syscall_nr);
		struct sock_filter *group_end_block = new_instr_buf(TWO_INSTRS);
		len = set_bpf_jump_lbl(group_end_block, id);
		/*
		 * The end of each AND statement falls after the
		 * jump to SUCCESS.
		 */
		id = group_end_lbl(labels, syscall_nr, group_idx++);
		len += set_bpf_lbl(group_end_block + len, id);
		append_filter_block(head, group_end_block, len);
	}

	/*
	 * If no AND statements succeed, we end up here,
	 * because we never jumped to SUCCESS.
	 * If we have to return an errno, do it,
	 * otherwise just kill the task.
	 */
	if (ret_errno) {
		char *errno_ptr;

		char *ret_str = strtok_r(ret_errno, " ", &errno_ptr);
		if (strncmp(ret_str, "return", strlen("return")))
			return NULL;

		char *errno_val_str = strtok_r(NULL, " ", &errno_ptr);

		if (errno_val_str) {
			char *errno_val_ptr;
			int errno_val = strtol(
					errno_val_str, &errno_val_ptr, 0);
			/* Checks to see if we parsed an actual errno. */
			if (errno_val_ptr == errno_val_str)
				return NULL;

			append_ret_errno(head, errno_val);
		} else {
			append_ret_kill(head);
		}
	} else {
		append_ret_kill(head);
	}

	/*
	 * Every time the filter succeeds we jump to a predefined SUCCESS
	 * label. Add that label and BPF RET_ALLOW code now.
	 */
	unsigned int id = success_lbl(labels, syscall_nr);
	struct sock_filter *success_block = new_instr_buf(TWO_INSTRS);
	len = set_bpf_lbl(success_block, id);
	len += set_bpf_ret_allow(success_block + len);
	append_filter_block(head, success_block, len);

	free(line);
	return head;
}

void free_block_list(struct filter_block *head)
{
	struct filter_block *current, *prev;

	current = head;
	while (current) {
		free(current->instrs);
		prev = current;
		current = current->next;
		free(prev);
	}
}
