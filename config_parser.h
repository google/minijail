/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct config_entry {
	const char *key;
	const char *value;
};

struct config_entry_list {
	struct config_entry *entries;
	size_t num_entries;
	size_t num_allocated_;
};

/* Allocate a new |config_entry_list| struct. */
struct config_entry_list *new_config_entry_list(void);

/* Free allocated pointers in |config_entry|. */
void clear_config_entry(struct config_entry *entry);

/* Free a |config_entry_list| struct. */
void free_config_entry_list(struct config_entry_list *list);

/*
 * Parse one config line into a entry.
 *
 * Returns true for success, otherwise false for parsing failures.
 */
bool parse_config_line(const char *config_line, struct config_entry *entry);

/*
 * Parse a minijail config file into a |config_entry_list|.
 *
 * Returns true for success, otherwise false for parsing failures.
 */
bool parse_config_file(FILE *config_file, struct config_entry_list *list);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* CONFIG_PARSER_H */
