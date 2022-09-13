/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"

#include "util.h"

#define LIST_DEFAULT_SIZE (100)

struct config_entry_list *new_config_entry_list(void)
{
	/*
	 * There are <100 CLI options, configuration file will likely have
	 * a similar number of config entries.
	 */
	struct config_entry *entries =
	    calloc(LIST_DEFAULT_SIZE, sizeof(struct config_entry));
	if (!entries)
		return NULL;

	struct config_entry_list *list =
	    calloc(1, sizeof(struct config_entry_list));
	if (!list) {
		free(entries);
		return NULL;
	}
	list->entries = entries;
	list->num_allocated_ = LIST_DEFAULT_SIZE;
	list->num_entries = 0;
	return list;
}

void clear_config_entry(struct config_entry *entry)
{
	free((char *)entry->key);
	free((char *)entry->value);
}

void free_config_entry_list(struct config_entry_list *list)
{
	if (!list)
		return;
	for (size_t i = 0; i < list->num_entries; i++) {
		clear_config_entry(&list->entries[i]);
	}
	free(list->entries);
	free(list);
}

bool parse_config_line(const char *config_line, struct config_entry *entry)
{
	/* Parsing will modify |config_line| in place, so make a copy. */
	attribute_cleanup_str char *line = strdup(config_line);
	if (!line)
		return false;
	char *value = line;

	/* After tokenize call, |value| will point to a substring after '='.
	 * If there is no '=' in the string, |key| will contain the entire
	 * string while |value| will be NULL.
	 */
	char *key = tokenize(&value, "=");
	if (key)
		key = strip(key);
	if (value)
		value = strip(value);
	if (!key || key[0] == '\0' || (value && value[0] == '\0')) {
		warn("unable to parse %s", config_line);
		return false;
	}
	entry->key = strdup(key);
	entry->value = value ? strdup(value) : NULL;
	if (!entry->key || (value && !entry->value)) {
		clear_config_entry(entry);
		return false;
	}
	return true;
}

static bool match_special_directive(const char *line)
{
	return streq(line, "% minijail-config-file v0\n");
}

bool parse_config_file(FILE *config_file, struct config_entry_list *list)
{
	attribute_cleanup_str char *line = NULL;
	size_t len = 0;

	/* The first line must match the special directive */
	if (getline(&line, &len, config_file) == -1 ||
	    !match_special_directive(line))
		return false;
	while (getmultiline(&line, &len, config_file) != -1) {
		char *stripped_line = strip(line);
		/*
		 * Skip blank lines and all comments. Comment lines start with
		 * '#'.
		 */
		if (stripped_line[0] == '\0' || stripped_line[0] == '#')
			continue;

		/*
		 * Check if the list is full, and reallocate with doubled
		 * capacity if so.
		 */
		if (list->num_entries >= list->num_allocated_) {
			list->num_allocated_ = list->num_allocated_ * 2;
			list->entries = realloc(
			    list->entries,
			    list->num_allocated_ * sizeof(struct config_entry));
			if (list->entries == NULL) {
				return false;
			}
		}

		struct config_entry *entry = &list->entries[list->num_entries];
		if (!parse_config_line(stripped_line, entry)) {
			return false;
		}
		++list->num_entries;
	}
	/*
	 * getmultiline() behaves similarly with getline(3). It returns -1
	 * when read into EOF or the following errors.
	 * Caveat: EINVAL may happen when EOF is encountered in a valid stream.
	 */
	if ((errno == EINVAL && config_file == NULL) || errno == ENOMEM) {
		return false;
	}

	/* Shrink the list to save memory. */
	if (list->num_entries < list->num_allocated_) {
		list->entries =
		    realloc(list->entries,
			    list->num_entries * sizeof(struct config_entry));
		list->num_allocated_ = list->num_entries;
	}

	return true;
}
