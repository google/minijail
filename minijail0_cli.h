/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Helpers for the minijail0 program.  Split out for unittesting.
 */

#ifndef MINIJAIL_MINIJAIL0_CLI_H_
#define MINIJAIL_MINIJAIL0_CLI_H_

#include "elfparse.h"

#ifdef __cplusplus
extern "C" {
#endif

struct minijail;

int parse_args(struct minijail *j, int argc, char *const argv[],
	       char *const environ[], int *exit_immediately,
	       ElfType *elftype, const char **preload_path,
	       char ***envp);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif  /* MINIJAIL_MINIJAIL0_CLI_H_ */
