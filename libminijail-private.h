/* libminijail-private.h
 * Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Values shared between libminijailpreload and libminijail, but not visible to
 * the outside world.
 */

#ifndef LIBMINIJAIL_PRIVATE_H
#define LIBMINIJAIL_PRIVATE_H

static const char *kCommandEnvVar = "__MINIJAIL_PRELOAD";
static const char *kLdPreloadEnvVar = "LD_PRELOAD";

#define MINIJAIL_MAX_SECCOMP_FILTER_LINE 512

#endif /* !LIBMINIJAIL_PRIVATE_H */
