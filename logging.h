/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdlib.h>
#include <syslog.h>

#define die(_msg, ...) do { \
	syslog(LOG_ERR, "libminijail: " _msg, ## __VA_ARGS__); \
	abort(); \
} while (0)

#define pdie(_msg, ...) \
	die(_msg ": %s", ## __VA_ARGS__, strerror(errno))

#define warn(_msg, ...) \
	syslog(LOG_WARNING, "libminijail: " _msg, ## __VA_ARGS__)

#define info(_msg, ...) \
	syslog(LOG_INFO, "libminijail: " _msg, ## __VA_ARGS__)

#endif /* _LOGGING_H_ */
