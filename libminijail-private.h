/* libminijail-private.h
 * Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Values shared between libminijailpreload and libminijail, but not visible to
 * the outside world.
 */

#ifndef LIBMINIJAIL_PRIVATE_H
#define LIBMINIJAIL_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Explicitly declare exported functions so that -fvisibility tricks
 * can be used for testing and minimal symbol leakage occurs.
 */
#define API __attribute__((__visibility__("default")))

static const char kFdEnvVar[] = "__MINIJAIL_FD";
static const char kLdPreloadEnvVar[] = "LD_PRELOAD";
static const char kSeccompPolicyPathEnvVar[] = "SECCOMP_POLICY_PATH";

struct minijail;

/* minijail_size: returns the size (in bytes) of @j if marshalled
 * @j jail to compute size of
 *
 * Returns 0 on error.
 */
extern size_t minijail_size(const struct minijail *j);

/* minijail_marshal: serializes @j to @buf
 * @j    minijail to serialize
 * @buf  buffer to serialize to
 * @size size of @buf
 *
 * Returns 0 on success.
 *
 * Writes |j| to |buf| such that it can be reparsed by the same
 * library on the same architecture.  This is meant to be used
 * by minijail0.c and libminijailpreload.c.  minijail flags that
 * require minijail_run() will be excluded.
 *
 * The marshalled data is not robust to differences between the child
 * and parent process (personality, etc).
 */
extern int minijail_marshal(const struct minijail *j, char *buf, size_t size);

/* minijail_unmarshal: initializes @j from @serialized
 * @j          minijail to initialize
 * @serialized serialized jail buffer
 * @length     length of buffer
 *
 * Returns 0 on success.
 */
extern int minijail_unmarshal(struct minijail *j, char *serialized,
			      size_t length);

/* minijail_from_fd: builds @j from @fd
 * @j  minijail to initialize
 * @fd fd to initialize from
 *
 * Returns 0 on success.
 */
extern int minijail_from_fd(int fd, struct minijail *j);

/* minijail_to_fd: sends @j over @fd
 * @j  minijail to send
 * @fd fd to send over
 *
 * Returns 0 on success, or a negative error code on error.
 */
extern int minijail_to_fd(struct minijail *j, int fd);

/* minijail_preexec: strips @j of all options handled by minijail_enter()
 * @j jail to strip
 */
extern void minijail_preexec(struct minijail *j);

/* minijail_preenter: strips @j of all options handled by minijail_run()
 * @j jail to strip
 */
extern void minijail_preenter(struct minijail *j);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* !LIBMINIJAIL_PRIVATE_H */
