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

static const char *kFdEnvVar = "__MINIJAIL_FD";
static const char *kLdPreloadEnvVar = "LD_PRELOAD";

#define MINIJAIL_MAX_SECCOMP_FILTER_LINE 512
#define MINIJAIL_MAX_ARG_LINE (MINIJAIL_MAX_SECCOMP_FILTER_LINE + 64)

struct seccomp_filter {
  int nr;
  char *filter;
  struct seccomp_filter *next, *prev;
};

struct minijail {
  struct {
    int uid : 1;
    int gid : 1;
    int caps : 1;
    int vfs : 1;
    int pids : 1;
    int seccomp : 1;
    int readonly : 1;
    int usergroups : 1;
    int ptrace : 1;
    int seccomp_filter : 1;
  } flags;
  uid_t uid;
  gid_t gid;
  gid_t usergid;
  char *user;
  uint64_t caps;
  pid_t initpid;
  struct seccomp_filter *filters;
};

/* minijail_size returns the size of |j| if marshalled.
 * 0 is returned on error.
 */
extern size_t minijail_size(const struct minijail *j);
/* minijail_marshal: serializes |j| to |buf|
 * Writes |j| to |buf| such that it can be reparsed by the same
 * library on the same architecture.  This is meant to be used
 * by minijail0.c and libminijailpreload.c.  minijail flags that
 * require minijail_run() will be excluded.
 *
 * The marshalled data is not robust to differences between the child
 * and parent process (personality, etc).
 *
 * Returns 0 on success.
 */
extern int minijail_marshal(const struct minijail *j,
                            char *buf,
                            size_t available);
/* minijail_unmarshal: initializes minijail |j| from |serialized|. */
extern int minijail_unmarshal(struct minijail *j,
                              char *serialized,
                              size_t length);
/* Using minijail_unmarshal, build |j| from |fd|. */
extern int minijail_from_fd(int fd, struct minijail *j);
/* Using minijail_marshal, sends |j| to |fd|. */
extern int minijail_to_fd(struct minijail *j, int fd);
/* minijail_preexec: strips |j| of all options handled by minijail_enter(). */
extern void minijail_preexec(struct minijail *j);
/* minijail_preenter: strips |j| of all options handled by minijail_run(). */
extern void minijail_preenter(struct minijail *j);

#endif /* !LIBMINIJAIL_PRIVATE_H */
