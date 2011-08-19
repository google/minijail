/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _BSD_SOURCE
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "libminijail.h"
#include "libsyscalls.h"
#include "libminijail-private.h"

/* Until these are reliably available in linux/prctl.h */
#ifndef PR_SET_SECCOMP_FILTER
#  define PR_SECCOMP_FILTER_SYSCALL 0
#  define PR_SECCOMP_FILTER_EVENT 1
#  define PR_GET_SECCOMP_FILTER 35
#  define PR_SET_SECCOMP_FILTER 36
#  define PR_CLEAR_SECCOMP_FILTER 37
#endif

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
  const char *user;
  uint64_t caps;
  pid_t initpid;
  struct seccomp_filter *filters;
};

#define die(_msg, ...) do { \
  syslog(LOG_ERR, "libminijail: " _msg, ## __VA_ARGS__); \
  abort(); \
} while (0)

#define pdie(_msg, ...) \
  die(_msg ": %s", ## __VA_ARGS__, strerror(errno))

#define warn(_msg, ...) \
  syslog(LOG_WARNING, "libminijail: " _msg, ## __VA_ARGS__)

struct minijail *minijail_new(void) {
  struct minijail *j = malloc(sizeof(*j));
  if (j)
    memset(j, 0, sizeof(*j));
  return j;
}

void minijail_change_uid(struct minijail *j, uid_t uid) {
  if (uid == 0)
    die("useless change to uid 0");
  j->uid = uid;
  j->flags.uid = 1;
}

void minijail_change_gid(struct minijail *j, gid_t gid) {
  if (gid == 0)
    die("useless change to gid 0");
  j->gid = gid;
  j->flags.gid = 1;
}

int minijail_change_user(struct minijail *j, const char *user) {
  /* In principle this should use getpwnam(), but:
   * 1) getpwnam_r() isn't actually reentrant anyway, since it uses a
   *    statically-allocated file descriptor internally
   * 2) fgetpwnam() (by analogy with fgetpwent) would solve (1) except that it
   *    doesn't exist
   * 3) sysconf() (see getpwnam_r(3)) is allowed to return a size that is not
   *    large enough, which means having to loop on growing the buffer we pass
   *    in
   */
  struct passwd *pw = getpwnam(user);
  if (!pw)
    return errno;
  minijail_change_uid(j, pw->pw_uid);
  j->user = user;
  j->usergid = pw->pw_gid;
  return 0;
}

int minijail_change_group(struct minijail *j, const char *group) {
  /* In principle this should use getgrnam(), but:
   * 1) getgrnam_r() isn't actually reentrant anyway, since it uses a
   *    statically-allocated file descriptor internally
   * 2) fgetgrnam() (by analogy with fgetgrent) would solve (1) except that it
   *    doesn't exist
   * 3) sysconf() (see getgrnam_r(3)) is allowed to return a size that is not
   *    large enough, which means having to loop on growing the buffer we pass
   *    in
   */
  struct group *gr = getgrnam(group);
  if (!gr)
    return errno;
  minijail_change_gid(j, gr->gr_gid);
  return 0;
}

void minijail_use_seccomp(struct minijail *j) {
  j->flags.seccomp = 1;
}

void minijail_use_seccomp_filter(struct minijail *j) {
  j->flags.seccomp_filter = 1;
}

void minijail_use_caps(struct minijail *j, uint64_t capmask) {
  j->caps = capmask;
  j->flags.caps = 1;
}

void minijail_namespace_vfs(struct minijail *j) {
  j->flags.vfs = 1;
}

void minijail_namespace_pids(struct minijail *j) {
  j->flags.pids = 1;
}

void minijail_remount_readonly(struct minijail *j) {
  j->flags.vfs = 1;
  j->flags.readonly = 1;
}

void minijail_inherit_usergroups(struct minijail *j) {
  j->flags.usergroups = 1;
}

void minijail_disable_ptrace(struct minijail *j) {
  j->flags.ptrace = 1;
}

int minijail_add_seccomp_filter(struct minijail *j, int nr,
                                const char *filter) {
  struct seccomp_filter *sf;
  if (!filter || nr < 0)
    return -EINVAL;

  sf = malloc(sizeof(*sf));
  if (!sf)
    return -ENOMEM;
  sf->nr = nr;
  sf->filter = strndup(filter, MINIJAIL_MAX_SECCOMP_FILTER_LINE);
  if (!sf->filter) {
    free(sf);
    return -ENOMEM;
  }

  if (!j->filters) {
    j->filters = sf;
    sf->next = sf;
    sf->prev = sf;
    return 0;
  }
  sf->next = j->filters;
  sf->prev = j->filters->prev;
  sf->prev->next = sf;
  j->filters->prev = sf;
  return 0;
}

int minijail_lookup_syscall(const char *name) {
  const struct syscall_entry *entry = syscall_table;
  for (; entry->name && entry->nr >= 0; ++entry)
    if (!strcmp(entry->name, name))
      return entry->nr;
  return -1;
}

static char *strip(char *s) {
  char *end;
  while (*s && isblank(*s))
    s++;
  end = s + strlen(s) - 1;
  while (*end && (isblank(*end) || *end == '\n'))
    end--;
  *(end+1) = '\0';
  return s;
}

void minijail_parse_seccomp_filters(struct minijail *j, const char *path) {
  FILE *file = fopen(path, "r");
  char line[MINIJAIL_MAX_SECCOMP_FILTER_LINE];
  int count = 1;
  if (!file)
    pdie("failed to open seccomp filters file");

  /* Format is simple:
   * syscall_name<COLON><FILTER STRING>[\n|EOF]
   * #...comment...
   * <empty line?
   */
  while (fgets(line, sizeof(line), file)) {
    char *filter = line;
    char *name = strsep(&filter, ":");
    char *name_end = NULL;
    int nr = -1;

    if (!name)
      die("invalid filter on line %d", count);

    name = strip(name);

    if (!filter) {
      if (strlen(name))
        die("invalid filter on line %d", count);
      /* Allow empty lines */
      continue;
    }

    /* Allow comment lines */
    if (*name == '#')
      continue;

    filter = strip(filter);

    /* Take direct syscall numbers */
    nr = strtol(name, &name_end, 0);
    /* Or fail-over to using names */
    if (*name_end != '\0')
      nr = minijail_lookup_syscall(name);
    if (nr < 0)
      die("syscall '%s' unknown", name);

    if (minijail_add_seccomp_filter(j, nr, filter))
      pdie("failed to add filter for syscall '%s'", name);
  }
  fclose(file);
}

static int remount_readonly(void) {
  const char *kProcPath = "/proc";
  const unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;
  /* Right now, we're holding a reference to our parent's old mount of /proc in
   * our namespace, which means using MS_REMOUNT here would mutate our parent's
   * mount as well, even though we're in a VFS namespace (!). Instead, remove
   * their mount from our namespace and make our own. */
  if (umount(kProcPath))
    return errno;
  if (mount("", kProcPath, "proc", kSafeFlags | MS_RDONLY, ""))
    return errno;
  return 0;
}

static void drop_caps(const struct minijail *j) {
  cap_t caps = cap_get_proc();
  cap_value_t raise_flag[1];
  unsigned int i;
  if (!caps)
    die("can't get process caps");
  if (cap_clear_flag(caps, CAP_INHERITABLE))
    die("can't clear inheritable caps");
  if (cap_clear_flag(caps, CAP_EFFECTIVE))
    die("can't clear effective caps");
  if (cap_clear_flag(caps, CAP_PERMITTED))
    die("can't clear permitted caps");
  for (i = 0; i < sizeof(j->caps) * 8 && cap_valid((int)i); ++i) {
    if (i != CAP_SETPCAP && !(j->caps & (1 << i)))
      continue;
    raise_flag[0] = i;
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, raise_flag, CAP_SET))
      die("can't add effective cap");
    if (cap_set_flag(caps, CAP_PERMITTED, 1, raise_flag, CAP_SET))
      die("can't add permitted cap");
    if (cap_set_flag(caps, CAP_INHERITABLE, 1, raise_flag, CAP_SET))
      die("can't add inheritable cap");
  }
  if (cap_set_proc(caps))
    die("can't apply cleaned capset");
  cap_free(caps);
  for (i = 0; i < sizeof(j->caps) * 8 && cap_valid((int)i); ++i) {
    if (j->caps & (1 << i))
      continue;
    if (prctl(PR_CAPBSET_DROP, i))
      pdie("prctl(PR_CAPBSET_DROP)");
  }
}

static int setup_seccomp_filters(const struct minijail *j) {
  const struct seccomp_filter *sf = j->filters;
  int ret = 0;
  int broaden = 0;

  /* No filters installed isn't necessarily an error. */
  if (!sf)
    return ret;

  do {
    errno = 0;
    ret = prctl(PR_SET_SECCOMP_FILTER, PR_SECCOMP_FILTER_SYSCALL,
                    sf->nr, broaden ? "1" : sf->filter);
    if (ret) {
      switch (errno) {
        case ENOSYS:
          /* TODO(wad) make this a config option */
          if (broaden)
            die("CONFIG_SECCOMP_FILTER is not supported by your kernel");
          warn("missing CONFIG_FTRACE_SYSCALLS; relaxing the filter for %d",
               sf->nr);
          broaden = 1;
          continue;
        case E2BIG:
          warn("seccomp filter too long: %d", sf->nr);
          pdie("filter too long");
        case ENOSPC:
          pdie("too many seccomp filters");
        case EPERM:
          warn("syscall filter disallowed for %d", sf->nr);
          pdie("failed to install seccomp filter");
        case EINVAL:
          warn("seccomp filter or call method is invalid. %d:'%s'",
               sf->nr, sf->filter);
        default:
          pdie("failed to install seccomp filter");
      }
    }
    sf = sf->next;
    broaden = 0;
  } while (sf != j->filters);
  return ret;
}

void minijail_enter(const struct minijail *j) {
  int ret;
  if (j->flags.pids)
    die("tried to enter a pid-namespaced jail; try minijail_run()?");

  ret = setup_seccomp_filters(j);
  if (j->flags.seccomp_filter && ret)
    die("failed to configure seccomp filters");

  if (j->flags.usergroups && !j->user)
    die("usergroup inheritance without username");

  /* We can't recover from failures if we've dropped privileges partially,
   * so we don't even try. If any of our operations fail, we abort() the
   * entire process. */
  if (j->flags.vfs && unshare(CLONE_NEWNS))
    pdie("unshare");

  if (j->flags.readonly && remount_readonly())
    pdie("remount");

  if (j->flags.caps) {
    /* POSIX capabilities are a bit tricky. If we drop our capability to change
     * uids, our attempt to use setuid() below will fail. Hang on to root caps
     * across setuid(), then lock securebits. */
    if (prctl(PR_SET_KEEPCAPS, 1))
      pdie("prctl(PR_SET_KEEPCAPS)");
    if (prctl(PR_SET_SECUREBITS, SECURE_ALL_BITS | SECURE_ALL_LOCKS))
      pdie("prctl(PR_SET_SECUREBITS)");
  }

  if (j->flags.usergroups && initgroups(j->user, j->usergid)) {
    pdie("initgroups");
  } else if (!j->flags.usergroups && setgroups(0, NULL)) {
    pdie("setgroups");
  }

  if (j->flags.gid && setresgid(j->gid, j->gid, j->gid))
    pdie("setresgid");

  if (j->flags.uid && setresuid(j->uid, j->uid, j->uid))
    pdie("setresuid");

  if (j->flags.caps)
    drop_caps(j);

  /* seccomp has to come last since it cuts off all the other
   * privilege-dropping syscalls :) */
  if (j->flags.seccomp_filter && prctl(PR_SET_SECCOMP, 13))
        pdie("prctl(PR_SET_SECCOMP, 13)");

  if (j->flags.seccomp && prctl(PR_SET_SECCOMP, 1))
    pdie("prctl(PR_SET_SECCOMP)");
}

static int init_exitstatus = 0;

static void init_term(int __attribute__((unused)) sig) {
  _exit(init_exitstatus);
}

static int init(pid_t rootpid) {
  pid_t pid;
  int status;
  signal(SIGTERM, init_term); /* so that we exit with the right status */
  while ((pid = wait(&status)) > 0) {
    /* This loop will only end when either there are no processes left inside
     * our pid namespace or we get a signal. */
    if (pid == rootpid)
      init_exitstatus = status;
  }
  if (!WIFEXITED(init_exitstatus))
    _exit(MINIJAIL_ERR_INIT);
  _exit(WEXITSTATUS(init_exitstatus));
}

/** @brief Move any commands that need to be done post-exec into an environment
 *         variable
 *  @param j Jail to move commands from.
 *
 *  Serializes post-exec() commands into a string, removes them from the jail,
 *  and adds them to the environment; they will be deserialized later (see
 *  __minijail_preloaded) and executed inside the execve()'d process.
 */
static int move_commands_to_env(struct minijail *j) {
  const int kEnvBufSize = 256;
  const char *ptrace = j->flags.ptrace ? "ptrace " : "";
  const char *seccomp = j->flags.seccomp ? "seccomp " : "";
  char setuid[64] = "";
  char caps[32] = "";
  char *newenv;
  char *oldenv;
  char *envbuf = malloc(kEnvBufSize);
  int r;

  if (!envbuf)
    return -ENOMEM;

  if (j->flags.caps)
    snprintf(caps, sizeof(caps), "caps=%" PRIx64 " ", j->caps);

  if (j->flags.uid && j->flags.caps) {
    snprintf(setuid, sizeof(setuid), "uid=%d ", j->uid);
    j->flags.uid = 0;
  }

  j->flags.caps = 0;
  j->flags.ptrace = 0;
  j->flags.seccomp = 0;

  if (j->flags.seccomp_filter)
    warn("TODO(wad) seccomp_filter is installed in the parent which "
         "requires overly permissive rules for execve(2)ing.");

  r = snprintf(envbuf, kEnvBufSize, "%s%s%s%s", setuid, ptrace, seccomp, caps);
  if (!r) {
    /* No commands generated, so no preload needed :) */
    free(envbuf);
    return 0;
  }
  if (r == kEnvBufSize) {
    free(envbuf);
    return -E2BIG;
  }

  oldenv = getenv(kLdPreloadEnvVar) ? : "";
  newenv = malloc(strlen(oldenv) + 2 + strlen(PRELOADPATH));
  if (!newenv) {
    free(envbuf);
    return -ENOMEM;
  }

  /* Only insert a separating space if we have something to separate... */
  sprintf(newenv, "%s%s%s", oldenv, strlen(oldenv) ? " " : "", PRELOADPATH);

  /* setenv() makes a copy of the string we give it */
  setenv(kLdPreloadEnvVar, newenv, 1);
  setenv(kCommandEnvVar, envbuf, 1);
  free(newenv);
  free(envbuf);
  return 0;
}

int minijail_run(struct minijail *j, const char *filename, char *const argv[]) {
  unsigned int pidns = j->flags.pids ? CLONE_NEWPID : 0;
  char *oldenv, *oldenv_copy = NULL;
  pid_t r;

  oldenv = getenv(kLdPreloadEnvVar);
  if (oldenv) {
    oldenv_copy = strdup(oldenv);
    if (!oldenv_copy)
      return -ENOMEM;
  }

  r = move_commands_to_env(j);
  if (r) {
    /* No environment variable is modified if move_commands_to_env returns
     * a non-zero value. */
    free(oldenv_copy);
    return r;
  }

  r = syscall(SYS_clone, pidns | SIGCHLD, NULL);
  if (r > 0) {
    if (oldenv_copy) {
      setenv(kLdPreloadEnvVar, oldenv_copy, 1);
      free(oldenv_copy);
    } else {
      unsetenv(kLdPreloadEnvVar);
    }
    unsetenv(kCommandEnvVar);
    j->initpid = r;
    return 0;
  }

  free(oldenv_copy);

  if (r < 0)
    return r;

  j->flags.pids = 0;

  /* Jail this process and its descendants... */
  minijail_enter(j);

  if (pidns) {
    /* pid namespace: this process will become init inside the new namespace, so
     * fork off a child to actually run the program (we don't want all programs
     * we might exec to have to know how to be init). */
    r = fork();
    if (r < 0)
      _exit(r);
    else if (r > 0)
      init(r);  /* never returns */
  }

  /* If we aren't pid-namespaced:
   *   calling process
   *   -> execve()-ing process
   * If we are:
   *   calling process
   *   -> init()-ing process
   *      -> execve()-ing process
   */
  _exit(execve(filename, argv, environ));
}

int minijail_kill(struct minijail *j) {
  int st;
  if (kill(j->initpid, SIGTERM))
    return errno;
  if (waitpid(j->initpid, &st, 0) < 0)
    return errno;
  return st;
}

int minijail_wait(struct minijail *j) {
  int st;
  if (waitpid(j->initpid, &st, 0) < 0)
    return errno;
  if (!WIFEXITED(st))
    return MINIJAIL_ERR_JAIL;
  return WEXITSTATUS(st);
}

void minijail_destroy(struct minijail *j) {
  struct seccomp_filter *f = j->filters;
  /* Unlink the tail and head */
  if (f)
    f->prev->next = NULL;
  while (f) {
    struct seccomp_filter *next = f->next;
    free(f->filter);
    free(f);
    f = next;
  }
  free(j);
}
