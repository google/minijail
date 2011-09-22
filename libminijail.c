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
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/param.h>
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

#define die(_msg, ...) do { \
  syslog(LOG_ERR, "libminijail: " _msg, ## __VA_ARGS__); \
  abort(); \
} while (0)

#define pdie(_msg, ...) \
  die(_msg ": %s", ## __VA_ARGS__, strerror(errno))

#define warn(_msg, ...) \
  syslog(LOG_WARNING, "libminijail: " _msg, ## __VA_ARGS__)

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
  int filter_count;
  struct seccomp_filter *filters;
};

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
  char *buf = NULL;
  struct passwd pw;
  struct passwd *ppw = NULL;
  ssize_t sz = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (sz == -1)
    sz = 65536;   /* your guess is as good as mine... */

  /* sysconf(_SC_GETPW_R_SIZE_MAX), under glibc, is documented to return the
   * maximum needed size of the buffer, so we don't have to search. */
  buf = malloc(sz);
  if (!buf)
    return -ENOMEM;
  getpwnam_r(user, &pw, buf, sz, &ppw);
  free(buf);
  if (!ppw)
    return errno;
  minijail_change_uid(j, ppw->pw_uid);
  j->user = strdup(user);
  if (!j->user)
    return -ENOMEM;
  j->usergid = ppw->pw_gid;
  return 0;
}

int minijail_change_group(struct minijail *j, const char *group) {
  char *buf = NULL;
  struct group gr;
  struct group *pgr = NULL;
  ssize_t sz = sysconf(_SC_GETGR_R_SIZE_MAX);
  if (sz == -1)
    sz = 65536;   /* and mine is as good as yours, really */

  /* sysconf(_SC_GETGR_R_SIZE_MAX), under glibc, is documented to return the
   * maximum needed size of the buffer, so we don't have to search. */
  buf = malloc(sz);
  if (!buf)
    return -ENOMEM;
  getgrnam_r(group, &gr, buf, sz, &pgr);
  free(buf);
  if (!pgr)
    return errno;
  minijail_change_gid(j, pgr->gr_gid);
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

  j->filter_count++;

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

struct marshal_state {
  size_t available;
  size_t total;
  char *buf;
};

static void marshal_state_init(struct marshal_state *state,
                            char *buf,
                            size_t available) {
  state->available = available;
  state->buf = buf;
  state->total = 0;
}

static void marshal_append(struct marshal_state *state,
                          char *src,
                          size_t length) {
  size_t copy_len = MIN(state->available, length);

  /* Up to |available| will be written. */
  if (copy_len) {
    memcpy(state->buf, src, copy_len);
    state->buf += copy_len;
    state->available -= copy_len;
  }
  /* |total| will contain the expected length. */
  state->total += length;
}

static void minijail_marshal_helper(struct marshal_state *state,
                                    const struct minijail *j) {
  marshal_append(state, (char *) j, sizeof(*j));
  if (j->user)
    marshal_append(state, j->user, strlen(j->user) + 1);
  if (j->flags.seccomp_filter && j->filters) {
    struct seccomp_filter *f = j->filters;
    do {
      marshal_append(state, (char *) &f->nr, sizeof(f->nr));
      marshal_append(state, f->filter, strlen(f->filter) + 1);
      f = f->next;
    } while (f != j->filters);
  }
}

size_t minijail_size(const struct minijail *j) {
  struct marshal_state state;
  marshal_state_init(&state, NULL, 0);
  minijail_marshal_helper(&state, j);
  return state.total;
}

int minijail_marshal(const struct minijail *j, char *buf, size_t available) {
  struct marshal_state state;
  marshal_state_init(&state, buf, available);
  minijail_marshal_helper(&state, j);
  return (state.total > available);
}

int minijail_unmarshal(struct minijail *j, char *serialized, size_t length) {
  if (length < sizeof(*j))
    return -EINVAL;
  memcpy((void *) j, serialized, sizeof(*j));
  serialized += sizeof(*j);
  length -= sizeof(*j);

  if (j->user) { /* stale pointer */
    if (!length)
      return -EINVAL;
    j->user = strndup(serialized, length);
    length -= strlen(j->user) + 1;
    serialized += strlen(j->user) + 1;
  }

  if (j->flags.seccomp_filter && j->filter_count) {
    int count = j->filter_count;
    /* Let add_seccomp_filter recompute the value. */
    j->filter_count = 0;
    j->filters = NULL;  /* Don't follow the stale pointer. */
    for ( ; count > 0; --count) {
      int *nr = (int *) serialized;
      char *filter;
      if (length < sizeof(*nr))
        return -EINVAL;
      length -= sizeof(*nr);
      serialized += sizeof(*nr);
      if (!length)
        return -EINVAL;
      filter = serialized;
      if (minijail_add_seccomp_filter(j, *nr, filter))
        return -EINVAL;
      length -= strlen(filter) + 1;
      serialized += strlen(filter) + 1;
    }
  }
  return 0;
}

void minijail_preenter(struct minijail *j) {
  /* Strip out options which are minijail_run() only. */
  j->flags.vfs = 0;
  j->flags.readonly = 0;
  j->flags.pids = 0;
}

void minijail_preexec(struct minijail *j) {
  int vfs = j->flags.vfs;
  int readonly = j->flags.readonly;
  if (j->user)
    free(j->user);
  j->user = NULL;
  memset(&j->flags, 0, sizeof(j->flags));
  /* Now restore anything we meant to keep. */
  j->flags.vfs = vfs;
  j->flags.readonly = readonly;
  /* Note, pidns will already have been used before this call. */
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
  if (j->flags.pids)
    die("tried to enter a pid-namespaced jail; try minijail_run()?");

  if (j->flags.seccomp_filter && setup_seccomp_filters(j))
    pdie("failed to configure seccomp filters");

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

  if (j->flags.usergroups) {
    if (initgroups(j->user, j->usergid))
      pdie("initgroups");
  } else {
    /* Only attempt to clear supplemental groups if we are changing users. */
    if ((j->uid || j->gid) && setgroups(0, NULL))
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
  /* TODO(wad) self jail with seccomp_filters here. */
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

int minijail_from_fd(int fd, struct minijail *j) {
  size_t sz = 0;
  size_t bytes = read(fd, &sz, sizeof(sz));
  char *buf;
  int r;
  if (sizeof(sz) != bytes)
    return -EINVAL;
  if (sz > USHRT_MAX)  /* Arbitrary sanity check */
    return -E2BIG;
  buf = malloc(sz);
  if (!buf)
    return -ENOMEM;
  bytes = read(fd, buf, sz);
  if (bytes != sz) {
    free(buf);
    return -EINVAL;
  }
  r = minijail_unmarshal(j, buf, sz);
  free(buf);
  return r;
}

int minijail_to_fd(struct minijail *j, int fd) {
  char *buf;
  size_t sz = minijail_size(j);
  ssize_t written;
  int r;

  if (!sz)
    return -EINVAL;
  buf = malloc(sz);
  if ((r = minijail_marshal(j, buf, sz))) {
    free(buf);
    return r;
  }
  /* Sends [size][minijail]. */
  written = write(fd, &sz, sizeof(sz));
  if (written != sizeof(sz)) {
    free(buf);
    return -EFAULT;
  }
  written = write(fd, buf, sz);
  if (written < 0 || (size_t) written != sz) {
    free(buf);
    return -EFAULT;
  }
  free(buf);
  return 0;
}

static int setup_preload(void) {
  char *oldenv = getenv(kLdPreloadEnvVar) ? : "";
  char *newenv = malloc(strlen(oldenv) + 2 + strlen(PRELOADPATH));
  if (!newenv)
    return -ENOMEM;

  /* Only insert a separating space if we have something to separate... */
  sprintf(newenv, "%s%s%s", oldenv, strlen(oldenv) ? " " : "", PRELOADPATH);

  /* setenv() makes a copy of the string we give it */
  setenv(kLdPreloadEnvVar, newenv, 1);
  free(newenv);
  return 0;
}

static int setup_pipe(int fds[2]) {
  int r = pipe(fds);
  char fd_buf[11];
  if (r)
    return r;
  r = snprintf(fd_buf, sizeof(fd_buf), "%d", fds[0]);
  if (r <= 0)
    return -EINVAL;
  setenv(kFdEnvVar, fd_buf, 1);
  return 0;
}

int minijail_run(struct minijail *j, const char *filename, char *const argv[]) {
  unsigned int pidns = j->flags.pids ? CLONE_NEWPID : 0;
  char *oldenv, *oldenv_copy = NULL;
  pid_t child_pid;
  int pipe_fds[2];
  int ret;

  oldenv = getenv(kLdPreloadEnvVar);
  if (oldenv) {
    oldenv_copy = strdup(oldenv);
    if (!oldenv_copy)
      return -ENOMEM;
  }

  if (setup_preload())
    return -EFAULT;

  /* Before we fork(2) and execve(2) the child process, we need to open
   * a pipe(2) to send the minijail configuration over.
   */
  if (setup_pipe(pipe_fds))
    return -EFAULT;

  child_pid = syscall(SYS_clone, pidns | SIGCHLD, NULL);
  if (child_pid < 0) {
    free(oldenv_copy);
    return child_pid;
  }

  if (child_pid) {
    /* Restore parent's LD_PRELOAD. */
    if (oldenv_copy) {
      setenv(kLdPreloadEnvVar, oldenv_copy, 1);
      free(oldenv_copy);
    } else {
      unsetenv(kLdPreloadEnvVar);
    }
    unsetenv(kFdEnvVar);
    j->initpid = child_pid;
    close(pipe_fds[0]);  /* read endpoint */
    ret = minijail_to_fd(j, pipe_fds[1]);
    close(pipe_fds[1]);  /* write endpoint */
    if (ret) {
      kill(j->initpid, SIGKILL);
      die("failed to send marshalled minijail");
    }
    return 0;
  }
  free(oldenv_copy);

  /* Drop everything that cannot be inherited across execve. */
  minijail_preexec(j);
  /* Jail this process and its descendants... */
  minijail_enter(j);

  if (pidns) {
    /* pid namespace: this process will become init inside the new namespace, so
     * fork off a child to actually run the program (we don't want all programs
     * we might exec to have to know how to be init). */
    child_pid = fork();
    if (child_pid < 0)
      _exit(child_pid);
    else if (child_pid > 0)
      init(child_pid);  /* never returns */
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
  if (j->user)
    free(j->user);
  free(j);
}
