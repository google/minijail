/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libminijail.h"

static void set_user(struct minijail *j, const char *arg) {
  char *end = NULL;
  int uid = strtod(arg, &end);
  if (!*end && *arg) {
    minijail_change_uid(j, uid);
    return;
  }

  if (minijail_change_user(j, arg)) {
    fprintf(stderr, "Bad user: '%s'\n", arg);
    exit(1);
  }
}

static void set_group(struct minijail *j, const char *arg) {
  char *end = NULL;
  int gid = strtod(arg, &end);
  if (!*end && *arg) {
    minijail_change_gid(j, gid);
    return;
  }

  if (minijail_change_group(j, arg)) {
    fprintf(stderr, "Bad group: '%s'\n", arg);
    exit(1);
  }
}

static void use_caps(struct minijail *j, const char *arg) {
  uint64_t caps;
  char *end = NULL;
  caps = strtoull(arg, &end, 16);
  if (*end) {
    fprintf(stderr, "Invalid cap set: '%s'\n", arg);
    exit(1);
  }
  minijail_use_caps(j, caps);
}

static void usage(const char *progn) {
  printf("Usage: %s [-Ghprsv] [-c <caps>] [-g <group>] [-S <file>] [-u <user>] "
         "<program> [args...]\n"
         "  -c: restrict caps to <caps>\n"
         "  -G: inherit groups from uid\n"
         "  -g: change gid to <group>\n"
         "  -h: help (this message)\n"
         "  -p: use pid namespace\n"
         "  -r: remount filesystems readonly (implies -v)\n"
         "  -s: use seccomp\n"
         "  -S: set seccomp filters using <file>\n"
         "      E.g., -S /usr/share/blah/seccomp_filters.$(uname -m)\n"
         "  -u: change uid to <user>\n"
         "  -v: use vfs namespace\n", progn);
}

int main(int argc, char *argv[]) {
  struct minijail *j = minijail_new();

  int opt;
  while ((opt = getopt(argc, argv, "u:g:sS:c:vrGhp")) != -1) {
    switch (opt) {
      case 'u':
        set_user(j, optarg);
        break;
      case 'g':
        set_group(j, optarg);
        break;
      case 's':
        minijail_use_seccomp(j);
        break;
      case 'S':
        minijail_parse_seccomp_filters(j, optarg);
        minijail_use_seccomp_filter(j);
        break;
      case 'c':
        use_caps(j, optarg);
        break;
      case 'v':
        minijail_namespace_vfs(j);
        break;
      case 'r':
        minijail_remount_readonly(j);
        break;
      case 'G':
        minijail_inherit_usergroups(j);
        break;
      case 'p':
        minijail_namespace_pids(j);
        break;
      default:
        usage(argv[0]);
        exit(1);
    }
  }

  if (argc == optind) {
    usage(argv[0]);
    exit(1);
  }

  argc -= optind;
  argv += optind;

  minijail_run(j, argv[0], argv);
  return minijail_wait(j);
}
