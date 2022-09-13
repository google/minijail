/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "bpf.h"
#include "syscall_filter.h"
#include "util.h"

namespace {

void DumpBpfProg(struct sock_fprog* fprog) {
  struct sock_filter* filter = fprog->filter;
  unsigned short len = fprog->len;

  printf("len == %d\n", len);
  printf("filter:\n");
  for (size_t i = 0; i < len; i++) {
    printf("%zu: \t{ code=%#x, jt=%u, jf=%u, k=%#x \t}\n", i, filter[i].code,
           filter[i].jt, filter[i].jf, filter[i].k);
  }
}

void Usage(const char* progn, int status) {
  // clang-format off
  fprintf(status ? stderr : stdout,
          "Usage: %s [--dump[=<output.bpf>]] [<policy file>]\n"
          "\n"
          "With no <policy file>, or when <policy file> is -, reads from standard input.\n"
          "\n"
          " --dump[=<output>]:  Dump the BPF program into stdout (or <output>,\n"
          "      -d[<output>]:  if provided). Useful if you want to inspect it\n"
          "                     with libseccomp's scmp_bpf_disasm.\n",
          progn);
  // clang-format on
  exit(status);
}

}  // namespace

int main(int argc, char** argv) {
  init_logging(LOG_TO_FD, STDERR_FILENO, LOG_INFO);

  static const char optstring[] = "d:h";
  static const struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"dump", optional_argument, 0, 'd'},
      {0, 0, 0, 0},
  };

  bool dump = false;
  std::string dump_path;
  int opt;
  while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
    switch (opt) {
      case 'h':
        Usage(argv[0], 0);
        return 0;
      case 'd':
        dump = true;
        if (optarg)
          dump_path = optarg;
        break;
    }
  }

  FILE* f = stdin;
  // If there is at least one additional unparsed argument, treat it as the
  // policy script.
  if (argc > optind && !streq(argv[optind], "-"))
    f = fopen(argv[optind], "re");
  if (!f)
    pdie("fopen(%s) failed", argv[1]);

  struct filter_options fopts {
    .action = ACTION_RET_KILL,
    .allow_logging = 0,
    .allow_syscalls_for_logging = 0,
    .allow_duplicate_syscalls = allow_duplicate_syscalls(),
  };

  struct sock_fprog fp;
  int res = compile_filter(argv[1], f, &fp, &fopts);
  fclose(f);
  if (res != 0)
    die("compile_filter failed");

  if (dump) {
    FILE* out = stdout;
    if (!dump_path.empty()) {
      out = fopen(dump_path.c_str(), "we");
      if (!out)
        pdie("fopen(%s) failed", dump_path.c_str());
    }
    if (fwrite(fp.filter, sizeof(struct sock_filter), fp.len, out) != fp.len)
      pdie("fwrite(%s) failed", dump_path.c_str());
    fclose(out);
  } else {
    DumpBpfProg(&fp);
  }

  free(fp.filter);
  return 0;
}
