// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Microbenchmark of basic read/write throughput
#include "microbenchmark/microbenchmark.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <syscall.h>
#include <time.h>

namespace chromeos {
namespace benchmarks {

#define IO_SIZE 4096
#define CALL_SYSCALL(_SCAF, syscallargs...) \
  (_SCAF ? IO_SIZE : syscall(syscallargs))
static long kDefaultAmount = 0x4000;
static const char *kDevUrandom = "/dev/urandom";
static const char *kDevNull = "/dev/null";

// Lovely globals used from Setup->Test.
static int rfd = -1;
static int wfd = -1;
static long amount = kDefaultAmount;

static void ReadWriteSetup(uint64 runs) {
  CommandLine *cl = CommandLine::ForCurrentProcess();
  std::string amount_str = cl->GetSwitchValueASCII("readwrite-amount");
  std::string source = cl->GetSwitchValueASCII("readwrite-source");
  std::string destination = cl->GetSwitchValueASCII("readwrite-destination");

  if (amount_str.empty()) {
    LOG(INFO) << "--readwrite-amount is missing.";
    LOG(INFO) << "Defaulting to " << amount << " bytes";
  } else {
    amount = strtol(amount_str.c_str(), NULL, 0);
    if (amount < 0 || amount > 0xffffff) {
      LOG(ERROR) << "Amount specified was too large: " << amount;
      LOG(INFO) << "Using default amount of " << kDefaultAmount;
    }
    amount = kDefaultAmount;
  }
  if (source.empty()) {
    LOG(INFO) << "--readwrite-source missing.";
    LOG(INFO) << "Defaulting to /dev/urandom as a source";
    source = kDevUrandom;
  }
  if (destination.empty()) {
    LOG(INFO) << "--readwrite-destination missing.";
    LOG(INFO) << "Defaulting to /dev/null as a destination";
    destination = kDevNull;
  }
  wfd = open("/dev/null", O_WRONLY);
  rfd = open("/dev/zero", O_RDONLY);
  LOG_IF(FATAL, wfd < 0 || rfd < 0) << "Failed to open /dev/null or /dev/zero";
}

static void ReadWrite(bool scaffold_only) {
  ssize_t so_far = 0;
  ssize_t bytes = 0;
  char buf[IO_SIZE];
  while (so_far < amount) {
    bytes = CALL_SYSCALL(scaffold_only, __NR_read, rfd, buf, sizeof(buf));
    PLOG_IF(FATAL, bytes < 0) << "An unexpected error occurred during read.";
    so_far += bytes;
    PLOG_IF(FATAL,
            CALL_SYSCALL(scaffold_only, __NR_write, wfd, buf, bytes) != bytes)
           << "An unexpected error occurred during write.";
  }
}
CHROMEOS_MICROBENCHMARK_WITH_SETUP(ReadWriteSetup, ReadWrite, 1000);
#undef IO_SIZE
#undef CALL_SYSCALL

}  // namespace benchmarks
}  // namespace chromeos
