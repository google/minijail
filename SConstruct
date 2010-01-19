# -*- python -*-

# Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import glob
import os

env = Environment()

lib_sources = env.Split("""env.cc
                           interface.cc
                           minijail.cc
                           options.cc""")
bin_sources = env.Split("""minijail_main.cc""")
test_sources = env.Split("""minijail_unittest.cc
                            options_unittest.cc
                            minijail_testrunner.cc""")
benchmark_sources = glob.glob("*_microbenchmark.cc")

env.Append(
    CPPPATH=['..', '../../third_party/chrome/files', '../../common'],
    CCFLAGS=['-g', '-fno-exceptions', '-Wall', '-Werror'],
    LIBPATH=['../../third_party/chrome'],
    LIBS=['cap', 'base', 'pthread', 'rt'],
)
for key in Split('CC CXX AR RANLIB LD NM CFLAGS CCFLAGS'):
  value = os.environ.get(key)
  if value != None:
    env[key] = value

env_lib = env.Clone()
env_lib.SharedLibrary('minijail', lib_sources)

env_bin = env.Clone()
env_bin.Program('minijail', lib_sources + bin_sources)

env_test = env.Clone()
env_test.Append(LIBS=['gtest', 'gmock'])
env_test.Program('minijail_unittests', lib_sources + test_sources)

env_benchmarks = env.Clone()
# Note, LIBS needs to have: 'gtest', 'base', 'rt', 'pthread'
env_benchmarks.Append(LIBS=['microbenchmark_main.a',
                            # Since we want to run this on a prod image,
                            # we just statically pull in gtest.a.
                            File('/usr/lib/libgtest.a')])
env_benchmarks.Program('minijail_benchmarks', benchmark_sources)
