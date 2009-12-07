# -*- python -*-

# Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

env = Environment()

lib_sources = env.Split("""env.cc
                           interface.cc
                           minijail.cc
                           options.cc""")
bin_sources = env.Split("""minijail_main.cc""")
test_sources = env.Split("""minijail_unittest.cc
                            minijail_testrunner.cc""")

#test_sources = env.Split("""../base/strutil.cc""")

env.Append(
    CPPPATH=['..', '../../third_party/chrome/files', '../../common'],
    CCFLAGS=['-g', '-fno-exceptions', '-Wall', '-Werror'],
    LIBPATH=['../../third_party/chrome'],
    LIBS=['cap', 'base', 'pthread', 'rt'],
)

env_lib = env.Clone()
env_lib.SharedLibrary('minijail', lib_sources)

env_bin = env.Clone()
env_bin.Program('minijail', lib_sources + bin_sources)

env_test = env.Clone()
env_test.Append(LIBS=['gtest', 'pcrecpp'])
env_test.Program('minijail_unittests', lib_sources + test_sources)
