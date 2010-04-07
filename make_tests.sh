#!/bin/bash

# Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Builds tests.

SCRIPT_DIR=`dirname "$0"`
SCRIPT_DIR=`readlink -f "$SCRIPT_DIR"`

BUILD_ROOT=${BUILD_ROOT:-${SCRIPT_DIR}/../../../src/build}
OUT_DIR=${BUILD_ROOT}/x86/tests
mkdir -p ${OUT_DIR}

pushd $SCRIPT_DIR

scons minijail_unittests
cp minijail_unittests ${OUT_DIR}

popd
