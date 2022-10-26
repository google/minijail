#!/bin/sh
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -ex
for m in $(git ls-tree main | awk '$NF ~ /\.[0-9]$/ { print $NF }'); do
  git show main:$m > x.1
  ./pandoc-filter.py x.1 $m.md
done
rm -f x.1
