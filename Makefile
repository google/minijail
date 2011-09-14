# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PRELOADPATH ?= \"/lib/libminijailpreload.so\"
CFLAGS += -fPIC -Wall -Wextra -Werror -DPRELOADPATH="$(PRELOADPATH)"

all : minijail0 libminijail.so libminijailpreload.so

minijail0 : libminijail.o minijail0.c
	$(CC) $(CFLAGS) -o $@ $^ -lcap

libminijail.so : libminijail.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -lcap

libminijailpreload.so : libminijailpreload.c libminijail.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -ldl -lcap

libminijail.o : libminijail.c libminijail.h
