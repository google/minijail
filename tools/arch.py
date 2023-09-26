#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Architecture-specific information."""

import collections
import json


class Arch(
        collections.namedtuple('Arch', [
            'arch_nr', 'arch_name', 'bits', 'syscalls', 'constants',
            'syscall_groups'
        ])):
    """Holds architecture-specific information."""

    def truncate_word(self, value):
        """Return the value truncated to fit in a word."""
        return value & self.max_unsigned

    @property
    def min_signed(self):
        """The smallest signed value that can be represented in a word."""
        return -(1 << (self.bits - 1))

    @property
    def max_unsigned(self):
        """The largest unsigned value that can be represented in a word."""
        return (1 << self.bits) - 1

    @staticmethod
    def load_from_json(json_path):
        """Return an Arch from a .json file."""
        with open(json_path, 'r') as json_file:
            constants = json.load(json_file)
            return Arch(
                arch_nr=constants['arch_nr'],
                arch_name=constants['arch_name'],
                bits=constants['bits'],
                syscalls=constants['syscalls'],
                constants=constants['constants'],
                syscall_groups=constants.get('syscall_groups', {}),
            )
