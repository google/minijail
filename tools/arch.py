#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
