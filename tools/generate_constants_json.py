#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 The Android Open Source Project
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
"""Helper tool to generate cross-compiled syscall and constant tables to JSON.

This script takes the LLVM IR of libconstants.gen.c and libsyscalls.gen.c and
generates the `constants.json` file with that. LLVM IR files are moderately
architecture-neutral (at least for this case).
"""

import argparse
import collections
import json
import re
import sys

_STRING_CONSTANT_RE = re.compile(r'(@[a-zA-Z0-9.]+) = .*c"([^"\\]+)\\00".*')
_TABLE_ENTRY_RE = re.compile(
    r'%struct.(?:constant|syscall)_entry\s*{\s*([^}]+)\s*}')
# This looks something like
#
#  i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str.5, i32 0, i32 0), i32 5
#
# For arm-v7a. What we are interested in are the @.str.x and the very last
# number.
_TABLE_ENTRY_CONTENTS = re.compile(r'.*?(null|@[a-zA-Z0-9.]+).* (-?\d+)')

ParseResults = collections.namedtuple('ParseResults', ['table_name',
                                                       'table_entries'])


def parse_llvm_ir(ir):
    """Parses a single LLVM IR file."""
    string_constants = collections.OrderedDict()
    table_entries = collections.OrderedDict()
    table_name = ''
    for line in ir:
        string_constant_match = _STRING_CONSTANT_RE.match(line)
        if string_constant_match:
            string_constants[string_constant_match.group(
                1)] = string_constant_match.group(2)
            continue

        if '@syscall_table' in line or '@constant_table' in line:
            if '@syscall_table' in line:
                table_name = 'syscalls'
            else:
                table_name = 'constants'
            for entry in _TABLE_ENTRY_RE.findall(line):
                groups = _TABLE_ENTRY_CONTENTS.match(entry)
                if not groups:
                    raise ValueError('Failed to parse table entry %r' % entry)
                name, value = groups.groups()
                if name == 'null':
                    # This is the end-of-table marker.
                    break
                table_entries[string_constants[name]] = int(value)

    return ParseResults(table_name=table_name, table_entries=table_entries)


def main(argv=None):
    """Main entrypoint."""

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',
                        help='The path of the generated constants.json file.',
                        type=argparse.FileType('w'),
                        required=True)
    parser.add_argument(
        'llvm_ir_files',
        help='An LLVM IR file with one of the {constants,syscall} table.',
        metavar='llvm_ir_file',
        nargs='+',
        type=argparse.FileType('r'))
    opts = parser.parse_args(argv)

    constants_json = {}
    for ir in opts.llvm_ir_files:
        parse_results = parse_llvm_ir(ir)
        constants_json[parse_results.table_name] = parse_results.table_entries

    # Populate the top-level fields.
    constants_json['arch_nr'] = constants_json['constants']['MINIJAIL_ARCH_NR']
    constants_json['bits'] = constants_json['constants']['MINIJAIL_ARCH_BITS']

    # It is a bit more complicated to generate the arch_name, since the constants
    # can only output numeric values. Use a hardcoded mapping instead.
    if constants_json['arch_nr'] == 0xC000003E:
        constants_json['arch_name'] = 'x86_64'
    elif constants_json['arch_nr'] == 0x40000003:
        constants_json['arch_name'] = 'x86'
    elif constants_json['arch_nr'] == 0xC00000B7:
        constants_json['arch_name'] = 'arm64'
    elif constants_json['arch_nr'] == 0x40000028:
        constants_json['arch_name'] = 'arm'
    else:
        raise ValueError('Unknown architecture: 0x%08X' %
                         constants_json['arch_nr'])

    json.dump(constants_json, opts.output, indent='  ')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
