#!/usr/bin/env python3
#
# Copyright (C) 2021 The Android Open Source Project
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
"""A linter for the Minijail seccomp policy file."""

import argparse
import re
import sys

from typing import List, NamedTuple

# The syscalls we have determined are more dangerous and need justification
# for inclusion in a policy.
DANGEROUS_SYSCALLS = (
    'clone',
    'mount',
    'setns',
    'kill',
    'execve',
    'execveat',
    'bpf',
    'socket',
    'ptrace',
    'swapon',
    'swapoff',
    # TODO(b/193169195): Add argument granularity for the below syscalls.
    'prctl',
    'ioctl',
#   'mmap',
#   'mprotect',
#   'mmap2',
)

class CheckPolicyReturn(NamedTuple):
    """Represents a return value from check_seccomp_policy

    Contains a message to print to the user and a list of errors that were
    found in the file.
    """
    message: str
    errors: List[str]

def parse_args(argv):
    """Return the parsed CLI arguments for this tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--denylist',
        action='store_true',
        help='Check as a denylist policy rather than the default allowlist.')
    parser.add_argument(
        '--dangerous-syscalls',
        action='store',
        default=','.join(DANGEROUS_SYSCALLS),
        help='Comma-separated list of dangerous sycalls (overrides default).'
    )
    parser.add_argument('policy',
                            help='The seccomp policy.',
                            type=argparse.FileType('r', encoding='utf-8'))
    return parser.parse_args(argv), parser

def check_seccomp_policy(check_file, dangerous_syscalls):
    """Fail if the seccomp policy file has dangerous, undocumented syscalls.

    Takes in a file object and a set of dangerous syscalls as arguments.
    """

    found_syscalls = set()
    errors = []
    msg = ''
    contains_dangerous_syscall = False
    prev_line_comment = False

    for line_num, line in enumerate(check_file):
        if re.match(r'^\s*#', line):
            prev_line_comment = True
        elif re.match(r'^\s*$', line):
            # Empty lines shouldn't reset prev_line_comment.
            continue
        else:
            match = re.match(fr'^\s*(\w*)\s*:', line)
            if match:
                syscall = match.group(1)
                if syscall in found_syscalls:
                    errors.append(f'{check_file.name}, line {line_num}: repeat '
                                  f'syscall: {syscall}')
                else:
                    found_syscalls.add(syscall)
                    for dangerous in dangerous_syscalls:
                        if dangerous == syscall:
                            # Dangerous syscalls must be preceded with a
                            # comment.
                            contains_dangerous_syscall = True
                            if not prev_line_comment:
                                errors.append(f'{check_file.name}, line '
                                              f'{line_num}: {syscall} syscall '
                                              'is a dangerous syscall so '
                                              'requires a comment on the '
                                              'preceding line')
                prev_line_comment = False
            else:
                # This line is probably a continuation from the previous line.
                # TODO(b/203216289): Support line breaks.
                pass

    if contains_dangerous_syscall:
        msg = (f'seccomp: {check_file.name} contains dangerous syscalls, so'
               ' requires review from chromeos-security@')
    else:
        msg = (f'seccomp: {check_file.name} does not contain any dangerous'
               ' syscalls, so does not require review from'
               ' chromeos-security@')

    if errors:
        return CheckPolicyReturn(msg, errors)

    return CheckPolicyReturn(msg, errors)

def main(argv=None):
    """Main entrypoint."""

    if argv is None:
        argv = sys.argv[1:]

    opts, _arg_parser = parse_args(argv)

    check = check_seccomp_policy(opts.policy,
                                 set(opts.dangerous_syscalls.split(',')))

    formatted_items = ''
    if check.errors:
        item_prefix = '\n    * '
        formatted_items = item_prefix + item_prefix.join(check.errors)

    print('* ' + check.message + formatted_items)

    return 1 if check.errors else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
