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
"""Unittests for the seccomp policy linter module."""

from pathlib import Path
import tempfile
import unittest

import seccomp_policy_lint

class CheckSeccompPolicyTests(unittest.TestCase):
    """Tests for check_seccomp_policy."""

    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp())

    def _write_file(self, filename, contents):
        """Helper to write out a file for testing."""
        path = self.tempdir / filename
        path.write_text(contents)
        return path

    def test_check_simple(self):
        """Allow simple policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.\n
            read: 1\n
            write: 1\n
        """)

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
                    f'seccomp: {path.resolve()} does not contain any dangerous'
                    ' syscalls, so does not require review from'
                    ' chromeos-security@',
                    [])

        with path.open('r', encoding='utf-8') as check_file:
            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
                    exp_out)

    def test_check_dangerous_comment(self):
        """Dangerous syscalls must have a comment and need to be reviewed."""
        path = self._write_file(
            'test.policy', """
            # Comment.\n\n\n
            clone: 1\n
            write: 1\n
        """)

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
                    ' so requires review from chromeos-security@',
                    [])

        with path.open('r', encoding='utf-8') as check_file:
            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
                    exp_out)

    def test_check_dangerous_no_comment(self):
        """Dangerous syscalls without a comment should cause an error."""
        path = self._write_file(
            'test.policy', """
            # Comment.\n
            mount: 1\n
            clone: 1\n
        """)

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
                    ' so requires review from chromeos-security@',
                   [(f'{path.resolve()}, line 5: clone syscall is a dangerous '
                   'syscall so requires a comment on the preceding line')])

        with path.open('r', encoding='utf-8') as check_file:
            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
                    exp_out)

    def test_check_duplicate_syscall(self):
        """Policy files cannot have duplicate syscalls.."""
        path = self._write_file(
            'test.policy', """
            # Comment.\n
            clone: 1\n
            clone: arg0 == 3
        """)

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
                    ' so requires review from chromeos-security@',
                   [(f'{path.resolve()}, line 5: repeat syscall: clone')])

        with path.open('r', encoding='utf-8') as check_file:
            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS),
                    exp_out)


if __name__ == '__main__':
    unittest.main()
