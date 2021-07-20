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
            read: 0\n
            write: 0\n
        """)

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
                    f'seccomp: {path.resolve()} does not contain any dangerous'
                    ' syscalls, so does not require review from'
                    ' chromeos-security@\n',
                    [])

        with path.open('r', encoding='utf-8') as check_file:
            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
                    check_file),
                    exp_out)

    def test_check_dangerous_comment(self):
        """Dangerous syscalls must have a comment and need to be reviewed."""
        path = self._write_file(
            'test.policy', """
            # Comment.\n\n\n
            clone: 0\n
            write: 0\n
        """)

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
                    ' so requires review from chromeos-security@\n',
                    [])

        with path.open('r', encoding='utf-8') as check_file:
            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
                    check_file),
                    exp_out)

    def test_check_dangerous_no_comment(self):
        """Dangerous syscalls without a comment should cause an error.."""
        path = self._write_file(
            'test.policy', """
            # Comment.\n
            mount: 0\n
            clone: 0\n
        """)

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
                    f'seccomp: {path.resolve()} contains dangerous syscalls,'
                    ' so requires review from chromeos-security@\n'
                    'Dangerous syscalls must be preceded by a comment'
                    ' explaining why they are necessary:',
                   [(f'{path.resolve()}, line 5, clone syscall requires a'
                   ' comment on the preceding line')])

        with path.open('r', encoding='utf-8') as check_file:
            self.assertEqual(seccomp_policy_lint.check_seccomp_policy(
                    check_file),
                    exp_out)


if __name__ == '__main__':
    unittest.main()
