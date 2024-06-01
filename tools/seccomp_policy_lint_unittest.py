#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

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
            "test.policy",
            """
            # Comment.\n
            read: 1\n
            write: 1\n
        """,
        )

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
            f"seccomp: {path.resolve()} does not contain any dangerous"
            " syscalls, so does not require review from"
            " chromeos-security@",
            [],
        )

        with path.open("r", encoding="utf-8") as check_file:
            self.assertEqual(
                seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
                ),
                exp_out,
            )

    def test_check_dangerous_comment(self):
        """Dangerous syscalls must have a comment and need to be reviewed."""
        path = self._write_file(
            "test.policy",
            """
            # Comment.\n\n\n
            clone: 1\n
            write: 1\n
        """,
        )

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
            f"seccomp: {path.resolve()} contains dangerous syscalls,"
            " so requires review from chromeos-security@",
            [],
        )

        with path.open("r", encoding="utf-8") as check_file:
            self.assertEqual(
                seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
                ),
                exp_out,
            )

    def test_check_dangerous_no_comment(self):
        """Dangerous syscalls without a comment should cause an error."""
        path = self._write_file(
            "test.policy",
            """
            # Comment.\n
            mount: 1\n
            clone: 1\n
        """,
        )

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
            f"seccomp: {path.resolve()} contains dangerous syscalls,"
            " so requires review from chromeos-security@",
            [
                (
                    f"{path.resolve()}:5:clone: syscall is dangerous "
                    "and requires a comment on the preceding line"
                )
            ],
        )

        with path.open("r", encoding="utf-8") as check_file:
            self.assertEqual(
                seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
                ),
                exp_out,
            )

    def test_check_duplicate_syscall(self):
        """Policy files cannot have duplicate syscalls.."""
        path = self._write_file(
            "test.policy",
            """
            # Comment.\n
            clone: 1\n
            clone: arg0 == 3
        """,
        )

        exp_out = seccomp_policy_lint.CheckPolicyReturn(
            f"seccomp: {path.resolve()} contains dangerous syscalls,"
            " so requires review from chromeos-security@",
            [f"{path.resolve()}:5:clone: duplicate entry found"],
        )

        with path.open("r", encoding="utf-8") as check_file:
            self.assertEqual(
                seccomp_policy_lint.check_seccomp_policy(
                    check_file, seccomp_policy_lint.DANGEROUS_SYSCALLS
                ),
                exp_out,
            )


if __name__ == "__main__":
    unittest.main()
