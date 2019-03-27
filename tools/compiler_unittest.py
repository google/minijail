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
"""Unittests for the compiler module."""

from __future__ import print_function

import os
import random
import shutil
import tempfile
import unittest

import arch
import bpf
import compiler
import parser  # pylint: disable=wrong-import-order

ARCH_64 = arch.Arch.load_from_json(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'testdata/arch_64.json'))


class CompileFilterStatementTests(unittest.TestCase):
    """Tests for PolicyCompiler.compile_filter_statement."""

    def setUp(self):
        self.arch = ARCH_64
        self.compiler = compiler.PolicyCompiler(self.arch)

    def _compile(self, line):
        with tempfile.NamedTemporaryFile(mode='w') as policy_file:
            policy_file.write(line)
            policy_file.flush()
            policy_parser = parser.PolicyParser(
                self.arch, kill_action=bpf.KillProcess())
            parsed_policy = policy_parser.parse_file(policy_file.name)
            assert len(parsed_policy.filter_statements) == 1
            return self.compiler.compile_filter_statement(
                parsed_policy.filter_statements[0],
                kill_action=bpf.KillProcess())

    def test_allow(self):
        """Accept lines where the syscall is accepted unconditionally."""
        block = self._compile('read: allow')
        self.assertEqual(block.filter, None)
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1], 'ALLOW')

    def test_arg0_eq_generated_code(self):
        """Accept lines with an argument filter with ==."""
        block = self._compile('read: arg0 == 0x100')
        # It might be a bit brittle to check the generated code in each test
        # case instead of just the behavior, but there should be at least one
        # test where this happens.
        self.assertEqual(
            block.filter.instructions,
            [
                bpf.SockFilter(bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS, 0, 0,
                               bpf.arg_offset(0, True)),
                # Jump to KILL_PROCESS if the high word does not match.
                bpf.SockFilter(bpf.BPF_JMP | bpf.BPF_JEQ | bpf.BPF_K, 0, 2, 0),
                bpf.SockFilter(bpf.BPF_LD | bpf.BPF_W | bpf.BPF_ABS, 0, 0,
                               bpf.arg_offset(0, False)),
                # Jump to KILL_PROCESS if the low word does not match.
                bpf.SockFilter(bpf.BPF_JMP | bpf.BPF_JEQ | bpf.BPF_K, 1, 0,
                               0x100),
                bpf.SockFilter(bpf.BPF_RET, 0, 0,
                               bpf.SECCOMP_RET_KILL_PROCESS),
                bpf.SockFilter(bpf.BPF_RET, 0, 0, bpf.SECCOMP_RET_ALLOW),
            ])

    def test_arg0_comparison_operators(self):
        """Accept lines with an argument filter with comparison operators."""
        biases = (-1, 0, 1)
        # For each operator, store the expectations of simulating the program
        # against the constant plus each entry from the |biases| array.
        cases = (
            ('==', ('KILL_PROCESS', 'ALLOW', 'KILL_PROCESS')),
            ('!=', ('ALLOW', 'KILL_PROCESS', 'ALLOW')),
            ('<', ('ALLOW', 'KILL_PROCESS', 'KILL_PROCESS')),
            ('<=', ('ALLOW', 'ALLOW', 'KILL_PROCESS')),
            ('>', ('KILL_PROCESS', 'KILL_PROCESS', 'ALLOW')),
            ('>=', ('KILL_PROCESS', 'ALLOW', 'ALLOW')),
        )
        for operator, expectations in cases:
            block = self._compile('read: arg0 %s 0x100' % operator)

            # Check the filter's behavior.
            for bias, expectation in zip(biases, expectations):
                self.assertEqual(
                    block.simulate(self.arch.arch_nr,
                                   self.arch.syscalls['read'],
                                   0x100 + bias)[1], expectation)

    def test_arg0_mask_operator(self):
        """Accept lines with an argument filter with &."""
        block = self._compile('read: arg0 & 0x3')

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'KILL_PROCESS')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           2)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           3)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           4)[1], 'KILL_PROCESS')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           5)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           6)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           7)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           8)[1], 'KILL_PROCESS')

    def test_arg0_in_operator(self):
        """Accept lines with an argument filter with in."""
        block = self._compile('read: arg0 in 0x3')

        # The 'in' operator only ensures that no bits outside the mask are set,
        # which means that 0 is always allowed.
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           2)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           3)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           4)[1], 'KILL_PROCESS')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           5)[1], 'KILL_PROCESS')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           6)[1], 'KILL_PROCESS')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           7)[1], 'KILL_PROCESS')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           8)[1], 'KILL_PROCESS')

    def test_arg0_short_gt_ge_comparisons(self):
        """Ensure that the short comparison optimization kicks in."""
        if self.arch.bits == 32:
            return
        short_constant_str = '0xdeadbeef'
        short_constant = int(short_constant_str, base=0)
        long_constant_str = '0xbadc0ffee0ddf00d'
        long_constant = int(long_constant_str, base=0)
        biases = (-1, 0, 1)
        # For each operator, store the expectations of simulating the program
        # against the constant plus each entry from the |biases| array.
        cases = (
            ('<', ('ALLOW', 'KILL_PROCESS', 'KILL_PROCESS')),
            ('<=', ('ALLOW', 'ALLOW', 'KILL_PROCESS')),
            ('>', ('KILL_PROCESS', 'KILL_PROCESS', 'ALLOW')),
            ('>=', ('KILL_PROCESS', 'ALLOW', 'ALLOW')),
        )
        for operator, expectations in cases:
            short_block = self._compile(
                'read: arg0 %s %s' % (operator, short_constant_str))
            long_block = self._compile(
                'read: arg0 %s %s' % (operator, long_constant_str))

            # Check that the emitted code is shorter when the high word of the
            # constant is zero.
            self.assertLess(
                len(short_block.filter.instructions),
                len(long_block.filter.instructions))

            # Check the filter's behavior.
            for bias, expectation in zip(biases, expectations):
                self.assertEqual(
                    long_block.simulate(self.arch.arch_nr,
                                        self.arch.syscalls['read'],
                                        long_constant + bias)[1], expectation)
                self.assertEqual(
                    short_block.simulate(
                        self.arch.arch_nr, self.arch.syscalls['read'],
                        short_constant + bias)[1], expectation)

    def test_and_or(self):
        """Accept lines with a complex expression in DNF."""
        block = self._compile('read: arg0 == 0 && arg1 == 0 || arg0 == 1')

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 0,
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 0,
                           1)[1], 'KILL_PROCESS')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 1,
                           0)[1], 'ALLOW')
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'], 1,
                           1)[1], 'ALLOW')

    def test_trap(self):
        """Accept lines that trap unconditionally."""
        block = self._compile('read: trap')

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'TRAP')

    def test_ret_errno(self):
        """Accept lines that return errno."""
        block = self._compile('read : arg0 == 0 || arg0 == 1 ; return 1')

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1:], ('ERRNO', 1))
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           1)[1:], ('ERRNO', 1))
        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           2)[1], 'KILL_PROCESS')

    def test_ret_errno_unconditionally(self):
        """Accept lines that return errno unconditionally."""
        block = self._compile('read: return 1')

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1:], ('ERRNO', 1))

    def test_trace(self):
        """Accept lines that trace unconditionally."""
        block = self._compile('read: trace')

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'TRACE')

    def test_log(self):
        """Accept lines that log unconditionally."""
        block = self._compile('read: log')

        self.assertEqual(
            block.simulate(self.arch.arch_nr, self.arch.syscalls['read'],
                           0)[1], 'LOG')

    def test_mmap_write_xor_exec(self):
        """Accept the idiomatic filter for mmap."""
        block = self._compile(
            'read : arg0 in ~PROT_WRITE || arg0 in ~PROT_EXEC')

        prot_exec_and_write = 6
        for prot in range(0, 0xf):
            if (prot & prot_exec_and_write) == prot_exec_and_write:
                self.assertEqual(
                    block.simulate(self.arch.arch_nr,
                                   self.arch.syscalls['read'], prot)[1],
                    'KILL_PROCESS')
            else:
                self.assertEqual(
                    block.simulate(self.arch.arch_nr,
                                   self.arch.syscalls['read'], prot)[1],
                    'ALLOW')


class CompileFileTests(unittest.TestCase):
    """Tests for PolicyCompiler.compile_file."""

    def setUp(self):
        self.arch = ARCH_64
        self.compiler = compiler.PolicyCompiler(self.arch)
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_file(self, filename, contents):
        """Helper to write out a file for testing."""
        path = os.path.join(self.tempdir, filename)
        with open(path, 'w') as outf:
            outf.write(contents)
        return path

    def test_compile(self):
        """Ensure compilation works with all strategies."""
        self._write_file(
            'test.frequency', """
            read: 1
            close: 10
        """)
        path = self._write_file(
            'test.policy', """
            @frequency ./test.frequency
            read: 1
            close: 1
        """)

        program = self.compiler.compile_file(
            path,
            optimization_strategy=compiler.OptimizationStrategy.LINEAR,
            kill_action=bpf.KillProcess())
        self.assertGreater(
            bpf.simulate(program.instructions, self.arch.arch_nr,
                         self.arch.syscalls['read'], 0)[0],
            bpf.simulate(program.instructions, self.arch.arch_nr,
                         self.arch.syscalls['close'], 0)[0],
        )

    def test_compile_bst(self):
        """Ensure compilation with BST is cheaper than the linear model."""
        self._write_file(
            'test.frequency', """
            read: 1
            close: 10
        """)
        path = self._write_file(
            'test.policy', """
            @frequency ./test.frequency
            read: 1
            close: 1
        """)

        for strategy in list(compiler.OptimizationStrategy):
            program = self.compiler.compile_file(
                path,
                optimization_strategy=strategy,
                kill_action=bpf.KillProcess())
            self.assertGreater(
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls['read'], 0)[0],
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls['close'], 0)[0],
            )
            self.assertEqual(
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls['read'], 0)[1], 'ALLOW')
            self.assertEqual(
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls['close'], 0)[1], 'ALLOW')

    def test_compile_empty_file(self):
        """Accept empty files."""
        path = self._write_file(
            'test.policy', """
            @default kill-thread
        """)

        for strategy in list(compiler.OptimizationStrategy):
            program = self.compiler.compile_file(
                path,
                optimization_strategy=strategy,
                kill_action=bpf.KillProcess())
            self.assertEqual(
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls['read'], 0)[1], 'KILL_THREAD')

    def test_compile_simulate(self):
        """Ensure policy reflects script by testing some random scripts."""
        iterations = 5
        for i in range(iterations):
            num_entries = 64 * (i + 1) // iterations
            syscalls = dict(
                zip(
                    random.sample(self.arch.syscalls.keys(), num_entries),
                    (random.randint(1, 1024) for _ in range(num_entries)),
                ))

            frequency_contents = '\n'.join(
                '%s: %d' % s for s in syscalls.items())
            policy_contents = '@frequency ./test.frequency\n' + '\n'.join(
                '%s: 1' % s[0] for s in syscalls.items())

            self._write_file('test.frequency', frequency_contents)
            path = self._write_file('test.policy', policy_contents)

            for strategy in list(compiler.OptimizationStrategy):
                program = self.compiler.compile_file(
                    path,
                    optimization_strategy=strategy,
                    kill_action=bpf.KillProcess())
                for name, number in self.arch.syscalls.items():
                    expected_result = ('ALLOW'
                                       if name in syscalls else 'KILL_PROCESS')
                    self.assertEqual(
                        bpf.simulate(program.instructions, self.arch.arch_nr,
                                     number, 0)[1], expected_result,
                        ('syscall name: %s, syscall number: %d, '
                         'strategy: %s, policy:\n%s') %
                        (name, number, strategy, policy_contents))

    @unittest.skipIf(not int(os.getenv('SLOW_TESTS', '0')), 'slow')
    def test_compile_huge_policy(self):
        """Ensure jumps while compiling a huge policy are still valid."""
        # Given that the BST strategy is O(n^3), don't choose a crazy large
        # value, but it still needs to be around 128 so that we exercise the
        # codegen paths that depend on the length of the jump.
        #
        # Immediate jump offsets in BPF comparison instructions are limited to
        # 256 instructions, so given that every syscall filter consists of a
        # load and jump instructions, with 128 syscalls there will be at least
        # one jump that's further than 256 instructions.
        num_entries = 128
        syscalls = dict(random.sample(self.arch.syscalls.items(), num_entries))
        # Here we force every single filter to be distinct. Otherwise the
        # codegen layer will coalesce filters that compile to the same
        # instructions.
        policy_contents = '\n'.join(
            '%s: arg0 == %d' % s for s in syscalls.items())

        path = self._write_file('test.policy', policy_contents)

        program = self.compiler.compile_file(
            path,
            optimization_strategy=compiler.OptimizationStrategy.BST,
            kill_action=bpf.KillProcess())
        for name, number in self.arch.syscalls.items():
            expected_result = ('ALLOW'
                               if name in syscalls else 'KILL_PROCESS')
            self.assertEqual(
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls[name], number)[1],
                expected_result)
            self.assertEqual(
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls[name], number + 1)[1],
                'KILL_PROCESS')

    def test_compile_huge_filter(self):
        """Ensure jumps while compiling a huge policy are still valid."""
        # This is intended to force cases where the AST visitation would result
        # in a combinatorial explosion of calls to Block.accept(). An optimized
        # implementation should be O(n).
        num_entries = 128
        syscalls = {}
        # Here we force every single filter to be distinct. Otherwise the
        # codegen layer will coalesce filters that compile to the same
        # instructions.
        policy_contents = []
        for name in random.sample(self.arch.syscalls.keys(), num_entries):
            values = random.sample(range(1024), num_entries)
            syscalls[name] = values
            policy_contents.append(
                '%s: %s' % (name, ' || '.join('arg0 == %d' % value
                                              for value in values)))

        path = self._write_file('test.policy', '\n'.join(policy_contents))

        program = self.compiler.compile_file(
            path,
            optimization_strategy=compiler.OptimizationStrategy.LINEAR,
            kill_action=bpf.KillProcess())
        for name, values in syscalls.items():
            self.assertEqual(
                bpf.simulate(program.instructions,
                             self.arch.arch_nr, self.arch.syscalls[name],
                             random.choice(values))[1], 'ALLOW')
            self.assertEqual(
                bpf.simulate(program.instructions, self.arch.arch_nr,
                             self.arch.syscalls[name], 1025)[1],
                'KILL_PROCESS')


if __name__ == '__main__':
    unittest.main()
