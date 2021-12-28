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
"""Unittests for the parser module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import shutil
import tempfile
import unittest

import arch
import bpf
import parser  # pylint: disable=wrong-import-order

ARCH_64 = arch.Arch.load_from_json(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'testdata/arch_64.json'))


class TokenizerTests(unittest.TestCase):
    """Tests for ParserState.tokenize."""

    @staticmethod
    def _tokenize(line):
        parser_state = parser.ParserState('<memory>')
        return list(parser_state.tokenize([line]))[0]

    def test_tokenize(self):
        """Accept valid tokens."""
        self.assertEqual([
            (token.type, token.value)
            for token in TokenizerTests._tokenize('@include /minijail.policy')
        ], [
            ('INCLUDE', '@include'),
            ('PATH', '/minijail.policy'),
        ])
        self.assertEqual([
            (token.type, token.value)
            for token in TokenizerTests._tokenize('@include ./minijail.policy')
        ], [
            ('INCLUDE', '@include'),
            ('PATH', './minijail.policy'),
        ])
        self.assertEqual(
            [(token.type, token.value) for token in TokenizerTests._tokenize(
                'read: arg0 in ~0xffff || arg0 & (1|2) && arg0 == 0755; '
                'return ENOSYS # ignored')], [
                    ('IDENTIFIER', 'read'),
                    ('COLON', ':'),
                    ('ARGUMENT', 'arg0'),
                    ('OP', 'in'),
                    ('BITWISE_COMPLEMENT', '~'),
                    ('NUMERIC_CONSTANT', '0xffff'),
                    ('OR', '||'),
                    ('ARGUMENT', 'arg0'),
                    ('OP', '&'),
                    ('LPAREN', '('),
                    ('NUMERIC_CONSTANT', '1'),
                    ('BITWISE_OR', '|'),
                    ('NUMERIC_CONSTANT', '2'),
                    ('RPAREN', ')'),
                    ('AND', '&&'),
                    ('ARGUMENT', 'arg0'),
                    ('OP', '=='),
                    ('NUMERIC_CONSTANT', '0755'),
                    ('SEMICOLON', ';'),
                    ('RETURN', 'return'),
                    ('IDENTIFIER', 'ENOSYS'),
                ])
        # Ensure that tokens that have an otherwise valid token as prefix are
        # still matched correctly.
        self.assertEqual([
            (token.type, token.value)
            for token in TokenizerTests._tokenize(
                'inotify_wait return_sys killall trace_sys')
        ], [
            ('IDENTIFIER', 'inotify_wait'),
            ('IDENTIFIER', 'return_sys'),
            ('IDENTIFIER', 'killall'),
            ('IDENTIFIER', 'trace_sys'),
        ])

    def test_tokenize_invalid_token(self):
        """Reject tokenizer errors."""
        with self.assertRaisesRegex(parser.ParseException,
                                    (r'<memory>\(1:1\): invalid token\n'
                                     r'    %invalid-token%\n'
                                     r'    \^')):
            TokenizerTests._tokenize('%invalid-token%')


class ParseConstantTests(unittest.TestCase):
    """Tests for PolicyParser.parse_value."""

    def setUp(self):
        self.arch = ARCH_64
        self.parser = parser.PolicyParser(
            self.arch, kill_action=bpf.KillProcess())

    def _tokenize(self, line):
        # pylint: disable=protected-access
        return list(self.parser._parser_state.tokenize([line]))[0]

    def test_parse_constant_unsigned(self):
        """Accept reasonably-sized unsigned constants."""
        self.assertEqual(
            self.parser.parse_value(self._tokenize('0x80000000')), 0x80000000)
        if self.arch.bits == 64:
            self.assertEqual(
                self.parser.parse_value(self._tokenize('0x8000000000000000')),
                0x8000000000000000)

    def test_parse_constant_unsigned_too_big(self):
        """Reject unreasonably-sized unsigned constants."""
        if self.arch.bits == 32:
            with self.assertRaisesRegex(parser.ParseException,
                                        'unsigned overflow'):
                self.parser.parse_value(self._tokenize('0x100000000'))
        with self.assertRaisesRegex(parser.ParseException,
                                    'unsigned overflow'):
            self.parser.parse_value(self._tokenize('0x10000000000000000'))

    def test_parse_constant_signed(self):
        """Accept reasonably-sized signed constants."""
        self.assertEqual(
            self.parser.parse_value(self._tokenize('-1')),
            self.arch.max_unsigned)

    def test_parse_constant_signed_too_negative(self):
        """Reject unreasonably-sized signed constants."""
        if self.arch.bits == 32:
            with self.assertRaisesRegex(parser.ParseException,
                                        'signed underflow'):
                self.parser.parse_value(self._tokenize('-0x800000001'))
        with self.assertRaisesRegex(parser.ParseException, 'signed underflow'):
            self.parser.parse_value(self._tokenize('-0x8000000000000001'))

    def test_parse_mask(self):
        """Accept parsing a mask value."""
        self.assertEqual(
            self.parser.parse_value(self._tokenize('0x1|0x2|0x4|0x8')), 0xf)

    def test_parse_parenthesized_expressions(self):
        """Accept parsing parenthesized expressions."""
        bad_expressions = [
            '(1',
            '|(1)',
            '(1)|',
            '()',
            '(',
            '((',
            '(()',
            '(()1',
        ]
        for expression in bad_expressions:
            with self.assertRaises(parser.ParseException, msg=expression):
                self.parser.parse_value(self._tokenize(expression))

        bad_partial_expressions = [
            '1)',
            '(1)1',
            '1(0)',
        ]
        for expression in bad_partial_expressions:
            tokens = self._tokenize(expression)
            self.parser.parse_value(tokens)
            self.assertNotEqual(tokens, [])

        good_expressions = [
            '(3)',
            '(1)|2',
            '1|(2)',
            '(1)|(2)',
            '((3))',
            '0|(1|2)',
            '(0|1|2)',
        ]
        for expression in good_expressions:
            self.assertEqual(
                self.parser.parse_value(self._tokenize(expression)), 3)

    def test_parse_constant_complements(self):
        """Accept complementing constants."""
        self.assertEqual(
            self.parser.parse_value(self._tokenize('~0')),
            self.arch.max_unsigned)
        self.assertEqual(
            self.parser.parse_value(self._tokenize('~0|~0')),
            self.arch.max_unsigned)
        if self.arch.bits == 32:
            self.assertEqual(
                self.parser.parse_value(
                    self._tokenize('~0x005AF0FF|~0xFFA50FFF')), 0xFFFFFF00)
            self.assertEqual(
                self.parser.parse_value(
                    self._tokenize('0x0F|~(0x005AF000|0x00A50FFF)|0xF0')),
                0xFF0000FF)
        else:
            self.assertEqual(
                self.parser.parse_value(
                    self._tokenize('~0x00005A5AF0F0FFFF|~0xFFFFA5A50F0FFFFF')),
                0xFFFFFFFFFFFF0000)
            self.assertEqual(
                self.parser.parse_value(
                    self._tokenize(
                        '0x00FF|~(0x00005A5AF0F00000|0x0000A5A50F0FFFFF)|0xFF00'
                    )), 0xFFFF00000000FFFF)

    def test_parse_double_complement(self):
        """Reject double-complementing constants."""
        with self.assertRaisesRegex(parser.ParseException,
                                    'double complement'):
            self.parser.parse_value(self._tokenize('~~0'))

    def test_parse_empty_complement(self):
        """Reject complementing nothing."""
        with self.assertRaisesRegex(parser.ParseException, 'empty complement'):
            self.parser.parse_value(self._tokenize('0|~'))

    def test_parse_named_constant(self):
        """Accept parsing a named constant."""
        self.assertEqual(
            self.parser.parse_value(self._tokenize('O_RDONLY')), 0)

    def test_parse_empty_constant(self):
        """Reject parsing nothing."""
        with self.assertRaisesRegex(parser.ParseException, 'empty constant'):
            self.parser.parse_value([])
        with self.assertRaisesRegex(parser.ParseException, 'empty constant'):
            self.parser.parse_value(self._tokenize('0|'))

    def test_parse_invalid_constant(self):
        """Reject parsing invalid constants."""
        with self.assertRaisesRegex(parser.ParseException, 'invalid constant'):
            self.parser.parse_value(self._tokenize('foo'))


class ParseFilterExpressionTests(unittest.TestCase):
    """Tests for PolicyParser.parse_argument_expression."""

    def setUp(self):
        self.arch = ARCH_64
        self.parser = parser.PolicyParser(
            self.arch, kill_action=bpf.KillProcess())

    def _tokenize(self, line):
        # pylint: disable=protected-access
        return list(self.parser._parser_state.tokenize([line]))[0]

    def test_parse_argument_expression(self):
        """Accept valid argument expressions."""
        self.assertEqual(
            self.parser.parse_argument_expression(
                self._tokenize(
                    'arg0 in 0xffff || arg0 == PROT_EXEC && arg1 == PROT_WRITE'
                )), [
                    [parser.Atom(0, 'in', 0xffff)],
                    [parser.Atom(0, '==', 4),
                     parser.Atom(1, '==', 2)],
                ])

    def test_parse_number_argument_expression(self):
        """Accept valid argument expressions with any octal/decimal/hex number."""
        # 4607 == 010777 == 0x11ff
        self.assertEqual(
            self.parser.parse_argument_expression(
                self._tokenize('arg0 in 4607')), [
                    [parser.Atom(0, 'in', 4607)],
            ])

        self.assertEqual(
            self.parser.parse_argument_expression(
                self._tokenize('arg0 in 010777')), [
                    [parser.Atom(0, 'in', 4607)],
            ])

        self.assertEqual(
            self.parser.parse_argument_expression(
                self._tokenize('arg0 in 0x11ff')), [
                    [parser.Atom(0, 'in', 4607)],
            ])

    def test_parse_empty_argument_expression(self):
        """Reject empty argument expressions."""
        with self.assertRaisesRegex(parser.ParseException,
                                    'empty argument expression'):
            self.parser.parse_argument_expression(
                self._tokenize('arg0 in 0xffff ||'))

    def test_parse_empty_clause(self):
        """Reject empty clause."""
        with self.assertRaisesRegex(parser.ParseException, 'empty clause'):
            self.parser.parse_argument_expression(
                self._tokenize('arg0 in 0xffff &&'))

    def test_parse_invalid_argument(self):
        """Reject invalid argument."""
        with self.assertRaisesRegex(parser.ParseException, 'invalid argument'):
            self.parser.parse_argument_expression(
                self._tokenize('argX in 0xffff'))

    def test_parse_invalid_operator(self):
        """Reject invalid operator."""
        with self.assertRaisesRegex(parser.ParseException, 'invalid operator'):
            self.parser.parse_argument_expression(
                self._tokenize('arg0 = 0xffff'))

    def test_parse_missing_operator(self):
        """Reject missing operator."""
        with self.assertRaisesRegex(parser.ParseException, 'missing operator'):
            self.parser.parse_argument_expression(self._tokenize('arg0'))

    def test_parse_missing_operand(self):
        """Reject missing operand."""
        with self.assertRaisesRegex(parser.ParseException, 'empty constant'):
            self.parser.parse_argument_expression(self._tokenize('arg0 =='))


class ParseFilterTests(unittest.TestCase):
    """Tests for PolicyParser.parse_filter."""

    def setUp(self):
        self.arch = ARCH_64
        self.parser = parser.PolicyParser(
            self.arch, kill_action=bpf.KillProcess())

    def _tokenize(self, line):
        # pylint: disable=protected-access
        return list(self.parser._parser_state.tokenize([line]))[0]

    def test_parse_filter(self):
        """Accept valid filters."""
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('arg0 == 0')), [
                parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('kill-process')), [
                parser.Filter(None, bpf.KillProcess()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('kill-thread')), [
                parser.Filter(None, bpf.KillThread()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('trap')), [
                parser.Filter(None, bpf.Trap()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('return ENOSYS')), [
                parser.Filter(None,
                              bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('trace')), [
                parser.Filter(None, bpf.Trace()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('user-notify')), [
                parser.Filter(None, bpf.UserNotify()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('log')), [
                parser.Filter(None, bpf.Log()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('allow')), [
                parser.Filter(None, bpf.Allow()),
            ])
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('1')), [
                parser.Filter(None, bpf.Allow()),
            ])
        self.assertEqual(
            self.parser.parse_filter(
                self._tokenize(
                    '{ arg0 == 0, arg0 == 1; return ENOSYS, trap }')),
            [
                parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                parser.Filter([[parser.Atom(0, '==', 1)]],
                              bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
                parser.Filter(None, bpf.Trap()),
            ])

    def test_parse_missing_return_value(self):
        """Reject missing return value."""
        with self.assertRaisesRegex(parser.ParseException,
                                    'missing return value'):
            self.parser.parse_filter(self._tokenize('return'))

    def test_parse_invalid_return_value(self):
        """Reject invalid return value."""
        with self.assertRaisesRegex(parser.ParseException, 'invalid constant'):
            self.parser.parse_filter(self._tokenize('return arg0'))

    def test_parse_unclosed_brace(self):
        """Reject unclosed brace."""
        with self.assertRaisesRegex(parser.ParseException, 'unclosed brace'):
            self.parser.parse_filter(self._tokenize('{ allow'))


class ParseFilterDenylistTests(unittest.TestCase):
    """Tests for PolicyParser.parse_filter with a denylist policy."""

    def setUp(self):
        self.arch = ARCH_64
        self.kill_action = bpf.KillProcess()
        self.parser = parser.PolicyParser(
            self.arch, kill_action=self.kill_action, denylist=True)

    def _tokenize(self, line):
        # pylint: disable=protected-access
        return list(self.parser._parser_state.tokenize([line]))[0]

    def test_parse_filter(self):
        """Accept only filters that return an errno."""
        self.assertEqual(
            self.parser.parse_filter(self._tokenize('arg0 == 0; return ENOSYS')),
            [
                parser.Filter([[parser.Atom(0, '==', 0)]],
                bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
            ])


class ParseFilterStatementTests(unittest.TestCase):
    """Tests for PolicyParser.parse_filter_statement."""

    def setUp(self):
        self.arch = ARCH_64
        self.parser = parser.PolicyParser(
            self.arch, kill_action=bpf.KillProcess())

    def _tokenize(self, line):
        # pylint: disable=protected-access
        return list(self.parser._parser_state.tokenize([line]))[0]

    def assertEqualIgnoringToken(self, actual, expected, msg=None):
        """Similar to assertEqual, but ignores the token field."""
        if (actual.syscalls != expected.syscalls or
            actual.filters != expected.filters):
            self.fail('%r != %r' % (actual, expected), msg)

    def test_parse_filter_statement(self):
        """Accept valid filter statements."""
        self.assertEqualIgnoringToken(
            self.parser.parse_filter_statement(
                self._tokenize('read: arg0 == 0')),
            parser.ParsedFilterStatement(
                syscalls=(parser.Syscall('read', 0), ),
                filters=[
                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                ],
                token=None))
        self.assertEqualIgnoringToken(
            self.parser.parse_filter_statement(
                self._tokenize('{read, write}: arg0 == 0')),
            parser.ParsedFilterStatement(
                syscalls=(
                    parser.Syscall('read', 0),
                    parser.Syscall('write', 1),
                ),
                filters=[
                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                ],
                token=None))
        self.assertEqualIgnoringToken(
            self.parser.parse_filter_statement(
                self._tokenize('io@libc: arg0 == 0')),
            parser.ParsedFilterStatement(
                syscalls=(
                    parser.Syscall('read', 0),
                    parser.Syscall('write', 1),
                ),
                filters=[
                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                ],
                token=None))
        self.assertEqualIgnoringToken(
            self.parser.parse_filter_statement(
                self._tokenize('file-io@systemd: arg0 == 0')),
            parser.ParsedFilterStatement(
                syscalls=(
                    parser.Syscall('read', 0),
                    parser.Syscall('write', 1),
                ),
                filters=[
                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                ],
                token=None))
        self.assertEqualIgnoringToken(
            self.parser.parse_filter_statement(
                self._tokenize('kill: arg0 == 0')),
            parser.ParsedFilterStatement(
                syscalls=(
                    parser.Syscall('kill', 62),
                ),
                filters=[
                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                ],
                token=None))

    def test_parse_metadata(self):
        """Accept valid filter statements with metadata."""
        self.assertEqualIgnoringToken(
            self.parser.parse_filter_statement(
                self._tokenize('read[arch=test]: arg0 == 0')),
            parser.ParsedFilterStatement(
                syscalls=(
                    parser.Syscall('read', 0),
                ),
                filters=[
                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                ],
                token=None))
        self.assertEqualIgnoringToken(
            self.parser.parse_filter_statement(
                self._tokenize(
                    '{read, nonexistent[arch=nonexistent]}: arg0 == 0')),
            parser.ParsedFilterStatement(
                syscalls=(
                    parser.Syscall('read', 0),
                ),
                filters=[
                    parser.Filter([[parser.Atom(0, '==', 0)]], bpf.Allow()),
                ],
                token=None))

    def test_parse_unclosed_brace(self):
        """Reject unclosed brace."""
        with self.assertRaisesRegex(parser.ParseException, 'unclosed brace'):
            self.parser.parse_filter(self._tokenize('{ allow'))

    def test_parse_invalid_syscall_group(self):
        """Reject invalid syscall groups."""
        with self.assertRaisesRegex(parser.ParseException, 'unclosed brace'):
            self.parser.parse_filter_statement(
                self._tokenize('{ read, write: arg0 == 0'))

    def test_parse_missing_colon(self):
        """Reject missing colon."""
        with self.assertRaisesRegex(parser.ParseException, 'missing colon'):
            self.parser.parse_filter_statement(self._tokenize('read'))

    def test_parse_invalid_colon(self):
        """Reject invalid colon."""
        with self.assertRaisesRegex(parser.ParseException, 'invalid colon'):
            self.parser.parse_filter_statement(self._tokenize('read arg0'))

    def test_parse_missing_filter(self):
        """Reject missing filter."""
        with self.assertRaisesRegex(parser.ParseException, 'missing filter'):
            self.parser.parse_filter_statement(self._tokenize('read:'))


class ParseFileTests(unittest.TestCase):
    """Tests for PolicyParser.parse_file."""

    def setUp(self):
        self.arch = ARCH_64
        self.parser = parser.PolicyParser(
            self.arch, kill_action=bpf.KillProcess())
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_file(self, filename, contents):
        """Helper to write out a file for testing."""
        path = os.path.join(self.tempdir, filename)
        with open(path, 'w') as outf:
            outf.write(contents)
        return path

    def test_parse_simple(self):
        """Allow simple policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            read: allow
            write: allow
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.KillProcess(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                    parser.FilterStatement(
                        syscall=parser.Syscall('write', 1),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                ]))

    def test_parse_multiline(self):
        """Allow simple multi-line policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            read: \
                allow
            write: allow
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.KillProcess(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                    parser.FilterStatement(
                        syscall=parser.Syscall('write', 1),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                ]))

    def test_parse_default(self):
        """Allow defining a default action."""
        path = self._write_file(
            'test.policy', """
            @default kill-thread
            read: allow
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.KillThread(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                ]))

    def test_parse_default_permissive(self):
        """Reject defining a permissive default action."""
        path = self._write_file(
            'test.policy', """
            @default log
            read: allow
        """)

        with self.assertRaisesRegex(parser.ParseException,
                                    r'invalid permissive default action'):
            self.parser.parse_file(path)

    def test_parse_simple_grouped(self):
        """Allow simple policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            {read, write}: allow
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.KillProcess(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                    parser.FilterStatement(
                        syscall=parser.Syscall('write', 1),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                ]))

    def test_parse_other_arch(self):
        """Allow entries that only target another architecture."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            read[arch=nonexistent]: allow
            write: allow
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.KillProcess(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('write', 1),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                ]))

    def test_parse_include(self):
        """Allow including policy files."""
        path = self._write_file(
            'test.include.policy', """
            {read, write}: arg0 == 0; allow
        """)
        path = self._write_file(
            'test.policy', """
            @include ./test.include.policy
            read: return ENOSYS
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.KillProcess(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=1,
                        filters=[
                            parser.Filter([[parser.Atom(0, '==', 0)]],
                                          bpf.Allow()),
                            parser.Filter(
                                None,
                                bpf.ReturnErrno(
                                    self.arch.constants['ENOSYS'])),
                        ]),
                    parser.FilterStatement(
                        syscall=parser.Syscall('write', 1),
                        frequency=1,
                        filters=[
                            parser.Filter([[parser.Atom(0, '==', 0)]],
                                          bpf.Allow()),
                            parser.Filter(None, bpf.KillProcess()),
                        ]),
                ]))

    def test_parse_invalid_include(self):
        """Reject including invalid policy files."""
        with self.assertRaisesRegex(parser.ParseException,
                                    r'empty include path'):
            path = self._write_file(
                'test.policy', """
                @include
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException,
                                    r'invalid include path'):
            path = self._write_file(
                'test.policy', """
                @include arg0
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException,
                                    r'@include statement nested too deep'):
            path = self._write_file(
                'test.policy', """
                @include ./test.policy
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException,
                                    r'Could not @include .*'):
            path = self._write_file(
                'test.policy', """
                @include ./nonexistent.policy
            """)
            self.parser.parse_file(path)

    def test_parse_frequency(self):
        """Allow including frequency files."""
        self._write_file(
            'test.frequency', """
            read: 2
            write: 3
        """)
        path = self._write_file(
            'test.policy', """
            @frequency ./test.frequency
            read: allow
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.KillProcess(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=2,
                        filters=[
                            parser.Filter(None, bpf.Allow()),
                        ]),
                ]))

    def test_parse_invalid_frequency(self):
        """Reject including invalid frequency files."""
        path = self._write_file('test.policy',
                                """@frequency ./test.frequency""")

        with self.assertRaisesRegex(parser.ParseException, r'missing colon'):
            self._write_file('test.frequency', """
                read
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException, r'invalid colon'):
            self._write_file('test.frequency', """
                read foo
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException, r'missing number'):
            self._write_file('test.frequency', """
                read:
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException, r'invalid number'):
            self._write_file('test.frequency', """
                read: foo
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException, r'invalid number'):
            self._write_file('test.frequency', """
                read: -1
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException,
                                    r'empty frequency path'):
            path = self._write_file(
                'test.policy', """
                @frequency
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException,
                                    r'invalid frequency path'):
            path = self._write_file(
                'test.policy', """
                @frequency arg0
            """)
            self.parser.parse_file(path)

        with self.assertRaisesRegex(parser.ParseException,
                                    r'Could not open frequency file.*'):
            path = self._write_file(
                'test.policy', """
                @frequency ./nonexistent.frequency
            """)
            self.parser.parse_file(path)

    def test_parse_multiple_unconditional(self):
        """Reject actions after an unconditional action."""
        path = self._write_file(
            'test.policy', """
            read: allow
            read: allow
        """)

        with self.assertRaisesRegex(
                parser.ParseException,
                (r'test.policy\(3:17\): '
                 r'Syscall read.*already had an unconditional action '
                 r'applied')):
            self.parser.parse_file(path)

        path = self._write_file(
            'test.policy', """
            read: log
            read: arg0 == 0; log
        """)

        with self.assertRaisesRegex(
                parser.ParseException,
                (r'test.policy\(3:17\): '
                 r'Syscall read.*already had an unconditional action '
                 r'applied')):
            self.parser.parse_file(path)

    def test_parse_allowlist_denylist_header(self):
        """Reject trying to compile denylist policy file as allowlist."""
        with self.assertRaisesRegex(parser.ParseException,
                                    r'policy is denylist, but flag --denylist '
                                    'not passed in'):
            path = self._write_file(
                'test.policy', """
                @denylist
            """)
            self.parser.parse_file(path)


class ParseFileDenylistTests(unittest.TestCase):
    """Tests for PolicyParser.parse_file."""

    def setUp(self):
        self.arch = ARCH_64
        self.kill_action = bpf.KillProcess()
        self.parser = parser.PolicyParser(
            self.arch, kill_action=self.kill_action, denylist=True)
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_file(self, filename, contents):
        """Helper to write out a file for testing."""
        path = os.path.join(self.tempdir, filename)
        with open(path, 'w') as outf:
            outf.write(contents)
        return path

    def test_parse_simple(self):
        """Allow simple denylist policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            @denylist
            read: return ENOSYS
            write: return ENOSYS
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.Allow(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.ReturnErrno(
                                    self.arch.constants['ENOSYS'])),
                        ]),
                    parser.FilterStatement(
                        syscall=parser.Syscall('write', 1),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.ReturnErrno(
                                    self.arch.constants['ENOSYS'])),
                        ]),
                ]))

    def test_parse_simple_with_arg(self):
        """Allow simple denylist policy files."""
        path = self._write_file(
            'test.policy', """
            # Comment.
            @denylist
            read: return ENOSYS
            write: arg0 == 0 ; return ENOSYS
        """)

        self.assertEqual(
            self.parser.parse_file(path),
            parser.ParsedPolicy(
                default_action=bpf.Allow(),
                filter_statements=[
                    parser.FilterStatement(
                        syscall=parser.Syscall('read', 0),
                        frequency=1,
                        filters=[
                            parser.Filter(None, bpf.ReturnErrno(
                                    self.arch.constants['ENOSYS'])),
                        ]),
                    parser.FilterStatement(
                        syscall=parser.Syscall('write', 1),
                        frequency=1,
                        filters=[
                            parser.Filter([[parser.Atom(0, '==', 0)]],
                                bpf.ReturnErrno(self.arch.constants['ENOSYS'])),
                            parser.Filter(None, bpf.Allow()),
                        ]),
                ]))


    def test_parse_denylist_no_header(self):
        """Reject trying to compile denylist policy file as allowlist."""
        with self.assertRaisesRegex(parser.ParseException,
                                    r'policy must contain @denylist flag to be '
                                    'compiled with --denylist flag'):
            path = self._write_file(
                'test.policy', """
                read: return ENOSYS
            """)
            self.parser.parse_file(path)

if __name__ == '__main__':
    unittest.main()
