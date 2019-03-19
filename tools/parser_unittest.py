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
import unittest

import arch
import parser  # pylint: disable=wrong-import-order

ARCH_64 = arch.Arch.load_from_json(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'testdata/arch_64.json'))


class TokenizerTests(unittest.TestCase):
    """Tests for ParserState.tokenize."""

    @staticmethod
    def _tokenize(line):
        parser_state = parser.ParserState('<memory>')
        parser_state.set_line(line)
        return parser_state.tokenize()

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
                'read: arg0 in ~0xffff || arg0 & (1|2) && arg0 == 0o755; '
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
                    ('NUMERIC_CONSTANT', '0o755'),
                    ('SEMICOLON', ';'),
                    ('RETURN', 'return'),
                    ('IDENTIFIER', 'ENOSYS'),
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
        self.parser = parser.PolicyParser(self.arch)

    def _tokenize(self, line):
        # pylint: disable=protected-access
        self.parser._parser_state.set_line(line)
        return self.parser._parser_state.tokenize()

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
            self.parser.parse_value(self._tokenize(''))
        with self.assertRaisesRegex(parser.ParseException, 'empty constant'):
            self.parser.parse_value(self._tokenize('0|'))


if __name__ == '__main__':
    unittest.main()
