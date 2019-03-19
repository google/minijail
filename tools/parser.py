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
"""A parser for the Minijail policy file."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import collections
import re

Token = collections.namedtuple('token',
                               ['type', 'value', 'filename', 'line', 'column'])

# A regex that can tokenize a Minijail policy file line.
_TOKEN_SPECIFICATION = (
    ('COMMENT', r'#.*$'),
    ('WHITESPACE', r'\s+'),
    ('INCLUDE', r'@include'),
    ('PATH', r'(?:\.)?/\S+'),
    ('NUMERIC_CONSTANT', r'-?0[xX][0-9a-fA-F]+|-?0[Oo][0-7]+|-?[0-9]+'),
    ('COLON', r':'),
    ('SEMICOLON', r';'),
    ('COMMA', r','),
    ('BITWISE_COMPLEMENT', r'~'),
    ('LPAREN', r'\('),
    ('RPAREN', r'\)'),
    ('LBRACE', r'\{'),
    ('RBRACE', r'\}'),
    ('RBRACKET', r'\]'),
    ('LBRACKET', r'\['),
    ('OR', r'\|\|'),
    ('AND', r'&&'),
    ('BITWISE_OR', r'\|'),
    ('OP', r'&|in|==|!=|<=|<|>=|>'),
    ('EQUAL', r'='),
    ('ARGUMENT', r'arg[0-9]+'),
    ('RETURN', r'return'),
    ('ACTION', r'allow|kill-process|kill-thread|kill|trap|trace|log'),
    ('IDENTIFIER', r'[a-zA-Z_][a-zA-Z_0-9@]*'),
)
_TOKEN_RE = re.compile('|'.join(
    r'(?P<%s>%s)' % pair for pair in _TOKEN_SPECIFICATION))


class ParseException(Exception):
    """An exception that is raised when parsing fails."""

    # pylint: disable=too-many-arguments
    def __init__(self, message, filename, line, line_number=1, token=None):
        if token:
            column = token.column
            length = len(token.value)
        else:
            column = len(line)
            length = 1

        message = ('%s(%d:%d): %s') % (filename, line_number, column + 1,
                                       message)
        message += '\n    %s' % line
        message += '\n    %s%s' % (' ' * column, '^' * length)
        super().__init__(message)


class ParserState:
    """Stores the state of the Parser to provide better diagnostics."""

    def __init__(self, filename):
        self._filename = filename
        self._line = ''
        self._line_number = 0

    @property
    def filename(self):
        """Return the name of the file being processed."""
        return self._filename

    @property
    def line(self):
        """Return the current line being processed."""
        return self._line

    @property
    def line_number(self):
        """Return the current line number being processed."""
        return self._line_number

    def set_line(self, line):
        """Update the current line being processed."""
        self._line = line
        self._line_number += 1

    def error(self, message, token=None):
        """Raise a ParserException with the provided message."""
        raise ParseException(message, self.filename, self.line,
                             self.line_number, token)

    def tokenize(self):
        """Return a list of tokens for the current line."""
        tokens = []

        last_end = 0
        for token in _TOKEN_RE.finditer(self.line):
            if token.start() != last_end:
                self.error(
                    'invalid token',
                    token=Token('INVALID', self.line[last_end:token.start()],
                                self.filename, self.line_number, last_end))
            last_end = token.end()

            # Omit whitespace and comments now to avoid sprinkling this logic
            # elsewhere.
            if token.lastgroup in ('WHITESPACE', 'COMMENT'):
                continue
            tokens.append(
                Token(token.lastgroup, token.group(), self.filename,
                      self.line_number, token.start()))
        if last_end != len(self.line):
            self.error(
                'invalid token',
                token=Token('INVALID', self.line[last_end:], self.filename,
                            self.line_number, last_end))
        return tokens


# pylint: disable=too-few-public-methods
class PolicyParser:
    """A parser for the Minijail seccomp policy file format."""

    def __init__(self, arch):
        self._parser_states = [ParserState("<memory>")]
        self._arch = arch

    @property
    def _parser_state(self):
        return self._parser_states[-1]

    # single-constant = identifier
    #                 | numeric-constant
    #                 ;
    def _parse_single_constant(self, token):
        if token.type == 'IDENTIFIER':
            if token.value not in self._arch.constants:
                self._parser_state.error('invalid constant', token=token)
            single_constant = self._arch.constants[token.value]
        elif token.type == 'NUMERIC_CONSTANT':
            try:
                single_constant = int(token.value, base=0)
            except ValueError:
                self._parser_state.error('invalid constant', token=token)
        else:
            self._parser_state.error('invalid constant', token=token)
        if single_constant > self._arch.max_unsigned:
            self._parser_state.error('unsigned overflow', token=token)
        elif single_constant < self._arch.min_signed:
            self._parser_state.error('signed underflow', token=token)
        elif single_constant < 0:
            # This converts the constant to an unsigned representation of the
            # same value, since BPF only uses unsigned values.
            single_constant = self._arch.truncate_word(single_constant)
        return single_constant

    # constant = [ '~' ] , '(' , value , ')'
    #          | [ '~' ] , single-constant
    #          ;
    def _parse_constant(self, tokens):
        negate = False
        if tokens[0].type == 'BITWISE_COMPLEMENT':
            negate = True
            tokens.pop(0)
            if not tokens:
                self._parser_state.error('empty complement')
            if tokens[0].type == 'BITWISE_COMPLEMENT':
                self._parser_state.error(
                    'invalid double complement', token=tokens[0])
        if tokens[0].type == 'LPAREN':
            last_open_paren = tokens.pop(0)
            single_value = self.parse_value(tokens)
            if not tokens or tokens[0].type != 'RPAREN':
                self._parser_state.error(
                    'unclosed parenthesis', token=last_open_paren)
        else:
            single_value = self._parse_single_constant(tokens[0])
        tokens.pop(0)
        if negate:
            single_value = self._arch.truncate_word(~single_value)
        return single_value

    # value = constant , [ { '|' , constant } ]
    #       ;
    def parse_value(self, tokens):
        """Parse constants separated bitwise OR operator |.

        Constants can be:

        - A number that can be parsed with int(..., base=0)
        - A named constant expression.
        - A parenthesized, valid constant expression.
        - A valid constant expression prefixed with the unary bitwise
          complement operator ~.
        - A series of valid constant expressions separated by bitwise
          OR operator |.

        If there is an error parsing any of the constants, the whole process
        fails.
        """

        value = 0
        while tokens:
            value |= self._parse_constant(tokens)
            if not tokens or tokens[0].type != 'BITWISE_OR':
                break
            tokens.pop(0)
        else:
            self._parser_state.error('empty constant')
        return value
