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

import bpf

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


Atom = collections.namedtuple('Atom', ['argument_index', 'op', 'value'])
"""A single boolean comparison within a filter expression."""

Filter = collections.namedtuple('Filter', ['expression', 'action'])
"""The result of parsing a DNF filter expression, with its action.

Since the expression is in Disjunctive Normal Form, it is composed of two levels
of lists, one for disjunctions and the inner one for conjunctions. The elements
of the inner list are Atoms.
"""

Syscall = collections.namedtuple('Syscall', ['name', 'number'])
"""A system call."""

ParsedFilterStatement = collections.namedtuple('ParsedFilterStatement',
                                               ['syscalls', 'filters'])
"""The result of parsing a filter statement.

Statements have a list of syscalls, and an associated list of filters that will
be evaluated sequentially when any of the syscalls is invoked.
"""


# pylint: disable=too-few-public-methods
class PolicyParser:
    """A parser for the Minijail seccomp policy file format."""

    def __init__(self, arch, *, kill_action):
        self._parser_states = [ParserState("<memory>")]
        self._kill_action = kill_action
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

    # atom = argument , op , value
    #      ;
    def _parse_atom(self, tokens):
        if not tokens:
            self._parser_state.error('missing argument')
        argument = tokens.pop(0)
        if argument.type != 'ARGUMENT':
            self._parser_state.error('invalid argument', token=argument)

        if not tokens:
            self._parser_state.error('missing operator')
        operator = tokens.pop(0)
        if operator.type != 'OP':
            self._parser_state.error('invalid operator', token=operator)

        value = self.parse_value(tokens)
        argument_index = int(argument.value[3:])
        if not (0 <= argument_index < bpf.MAX_SYSCALL_ARGUMENTS):
            self._parser_state.error('invalid argument', token=argument)
        return Atom(argument_index, operator.value, value)

    # clause = atom , [ { '&&' , atom } ]
    #        ;
    def _parse_clause(self, tokens):
        atoms = []
        while tokens:
            atoms.append(self._parse_atom(tokens))
            if not tokens or tokens[0].type != 'AND':
                break
            tokens.pop(0)
        else:
            self._parser_state.error('empty clause')
        return atoms

    # argument-expression = clause , [ { '||' , clause } ]
    #                   ;
    def parse_argument_expression(self, tokens):
        """Parse a argument expression in Disjunctive Normal Form.

        Since BPF disallows back jumps, we build the basic blocks in reverse
        order so that all the jump targets are known by the time we need to
        reference them.
        """

        clauses = []
        while tokens:
            clauses.append(self._parse_clause(tokens))
            if not tokens or tokens[0].type != 'OR':
                break
            tokens.pop(0)
        else:
            self._parser_state.error('empty argument expression')
        return clauses

    # action = 'allow' | '1'
    #        | 'kill-process'
    #        | 'kill-thread'
    #        | 'kill'
    #        | 'trap'
    #        | 'trace'
    #        | 'log'
    #        | 'return' , single-constant
    #        ;
    def _parse_action(self, tokens):
        if not tokens:
            self._parser_state.error('missing action')
        action_token = tokens.pop(0)
        if action_token.type == 'ACTION':
            if action_token.value == 'allow':
                return bpf.Allow()
            if action_token.value == 'kill':
                return self._kill_action
            if action_token.value == 'kill-process':
                return bpf.KillProcess()
            if action_token.value == 'kill-thread':
                return bpf.KillThread()
            if action_token.value == 'trap':
                return bpf.Trap()
            if action_token.value == 'trace':
                return bpf.Trace()
            if action_token.value == 'log':
                return bpf.Log()
        elif action_token.type == 'NUMERIC_CONSTANT':
            constant = self._parse_single_constant(action_token)
            if constant == 1:
                return bpf.Allow()
        elif action_token.type == 'RETURN':
            if not tokens:
                self._parser_state.error('missing return value')
            return bpf.ReturnErrno(self._parse_single_constant(tokens.pop(0)))
        return self._parser_state.error('invalid action', token=action_token)

    # single-filter = action
    #               | argument-expression , [ ';' , action ]
    #               ;
    def _parse_single_filter(self, tokens):
        if not tokens:
            self._parser_state.error('missing filter')
        if tokens[0].type == 'ARGUMENT':
            # Only argument expressions can start with an ARGUMENT token.
            argument_expression = self.parse_argument_expression(tokens)
            if tokens and tokens[0].type == 'SEMICOLON':
                tokens.pop(0)
                action = self._parse_action(tokens)
            else:
                action = bpf.Allow()
            return Filter(argument_expression, action)
        else:
            return Filter(None, self._parse_action(tokens))

    # filter = '{' , single-filter , [ { ',' , single-filter } ] , '}'
    #        | single-filter
    #        ;
    def parse_filter(self, tokens):
        """Parse a filter and return a list of Filter objects."""
        if not tokens:
            self._parser_state.error('missing filter')
        filters = []
        if tokens[0].type == 'LBRACE':
            opening_brace = tokens.pop(0)
            while tokens:
                filters.append(self._parse_single_filter(tokens))
                if not tokens or tokens[0].type != 'COMMA':
                    break
                tokens.pop(0)
            if not tokens or tokens[0].type != 'RBRACE':
                self._parser_state.error('unclosed brace', token=opening_brace)
            tokens.pop(0)
        else:
            filters.append(self._parse_single_filter(tokens))
        return filters

    # syscall-descriptor = syscall-name , [ metadata ]
    #                    | libc-function , [ metadata ]
    #                    ;
    def _parse_syscall_descriptor(self, tokens):
        if not tokens:
            self._parser_state.error('missing syscall descriptor')
        syscall_descriptor = tokens.pop(0)
        if syscall_descriptor.type != 'IDENTIFIER':
            self._parser_state.error(
                'invalid syscall descriptor', token=syscall_descriptor)
        if syscall_descriptor.value not in self._arch.syscalls:
            self._parser_state.error(
                'nonexistent syscall', token=syscall_descriptor)
        # TODO(lhchavez): Support libc function names.
        # TODO(lhchavez): Support metadata.
        return (Syscall(syscall_descriptor.value,
                        self._arch.syscalls[syscall_descriptor.value]), )

    # filter-statement = '{' , syscall-descriptor , [ { ',', syscall-descriptor } ] , '}' ,
    #                       ':' , filter
    #                  | syscall-descriptor , ':' , filter
    #                  ;
    def parse_filter_statement(self, tokens):
        """Parse a filter statement and return a ParsedFilterStatement."""
        if not tokens:
            self._parser_state.error('empty filter statement')
        syscall_descriptors = []
        if tokens[0].type == 'LBRACE':
            opening_brace = tokens.pop(0)
            while tokens:
                syscall_descriptors.extend(
                    self._parse_syscall_descriptor(tokens))
                if not tokens or tokens[0].type != 'COMMA':
                    break
                tokens.pop(0)
            if not tokens or tokens[0].type != 'RBRACE':
                self._parser_state.error('unclosed brace', token=opening_brace)
            tokens.pop(0)
        else:
            syscall_descriptors.extend(self._parse_syscall_descriptor(tokens))
        if not tokens:
            self._parser_state.error('missing colon')
        if tokens[0].type != 'COLON':
            self._parser_state.error('invalid colon', token=tokens[0])
        tokens.pop(0)
        parsed_filter = self.parse_filter(tokens)
        if not syscall_descriptors:
            return None
        return ParsedFilterStatement(tuple(syscall_descriptors), parsed_filter)
