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
import itertools
import os.path
import re

try:
    import bpf
except ImportError:
    from minijail import bpf


Token = collections.namedtuple(
    'Token', ['type', 'value', 'filename', 'line', 'line_number', 'column'])

# A regex that can tokenize a Minijail policy file line.
_TOKEN_SPECIFICATION = (
    ('COMMENT', r'#.*$'),
    ('WHITESPACE', r'\s+'),
    ('CONTINUATION', r'\\$'),
    ('DEFAULT', r'@default\b'),
    ('INCLUDE', r'@include\b'),
    ('FREQUENCY', r'@frequency\b'),
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
    ('OP', r'&|\bin\b|==|!=|<=|<|>=|>'),
    ('EQUAL', r'='),
    ('ARGUMENT', r'\barg[0-9]+\b'),
    ('RETURN', r'\breturn\b'),
    ('ACTION',
     r'\ballow\b|\bkill-process\b|\bkill-thread\b|\bkill\b|\btrap\b|'
     r'\btrace\b|\blog\b'
    ),
    ('IDENTIFIER', r'[a-zA-Z_][a-zA-Z_0-9-@]*'),
)
_TOKEN_RE = re.compile('|'.join(
    r'(?P<%s>%s)' % pair for pair in _TOKEN_SPECIFICATION))


class ParseException(Exception):
    """An exception that is raised when parsing fails."""

    # pylint: disable=too-many-arguments
    def __init__(self,
                 message,
                 filename,
                 *,
                 line='',
                 line_number=1,
                 token=None):
        if token:
            line = token.line
            line_number = token.line_number
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

    def error(self, message, token=None):
        """Raise a ParserException with the provided message."""
        raise ParseException(
            message,
            self.filename,
            line=self._line,
            line_number=self._line_number,
            token=token)

    def tokenize(self, lines):
        """Return a list of tokens for the current line."""
        tokens = []

        for line_number, line in enumerate(lines):
            self._line_number = line_number + 1
            self._line = line.rstrip('\r\n')

            last_end = 0
            for token in _TOKEN_RE.finditer(self._line):
                if token.start() != last_end:
                    self.error(
                        'invalid token',
                        token=Token('INVALID',
                                    self._line[last_end:token.start()],
                                    self.filename, self._line,
                                    self._line_number, last_end))
                last_end = token.end()

                # Omit whitespace and comments now to avoid sprinkling this logic
                # elsewhere.
                if token.lastgroup in ('WHITESPACE', 'COMMENT',
                                       'CONTINUATION'):
                    continue
                tokens.append(
                    Token(token.lastgroup, token.group(), self.filename,
                          self._line, self._line_number, token.start()))
            if last_end != len(self._line):
                self.error(
                    'invalid token',
                    token=Token('INVALID', self._line[last_end:],
                                self.filename, self._line, self._line_number,
                                last_end))

            if self._line.endswith('\\'):
                # This line is not finished yet.
                continue

            if tokens:
                # Return a copy of the token list so that the caller can be free
                # to modify it.
                yield tokens[::]
            tokens.clear()


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

ParsedFilterStatement = collections.namedtuple(
    'ParsedFilterStatement', ['syscalls', 'filters', 'token'])
"""The result of parsing a filter statement.

Statements have a list of syscalls, and an associated list of filters that will
be evaluated sequentially when any of the syscalls is invoked.
"""

FilterStatement = collections.namedtuple('FilterStatement',
                                         ['syscall', 'frequency', 'filters'])
"""The filter list for a particular syscall.

This is a mapping from one syscall to a list of filters that are evaluated
sequentially. The last filter is always an unconditional action.
"""

ParsedPolicy = collections.namedtuple('ParsedPolicy',
                                      ['default_action', 'filter_statements'])
"""The result of parsing a minijail .policy file."""


# pylint: disable=too-few-public-methods
class PolicyParser:
    """A parser for the Minijail seccomp policy file format."""

    def __init__(self,
                 arch,
                 *,
                 kill_action,
                 include_depth_limit=10,
                 override_default_action=None):
        self._parser_states = [ParserState("<memory>")]
        self._kill_action = kill_action
        self._include_depth_limit = include_depth_limit
        self._default_action = self._kill_action
        self._override_default_action = override_default_action
        self._frequency_mapping = collections.defaultdict(int)
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

    # default-action = 'kill-process'
    #                | 'kill-thread'
    #                | 'kill'
    #                | 'trap'
    #                ;
    def _parse_default_action(self, tokens):
        if not tokens:
            self._parser_state.error('missing default action')
        action_token = tokens.pop(0)
        if action_token.type != 'ACTION':
            return self._parser_state.error(
                'invalid default action', token=action_token)
        if action_token.value == 'kill-process':
            return bpf.KillProcess()
        if action_token.value == 'kill-thread':
            return bpf.KillThread()
        if action_token.value == 'kill':
            return self._kill_action
        if action_token.value == 'trap':
            return bpf.Trap()
        return self._parser_state.error(
            'invalid permissive default action', token=action_token)

    # action = 'allow' | '1'
    #        | 'kill-process'
    #        | 'kill-thread'
    #        | 'kill'
    #        | 'trap'
    #        | 'trace'
    #        | 'log'
    #        | 'return' , single-constant
    #        ;
    def parse_action(self, tokens):
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
                action = self.parse_action(tokens)
            else:
                action = bpf.Allow()
            return Filter(argument_expression, action)
        else:
            return Filter(None, self.parse_action(tokens))

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

    # key-value-pair = identifier , '=', identifier , [ { ',' , identifier } ]
    #                ;
    def _parse_key_value_pair(self, tokens):
        if not tokens:
            self._parser_state.error('missing key')
        key = tokens.pop(0)
        if key.type != 'IDENTIFIER':
            self._parser_state.error('invalid key', token=key)
        if not tokens:
            self._parser_state.error('missing equal')
        if tokens[0].type != 'EQUAL':
            self._parser_state.error('invalid equal', token=tokens[0])
        tokens.pop(0)
        value_list = []
        while tokens:
            value = tokens.pop(0)
            if value.type != 'IDENTIFIER':
                self._parser_state.error('invalid value', token=value)
            value_list.append(value.value)
            if not tokens or tokens[0].type != 'COMMA':
                break
            tokens.pop(0)
        else:
            self._parser_state.error('empty value')
        return (key.value, value_list)

    # metadata = '[' , key-value-pair , [ { ';' , key-value-pair } ] , ']'
    #          ;
    def _parse_metadata(self, tokens):
        if not tokens:
            self._parser_state.error('missing opening bracket')
        opening_bracket = tokens.pop(0)
        if opening_bracket.type != 'LBRACKET':
            self._parser_state.error(
                'invalid opening bracket', token=opening_bracket)
        metadata = {}
        while tokens:
            first_token = tokens[0]
            key, value = self._parse_key_value_pair(tokens)
            if key in metadata:
                self._parser_state.error(
                    'duplicate metadata key: "%s"' % key, token=first_token)
            metadata[key] = value
            if not tokens or tokens[0].type != 'SEMICOLON':
                break
            tokens.pop(0)
        if not tokens or tokens[0].type != 'RBRACKET':
            self._parser_state.error('unclosed bracket', token=opening_bracket)
        tokens.pop(0)
        return metadata

    # syscall-descriptor = syscall-name , [ metadata ]
    #                    | syscall-group-name , [ metadata ]
    #                    ;
    def _parse_syscall_descriptor(self, tokens):
        if not tokens:
            self._parser_state.error('missing syscall descriptor')
        syscall_descriptor = tokens.pop(0)
        # `kill` as a syscall name is a special case since kill is also a valid
        # action and actions have precendence over identifiers.
        if (syscall_descriptor.type != 'IDENTIFIER' and
            syscall_descriptor.value != 'kill'):
            self._parser_state.error(
                'invalid syscall descriptor', token=syscall_descriptor)
        if tokens and tokens[0].type == 'LBRACKET':
            metadata = self._parse_metadata(tokens)
            if 'arch' in metadata and self._arch.arch_name not in metadata['arch']:
                return ()
        if '@' in syscall_descriptor.value:
            # This is a syscall group.
            subtokens = syscall_descriptor.value.split('@')
            if len(subtokens) != 2:
                self._parser_state.error(
                    'invalid syscall group name', token=syscall_descriptor)
            syscall_group_name, syscall_namespace_name = subtokens
            if syscall_namespace_name not in self._arch.syscall_groups:
                self._parser_state.error(
                    'nonexistent syscall group namespace',
                    token=syscall_descriptor)
            syscall_namespace = self._arch.syscall_groups[
                syscall_namespace_name]
            if syscall_group_name not in syscall_namespace:
                self._parser_state.error(
                    'nonexistent syscall group', token=syscall_descriptor)
            return (Syscall(name, self._arch.syscalls[name])
                    for name in syscall_namespace[syscall_group_name])
        if syscall_descriptor.value not in self._arch.syscalls:
            self._parser_state.error(
                'nonexistent syscall', token=syscall_descriptor)
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
        # Given that there can be multiple syscalls and filters in a single
        # filter statement, use the colon token as the anchor for error location
        # purposes.
        colon_token = tokens.pop(0)
        parsed_filter = self.parse_filter(tokens)
        if not syscall_descriptors:
            return None
        return ParsedFilterStatement(
            tuple(syscall_descriptors), parsed_filter, colon_token)

    # include-statement = '@include' , posix-path
    #                   ;
    def _parse_include_statement(self, tokens):
        if not tokens:
            self._parser_state.error('empty filter statement')
        if tokens[0].type != 'INCLUDE':
            self._parser_state.error('invalid include', token=tokens[0])
        tokens.pop(0)
        if not tokens:
            self._parser_state.error('empty include path')
        include_path = tokens.pop(0)
        if include_path.type != 'PATH':
            self._parser_state.error(
                'invalid include path', token=include_path)
        if len(self._parser_states) == self._include_depth_limit:
            self._parser_state.error('@include statement nested too deep')
        include_filename = os.path.normpath(
            os.path.join(
                os.path.dirname(self._parser_state.filename),
                include_path.value))
        if not os.path.isfile(include_filename):
            self._parser_state.error(
                'Could not @include %s' % include_filename, token=include_path)
        return self._parse_policy_file(include_filename)

    def _parse_frequency_file(self, filename):
        self._parser_states.append(ParserState(filename))
        try:
            frequency_mapping = collections.defaultdict(int)
            with open(filename) as frequency_file:
                for tokens in self._parser_state.tokenize(frequency_file):
                    syscall_numbers = self._parse_syscall_descriptor(tokens)
                    if not tokens:
                        self._parser_state.error('missing colon')
                    if tokens[0].type != 'COLON':
                        self._parser_state.error(
                            'invalid colon', token=tokens[0])
                    tokens.pop(0)

                    if not tokens:
                        self._parser_state.error('missing number')
                    number = tokens.pop(0)
                    if number.type != 'NUMERIC_CONSTANT':
                        self._parser_state.error(
                            'invalid number', token=number)
                    number_value = int(number.value, base=0)
                    if number_value < 0:
                        self._parser_state.error(
                            'invalid number', token=number)

                    for syscall_number in syscall_numbers:
                        frequency_mapping[syscall_number] += number_value
            return frequency_mapping
        finally:
            self._parser_states.pop()

    # frequency-statement = '@frequency' , posix-path
    #                      ;
    def _parse_frequency_statement(self, tokens):
        if not tokens:
            self._parser_state.error('empty frequency statement')
        if tokens[0].type != 'FREQUENCY':
            self._parser_state.error('invalid frequency', token=tokens[0])
        tokens.pop(0)
        if not tokens:
            self._parser_state.error('empty frequency path')
        frequency_path = tokens.pop(0)
        if frequency_path.type != 'PATH':
            self._parser_state.error(
                'invalid frequency path', token=frequency_path)
        frequency_filename = os.path.normpath(
            os.path.join(
                os.path.dirname(self._parser_state.filename),
                frequency_path.value))
        if not os.path.isfile(frequency_filename):
            self._parser_state.error(
                'Could not open frequency file %s' % frequency_filename,
                token=frequency_path)
        return self._parse_frequency_file(frequency_filename)

    # default-statement = '@default' , default-action
    #                   ;
    def _parse_default_statement(self, tokens):
        if not tokens:
            self._parser_state.error('empty default statement')
        if tokens[0].type != 'DEFAULT':
            self._parser_state.error('invalid default', token=tokens[0])
        tokens.pop(0)
        if not tokens:
            self._parser_state.error('empty action')
        return self._parse_default_action(tokens)

    def _parse_policy_file(self, filename):
        self._parser_states.append(ParserState(filename))
        try:
            statements = []
            with open(filename) as policy_file:
                for tokens in self._parser_state.tokenize(policy_file):
                    if tokens[0].type == 'INCLUDE':
                        statements.extend(
                            self._parse_include_statement(tokens))
                    elif tokens[0].type == 'FREQUENCY':
                        for syscall_number, frequency in self._parse_frequency_statement(
                                tokens).items():
                            self._frequency_mapping[
                                syscall_number] += frequency
                    elif tokens[0].type == 'DEFAULT':
                        self._default_action = self._parse_default_statement(
                            tokens)
                    else:
                        statement = self.parse_filter_statement(tokens)
                        if statement is None:
                            # If all the syscalls in the statement are for
                            # another arch, skip the whole statement.
                            continue
                        statements.append(statement)

                    if tokens:
                        self._parser_state.error(
                            'extra tokens', token=tokens[0])
            return statements
        finally:
            self._parser_states.pop()

    def parse_file(self, filename):
        """Parse a file and return the list of FilterStatements."""
        self._frequency_mapping = collections.defaultdict(int)
        try:
            statements = [x for x in self._parse_policy_file(filename)]
        except RecursionError:
            raise ParseException(
                'recursion limit exceeded',
                filename,
                line=self._parser_states[-1].line)

        # Collapse statements into a single syscall-to-filter-list, remembering
        # the token for each filter for better diagnostics.
        syscall_filter_mapping = {}
        syscall_filter_definitions = {}
        filter_statements = []
        for syscalls, filters, token in statements:
            for syscall in syscalls:
                if syscall not in syscall_filter_mapping:
                    filter_statements.append(
                        FilterStatement(
                            syscall, self._frequency_mapping.get(syscall, 1),
                            []))
                    syscall_filter_mapping[syscall] = filter_statements[-1]
                    syscall_filter_definitions[syscall] = []
                for filt in filters:
                    syscall_filter_mapping[syscall].filters.append(filt)
                    syscall_filter_definitions[syscall].append(token)
        default_action = self._override_default_action or self._default_action
        for filter_statement in filter_statements:
            unconditional_actions_suffix = list(
                itertools.dropwhile(lambda filt: filt.expression is not None,
                                    filter_statement.filters))
            if len(unconditional_actions_suffix) == 1:
                # The last filter already has an unconditional action, no need
                # to add another one.
                continue
            if len(unconditional_actions_suffix) > 1:
                previous_definition_token = syscall_filter_definitions[
                    filter_statement.syscall][
                        -len(unconditional_actions_suffix)]
                current_definition_token = syscall_filter_definitions[
                    filter_statement.syscall][
                        -len(unconditional_actions_suffix) + 1]
                raise ParseException(
                    ('Syscall %s (number %d) already had '
                     'an unconditional action applied') %
                    (filter_statement.syscall.name,
                     filter_statement.syscall.number),
                    filename=current_definition_token.filename,
                    token=current_definition_token) from ParseException(
                        'Previous definition',
                        filename=previous_definition_token.filename,
                        token=previous_definition_token)
            assert not unconditional_actions_suffix
            filter_statement.filters.append(
                Filter(expression=None, action=default_action))
        return ParsedPolicy(default_action, filter_statements)
