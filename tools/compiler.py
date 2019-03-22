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
"""A BPF compiler for the Minijail policy file."""

from __future__ import print_function

import bpf
import parser  # pylint: disable=wrong-import-order


class SyscallPolicyEntry:
    """The parsed version of a seccomp policy line."""

    def __init__(self, name, number, frequency):
        self.name = name
        self.number = number
        self.frequency = frequency
        self.accumulated = 0
        self.filter = None

    def __repr__(self):
        return ('SyscallPolicyEntry<name: %s, number: %d, '
                'frequency: %d, filter: %r>') % (self.name, self.number,
                                                 self.frequency,
                                                 self.filter.instructions
                                                 if self.filter else None)

    def simulate(self, arch, syscall_number, *args):
        """Simulate the policy with the given arguments."""
        if not self.filter:
            return (0, 'ALLOW')
        return bpf.simulate(self.filter.instructions, arch, syscall_number,
                            *args)


class PolicyCompiler:
    """A parser for the Minijail seccomp policy file format."""

    def __init__(self, arch):
        self._arch = arch

    def compile_filter_statement(self, filter_statement, *, kill_action):
        """Compile one parser.FilterStatement into BPF."""
        policy_entry = SyscallPolicyEntry(filter_statement.syscall.name,
                                          filter_statement.syscall.number,
                                          filter_statement.frequency)
        # In each step of the way, the false action is the one that is taken if
        # the immediate boolean condition does not match. This means that the
        # false action taken here is the one that applies if the whole
        # expression fails to match.
        false_action = filter_statement.filters[-1].action
        if false_action == bpf.Allow():
            return policy_entry
        # We then traverse the list of filters backwards since we want
        # the root of the DAG to be the very first boolean operation in
        # the filter chain.
        for filt in filter_statement.filters[:-1][::-1]:
            for disjunction in filt.expression:
                # This is the jump target of the very last comparison in the
                # conjunction. Given that any conjunction that succeeds should
                # make the whole expression succeed, make the very last
                # comparison jump to the accept action if it succeeds.
                true_action = filt.action
                for atom in disjunction:
                    block = bpf.Atom(atom.argument_index, atom.op, atom.value,
                                     true_action, false_action)
                    true_action = block
                false_action = true_action
        policy_filter = false_action

        # Lower all Atoms into WideAtoms.
        lowering_visitor = bpf.LoweringVisitor(arch=self._arch)
        policy_filter = lowering_visitor.process(policy_filter)

        # Flatten the IR DAG into a single BasicBlock.
        flattening_visitor = bpf.FlatteningVisitor(
            arch=self._arch, kill_action=kill_action)
        policy_filter.accept(flattening_visitor)
        policy_entry.filter = flattening_visitor.result
        return policy_entry
