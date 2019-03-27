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

import enum

import bpf
import parser  # pylint: disable=wrong-import-order


class OptimizationStrategy(enum.Enum):
    """The available optimization strategies."""

    # Generate a linear chain of syscall number checks. Works best for policies
    # with very few syscalls.
    LINEAR = 'linear'

    # Generate a binary search tree for the syscalls. Works best for policies
    # with a lot of syscalls, where no one syscall dominates.
    BST = 'bst'

    def __str__(self):
        return self.value


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


class SyscallPolicyRange:
    """A contiguous range of SyscallPolicyEntries that have the same action."""

    def __init__(self, *entries):
        self.numbers = (entries[0].number, entries[-1].number + 1)
        self.frequency = sum(e.frequency for e in entries)
        self.accumulated = 0
        self.filter = entries[0].filter

    def __repr__(self):
        return 'SyscallPolicyRange<numbers: %r, frequency: %d, filter: %r>' % (
            self.numbers, self.frequency, self.filter.instructions
            if self.filter else None)

    def simulate(self, arch, syscall_number, *args):
        """Simulate the policy with the given arguments."""
        if not self.filter:
            return (0, 'ALLOW')
        return self.filter.simulate(arch, syscall_number, *args)


def _convert_to_ranges(entries):
    entries = list(sorted(entries, key=lambda r: r.number))
    lower = 0
    while lower < len(entries):
        upper = lower + 1
        while upper < len(entries):
            if entries[upper - 1].filter != entries[upper].filter:
                break
            if entries[upper - 1].number + 1 != entries[upper].number:
                break
            upper += 1
        yield SyscallPolicyRange(*entries[lower:upper])
        lower = upper


def _compile_single_range(entry,
                          accept_action,
                          reject_action,
                          visitor,
                          lower_bound=0,
                          upper_bound=1e99):
    action = accept_action
    if entry.filter:
        entry.filter.accept(visitor)
        action = entry.filter
    if entry.numbers[1] - entry.numbers[0] == 1:
        # Single syscall.
        # Accept if |X == nr|.
        return bpf.SyscallEntry(
            entry.numbers[0], action, reject_action, op=bpf.BPF_JEQ)
    elif entry.numbers[0] == lower_bound:
        # Syscall range aligned with the lower bound.
        # Accept if |X < nr[1]|.
        return bpf.SyscallEntry(
            entry.numbers[1], reject_action, action, op=bpf.BPF_JGE)
    elif entry.numbers[1] == upper_bound:
        # Syscall range aligned with the upper bound.
        # Accept if |X >= nr[0]|.
        return bpf.SyscallEntry(
            entry.numbers[0], action, reject_action, op=bpf.BPF_JGE)
    # Syscall range in the middle.
    # Accept if |nr[0] <= X < nr[1]|.
    upper_entry = bpf.SyscallEntry(
        entry.numbers[1], reject_action, action, op=bpf.BPF_JGE)
    return bpf.SyscallEntry(
        entry.numbers[0], upper_entry, reject_action, op=bpf.BPF_JGE)


def _compile_entries_linear(entries, accept_action, reject_action, visitor):
    # Compiles the list of entries into a simple linear list of comparisons. In
    # order to make the generated code a bit more efficient, we sort the
    # entries by frequency, so that the most frequently-called syscalls appear
    # earlier in the chain.
    next_action = reject_action
    ranges = sorted(_convert_to_ranges(entries), key=lambda r: -r.frequency)
    for entry in ranges[::-1]:
        next_action = _compile_single_range(entry, accept_action, next_action,
                                            visitor)
    return next_action


def _compile_entries_bst(entries, accept_action, reject_action, visitor):
    # Instead of generating a linear list of comparisons, this method generates
    # a binary search tree.
    #
    # Even though we are going to perform a binary search over the syscall
    # number, we would still like to rotate some of the internal nodes of the
    # binary search tree so that more frequently-used syscalls can be accessed
    # more cheaply (i.e. fewer internal nodes need to be traversed to reach
    # them).
    #
    # The overall idea then is to, at any step, instead of naively partitioning
    # the list of syscalls by the midpoint of the interval, we choose a
    # midpoint that minimizes the difference of the sum of all frequencies
    # between the left and right subtrees. For that, we need to sort the
    # entries by syscall number and keep track of the accumulated frequency of
    # all entries prior to the current one so that we can compue the midpoint
    # efficiently.
    #
    # TODO(lhchavez): There is one further possible optimization, which is to
    # hoist any syscalls that are more frequent than all other syscalls in the
    # BST combined into a linear chain before entering the BST.
    ranges = list(_convert_to_ranges(entries))

    accumulated = 0
    for entry in ranges:
        accumulated += entry.frequency
        entry.accumulated = accumulated

    # Recursively create the internal nodes.
    def _generate_syscall_bst(ranges, lower_bound=0, upper_bound=2**64 - 1):
        assert ranges
        if len(ranges) == 1:
            # This is a single syscall entry range, but the interval we are
            # currently considering contains other syscalls that we want to
            # reject. So instead of an internal node, create one or more leaf
            # nodes that check the range.
            assert lower_bound < upper_bound
            return _compile_single_range(ranges[0], accept_action,
                                         reject_action, visitor, lower_bound,
                                         upper_bound)

        # Find the midpoint that minimizes the difference between accumulated
        # costs in the left and right subtrees.
        previous_accumulated = ranges[0].accumulated - ranges[0].frequency
        last_accumulated = ranges[-1].accumulated - previous_accumulated
        best = (1e99, -1)
        for i, entry in enumerate(ranges):
            if not i:
                continue
            left_accumulated = entry.accumulated - previous_accumulated
            right_accumulated = last_accumulated - left_accumulated
            best = min(best, (abs(left_accumulated - right_accumulated), i))
        midpoint = best[1]
        assert midpoint >= 1, best

        cutoff_bound = ranges[midpoint].numbers[0]

        # Now we build the right and left subtrees independently. If any of the
        # subtrees consist of a single entry _and_ the bounds are tight around
        # that entry (that is, the bounds contain _only_ the syscall we are
        # going to consider), we can avoid emitting a leaf node and instead
        # have the comparison jump directly into the action that would be taken
        # by the entry.
        if (cutoff_bound, upper_bound) == ranges[midpoint].numbers:
            if ranges[midpoint].filter:
                ranges[midpoint].filter.accept(visitor)
                right_subtree = ranges[midpoint].filter
            else:
                right_subtree = accept_action
        else:
            right_subtree = _generate_syscall_bst(ranges[midpoint:],
                                                  cutoff_bound, upper_bound)

        if (lower_bound, cutoff_bound) == ranges[midpoint - 1].numbers:
            if ranges[midpoint - 1].filter:
                ranges[midpoint - 1].filter.accept(visitor)
                left_subtree = ranges[midpoint - 1].filter
            else:
                left_subtree = accept_action
        else:
            left_subtree = _generate_syscall_bst(ranges[:midpoint],
                                                 lower_bound, cutoff_bound)

        # Finally, now that both subtrees have been generated, we can create
        # the internal node of the binary search tree.
        return bpf.SyscallEntry(
            cutoff_bound, right_subtree, left_subtree, op=bpf.BPF_JGE)

    return _generate_syscall_bst(ranges)


class PolicyCompiler:
    """A parser for the Minijail seccomp policy file format."""

    def __init__(self, arch):
        self._arch = arch

    def compile_file(self,
                     policy_filename,
                     *,
                     optimization_strategy,
                     kill_action,
                     include_depth_limit=10):
        """Return a compiled BPF program from the provided policy file."""
        policy_parser = parser.PolicyParser(
            self._arch,
            kill_action=kill_action,
            include_depth_limit=include_depth_limit)
        parsed_policy = policy_parser.parse_file(policy_filename)
        entries = [
            self.compile_filter_statement(
                filter_statement, kill_action=kill_action)
            for filter_statement in parsed_policy.filter_statements
        ]

        visitor = bpf.FlatteningVisitor(
            arch=self._arch, kill_action=kill_action)
        accept_action = bpf.Allow()
        reject_action = parsed_policy.default_action
        if entries:
            if optimization_strategy == OptimizationStrategy.BST:
                next_action = _compile_entries_bst(entries, accept_action,
                                                   reject_action, visitor)
            else:
                next_action = _compile_entries_linear(entries, accept_action,
                                                      reject_action, visitor)
            reject_action.accept(visitor)
            accept_action.accept(visitor)
            bpf.ValidateArch(next_action).accept(visitor)
        else:
            reject_action.accept(visitor)
            bpf.ValidateArch(reject_action).accept(visitor)
        return visitor.result

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
