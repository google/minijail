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

try:
    import bpf
    import parser  # pylint: disable=wrong-import-order
except ImportError:
    from minijail import bpf
    from minijail import parser  # pylint: disable=wrong-import-order


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
                'frequency: %d, filter: %r>') % (
                    self.name, self.number, self.frequency,
                    self.filter.instructions if self.filter else None)

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
            self.numbers, self.frequency,
            self.filter.instructions if self.filter else None)

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
                          lower_bound=0,
                          upper_bound=1e99):
    action = accept_action
    if entry.filter:
        action = entry.filter
    if entry.numbers[1] - entry.numbers[0] == 1:
        # Single syscall.
        # Accept if |X == nr|.
        return (1,
                bpf.SyscallEntry(
                    entry.numbers[0], action, reject_action, op=bpf.BPF_JEQ))
    elif entry.numbers[0] == lower_bound:
        # Syscall range aligned with the lower bound.
        # Accept if |X < nr[1]|.
        return (1,
                bpf.SyscallEntry(
                    entry.numbers[1], reject_action, action, op=bpf.BPF_JGE))
    elif entry.numbers[1] == upper_bound:
        # Syscall range aligned with the upper bound.
        # Accept if |X >= nr[0]|.
        return (1,
                bpf.SyscallEntry(
                    entry.numbers[0], action, reject_action, op=bpf.BPF_JGE))
    # Syscall range in the middle.
    # Accept if |nr[0] <= X < nr[1]|.
    upper_entry = bpf.SyscallEntry(
        entry.numbers[1], reject_action, action, op=bpf.BPF_JGE)
    return (2,
            bpf.SyscallEntry(
                entry.numbers[0], upper_entry, reject_action, op=bpf.BPF_JGE))


def _compile_ranges_linear(ranges, accept_action, reject_action):
    # Compiles the list of ranges into a simple linear list of comparisons. In
    # order to make the generated code a bit more efficient, we sort the
    # ranges by frequency, so that the most frequently-called syscalls appear
    # earlier in the chain.
    cost = 0
    accumulated_frequencies = 0
    next_action = reject_action
    for entry in sorted(ranges, key=lambda r: r.frequency):
        current_cost, next_action = _compile_single_range(
            entry, accept_action, next_action)
        accumulated_frequencies += entry.frequency
        cost += accumulated_frequencies * current_cost
    return (cost, next_action)


def _compile_entries_linear(entries, accept_action, reject_action):
    return _compile_ranges_linear(
        _convert_to_ranges(entries), accept_action, reject_action)[1]


def _compile_entries_bst(entries, accept_action, reject_action):
    # Instead of generating a linear list of comparisons, this method generates
    # a binary search tree, where some of the leaves can be linear chains of
    # comparisons.
    #
    # Even though we are going to perform a binary search over the syscall
    # number, we would still like to rotate some of the internal nodes of the
    # binary search tree so that more frequently-used syscalls can be accessed
    # more cheaply (i.e. fewer internal nodes need to be traversed to reach
    # them).
    #
    # This uses Dynamic Programming to generate all possible BSTs efficiently
    # (in O(n^3)) so that we can get the absolute minimum-cost tree that matches
    # all syscall entries. It does so by considering all of the O(n^2) possible
    # sub-intervals, and for each one of those try all of the O(n) partitions of
    # that sub-interval. At each step, it considers putting the remaining
    # entries in a linear comparison chain as well as another BST, and chooses
    # the option that minimizes the total overall cost.
    #
    # Between every pair of non-contiguous allowed syscalls, there are two
    # locally optimal options as to where to set the partition for the
    # subsequent ranges: aligned to the end of the left subrange or to the
    # beginning of the right subrange. The fact that these two options have
    # slightly different costs, combined with the possibility of a subtree to
    # use the linear chain strategy (which has a completely different cost
    # model), causes the target cost function that we are trying to optimize to
    # not be unimodal / convex. This unfortunately means that more clever
    # techniques like using ternary search (which would reduce the overall
    # complexity to O(n^2 log n)) do not work in all cases.
    ranges = list(_convert_to_ranges(entries))

    accumulated = 0
    for entry in ranges:
        accumulated += entry.frequency
        entry.accumulated = accumulated

    # Memoization cache to build the DP table top-down, which is easier to
    # understand.
    memoized_costs = {}

    def _generate_syscall_bst(ranges, indices, bounds=(0, 2**64 - 1)):
        assert bounds[0] <= ranges[indices[0]].numbers[0], (indices, bounds)
        assert ranges[indices[1] - 1].numbers[1] <= bounds[1], (indices,
                                                                bounds)

        if bounds in memoized_costs:
            return memoized_costs[bounds]
        if indices[1] - indices[0] == 1:
            if bounds == ranges[indices[0]].numbers:
                # If bounds are tight around the syscall, it costs nothing.
                memoized_costs[bounds] = (0, ranges[indices[0]].filter
                                          or accept_action)
                return memoized_costs[bounds]
            result = _compile_single_range(ranges[indices[0]], accept_action,
                                           reject_action)
            memoized_costs[bounds] = (result[0] * ranges[indices[0]].frequency,
                                      result[1])
            return memoized_costs[bounds]

        # Try the linear model first and use that as the best estimate so far.
        best_cost = _compile_ranges_linear(ranges[slice(*indices)],
                                           accept_action, reject_action)

        # Now recursively go through all possible partitions of the interval
        # currently being considered.
        previous_accumulated = ranges[indices[0]].accumulated - ranges[
            indices[0]].frequency
        bst_comparison_cost = (
            ranges[indices[1] - 1].accumulated - previous_accumulated)
        for i, entry in enumerate(ranges[slice(*indices)]):
            candidates = [entry.numbers[0]]
            if i:
                candidates.append(ranges[i - 1 + indices[0]].numbers[1])
            for cutoff_bound in candidates:
                if not bounds[0] < cutoff_bound < bounds[1]:
                    continue
                if not indices[0] < i + indices[0] < indices[1]:
                    continue
                left_subtree = _generate_syscall_bst(
                    ranges, (indices[0], i + indices[0]),
                    (bounds[0], cutoff_bound))
                right_subtree = _generate_syscall_bst(
                    ranges, (i + indices[0], indices[1]),
                    (cutoff_bound, bounds[1]))
                best_cost = min(
                    best_cost,
                    (bst_comparison_cost + left_subtree[0] + right_subtree[0],
                     bpf.SyscallEntry(
                         cutoff_bound,
                         right_subtree[1],
                         left_subtree[1],
                         op=bpf.BPF_JGE)))

        memoized_costs[bounds] = best_cost
        return memoized_costs[bounds]

    return _generate_syscall_bst(ranges, (0, len(ranges)))[1]


class PolicyCompiler:
    """A parser for the Minijail seccomp policy file format."""

    def __init__(self, arch):
        self._arch = arch

    def compile_file(self,
                     policy_filename,
                     *,
                     optimization_strategy,
                     kill_action,
                     include_depth_limit=10,
                     override_default_action=None,
                     denylist=False,
                     ret_log=False):
        """Return a compiled BPF program from the provided policy file."""
        policy_parser = parser.PolicyParser(
            self._arch,
            kill_action=kill_action,
            include_depth_limit=include_depth_limit,
            override_default_action=override_default_action,
            denylist=denylist,
            ret_log=ret_log)
        parsed_policy = policy_parser.parse_file(policy_filename)
        entries = [
            self.compile_filter_statement(
                filter_statement, kill_action=kill_action, denylist=denylist)
            for filter_statement in parsed_policy.filter_statements
        ]

        visitor = bpf.FlatteningVisitor(
            arch=self._arch, kill_action=kill_action)
        if denylist:
            accept_action = kill_action
            reject_action = bpf.Allow()
        else:
            accept_action = bpf.Allow()
            reject_action = parsed_policy.default_action
        if entries:
            if optimization_strategy == OptimizationStrategy.BST:
                next_action = _compile_entries_bst(entries, accept_action,
                                                   reject_action)
            else:
                next_action = _compile_entries_linear(entries, accept_action,
                                                      reject_action)
            next_action.accept(bpf.ArgFilterForwardingVisitor(visitor))
            reject_action.accept(visitor)
            accept_action.accept(visitor)
            bpf.ValidateArch(next_action).accept(visitor)
        else:
            reject_action.accept(visitor)
            bpf.ValidateArch(reject_action).accept(visitor)
        return visitor.result

    def compile_filter_statement(self,
                                 filter_statement,
                                 *,
                                 kill_action,
                                 denylist=False):
        """Compile one parser.FilterStatement into BPF."""
        policy_entry = SyscallPolicyEntry(filter_statement.syscall.name,
                                          filter_statement.syscall.number,
                                          filter_statement.frequency)
        # In each step of the way, the false action is the one that is taken if
        # the immediate boolean condition does not match. This means that the
        # false action taken here is the one that applies if the whole
        # expression fails to match.
        false_action = filter_statement.filters[-1].action
        if not denylist and false_action == bpf.Allow():
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
