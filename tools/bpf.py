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
"""Tools to interact with BPF programs."""

import abc
import collections
import struct

# This comes from syscall(2). Most architectures only support passing 6 args to
# syscalls, but ARM supports passing 7.
MAX_SYSCALL_ARGUMENTS = 7

# The following fields were copied from <linux/bpf_common.h>:

# Instruction classes
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

# LD/LDX fields.
# Size
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10
# Mode
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0

# JMP fields.
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40

# Source
BPF_K = 0x00
BPF_X = 0x08

BPF_MAXINSNS = 4096

# The following fields were copied from <linux/seccomp.h>:

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_TRACE = 0x7ff00000
SECCOMP_RET_LOG = 0x7ffc0000
SECCOMP_RET_ALLOW = 0x7fff0000

SECCOMP_RET_ACTION_FULL = 0xffff0000
SECCOMP_RET_DATA = 0x0000ffff


def arg_offset(arg_index, hi=False):
    """Return the BPF_LD|BPF_W|BPF_ABS addressing-friendly register offset."""
    offsetof_args = 4 + 4 + 8
    arg_width = 8
    return offsetof_args + arg_width * arg_index + (arg_width // 2) * hi


def simulate(instructions, arch, syscall_number, *args):
    """Simulate a BPF program with the given arguments."""
    args = ((args + (0, ) *
             (MAX_SYSCALL_ARGUMENTS - len(args)))[:MAX_SYSCALL_ARGUMENTS])
    input_memory = struct.pack('IIQ' + 'Q' * MAX_SYSCALL_ARGUMENTS,
                               syscall_number, arch, 0, *args)

    register = 0
    program_counter = 0
    cost = 0
    while program_counter < len(instructions):
        ins = instructions[program_counter]
        program_counter += 1
        cost += 1
        if ins.code == BPF_LD | BPF_W | BPF_ABS:
            register = struct.unpack('I', input_memory[ins.k:ins.k + 4])[0]
        elif ins.code == BPF_JMP | BPF_JA | BPF_K:
            program_counter += ins.k
        elif ins.code == BPF_JMP | BPF_JEQ | BPF_K:
            if register == ins.k:
                program_counter += ins.jt
            else:
                program_counter += ins.jf
        elif ins.code == BPF_JMP | BPF_JGT | BPF_K:
            if register > ins.k:
                program_counter += ins.jt
            else:
                program_counter += ins.jf
        elif ins.code == BPF_JMP | BPF_JGE | BPF_K:
            if register >= ins.k:
                program_counter += ins.jt
            else:
                program_counter += ins.jf
        elif ins.code == BPF_JMP | BPF_JSET | BPF_K:
            if register & ins.k != 0:
                program_counter += ins.jt
            else:
                program_counter += ins.jf
        elif ins.code == BPF_RET:
            if ins.k == SECCOMP_RET_KILL_PROCESS:
                return (cost, 'KILL_PROCESS')
            if ins.k == SECCOMP_RET_KILL_THREAD:
                return (cost, 'KILL_THREAD')
            if ins.k == SECCOMP_RET_TRAP:
                return (cost, 'TRAP')
            if (ins.k & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_ERRNO:
                return (cost, 'ERRNO', ins.k & SECCOMP_RET_DATA)
            if ins.k == SECCOMP_RET_TRACE:
                return (cost, 'TRACE')
            if ins.k == SECCOMP_RET_LOG:
                return (cost, 'LOG')
            if ins.k == SECCOMP_RET_ALLOW:
                return (cost, 'ALLOW')
            raise Exception('unknown return %#x' % ins.k)
        else:
            raise Exception('unknown instruction %r' % (ins, ))
    raise Exception('out-of-bounds')


class SockFilter(
        collections.namedtuple('SockFilter', ['code', 'jt', 'jf', 'k'])):
    """A representation of struct sock_filter."""

    __slots__ = ()

    def encode(self):
        """Return an encoded version of the SockFilter."""
        return struct.pack('HBBI', self.code, self.jt, self.jf, self.k)


class AbstractBlock(abc.ABC):
    """A class that implements the visitor pattern."""

    def __init__(self):
        super().__init__()

    @abc.abstractmethod
    def accept(self, visitor):
        pass


class BasicBlock(AbstractBlock):
    """A concrete implementation of AbstractBlock that has been compiled."""

    def __init__(self, instructions):
        super().__init__()
        self._instructions = instructions

    def accept(self, visitor):
        if visitor.visited(self):
            return
        visitor.visit(self)

    @property
    def instructions(self):
        return self._instructions

    @property
    def opcodes(self):
        return b''.join(i.encode() for i in self._instructions)

    def __eq__(self, o):
        if not isinstance(o, BasicBlock):
            return False
        return self._instructions == o._instructions


class KillProcess(BasicBlock):
    """A BasicBlock that unconditionally returns KILL_PROCESS."""

    def __init__(self):
        super().__init__(
            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_KILL_PROCESS)])


class KillThread(BasicBlock):
    """A BasicBlock that unconditionally returns KILL_THREAD."""

    def __init__(self):
        super().__init__(
            [SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_KILL_THREAD)])


class Trap(BasicBlock):
    """A BasicBlock that unconditionally returns TRAP."""

    def __init__(self):
        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_TRAP)])


class Trace(BasicBlock):
    """A BasicBlock that unconditionally returns TRACE."""

    def __init__(self):
        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_TRACE)])


class Log(BasicBlock):
    """A BasicBlock that unconditionally returns LOG."""

    def __init__(self):
        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_LOG)])


class ReturnErrno(BasicBlock):
    """A BasicBlock that unconditionally returns the specified errno."""

    def __init__(self, errno):
        super().__init__([
            SockFilter(BPF_RET, 0x00, 0x00,
                       SECCOMP_RET_ERRNO | (errno & SECCOMP_RET_DATA))
        ])
        self.errno = errno


class Allow(BasicBlock):
    """A BasicBlock that unconditionally returns ALLOW."""

    def __init__(self):
        super().__init__([SockFilter(BPF_RET, 0x00, 0x00, SECCOMP_RET_ALLOW)])


class ValidateArch(AbstractBlock):
    """An AbstractBlock that validates the architecture."""

    def __init__(self, next_block):
        super().__init__()
        self.next_block = next_block

    def accept(self, visitor):
        if visitor.visited(self):
            return
        self.next_block.accept(visitor)
        visitor.visit(self)


class SyscallEntry(AbstractBlock):
    """An abstract block that represents a syscall comparison in a DAG."""

    def __init__(self, syscall_number, jt, jf, *, op=BPF_JEQ):
        super().__init__()
        self.op = op
        self.syscall_number = syscall_number
        self.jt = jt
        self.jf = jf

    def __lt__(self, o):
        # Defined because we want to compare tuples that contain SyscallEntries.
        return False

    def __gt__(self, o):
        # Defined because we want to compare tuples that contain SyscallEntries.
        return False

    def accept(self, visitor):
        if visitor.visited(self):
            return
        self.jt.accept(visitor)
        self.jf.accept(visitor)
        visitor.visit(self)

    def __lt__(self, o):
        # Defined because we want to compare tuples that contain SyscallEntries.
        return False

    def __gt__(self, o):
        # Defined because we want to compare tuples that contain SyscallEntries.
        return False


class WideAtom(AbstractBlock):
    """A BasicBlock that represents a 32-bit wide atom."""

    def __init__(self, arg_offset, op, value, jt, jf):
        super().__init__()
        self.arg_offset = arg_offset
        self.op = op
        self.value = value
        self.jt = jt
        self.jf = jf

    def accept(self, visitor):
        if visitor.visited(self):
            return
        self.jt.accept(visitor)
        self.jf.accept(visitor)
        visitor.visit(self)


class Atom(AbstractBlock):
    """A BasicBlock that represents an atom (a simple comparison operation)."""

    def __init__(self, arg_index, op, value, jt, jf):
        super().__init__()
        if op == '==':
            op = BPF_JEQ
        elif op == '!=':
            op = BPF_JEQ
            jt, jf = jf, jt
        elif op == '>':
            op = BPF_JGT
        elif op == '<=':
            op = BPF_JGT
            jt, jf = jf, jt
        elif op == '>=':
            op = BPF_JGE
        elif op == '<':
            op = BPF_JGE
            jt, jf = jf, jt
        elif op == '&':
            op = BPF_JSET
        elif op == 'in':
            op = BPF_JSET
            # The mask is negated, so the comparison will be true when the
            # argument includes a flag that wasn't listed in the original
            # (non-negated) mask. This would be the failure case, so we switch
            # |jt| and |jf|.
            value = (~value) & ((1 << 64) - 1)
            jt, jf = jf, jt
        else:
            raise Exception('Unknown operator %s' % op)

        self.arg_index = arg_index
        self.op = op
        self.jt = jt
        self.jf = jf
        self.value = value

    def accept(self, visitor):
        if visitor.visited(self):
            return
        self.jt.accept(visitor)
        self.jf.accept(visitor)
        visitor.visit(self)


class AbstractVisitor(abc.ABC):
    """An abstract visitor."""

    def __init__(self):
        self._visited = set()

    def visited(self, block):
        if id(block) in self._visited:
            return True
        self._visited.add(id(block))
        return False

    def process(self, block):
        block.accept(self)
        return block

    def visit(self, block):
        if isinstance(block, KillProcess):
            self.visitKillProcess(block)
        elif isinstance(block, KillThread):
            self.visitKillThread(block)
        elif isinstance(block, Trap):
            self.visitTrap(block)
        elif isinstance(block, ReturnErrno):
            self.visitReturnErrno(block)
        elif isinstance(block, Trace):
            self.visitTrace(block)
        elif isinstance(block, Log):
            self.visitLog(block)
        elif isinstance(block, Allow):
            self.visitAllow(block)
        elif isinstance(block, BasicBlock):
            self.visitBasicBlock(block)
        elif isinstance(block, ValidateArch):
            self.visitValidateArch(block)
        elif isinstance(block, SyscallEntry):
            self.visitSyscallEntry(block)
        elif isinstance(block, WideAtom):
            self.visitWideAtom(block)
        elif isinstance(block, Atom):
            self.visitAtom(block)
        else:
            raise Exception('Unknown block type: %r' % block)

    @abc.abstractmethod
    def visitKillProcess(self, block):
        pass

    @abc.abstractmethod
    def visitKillThread(self, block):
        pass

    @abc.abstractmethod
    def visitTrap(self, block):
        pass

    @abc.abstractmethod
    def visitReturnErrno(self, block):
        pass

    @abc.abstractmethod
    def visitTrace(self, block):
        pass

    @abc.abstractmethod
    def visitLog(self, block):
        pass

    @abc.abstractmethod
    def visitAllow(self, block):
        pass

    @abc.abstractmethod
    def visitBasicBlock(self, block):
        pass

    @abc.abstractmethod
    def visitValidateArch(self, block):
        pass

    @abc.abstractmethod
    def visitSyscallEntry(self, block):
        pass

    @abc.abstractmethod
    def visitWideAtom(self, block):
        pass

    @abc.abstractmethod
    def visitAtom(self, block):
        pass


class CopyingVisitor(AbstractVisitor):
    """A visitor that copies Blocks."""

    def __init__(self):
        super().__init__()
        self._mapping = {}

    def process(self, block):
        self._mapping = {}
        block.accept(self)
        return self._mapping[id(block)]

    def visitKillProcess(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = KillProcess()

    def visitKillThread(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = KillThread()

    def visitTrap(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = Trap()

    def visitReturnErrno(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = ReturnErrno(block.errno)

    def visitTrace(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = Trace()

    def visitLog(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = Log()

    def visitAllow(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = Allow()

    def visitBasicBlock(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = BasicBlock(block.instructions)

    def visitValidateArch(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = ValidateArch(
            block.arch, self._mapping[id(block.next_block)])

    def visitSyscallEntry(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = SyscallEntry(
            block.syscall_number,
            self._mapping[id(block.jt)],
            self._mapping[id(block.jf)],
            op=block.op)

    def visitWideAtom(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = WideAtom(
            block.arg_offset, block.op, block.value, self._mapping[id(
                block.jt)], self._mapping[id(block.jf)])

    def visitAtom(self, block):
        assert id(block) not in self._mapping
        self._mapping[id(block)] = Atom(block.arg_index, block.op, block.value,
                                        self._mapping[id(block.jt)],
                                        self._mapping[id(block.jf)])


class LoweringVisitor(CopyingVisitor):
    """A visitor that lowers Atoms into WideAtoms."""

    def __init__(self, *, arch):
        super().__init__()
        self._bits = arch.bits

    def visitAtom(self, block):
        assert id(block) not in self._mapping

        lo = block.value & 0xFFFFFFFF
        hi = (block.value >> 32) & 0xFFFFFFFF

        lo_block = WideAtom(
            arg_offset(block.arg_index, False), block.op, lo,
            self._mapping[id(block.jt)], self._mapping[id(block.jf)])

        if self._bits == 32:
            self._mapping[id(block)] = lo_block
            return

        if block.op in (BPF_JGE, BPF_JGT):
            # hi_1,lo_1 <op> hi_2,lo_2
            #
            # hi_1 > hi_2 || hi_1 == hi_2 && lo_1 <op> lo_2
            if hi == 0:
                # Special case: it's not needed to check whether |hi_1 == hi_2|,
                # because it's true iff the JGT test fails.
                self._mapping[id(block)] = WideAtom(
                    arg_offset(block.arg_index, True), BPF_JGT, hi,
                    self._mapping[id(block.jt)], lo_block)
                return
            hi_eq_block = WideAtom(
                arg_offset(block.arg_index, True), BPF_JEQ, hi, lo_block,
                self._mapping[id(block.jf)])
            self._mapping[id(block)] = WideAtom(
                arg_offset(block.arg_index, True), BPF_JGT, hi,
                self._mapping[id(block.jt)], hi_eq_block)
            return
        if block.op == BPF_JSET:
            # hi_1,lo_1 & hi_2,lo_2
            #
            # hi_1 & hi_2 || lo_1 & lo_2
            if hi == 0:
                # Special case: |hi_1 & hi_2| will never be True, so jump
                # directly into the |lo_1 & lo_2| case.
                self._mapping[id(block)] = lo_block
                return
            self._mapping[id(block)] = WideAtom(
                arg_offset(block.arg_index, True), block.op, hi,
                self._mapping[id(block.jt)], lo_block)
            return

        assert block.op == BPF_JEQ, block.op

        # hi_1,lo_1 == hi_2,lo_2
        #
        # hi_1 == hi_2 && lo_1 == lo_2
        self._mapping[id(block)] = WideAtom(
            arg_offset(block.arg_index, True), block.op, hi, lo_block,
            self._mapping[id(block.jf)])


class FlatteningVisitor:
    """A visitor that flattens a DAG of Block objects."""

    def __init__(self, *, arch, kill_action):
        self._visited = set()
        self._kill_action = kill_action
        self._instructions = []
        self._arch = arch
        self._offsets = {}

    @property
    def result(self):
        return BasicBlock(self._instructions)

    def _distance(self, block):
        distance = self._offsets[id(block)] + len(self._instructions)
        assert distance >= 0
        return distance

    def _emit_load_arg(self, offset):
        return [SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset)]

    def _emit_jmp(self, op, value, jt_distance, jf_distance):
        if jt_distance < 0x100 and jf_distance < 0x100:
            return [
                SockFilter(BPF_JMP | op | BPF_K, jt_distance, jf_distance,
                           value),
            ]
        if jt_distance + 1 < 0x100:
            return [
                SockFilter(BPF_JMP | op | BPF_K, jt_distance + 1, 0, value),
                SockFilter(BPF_JMP | BPF_JA, 0, 0, jf_distance),
            ]
        if jf_distance + 1 < 0x100:
            return [
                SockFilter(BPF_JMP | op | BPF_K, 0, jf_distance + 1, value),
                SockFilter(BPF_JMP | BPF_JA, 0, 0, jt_distance),
            ]
        return [
            SockFilter(BPF_JMP | op | BPF_K, 0, 1, value),
            SockFilter(BPF_JMP | BPF_JA, 0, 0, jt_distance + 1),
            SockFilter(BPF_JMP | BPF_JA, 0, 0, jf_distance),
        ]

    def visited(self, block):
        if id(block) in self._visited:
            return True
        self._visited.add(id(block))
        return False

    def visit(self, block):
        assert id(block) not in self._offsets

        if isinstance(block, BasicBlock):
            instructions = block.instructions
        elif isinstance(block, ValidateArch):
            instructions = [
                SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
                SockFilter(BPF_JMP | BPF_JEQ | BPF_K,
                           self._distance(block.next_block) + 1, 0,
                           self._arch.arch_nr),
            ] + self._kill_action.instructions + [
                SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
            ]
        elif isinstance(block, SyscallEntry):
            instructions = self._emit_jmp(block.op, block.syscall_number,
                                          self._distance(block.jt),
                                          self._distance(block.jf))
        elif isinstance(block, WideAtom):
            instructions = (
                self._emit_load_arg(block.arg_offset) + self._emit_jmp(
                    block.op, block.value, self._distance(block.jt),
                    self._distance(block.jf)))
        else:
            raise Exception('Unknown block type: %r' % block)

        self._instructions = instructions + self._instructions
        self._offsets[id(block)] = -len(self._instructions)
        return


class ArgFilterForwardingVisitor:
    """A visitor that forwards visitation to all arg filters."""

    def __init__(self, visitor):
        self._visited = set()
        self.visitor = visitor

    def visited(self, block):
        if id(block) in self._visited:
            return True
        self._visited.add(id(block))
        return False

    def visit(self, block):
        # All arg filters are BasicBlocks.
        if not isinstance(block, BasicBlock):
            return
        # But the ALLOW, KILL_PROCESS, TRAP, etc. actions are too and we don't
        # want to visit them just yet.
        if (isinstance(block, KillProcess) or isinstance(block, KillThread)
                or isinstance(block, Trap) or isinstance(block, ReturnErrno)
                or isinstance(block, Trace) or isinstance(block, Log)
                or isinstance(block, Allow)):
            return
        block.accept(self.visitor)
