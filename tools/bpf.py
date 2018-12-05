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

SECCOMP_RET_DATA = 0x0000ffff


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
