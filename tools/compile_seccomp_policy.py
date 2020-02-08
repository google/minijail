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
"""Helper tool to compile a BPF program from a Minijail seccomp filter.

This script will take a Minijail seccomp policy file and compile it into a
BPF program suitable for use with Minijail in the current architecture.
"""

from __future__ import print_function

import argparse
import sys

try:
    import arch
    import bpf
    import compiler
    import parser
except ImportError:
    from minijail import arch
    from minijail import bpf
    from minijail import compiler
    from minijail import parser


def parse_args(argv):
    """Return the parsed CLI arguments for this tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--optimization-strategy',
        default=compiler.OptimizationStrategy.BST,
        type=compiler.OptimizationStrategy,
        choices=list(compiler.OptimizationStrategy))
    parser.add_argument('--include-depth-limit', default=10)
    parser.add_argument('--arch-json', default='constants.json')
    parser.add_argument(
        '--default-action',
        type=str,
        help=('Use the specified default action, overriding any @default '
              'action found in the .policy files. '
              'This allows the use of permissive actions (allow, log, trace) '
              'since it is not valid to specify a permissive action in '
              '.policy files. This is useful for debugging.'))
    parser.add_argument(
        '--use-kill-process',
        action='store_true',
        help=('Use SECCOMP_RET_KILL_PROCESS instead of '
              'SECCOMP_RET_KILL_THREAD (requires Linux v4.14+).'))
    parser.add_argument(
        'policy', help='The seccomp policy.', type=argparse.FileType('r'))
    parser.add_argument(
        'output', help='The BPF program.', type=argparse.FileType('wb'))
    return parser.parse_args(argv)


def main(argv=None):
    """Main entrypoint."""

    if argv is None:
        argv = sys.argv[1:]

    opts = parse_args(argv)
    parsed_arch = arch.Arch.load_from_json(opts.arch_json)
    policy_compiler = compiler.PolicyCompiler(parsed_arch)
    if opts.use_kill_process:
        kill_action = bpf.KillProcess()
    else:
        kill_action = bpf.KillThread()
    override_default_action = None
    if opts.default_action:
        parser_state = parser.ParserState('<memory>')
        override_default_action = parser.PolicyParser(
            parsed_arch, kill_action=bpf.KillProcess()).parse_action(
                next(parser_state.tokenize([opts.default_action])))
    with opts.output as outf:
        outf.write(
            policy_compiler.compile_file(
                opts.policy.name,
                optimization_strategy=opts.optimization_strategy,
                kill_action=kill_action,
                include_depth_limit=opts.include_depth_limit,
                override_default_action=override_default_action).opcodes)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
