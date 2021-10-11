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
import os
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

CONSTANTS_ERR_MSG = """Could not find 'constants.json' file.
See 'generate_constants_json.py -h'."""

HEADER_TEMPLATE = """/* DO NOT EDIT GENERATED FILE */
#ifndef MJ_SECCOMP_%(upper_name)s_H
#define MJ_SECCOMP_%(upper_name)s_H
#include <stdint.h>

static const unsigned char %(name)s_binary_seccomp_policy[] __attribute__((__aligned__(4))) = {
    %(program)s
};

static const struct {
    uint16_t cnt;
    const void *bpf;
} %(name)s_seccomp_bpf_program = {
    .cnt = sizeof(%(name)s_binary_seccomp_policy) / 8,
    .bpf = %(name)s_binary_seccomp_policy,
};

#endif
"""

def parse_args(argv):
    """Return the parsed CLI arguments for this tool."""
    arg_parser = argparse.ArgumentParser(description=__doc__)
    arg_parser.add_argument('--optimization-strategy',
                            default=compiler.OptimizationStrategy.BST,
                            type=compiler.OptimizationStrategy,
                            choices=list(compiler.OptimizationStrategy))
    arg_parser.add_argument('--include-depth-limit', default=10)
    arg_parser.add_argument('--arch-json', default='constants.json')
    arg_parser.add_argument(
        '--denylist',
        action='store_true',
        help='Compile as a denylist policy rather than the default allowlist.')
    arg_parser.add_argument(
        '--default-action',
        type=str,
        help=('Use the specified default action, overriding any @default '
              'action found in the .policy files. '
              'This allows the use of permissive actions (allow, log, trace, '
              'user-notify) since it is not valid to specify a permissive '
              'action in .policy files. This is useful for debugging.'))
    arg_parser.add_argument(
        '--use-kill-process',
        action='store_true',
        help=('Use SECCOMP_RET_KILL_PROCESS instead of '
              'SECCOMP_RET_KILL_THREAD (requires Linux v4.14+).'))
    arg_parser.add_argument(
        '--use-ret-log',
        action='store_true',
        help=('Change all seccomp failures to return SECCOMP_RET_LOG instead '
              'of killing (requires SECCOMP_RET_LOG kernel support).'))
    arg_parser.add_argument(
        '--output-header-file',
        action='store_true',
        help=('Output the compiled bpf to a constant variable in a C header '
              'file instead of a binary file (output should not have a .h '
              'extension, one will be added).'))
    arg_parser.add_argument('policy',
                            help='The seccomp policy.',
                            type=argparse.FileType('r'))
    arg_parser.add_argument('output',
                            help='The BPF program.')
    return arg_parser.parse_args(argv), arg_parser


def main(argv=None):
    """Main entrypoint."""

    if argv is None:
        argv = sys.argv[1:]

    opts, arg_parser = parse_args(argv)
    if not os.path.exists(opts.arch_json):
        arg_parser.error(CONSTANTS_ERR_MSG)

    parsed_arch = arch.Arch.load_from_json(opts.arch_json)
    policy_compiler = compiler.PolicyCompiler(parsed_arch)
    # Set ret_log to true if the MINIJAIL_DEFAULT_RET_LOG environment variable
    # is present.
    if 'MINIJAIL_DEFAULT_RET_LOG' in os.environ:
        print("""
            \n**********************
Warning: MINJAIL_DEFAULT_RET_LOG is on, policy will not have any effect
**********************\n
""")
        opts.use_ret_log = True
    if opts.use_ret_log:
        kill_action = bpf.Log()
    elif opts.denylist:
        # Default action for a denylist policy is return EPERM
        kill_action = bpf.ReturnErrno(parsed_arch.constants['EPERM'])
    elif opts.use_kill_process:
        kill_action = bpf.KillProcess()
    else:
        kill_action = bpf.KillThread()
    override_default_action = None
    if opts.default_action:
        parser_state = parser.ParserState('<memory>')
        override_default_action = parser.PolicyParser(
            parsed_arch, kill_action=bpf.KillProcess()).parse_action(
                next(parser_state.tokenize([opts.default_action])))

    compiled_policy = policy_compiler.compile_file(
        opts.policy.name,
        optimization_strategy=opts.optimization_strategy,
        kill_action=kill_action,
        include_depth_limit=opts.include_depth_limit,
        override_default_action=override_default_action,
        denylist=opts.denylist,
        ret_log=opts.use_ret_log)
    # Outputs the bpf binary to a c header file instead of a binary file.
    if opts.output_header_file:
        output_file_base = opts.output
        with open(output_file_base + '.h', 'w') as output_file:
            program = ', '.join('%i' % x for x in compiled_policy.opcodes)
            output_file.write(HEADER_TEMPLATE % {
                'upper_name': output_file_base.upper(),
                'name': output_file_base,
                'program': program,
            })

    else:
        with open(opts.output, 'wb') as outf:
            outf.write(compiled_policy.opcodes)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
