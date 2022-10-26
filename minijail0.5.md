# minijail0(5): sandbox a process

- [Description](#description)
- [Examples](#examples)
- [Seccomp_Filter Policy](#seccomp_filter-policy)
- [Seccomp_Filter Syntax](#seccomp_filter-syntax)
  - [Atom Syntax](#atom-syntax)
  - [Return Values](#return-values)
- [Seccomp_Filter Policy Writing](#seccomp_filter-policy-writing)
- [Configuration File](#configuration-file)
- [Author](#author)
- [Copyright](#copyright)
- [See Also](#see-also)

## Description

Runs PROGRAM inside a sandbox. See [**minijail0**(1)](./minijail0.1) for
details.

## Examples

Safely switch from user *root* to *nobody*, switch to primary group
*nobody*, drop all capabilities, and inherit any supplementary groups
from user *nobody*:

    # minijail0 -u nobody -g nobody -c 0 -G /usr/bin/whoami
    nobody

Run in a PID and VFS namespace without superuser capabilities (but still
as root) and with a private view of /proc:

    # minijail0 -p -v -r -c 0 /bin/ps
      PID TTY           TIME CMD
        1 pts/0     00:00:00 minijail0
        2 pts/0     00:00:00 ps

Running a process with a seccomp filter policy at reduced privileges:

    # minijail0 -S /usr/share/minijail0/$(uname -m)/cat.policy -- \
                /bin/cat /proc/self/seccomp_filter

## Seccomp_Filter Policy

The policy file supplied to the **-S** argument supports the following
syntax:

    <syscall_name>:<ftrace filter policy>
    <syscall_number>:<ftrace filter policy>
    <empty line>
    # any single line comment

Long lines may be broken up using \\ at the end.

A policy that emulates
[**seccomp**(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)
in mode 1 may look like:

    read: 1
    write: 1
    sig_return: 1
    exit: 1

The \"1\" acts as a wildcard and allows any use of the mentioned system
call. More advanced filtering is possible if your kernel supports
CONFIG_FTRACE_SYSCALLS. For example, we can allow a process to open any
file read only and mmap PROT_READ only:

    # open with O_LARGEFILE|O_RDONLY|O_NONBLOCK or some combination.
    open: arg1 == 32768 || arg1 == 0 || arg1 == 34816 || arg1 == 2048
    mmap2: arg2 == 0x0
    munmap: 1
    close: 1

The supported arguments may be found by reviewing the system call
prototypes in the Linux kernel source code. Be aware that any
non-numeric comparison may be subject to time-of-check-time-of-use
attacks and cannot be considered safe.

**execve** may only be used when invoking with CAP_SYS_ADMIN privileges.

In order to promote reusability, policy files can include other policy
files using the following syntax:

    @include /absolute/path/to/file.policy
    @include ./path/relative/to/CWD/file.policy

Inclusion is limited to a single level (i.e. files that are
**@include**d cannot themselves **@include** more files), since that
makes the policies harder to understand.

## Seccomp_Filter Syntax

More formally, the expression after the colon can be an expression in
Disjunctive Normal Form (DNF): a disjunction (\"or\", *\|\|*) of
conjunctions (\"and\", *&&*) of atoms.

### Atom Syntax

Atoms are of the form *arg{DNUM} {OP} {VAL}* where:

- *DNUM* is a decimal number

- *OP* is an unsigned comparison operator: *==*, *!=*, *\<*, *\<=*,
  *\>*, *\>=*, *&* (flags set), or *in* (inclusion)

- *VAL* is a constant expression. It can be a named constant (like
  **O_RDONLY**), a number (octal, decimal, or hexadecimal), a mask of
  constants separated by *\|*, or a parenthesized constant expression.
  Constant expressions can also be prefixed with the bitwise complement
  operator *\~* to produce their complement.

*==*, *!=*, *\<*, *\<=*, *\>*, and *\>=* should be pretty self
explanatory.

*&* will test for a flag being set, for example, O_RDONLY for
[**open**(2)](https://man7.org/linux/man-pages/man2/open.2.html):

    open: arg1 & O_RDONLY

Minijail supports most common named constants, like O_RDONLY. It\'s
preferable to use named constants rather than numeric values as not all
architectures use the same numeric value.

When the possible combinations of allowed flags grow, specifying them
all can be cumbersome. This is where the *in* operator comes handy. The
system call will be allowed iff the flags set in the argument are
included (as a set) in the flags in the policy:

    mmap: arg3 in MAP_PRIVATE|MAP_ANONYMOUS

This will allow
[**mmap**(2)](https://man7.org/linux/man-pages/man2/mmap.2.html) as long
as *arg3* (flags) has any combination of MAP_PRIVATE and MAP_ANONYMOUS,
but nothing else. One common use of this is to restrict
[**mmap**(2)](https://man7.org/linux/man-pages/man2/mmap.2.html) /
[**mprotect**(2)](https://man7.org/linux/man-pages/man2/mprotect.2.html)
to only allow write^exec mappings:

    mmap: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
    mprotect: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE

### Return Values

By default, blocked syscalls call the process to be killed. The *return
{NUM}* syntax can be used to force a specific errno to be returned
instead.

    read: return EBADF

This expression will block the
[**read**(2)](https://man7.org/linux/man-pages/man2/read.2.html)
syscall, make it return -1, and set **errno** to EBADF (9 on x86
platforms).

An expression can also include an optional *return \<errno\>* clause,
separated by a semicolon:

    read: arg0 == 0; return EBADF

This is, if the first argument to read is 0, then allow the syscall;
else, block the syscall, return -1, and set **errno** to EBADF.

## Seccomp_Filter Policy Writing

Determining policy for seccomp_filter can be time consuming. System
calls are often named in arch-specific, or legacy tainted, ways. E.g.,
geteuid versus geteuid32. On process death due to a seccomp filter rule,
the offending system call number will be supplied with a best guess of
the ABI defined name. This information may be used to produce working
baseline policies. However, if the process being contained has a fairly
tight working domain, using **tools/generate_seccomp_policy.py** with
the output of **strace -f -e raw=all \<program\>** can generate the list
of system calls that are needed. Note that when using libminijail or
minijail with preloading, supporting initial process setup calls will
not be required. Be conservative.

It\'s also possible to analyze the binary checking for all non-dead
functions and determining if any of them issue system calls. There is no
active implementation for this, but something like
code.google.com/p/seccompsandbox is one possible runtime variant.

## Configuration File

A configuration file can be used to specify command line options and
other settings.

It supports the following syntax:

    % minijail-config-file v0
    <option>=<argument>
    <no-argument-option>
    <empty line>
    # any single line comment

Long lines may be broken up using \\ at the end.

The special directive \"% minijail-config-file v0\" must occupy the
first line. \"v0\" also declares the version of the config file format.

Keys contain only alphabetic characters and \'-\'. Values can be any
non-empty string. Leading and trailing whitespaces around keys and
values are permitted but will be stripped before processing.

Currently all long options are supported such as **mount**,
**bind-mount**. For a option that has no argument, the option will
occupy a single line, without \'=\' and value. Otherwise, any string
that is given after the \'=\' is interpreted as the argument.

## Author

The ChromiumOS Authors \<chromiumos-dev@chromium.org\>

## Copyright

Copyright © 2011 The ChromiumOS Authors License BSD-like.

## See Also

[**minijail0**(1)](./minijail0.1)