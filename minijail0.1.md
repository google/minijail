# minijail0(1): sandbox a process

  - [Synopsis](#synopsis)
  - [Description](#description)
  - [Sandboxing Profiles](#sandboxing-profiles)
  - [Implementation](#implementation)
  - [Author](#author)
  - [Copyright](#copyright)
  - [See Also](#see-also)

## Synopsis

**minijail0** \[*OPTION*\]... \<*PROGRAM*\> \[*args*\]...

## Description

Runs PROGRAM inside a sandbox.

  - **\-a \<table\>**  
    Run using the alternate syscall table named *table*. Only available
    on kernels and architectures that support the **PR\_ALT\_SYSCALL**
    option of
    [**prctl**(2)](https://man7.org/linux/man-pages/man2/prctl.2.html).

  - **\-b \<src\>\[,\[dest\]\[,\<writeable\>\]\]**, **\-\-bind\-mount=\<src\>\[,\[dest\]\[,\<writeable\>\]\]**  
    Bind-mount *src* into the chroot directory at *dest*, optionally
    writeable. The *src* path must be an absolute path.
    
    If *dest* is not specified, it will default to *src*. If the
    destination does not exist, it will be created as a file or
    directory based on the *src* type (including missing parent
    directories).
    
    To create a writable bind-mount set *writable* to **1**. If not
    specified it will default to **0** (read-only).

  - **\-B \<mask\>**  
    Skip setting securebits in *mask* when restricting capabilities
    (**\-c**). *mask* is a hex constant that represents the mask of
    securebits that will be preserved. See
    [**capabilities**(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
    for the complete list. By default, **SECURE\_NOROOT**,
    **SECURE\_NO\_SETUID\_FIXUP**, and **SECURE\_KEEP\_CAPS** (together
    with their respective locks) are set.
    **SECBIT\_NO\_CAP\_AMBIENT\_RAISE** (and its respective lock) is
    never set because the permitted and inheritable capability sets have
    already been set through **\-c**.

  - **\-c \<caps\>**  
    Restrict capabilities to *caps*, which is either a hex constant or a
    string that will be passed to
    [**cap\_from\_text**(3)](https://man7.org/linux/man-pages/man3/cap_from_text.3.html)
    (only the effective capability mask will be considered). The value
    will be used as the permitted, effective, and inheritable sets. When
    used in conjunction with **\-u** and **\-g**, this allows a program
    to have access to only certain parts of root's default privileges
    while running as another user and group ID altogether. Note that
    these capabilities are not inherited by subprocesses of the process
    given capabilities unless those subprocesses have POSIX file
    capabilities or the **\-\-ambient** flag is also passed. See
    [**capabilities**(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).

  - **\-C \<dir\>**  
    Change root (using
    [**chroot**(2)](https://man7.org/linux/man-pages/man2/chroot.2.html))
    to *dir*.

  - **\-d**, **\-\-mount\-dev**  
    Create a new /dev mount with a minimal set of nodes. Implies
    **\-v**. Additional nodes can be bound with the **\-b** or **\-k**
    options.
    
      - The initial set of nodes are: full null tty urandom zero.
    
      - Symlinks are also created for: fd ptmx stderr stdin stdout.
    
      - Directores are also created for: shm.

  - **\-e[file]**  
    Enter a new network namespace, or if *file* is specified, enter an
    existing network namespace specified by *file* which is typically of
    the form /proc/\<pid\>/ns/net.

  - **\-f \<file\>**  
    Write the pid of the jailed process to *file*.

  - **\-g \<group|gid\>**  
    Change groups to the specified *group* name, or numeric group ID
    *gid*.

  - **\-G**  
    Inherit all the supplementary groups of the user specified with
    **\-u**. It is an error to use this option without having specified
    a **user name** to **\-u**.

  - **\-\-add\-suppl\-group \<group|gid\>**  
    Add the specified *group* name, or numeric group ID *gid*, to the
    process' supplementary groups list. Can be specified multiple times
    to add several groups. Incompatible with -y and -G.

  - **\-h**  
    Print a help message.

  - **\-H**  
    Print a help message detailing supported system call names for
    seccomp\_filter. (Other direct numbers may be specified if minijail0
    is not in sync with the host kernel or something like 32/64-bit
    compatibility issues exist.)

  - **\-i**  
    Exit immediately after
    [**fork**(2)](https://man7.org/linux/man-pages/man2/fork.2.html).
    The jailed process will keep running in the background.
    
    Normally minijail will fork+exec the specified *program* so that it
    can set up the right security settings in the new child process. The
    initial minijail process will stay resident and wait for the
    *program* to exit so the script that ran minijail will correctly
    block (e.g. standalone scripts). Specifying **\-i** makes that
    initial process exit immediately and free up the resources.
    
    This option is recommended for daemons and init services when you
    want to background the long running *program*.

  - **\-I**  
    Run *program* as init (pid 1) inside a new pid namespace (implies
    **\-p**).
    
    Most programs don't expect to run as an init which is why minijail
    will do it for you by default. Basically, the *program* needs to
    reap any processes it forks to avoid leaving zombies behind. Signal
    handling needs care since the kernel will mask all signals that
    don't have handlers registered (all default handlers are ignored and
    cannot be changed).
    
    This means a minijail process (acting as init) will remain resident
    by default. While using **\-I** is recommended when possible, strict
    review is required to make sure the *program* continues to work as
    expected.
    
    **\-i** and **\-I** may be safely used together. The **\-i** option
    controls the first minijail process outside of the pid namespace
    while the **\-I** option controls the minijail process inside of the
    pid namespace.

  - **\-k \<src\>,\<dest\>,\<type\>\[,\<flags\>\[,\<data\>\]\]**, **\-\-mount=\<src\>,\<dest\>,\<type\>\[,\<flags\>\[,\<data\>\]\]**  
    Mount *src*, a *type* filesystem, at *dest*. If a chroot or pivot
    root is active, *dest* will automatically be placed below that path.
    
    The *flags* field is optional and may be a mix of *MS\_XXX* or hex
    constants separated by *|* characters. See
    [**mount**(2)](https://man7.org/linux/man-pages/man2/mount.2.html)
    for details. *MS\_NODEV|MS\_NOSUID|MS\_NOEXEC* is the default value
    (a writable mount with nodev/nosuid/noexec bits set), and it is
    strongly recommended that all mounts have these three bits set
    whenever possible. If you need to disable all three, then specify
    something like *MS\_SILENT*.
    
    The *data* field is optional and is a comma delimited string (see
    [**mount**(2)](https://man7.org/linux/man-pages/man2/mount.2.html)
    for details). It is passed directly to the kernel, so all fields
    here are filesystem specific. For *tmpfs*, if no data is specified,
    we will default to *mode=0755,size=10M*. If you want other settings,
    you will need to specify them explicitly yourself.
    
    If the mount is not a pseudo filesystem (e.g. proc or sysfs), *src*
    path must be an absolute path (e.g. */dev/sda1* and not *sda1*).
    
    If the destination does not exist, it will be created as a directory
    (including missing parent directories).

  - **\-K[mode]**  
    Don't mark all existing mounts as MS\_SLAVE. This option is
    **dangerous** as it negates most of the functionality of **\-v**.
    You very likely don't need this.
    
    You may specify a mount propagation mode in which case, that will be
    used instead of the default MS\_SLAVE. See the
    [**mount**(2)](https://man7.org/linux/man-pages/man2/mount.2.html)
    man page and the kernel docs
    [*Documentation/filesystems/sharedsubtree.txt*](https://docs.kernel.org/filesystems/sharedsubtree.html)
    for more technical details, but a brief guide:
    
      - **slave** Changes in the parent mount namespace will propagate
        in, but changes in this mount namespace will not propagate back
        out. This is usually what people want to use, and is the default
        behavior if you don't specify **\-K**.
    
      - **private** No changes in either mount namespace will propagate.
        This provides the most isolation.
    
      - **shared** Changes in the parent and this mount namespace will
        freely propagate back and forth. This is not recommended.
    
      - **unbindable** Mark all mounts as unbindable.

  - **\-l**  
    Run inside a new IPC namespace. This option makes the program's
    System V IPC namespace independent.

  - **\-L**  
    Report blocked syscalls when using a seccomp filter. On kernels with
    support for SECCOMP\_RET\_LOG, every blocked syscall will be
    reported through the audit subsystem (see
    [**seccomp**(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)
    for more details on SECCOMP\_RET\_LOG availability.) On all other
    kernels, the first failing syscall will be logged to syslog. This
    latter case will also force certain syscalls to be allowed in order
    to write to syslog. Note: this option is disabled and ignored for
    release builds.

  - **\-m\[\<uid\> \<loweruid\> \<count\>\[,\<uid\> \<loweruid\> \<count\>\]\]**  
    Set the uid mapping of a user namespace (implies **\-pU**). Same
    arguments as
    [**newuidmap**(1)](https://man7.org/linux/man-pages/man1/newuidmap.1.html).
    Multiple mappings should be separated by ','. With no mapping, map
    the current uid to root inside the user namespace.

  - **\-M\[\<uid\> \<loweruid\> \<count\>\[,\<uid\> \<loweruid\> \<count\>\]\]**  
    Set the gid mapping of a user namespace (implies **\-pU**). Same
    arguments as
    [**newgidmap**(1)](https://man7.org/linux/man-pages/man1/newgidmap.1.html).
    Multiple mappings should be separated by ','. With no mapping, map
    the current gid to root inside the user namespace.

  - **\-n**  
    Set the process's *no\_new\_privs* bit. See
    [**prctl**(2)](https://man7.org/linux/man-pages/man2/prctl.2.html)
    and the kernel source file
    [*Documentation/userspace-api/no\_new\_privs.txt*](https://docs.kernel.org/userspace-api/no_new_privs.html)
    for more info.

  - **\-N**  
    Run inside a new cgroup namespace. This option runs the program with
    a cgroup view showing the program's cgroup as the root. This is only
    available on v4.6+ of the Linux kernel.

  - **\-p**  
    Run inside a new PID namespace. This option will make it impossible
    for the program to see or affect processes that are not its
    descendants. This implies **\-v** and **\-r**, since otherwise the
    process can see outside its namespace by inspecting /proc.
    
    If the *program* exits, all of its children will be killed
    immediately by the kernel. If you need to daemonize or background
    things, use the **\-i** option.
    
    See
    [**pid\_namespaces**(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
    for more info.

  - **\-P \<dir\>**  
    Set *dir* as the root fs using **pivot\_root**. Implies **\-v**, not
    compatible with **\-C**.

  - **\-r**  
    Remount /proc readonly. This implies **\-v**. Remounting /proc
    readonly means that even if the process has write access to a system
    config knob in /proc (e.g., in /sys/kernel), it cannot change the
    value.

  - **\-R \<rlim\_type\>,\<rlim\_cur\>,\<rlim\_max\>**  
    Set an rlimit value, see
    [**getrlimit**(2)](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
    for more details.
    
    *rlim\_type* may be specified using symbolic constants like
    *RLIMIT\_AS*.
    
    *rlim\_cur* and *rlim\_max* are specified either with a number
    (decimal or hex starting with *0x*), or with the string *unlimited*
    (which will translate to *RLIM\_INFINITY*).

  - **\-s**  
    Enable
    [**seccomp**(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)
    in mode 1, which restricts the child process to a very small set of
    system calls. You most likely do not want to use this with the
    seccomp filter mode (**\-S**) as they are completely different (even
    though they have similar names).

  - **\-S \<arch-specific seccomp\_filter policy file\>**  
    Enable
    [**seccomp**(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)
    in mode 13 which restricts the child process to a set of system
    calls defined in the policy file. Note that system call names may be
    different based on the runtime environment; see
    [**minijail0**(5)](./minijail0.5) for more details.

  - **\-t[size]**  
    Mounts a tmpfs filesystem on /tmp. /tmp must exist already (e.g. in
    the chroot). The filesystem has a default size of "64M", overridden
    with an optional argument. It has standard /tmp permissions (1777),
    and is mounted nodev/noexec/nosuid. Implies **\-v**.

  - **\-T \<type\>**  
    Assume binary's ELF linkage type is *type*, which must be either
    'static' or 'dynamic'. Either setting will prevent minijail0 from
    manually parsing the ELF header to determine the type. Type 'static'
    can be used to avoid preload hooking, and will force minijail0 to
    instead set everything up before the program is executed. Type
    'dynamic' will force minijail0 to preload *libminijailpreload.so* to
    setup hooks, but will fail on actually statically-linked binaries.

  - **\-u \<user|uid\>**  
    Change users to the specified *user* name, or numeric user ID *uid*.

  - **\-U**  
    Enter a new user namespace (implies **\-p**).

  - **\-v**, **\-\-ns\-mount**  
    Run inside a new VFS namespace. This option prevents mounts
    performed by the program from affecting the rest of the system (but
    see **\-K**).

  - **\-V \<file\>**  
    Enter the VFS namespace specified by *file*.

  - **\-w**  
    Create and join a new anonymous session keyring. See
    [**keyrings**(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
    for more details.

  - **\-y**  
    Keep the current user's supplementary groups.

  - **\-Y**  
    Synchronize seccomp filters across thread group.

  - **\-z**  
    Don't forward any signals to the jailed process. For example, when
    not using **\-i**, sending **SIGINT** (e.g., CTRL-C on the
    terminal), will kill the minijail0 process, not the jailed process.

  - **\-\-ambient**  
    Raise ambient capabilities to match the mask specified by **\-c**.
    Since ambient capabilities are preserved across
    [**execve**(2)](https://man7.org/linux/man-pages/man2/execve.2.html),
    this allows for process trees to have a restricted set of
    capabilities, even if they are capability-dumb binaries. See
    [**capabilities**(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).

  - **\-\-uts[=hostname]**  
    Create a new UTS/hostname namespace, and optionally set the hostname
    in the new namespace to *hostname*.

  - **\-\-env\-reset**  
    Clear the current environment instead of having the program inherit
    the active environment. This is often used to start the program with
    a minimal sanitized environment.

  - **\-\-env\-add \<NAME=value\>**  
    Adds or replace the specified environment variable *NAME* in the
    program's environment before starting it, and set it to the
    specified *value*. This option can be used several times to set any
    number of environment variables.

  - **\-\-logging=\<system\>**  
    Use *system* as the logging system. *system* must be one of **auto**
    (the default), **syslog**, or **stderr**.
    
    **auto** will use **stderr** if connected to a tty (e.g. run
    directly by a user), otherwise it will use **syslog**.

  - **\-\-profile \<profile\>**  
    Choose from one of the available sandboxing profiles, which are
    simple way to get a standardized environment. See the **SANDBOXING
    PROFILES** section below for the full list of supported values for
    *profile*.

  - **\-\-preload\-library \<file path\>**  
    Allows overriding the default path of */lib/libminijailpreload.so*.
    This is only really useful for testing. **\-\-seccomp\-bpf\-binary
    \<arch-specific BPF binary\>** This is similar to **\-S**, but
    instead of using a policy file, **\-\-secomp\-bpf\-binary** expects
    a arch-and-kernel-version-specific pre-compiled BPF binary (such as
    the ones produced by **parse\_seccomp\_policy**). Note that the
    filter might be different based on the runtime environment; see
    [**minijail0**(5)](./minijail0.5) for more details.

  - **\-\-allow\-speculative\-execution**  
    Allow speculative execution features that may cause data leaks
    across processes. This passes the
    *SECCOMP\_FILTER\_FLAG\_SPEC\_ALLOW* flag to seccomp which disables
    mitigations against certain speculative execution attacks; namely
    Branch Target Injection (spectre-v2) and Speculative Store Bypass
    (spectre-v4). These mitigations incur a runtime performance hit, so
    it is useful to be able to disable them in order to quantify their
    performance impact.
    
    **WARNING:** It is dangerous to use this option on programs that
    process untrusted input, which is normally what Minijail is used
    for. Do not enable this option unless you know what you're doing.
    
    See the kernel documentation
    [*Documentation/userspace-api/spec\_ctrl.rst*](https://docs.kernel.org/userspace-api/spec_ctrl.html)
    and
    [*Documentation/admin-guide/hw-vuln/spectre.rst*](https://docs.kernel.org/admin-guide/hw-vuln/spectre.html)
    for more information.

  - **\-\-config \<file path\>**  
    Use a Minijail configuration file to set options, through
    commandline-option-equivalent key-value pairs. See
    [**minijail0**(5)](./minijail0.5) for more details on the format of
    the configuration file.

## Sandboxing Profiles

The following sandboxing profiles are supported:

  - **minimalistic-mountns**  
    Set up a minimalistic mount namespace. Equivalent to **\-v \-P
    /var/empty** -b / -b /proc -b /dev/log -t -r --mount-dev.

  - **minimalistic-mountns-nodev**  
    Set up a minimalistic mount namespace with an empty /dev path.
    Equivalent to **\-v \-P /var/empty \-b/ \-b/proc \-t \-r**.

## Implementation

This program is broken up into two parts: **minijail0** (the frontend)
and a helper library called **libminijailpreload**. Some jailings can
only be achieved from the process to which they will actually apply:

  - capability use (without using ambient capabilities): non-ambient
    capabilities are not inherited across
    [**execve**(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
    unless the file being executed has POSIX file capabilities. Ambient
    capabilities (the **\-\-ambient** flag) fix capability inheritance
    across
    [**execve**(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
    to avoid the need for file capabilities.

  - seccomp: a meaningful seccomp filter policy should disallow
    [**execve**(2)](https://man7.org/linux/man-pages/man2/execve.2.html),
    to prevent a compromised process from executing a different binary.
    However, this would prevent the seccomp policy from being applied
    before
    [**execve**(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

To this end, **libminijailpreload** is forcibly loaded into all
dynamically-linked target programs by default; we pass the specific
restrictions in an environment variable which the preloaded library
looks for. The forcibly-loaded library then applies the restrictions to
the newly-loaded program.

This behavior can be disabled by the use of the **\-T static** flag.
There are other cases in which the use of this flag might be useful:

  - When *program* is linked against a different version of **libc.so**
    than **libminijailpreload.so**.

  - When
    [**execve**(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
    has side-effects that interact badly with the jailing process. If
    the system uses SELinux,
    [**execve**(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
    can cause an automatic domain transition, which would then require
    that the target domain allows the operations to jail *program*.

## Author

The ChromiumOS Authors \<chromiumos-dev@chromium.org\>

## Copyright

Copyright © 2011 The ChromiumOS Authors License BSD-like.

## See Also

[**libminijail.h**](https://github.com/google/minijail/blob/HEAD/libminijail.h),
[**minijail0**(5)](./minijail0.5),
[**seccomp**(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)
