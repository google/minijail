# Minijail tools

## generate_seccomp_policy.py

This script lets you build a Minijail seccomp-bpf filter from strace output.
This is very useful if the process that is traced has a fairly tight working
domain, and it can be traced in a few scenarios that will exercise all of the
needed syscalls. In particular, you should always make sure that failure cases
are also exercised to account for calls to `abort(2)`.

If `libminijail` or `minijail0` are used with preloading (the default with
dynamically-linked executables), the first few system calls after the first call
to `execve(2)` might not be needed, since the seccomp-bpf filter is installed
after that point in a sandboxed process.

### Sample usage

```shell
strace -f -e raw=all -o strace.txt -- <program>
./tools/generate_seccomp_policy.py strace.txt > <program>.policy
```

## compile_seccomp_policy.py

An external seccomp-bpf compiler that is documented [here][1]. This uses a
slightly different syntax and generates highly-optimized BPF binaries that can
be provided to `minijail0`'s `--seccomp-bpf-binary` or `libminijail`'s
`minijail_set_secomp_filters()`. This requires the existence of an
architecture-specific `constants.json` file that contains the mapping of syscall
names to numbers, the values of any compile-time constants that could be used to
simplify the parameter declaration for filters (like `O_RDONLY` and any other
constant defined in typical headers in `/usr/include`).

Policy files can also include references to frequency files, which enable
profile-guided optimization of the generated BPF code.

The generated BPF code can be analyzed using
[libseccomp](https://github.com/seccomp/libseccomp)'s `tools/scmp_bpf_disasm`.

### Sample usage

```shell
make minijail0 constants.json

# Create the .policy file using the syntax described in the documentation.
cat > test/seccomp.policy <<EOF
read: allow
write: allow
rt_sigreturn: allow
exit: allow
EOF

# Compile the .policy file into a .bpf filter
./tools/compile_seccomp_policy.py test/seccomp.policy test/seccomp.bpf

# Load the filter to sandbox your program.
./minijail0 --seccomp-bpf-binary=test/seccomp.bpf -- <program>
```

## generate_constants_json.py

This script generates the `constants.json` file from LLVM IR assembly files.
This makes it easier to generate architecture-specific `constants.json` files at
build-time.

[1]: https://docs.google.com/document/d/e/2PACX-1vQOeYLWmJJrRWvglnMo5cynkUe0gZ9wVsndLLePkJg6dfUXSOUWoveBBeY3u5nQMlEU4dt_vRgj0ifR/pub
