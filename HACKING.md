# Hacking on Minijail

## Source

*   Minijail uses kernel coding style:
    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/process/coding-style.rst
*   Utility functions with no side-effects should go in `util.{h|c}`.
*   Functions with side effects or with dependencies on operating system
    details, but that don't take a `struct minijail` argument, should go
    in `system.{h|c}`.

## Documentation

### Markdown

Minijail uses markdown for general/source documentation.
We follow the [Google Markdown style guide].

### Man Pages

For users of minijail (e.g. `minijail0`), we use man pages.
We don't have style guides for this currently.
Just try to follow existing practice in them.

[minijail0.1] documents the command line interface.
Please keep it in sync with [minijail0_cli.c].

[minijail0.5] documents the syntax of config files (e.g. seccomp filters).

[minijail0.1]: ./minijail0.1
[minijail0.5]: ./minijail0.5
[minijail0_cli.c]: ./minijail0_cli.c
[Google Markdown style guide]: https://github.com/google/styleguide/blob/gh-pages/docguide/style.md
