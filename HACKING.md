# Hacking on Minijail

## Dependencies

You'll need these to build the source:
* [libcap]
* Linux kernel headers

You'll need to install the relevant packages from your distro.

## Building

For local experimentation (using Minijail libraries from the source directory):

```
$ make LIBDIR=/lib64
$ sudo ./minijail0.sh -u ${USER} -g 5000 -- /usr/bin/id
```

For system-wide usage, install `libminijail.so` and `libminijailpreload.so` to
`/lib64` and `minijail0` to a directory in your `PATH` (e.g. `/usr/bin`).

## Testing

We use [Google Test] (i.e. `gtest` & `gmock`) for unit tests.
You can download a suitable copy of Google Test using the
[get_googletest.sh](./get_googletest.sh) script.

```
$ ./get_googletest.sh
googletest-release-1.8.0/
...
$ make tests
```

Building the tests will automatically execute them.

## Code Review

We use [Android Review] for Minijail code review. The easiest way to submit
changes for review is using `repo upload` on a ChromiumOS or Android checkout.
Go to [Android Review HTTP Credentials] to obtain credentials to push code. For
more detailed instructions see the [Android source documentation] or the
[ChromiumOS documentation].

## Source Style

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

For users of Minijail (e.g. `minijail0`), we use man pages.
For style guides, check out the [Linux man-pages project] for general guidance.
It has a number of useful references for syntax and such.

* [man-pages(7)](http://man7.org/linux/man-pages/man7/man-pages.7.html)
* [groff-man(7)](http://man7.org/linux/man-pages/man7/groff_man.7.html)
* [groff(7)](http://man7.org/linux/man-pages/man7/groff.7.html)

[minijail0.1] documents the command line interface.
Please keep it in sync with [minijail0_cli.c].

[minijail0.5] documents the syntax of config files (e.g. seccomp filters).

[libcap]: https://git.kernel.org/pub/scm/linux/kernel/git/morgan/libcap.git/
[minijail0.1]: ./minijail0.1
[minijail0.5]: ./minijail0.5
[minijail0_cli.c]: ./minijail0_cli.c
[Android Review]: https://android-review.googlesource.com/
[Android Review HTTP Credentials]: https://android-review.googlesource.com/settings/#HTTPCredentials
[Android source documentation]: https://source.android.com/setup/start
[ChromiumOS documentation]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/developer_guide.md
[Google Markdown style guide]: https://github.com/google/styleguide/blob/gh-pages/docguide/style.md
[Google Test]: https://github.com/google/googletest
