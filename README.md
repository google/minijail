# Minijail

The Minijail homepage and main repo is
https://android.googlesource.com/platform/external/minijail/.

There might be other copies floating around, but this is the official one!

[TOC]

## What is it?

Minijail is a sandboxing and containment tool used in Chrome OS and Android.
It provides an executable that can be used to launch and sandbox other programs,
and a library that can be used by code to sandbox itself.

## Getting the code

You're one `git clone` away from happiness.

```
$ git clone https://android.googlesource.com/platform/external/minijail
$ cd minijail
```

Releases are tagged as `linux-vXX`:
https://android.googlesource.com/platform/external/minijail/+refs

## Building

See the [HACKING.md](./HACKING.md) document for more details.

## Release process

See the [RELEASE.md](./RELEASE.md) document for more details.

## Additional tools

See the [tools/README.md](./tools/README.md) document for more details.

## Contact

We've got a couple of contact points.

* [minijail@chromium.org]: Public user & developer mailing list.
* [minijail-users@google.com]: Internal Google user mailing list.
* [minijail-dev@google.com]: Internal Google developer mailing list.
* [crbug.com/list]: Existing bug reports & feature requests.
* [crbug.com/new]: File new bug reports & feature requests.
* [AOSP Gerrit]: Code reviews.

[minijail@chromium.org]: https://groups.google.com/a/chromium.org/forum/#!forum/minijail
[minijail-users@google.com]: https://groups.google.com/a/google.com/forum/#!forum/minijail-users
[minijail-dev@google.com]: https://groups.google.com/a/google.com/forum/#!forum/minijail-dev
[crbug.com/list]: https://crbug.com/?q=component:OS>Systems>Minijail
[crbug.com/new]: https://bugs.chromium.org/p/chromium/issues/entry?components=OS>Systems>Minijail
[AOSP Gerrit]: https://android-review.googlesource.com/q/project:platform/external/minijail

## Talks and presentations

The following talk serves as a good introduction to Minijail and how it can be used.

[Video](https://drive.google.com/file/d/0BwPS_JpKyELWZTFBcTVsa1hhYjA/preview),
[slides](https://docs.google.com/presentation/d/1r6LpvDZtYrsl7ryOV4HtpUR-phfCLRL6PA-chcL1Kno/present).

## Example usage

The Chromium OS project has a comprehensive
[sandboxing](https://chromium.googlesource.com/chromiumos/docs/+/master/sandboxing.md)
document that is largely based on Minijail.

After you play with the simple examples below, you should check that out.

### Change root to any user

```
# id
uid=0(root) gid=0(root) groups=0(root),128(pkcs11)
# minijail0 -u jorgelo -g 5000 /usr/bin/id
uid=72178(jorgelo) gid=5000(eng) groups=5000(eng)
```

### Drop root while keeping some capabilities

```
# minijail0 -u jorgelo -c 3000 -- /bin/cat /proc/self/status
Name: cat
...
CapInh: 0000000000003000
CapPrm: 0000000000003000
CapEff: 0000000000003000
CapBnd: 0000000000003000
```
