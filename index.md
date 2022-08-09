## About

Minijail is a sandboxing and containment tool used in ChromeOS and Android.
It provides an executable that can be used to launch and sandbox other programs,
and a library that can be used by code to sandbox itself.

## Sites

The Minijail homepage:<br/>
<https://google.github.io/minijail/>

The main repo:<br/>
<https://chromium.googlesource.com/chromiumos/platform/minijail/>

With a read-only mirror for people to fork:<br/>
<https://github.com/google/minijail/>

There might be other copies floating around, but those are the official ones!

## Getting the code

### Releases

Releases are tagged as `linux-vXX`:<br/>
<https://github.com/google/minijail/releases>

### Latest Development

You're one `git clone` away from happiness.

```
$ git clone https://chromium.googlesource.com/chromiumos/platform/minijail
$ cd minijail
```

## Documentation

Check out the [minijail0(1)](./minijail0.1) and [minijail0(5)](./minijail0.5)
online man pages for more details about using Minijail.

See the [tools/README.md](https://github.com/google/minijail/blob/master/tools/README.md)
document for info about extra tools we provide to help with development.

The following talk serves as a good introduction to Minijail and how it can be used.
[video](https://drive.google.com/file/d/0BwPS_JpKyELWZTFBcTVsa1hhYjA/preview)
[slides](https://docs.google.com/presentation/d/1r6LpvDZtYrsl7ryOV4HtpUR-phfCLRL6PA-chcL1Kno/present)

The Chromium OS project has a
[comprehensive sandboxing guide](https://chromium.googlesource.com/chromiumos/docs/+/master/sandboxing.md)
that is largely based on Minijail.

## Building

Just run `make` and you're good to go!

If that doesn't work out, please see the
[HACKING.md](https://github.com/google/minijail/blob/master/HACKING.md)
document for more details.

## Examples

Here's a few simple examples.
Check out the docs above for way more in-depth use.

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

## Contact

We've got a couple of contact points.

* [minijail@chromium.org](https://groups.google.com/a/chromium.org/forum/#!forum/minijail):
  Public user & developer mailing list.
* [minijail-users@google.com](https://groups.google.com/a/google.com/forum/#!forum/minijail-users):
  Internal Google user mailing list.
* [minijail-dev@google.com](https://groups.google.com/a/google.com/forum/#!forum/minijail-dev):
  Internal Google developer mailing list.
* [crbug.com/list](https://crbug.com/?q=component:OS>Systems>Minijail):
  Existing bug reports & feature requests.
* [crbug.com/new](https://bugs.chromium.org/p/chromium/issues/entry?components=OS>Systems>Minijail):
  File new bug reports & feature requests.
* [Chromium Gerrit](https://chromium-review.googlesource.com/q/project:chromiumos/platform/minijail):
  Code reviews.
