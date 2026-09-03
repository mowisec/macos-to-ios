# machomorph

**Run Apple's own macOS command line tools on iOS.**

macOS ships a large collection of low-level diagnostic and introspection tools —
`ioreg`, `lsmp`, `heap`, `vmmap`, ... and dozens more.
Their iOS counterparts either do not exist, are stripped down,
or are simply not shipped on the device.

iOS and macOS are the same operating system underneath.
The binaries are the same architecture (arm64e), link against the same
frameworks, and call the same kernel. What actually stops a macOS binary from
launching on an iPhone is a handful of metadata fields: the Mach-O says
"I am for platform macOS", a few framework paths carry a macOS-only
`Versions/A/` component, and the code signature is not one the device will
accept.

`machomorph` rewrites exactly those fields and re-signs the result.

It also brings the libraries along. Where a binary needs something iOS does not
ship, machomorph works out its whole dependency closure, **lifts each missing
library out of the macOS dyld shared cache** — where most of them exist as no
file at all — repairs it so it actually runs standalone, and stages it beside
the binary. One command, one binary, everything it needs:

```sh
./machomorph.py /usr/bin/csrutil -o out/csrutil -p ios -v 27.0
```


That is the primary way to use it. The batch case is the same mechanism pointed
at a whole system: `rebuild_cryptex.sh` fills an **SRD cryptex** with every
portable macOS tool and every library they need. TL;DR for SRD users, point it
at the IPSW of the build on the device and enjoy the new tooling:

```sh
./scripts/rebuild_cryptex.sh --ipsw ~/Downloads/iPhone18,3_27.0_24A5424a_Restore.ipsw \
    /path/to/cryptex
```


## Requirements

Python 3.9+ and macOS, and no Python packages at all — `machomorph.py` is one
stdlib-only file.

**`machomorph.py` itself shells out to exactly two things, both from macOS:**

| tool | what for | if missing |
|---|---|---|
| `/usr/bin/codesign` | re-signing, since anything moved invalidates the signature | conversion fails (`--no-sign` skips it, leaving an invalid signature) |
| `xcrun --sdk … --show-sdk-path` | locating the SDK stubs the launch prediction reads | the prediction is skipped, with a note on stderr, and a binary that cannot launch is still ported |

Everything else the tool replaces — `lipo`, `cbv`, `install_name_tool`,
`otool`, `ldid` — is reimplemented, which is the point of the project.

**Lifting a library out of the dyld shared cache needs more**, because it is a
different job from retargeting a file:

| tool | needed by | what for |
|---|---|---|
| [`ipsw`](https://github.com/blacktop/ipsw) | lifting a library out of the cache | reading the cache: `dyld slide`, `dyld patches`, `dyld extract`. `brew install blacktop/tap/ipsw` |
| `clang` + Xcode | lifting a library out of the cache | building `native/dsc_extract` against Apple's `dsc_extractor.bundle`, once |
| `srdtool` | `scripts/rebuild_cryptex.sh`, `scripts/device_probe.sh` | installing the cryptex on a Security Research Device, and spawning on it |
| `idevicecrashreport` | reading crash reports after a probe | libimobiledevice; `brew install libimobiledevice` |

`scripts/rebuild_cryptex.sh` degrades rather than failing when `ipsw` is
absent: it skips the bundled libraries and says so. Converting a binary that
needs no library from the cache needs none of this.

## Usage

```
machomorph.py INPUT... [-o OUTPUT] -p PLATFORM -v VERSION [options]
machomorph.py --scan [DIR...] --cryptex DIR -p PLATFORM -v VERSION [options]
```

A full run looks like this:

```
$ ./machomorph.py /usr/sbin/ioreg -o ioreg_ios -p ios -v 27.0
Thinned to arm64e (74816 bytes)
Original build version:   macOS 26.6.0 (sdk 26.6.1)
Converted to:             iOS 27.0.0 (sdk 27.0.0)
  path: /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
     -> /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
  path: /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
     -> /System/Library/Frameworks/IOKit.framework/IOKit
Rewrote 2 path(s)
Signed with identity      '-' (no entitlements)
Output to                 ioreg_ios
```

In one invocation that: picked the arm64e slice out of the universal binary,
retargeted the Mach-O at iOS 27.0, fixed the arm64e pointer-authentication
`cpusubtype`, stripped the macOS-only `Versions/A/` from both framework paths,
carried over the binary's existing entitlements, and re-signed ad hoc.

Platforms: `macos ios tvos watchos bridgeos maccatalyst driverkit visionos`
(and the matching simulators).

Useful options:

* `--no-libraries` — do not bring along the libraries the target lacks. By
  default every conversion works out its dependency closure and lifts what is
  missing; see [Bundling the libraries iOS
  lacks](#bundling-the-libraries-ios-lacks) for `--lib-layout`, `--max-libs`,
  `--dry-run` and the rest.
* `--info` — dump arch, platform, linked libraries and entitlements, then exit.
* `-a, --arch ARCH` — which slice to take out of a fat binary. Defaults to
  arm64e, then arm64, then the only slice present.
* `--change OLD NEW` — rewrite one dylib install name or rpath. Repeatable, for
  the cases where a library genuinely lives somewhere else on iOS.
* `--no-auto-paths` — keep `….framework/Versions/A/…` paths as they are.
* `--license-to-operate` — add `research.com.apple.license-to-operate` to the
  entitlements before signing. Required for entitled binaries on the SRD.
* `--entitlements FILE` — sign with these entitlements instead of the ones
  already in the binary.
* `--dump-entitlements FILE` — also write out the entitlements actually used, so
  you can inspect or edit them.
* `--sign-identity ID` / `--identifier ID` — passed through to `codesign`.
  Default identity is `-` (ad hoc).
* `--no-sign` — skip signing. The output will have an invalid signature.
* `--no-cpusubtype-fix` — leave `cpusubtype` alone.
* `--dylib-index FILE` — a list of the library paths the target can actually
  load, produced by `dsc.index` from the target's dyld shared cache. With it,
  a library is resolved to wherever it really lives on the target (iOS demotes
  several public macOS frameworks to `PrivateFrameworks`, for instance), and
  anything absent there is reported before you ever copy the binary over.
  **An iOS conversion uses `data/ios27_24A5424a_index.txt` by default**, and
  says which index it is using; this flag overrides it. Without an index there
  is no way to know that iOS keeps `DiskArbitration` in `PrivateFrameworks`,
  and flattening `Versions/A` alone produces a plausible path that does not
  exist — reported as a successful rewrite, and failing on device as a missing
  library. It also blinds half the launch prediction, since a library can only
  be judged absent when there is a list to judge it against.
* `--no-dylib-index` — do not fall back to that shipped index. Paths are then
  rewritten by rule alone, and nothing can be said about what the target has.

  To build an index for another iOS build, hand `dsc.index` the IPSW and it
  runs `ipsw extract --dyld` itself (the extraction is cached under
  `/tmp/machomorph-ipsw`, so only the first call pays for it):

  ```sh
  python3 -m dsc.index iPhone18,3_26.4_23E246_Restore.ipsw -o data/ios264_23E246_index.txt
  ```

  It also accepts the directory `ipsw extract --dyld` wrote, or the cache file
  itself. `./scripts/rebuild_cryptex.sh --ipsw FILE <cryptex>` does the same thing
  for a whole build.
* `--target-symbols FILE` — what each of those libraries *exports*, produced by
  `dsc.symindex` from the same cache. The launch prediction otherwise reads the
  target's surface from the SDK's `.tbd` stubs, and the SDK ships stubs for
  `/usr/lib` and the public frameworks only — **no PrivateFrameworks**. So a
  symbol from one is reported `unknown`, which fails no binary and weakens
  nothing, and that is how a `DiskManagement` with a hard import of
  `_DAUnregisterApprovalCallback` shipped and took `csrutil` down. With the
  index the answer for `DiskArbitration` is as good as the one for `libSystem`.

  ```sh
  python3 -m dsc.symindex iPhone18,3_27.0_24A5424a_Restore.ipsw -o ios27_symbols.txt.gz
  ```

  It is not shipped in `data/` — 4.7 million symbols, 37 MB gzipped — so
  `rebuild_cryptex.sh --ipsw FILE` builds and caches it beside the dylib index,
  and a bare `machomorph.py` run says that it is working without one.
* `--weak PATH` / `--weaken-missing` — rewrite `LC_LOAD_DYLIB` to
  `LC_LOAD_WEAK_DYLIB` so a binary launches even though a library is absent.
  The load command is rewritten, never deleted: chained-fixup binds address
  their library by ordinal, so removing one silently re-points every later
  import at the wrong library.

### Examples

Three real tools, in increasing order of how much work they needed. Each one is
a step further from "retarget the header" and closer to "supply what iOS does
not have".

**1. `ioreg` — nothing to fix.** Every library it needs is already on iOS, at a
path one `Versions/A` strip away. This is the whole conversion, and it is the
run shown above:

```sh
./machomorph.py /usr/sbin/ioreg -o ioreg_ios -p ios -v 27.0
```

Most of the ported tree is this case. Look before you convert — `--info` prints
the architecture, target platform, linked libraries (flagging macOS-only paths)
and entitlements:

```sh
./machomorph.py --info /usr/sbin/ioreg
```

**2. `vmmap` — needs a library iOS does not have, so lift it out of the cache.**
`--info` shows the problem on the first line of its library list:

```
    [dylib] /usr/lib/libxcselect.dylib
    [dylib] .../CoreSymbolication.framework/Versions/A/CoreSymbolication <- macOS-only path
```

`libxcselect` is the "where is the active Xcode" resolver. iOS has no such
thing and ships no such library, and 106 macOS tools link it. It exists on disk
nowhere — Xcode ships only a `.tbd` text stub, which carries no code — so the
macOS shared cache is the only copy there is. Nothing has to be said about
that: converting `vmmap` lifts it.

```sh
./machomorph.py /usr/bin/vmmap -o out/vmmap -p ios -v 26.0
```

The real library works unmodified on iOS: it looks for a developer directory,
does not find one, and returns false, which is the "carry on without Xcode"
path every caller already takes. This is what makes `vmmap`, `heap`, `leaks`,
`atos` and four more run on device.

**3. `tcpdump` — needs several libraries, transitively.** It wants
`libcrypto.46.dylib` and `libssl.48.dylib`, which iOS genuinely lacks, and
`libcrypto` in turn wants `TrustEvaluationAgent`. The closure is recursive and
so is the pass:

```sh
./machomorph.py /usr/sbin/tcpdump /usr/bin/openssl -p ios -v 26.0 \
    --cryptex /path/to/cryptex --cryptex-libdir lib --loader-path
```

Each one is *lifted*, not extracted, and that is the difference that matters. A
raw cache extraction's code still reaches a cache-wide GOT that will not exist
in the process — enough for `tcpdump` to capture and dissect traffic, and not
enough for `tcpdump --version`, which reads a string out of a global. What a
lift repairs is
[below](#lifting-a-library-out-of-the-dyld-shared-cache).

`--dry-run` prints the closure and stops, which is how you find out what a tool
would cost before committing to it — `curl` needs 0.7 MB, `system_profiler`
needs 58.8 MB of AppKit (and is refused by `--max-libs`), and `csrutil` needs
five libraries that as lifted would each reserve 1.3–2.0 GB of contiguous
address space, which is what compaction exists for.

**Other things you may need.** Rewrite a library that really does live
elsewhere on iOS:

```sh
./machomorph.py mytool -o mytool_ios -p ios -v 27.0 \
    --change /usr/lib/libfoo.dylib /usr/lib/system/libfoo.dylib
```

Convert an entitled tool, keeping its entitlements and adding the research one
(required for entitled binaries on the SRD, and added automatically whenever
the binary already carries entitlements):

```sh
./machomorph.py /usr/bin/vmmap -o vmmap_ios -p ios -v 27.0 \
    --license-to-operate --dump-entitlements ents_vmmap.xml
```

Go the other way, running an iOS-only binary on macOS:

```sh
./machomorph.py lsdiagnose -o lsdiagnose_mac -p macos -v 15.0
```

## The one command

To find every portable tool and library on this Mac, convert them, and add them
to a cryptex:

```sh
./scripts/rebuild_cryptex.sh --ipsw ~/Downloads/iPhone18,3_27.0_24A5424a_Restore.ipsw \
    /path/to/cryptex
srdtool cryptex install /path/to/cryptex
```

**`--ipsw` is part of the shortest working command, not a refinement.** It
names the iOS build actually on the device, and everything that decides what
can be ported is read out of that build's own shared cache: which libraries the
target has (the dylib index) and what each of them exports (the symbol index).
Without it the build falls back to the index shipped in `data/`, which is one
particular build, and to the SDK's `.tbd` stubs, which describe **no
PrivateFramework** — so a symbol from one comes back `unknown`, which fails no
binary and weakens nothing. That is exactly how a `DiskManagement` with a hard
import of `_DAUnregisterApprovalCallback` shipped and took `csrutil` down. The
extraction and both indexes are cached under `/tmp/machomorph-ipsw`, so only
the first build on a given IPSW pays for them.

That single command does the lot:

1. Removes only what a previous run of *this* tool put there. Anything else in
   the cryptex — binaries someone built natively for iOS — is left untouched,
   tracked through a `.machomorph-manifest` and enforced by `--no-clobber`.
2. Scans the macOS system directories **and** the Xcode toolchain, skipping
   the 95 xcrun shims, the binaries a device probe measured dying on a missing
   symbol, and everything the Xcode blocklist calls a compiler rather than an
   inspector. All three are machomorph's own defaults for a scan, not
   arguments this script passes. Symlink and hard-link aliases are reproduced
   as links.
   Every library iOS lacks is lifted out of the shared cache and staged as
   part of this step, because the binaries that need it say so — there is no
   list of libraries in the script.
3. Stages the toolchain's own `@rpath` dylibs (`libcodedirectory`, `libLTO`).
4. Copies the data trees no load command mentions: the perl module trees (core
   **and** Extras, retargeting every XS `.bundle`) and zsh's modules. zsh also
   needs its `functions` tree and a shipped `.zshenv`, because its
   `module_path` and `fpath` defaults are absolute macOS paths compiled into
   the binary — see "Running the ported tools on the device".
5. Stages a trust store, since iOS has no `/etc/ssl` at all.
6. Runs `cryptex.verify` and **exits non-zero if it fails**. An install cycle
   costs minutes and a reboot, and most of the mistakes this project has
   actually made are visible in the staged tree first.

Roughly 470 binaries plus 50 aliases, ~400 MB. The first run pays for the
lifts; they are cached in `lifted/` and re-made only when the lifting code is
newer, so a second run is minutes.

## Converting a whole system into a cryptex

Give it several inputs, or `--scan` to walk the system directories
(`/usr/bin /usr/sbin /bin /sbin` by default; pass your own, add
`--scan-recursive` to descend). `--cryptex DIR` stages the results into a
cryptex tree — binaries into `DIR/bin`, bundled libraries into `DIR/usr/lib` —
which is what `srdtool cryptex install` wants:

```sh
./machomorph.py --scan -p ios -v 26.0 --cryptex ~/srd/combined \
    --weaken-missing --keep-going
```

**A scan applies three things by default**, because they are what makes the
result usable rather than a matter of taste:

* the Xcode toolchain is scanned too — `/usr/bin/otool`, `nm`, `lipo` and
  `strip` are one hard-linked xcrun stub, not tools, so a sweep that takes them
  and leaves the real llvm binaries behind has picked the wrong half;
* `data/exclude_xcrun_shims.txt` drops those 95 stubs, by path;
* `data/blocklist_symbols.txt` drops the binaries a device probe measured dying
  at launch on a symbol iOS does not export.

`--no-scan-xcode` and `--no-exclude-defaults` turn them off, `--exclude-from`
adds more lists, and each is announced on the way past. **The lists apply only
to what a scan finds** — a path named on the command line is always converted,
since silently dropping a binary someone asked for by name would be
indefensible.

That converts every executable Mach-O it finds (572, on a current macOS) and
ends with a summary of what will not load anyway, ranked by how many binaries
each absent library blocks — the list worth working down, because one
replacement can unblock a whole group:

```
===== 733 binaries: 674 ready, 59 with libraries missing on the target, 0 failed

missing libraries, most-blocking first:
    12  /System/Library/PrivateFrameworks/…/OpenDirectory
          dscacheutil, dsconfigad, id, groups, …
```

The bin and lib directories are configurable with `--cryptex-bindir` and
`--cryptex-libdir`. `--keep-going` stops one bad binary from ending the batch.

## Taking the real tools out of Xcode

On macOS, `/usr/bin/otool`, `nm`, `lipo` and `strip` are not tools — they are
the same 118640-byte stub, which looks up Xcode's copy of itself and `exec`s it.
The real binaries live in the toolchain, and they port to iOS cleanly: 105 of
the 108 executables in `XcodeDefault.xctoolchain/usr/bin` resolve every
dependency against the iOS cache.

Any `--scan` takes them, skipping the ones that exist to *build* code rather
than inspect it:

```sh
./machomorph.py --scan -p ios -v 26.0 --cryptex ~/srd/combined \
    --weaken-missing --keep-going
```

`--no-scan-xcode` leaves the toolchain out; `--scan-xcode` on its own scans the
toolchain and nothing else. `--list-skipped` shows what a run would take and
what it would drop before you commit to it; `--exclude GLOB` drops more;
`--no-xcode-blocklist` takes everything, including `clang` (141 MB) and
`swift-frontend` (171 MB).

The blocklist is by *purpose*, not by name prefix — worth knowing if you edit
it, because the tools you want are themselves llvm binaries: `otool` **is**
`llvm-otool`, `nm` **is** `llvm-nm`, `objdump` **is** `llvm-objdump`. What
survives is the inspection set: the Mach-O dumpers and editors, `strings`, the
symbol and demangling tools (`nm`, `c++filt`, `swift-demangle`), `dyld_info`,
the DWARF tools, and `lipo`/`size`.

Two toolchain dylibs have to come along, `libcodedirectory.dylib` and
`libLTO.dylib` (which carries LLVM's disassembler — `dyld_info` calls into it).
Their rpath is `@executable_path/../lib/`, so they need no rewriting, just
staging in the right place:

```sh
./machomorph.py <toolchain>/usr/lib/lib{codedirectory,LTO}.dylib \
    -p ios -v 26.0 --cryptex ~/srd/combined --cryptex-bindir lib \
    --dylib-index ios27_index.txt
```

machomorph resolves `@rpath/...` against the binary's own `LC_RPATH` entries and
the staging directory, so once they are in place it stops reporting them as
missing.

## Bundling the libraries iOS lacks

This happens on its own, and it is most of what the tool does. For every binary
it converts, machomorph walks the dependency closure, asks the target's dylib
index which of those libraries the target actually has, and for each one it does
not:

1. gets a local copy — from `--prebuilt`, from the macOS filesystem if the
   library is a real file, or by **lifting it out of the shared cache**, which
   is the only copy of most of them;
2. compacts it, so it reserves its own size rather than the 1.3–2.0 GB of
   contiguous address space the cache's layout implies;
3. stages it into the output, rewriting its `LC_ID_DYLIB` and every reference
   *between* bundled libraries;
4. repoints the binary at it with a `@loader_path`-relative name, and weakens
   the reference so the binary still launches if the library somehow fails.

Where the libraries land is the output directory, mirroring the target's own
spelling of each path, so the result reads as a small root filesystem.

`--lib-layout flat` puts them all beside the binary instead (shorter per
reference, which matters — the load-command area is fixed, and `tcpdump` has
16 bytes of slack for its two), `--lib-subdir lib` puts them in one
subdirectory, and `--libs-into DIR` moves the whole tree elsewhere.
`--cryptex` is always flat, into `--cryptex-libdir`.

Two things it refuses to guess at:

* **`--max-libs N`** (default 7). It gates what to *lift*, not what a binary is
  allowed to see: a binary is always repointed at every library that ended up
  staged, whoever's closure paid for it. A larger closure means the binary is
  dragging in a whole macOS subsystem that cannot work on iOS anyway — `system_profiler`
  wants AppKit, SkyLight, HIToolbox and OpenGL, which is the macOS window
  server; it would load and have nothing to talk to. Such a binary is still
  converted, and simply reports its libraries as missing. `--dry-run` prints
  each closure with its size and address-space cost and stops.
* **`--weaken-unresolvable`**. A bundled library that imports a symbol the
  target does not export cannot load, and there is nothing to fix — iOS has no
  equivalent of Authorization Services or the `SecTransform` pipeline at all.
  The choice is between not shipping the library and binding those symbols
  NULL, so that it loads and only a path that reaches one of them crashes. That
  is a judgement about what the tool needs, so it is opt-in, and every symbol
  it weakens is named in the output. It applies to **bundled libraries only**:
  for one of the binaries being converted the same trade turns a clean skip into
  a crash later, and `--force` is how you ask for that instead.

`--no-libraries` turns the whole pass off. `--also PATH` bundles a library even
though the target has one of the same name, for when the target's build has a
smaller export surface.

`--provide-lib OLDPATH FILE` is still there for a library you built yourself:
it copies `FILE` into the cryptex library directory, repoints every reference to
`OLDPATH` at it, and machomorph then checks the substitution actually holds up: it reads which
symbols the binary imports from `OLDPATH` (out of the two-level-namespace
library ordinal in the symbol table) and which the replacement exports (out of
its `LC_DYLD_EXPORTS_TRIE`), and warns about the gap — a symbol that is imported
but not exported means the binary loads and then crashes if it calls it. On a
batch it also summarises who needs what:

```
symbols used from /usr/lib/libxcselect.dylib:
    94  _xcselect_invoke_xcrun
          DeRez, GetFileInfo, ResMerger, Rez, SetFile, SplitForks, +88 more
     9  _xcselect_get_developer_dir_path
          atos, filtercalltree, heap, kmutil, leaks, malloc_history, +3 more
```

which is usually the fastest way to see which binaries a replacement genuinely
serves.

If an input is a symlink to another input, it is reproduced as a relative
symlink rather than converted twice — `otool -> llvm-otool` stays a link, and
`clang++` keeps the `argv[0]` that tells it to be a C++ driver.

The rewritten reference is `@executable_path`-relative, never absolute: the
cryptex mount point on the device carries a per-install random suffix, so an
absolute path would break on the next install. machomorph derives that name
from the cryptex layout and warns if the dylib's own `LC_ID_DYLIB` disagrees.

A library can only reach the device *inside* the cryptex — the trust cache is
keyed by cdhash and built at install time from the staged directory, so copying
a dylib over with `scp` does not work. Adding one means reinstalling the cryptex.

### `libxcselect`: the real library, lifted from the cache

`/usr/lib/libxcselect.dylib` resolves "where is the active Xcode install". It is
the single most common missing library for ported macOS tools, and iOS has
neither the library nor the concept — nor does it exist as a file anywhere:
`Xcode.app` and the Command Line Tools ship only a `.tbd` text stub, which
carries no code. The shared cache is the only copy.

Converting any of the nine tools that need it
[lifts it out of there](#lifting-a-library-out-of-the-dyld-shared-cache), which
was impossible until the cache-uniqued GOT repair existed. To lift it on its
own, name it as the input:

```sh
./machomorph.py /usr/lib/libxcselect.dylib -o lifted/libxcselect.dylib \
    -p ios -v 26.0 --change /usr/lib/libxcselect.dylib \
                            @loader_path/../lib/libxcselect.dylib
```

The reason a macOS library helps at all on iOS is that its answer there is the
honest one. `xcselect_get_developer_dir_path` looks for `DEVELOPER_DIR`, then
the `/var/select/developer_dir`, `/var/db/xcode_select_link` and
`/usr/share/xcode-select/*` symlinks; on iOS there are none, so it returns
false, and every caller guards on exactly that:

```
bl _xcselect_get_developer_dir_path
cbz w0, <skip the respawn into Xcode's copy of this tool>
```

so the tools carry on and do their own work, with no environment variable
needed. `DEVELOPER_DIR` is honoured if you set one.

Lifting the real library is confirmed on the SRD — `vmmap` and `heap` both run
against it. That mattered to check, because the real library imports 63
libSystem symbols and a single unresolvable one would stop it loading, taking
all nine tools with it. Every one of them exists on iOS.

## Running the ported tools on the device

The cryptex is mounted at a path with a per-install random suffix, but the shell
on the device already has it in the environment:

```sh
echo $CRYPTEX_MOUNT_PATH
# /private/var/run/com.apple.security.cryptexd/mnt/com.research.base-cryptex.ZcDlFS
```

Its `bin`, `sbin` and `usr/bin` are already on `PATH`, so `otool`, `nm` and the
rest just work. Some tools need an environment variable first, because they look
for their own data at macOS paths that do not exist on iOS and are **compiled
into the binary** — C strings in `__TEXT`, not load commands, so machomorph
never sees them, and they could not be patched anyway because the mount point is
different every install.

Everything in one block, if you just want the tools to work:

```sh
export SSL_CERT_FILE=$CRYPTEX_MOUNT_PATH/share/ssl/cert.pem
export CURL_CA_BUNDLE=$SSL_CERT_FILE
export OPENSSL_CONF=$CRYPTEX_MOUNT_PATH/share/ssl/openssl.cnf
export PERL5LIB=$CRYPTEX_MOUNT_PATH/share/perl5:$CRYPTEX_MOUNT_PATH/share/perl5-extras
export RUBYLIB=$CRYPTEX_MOUNT_PATH/share/ruby:$CRYPTEX_MOUNT_PATH/share/ruby/universal-darwin25
export SDKROOT=/
export ZDOTDIR=$CRYPTEX_MOUNT_PATH/share/zsh/zdotdir
```

The cryptex ships `etc/profile` and `etc/zshenv` containing exactly that,
derived from `$CRYPTEX_MOUNT_PATH` at runtime — so rather than typing the block,
copy them to the device **once**:

```sh
ssh -p 2222 root@localhost 'cat > ~/.zshenv'  < <cryptex>/etc/zshenv
ssh -p 2222 root@localhost 'cat > ~/.profile' < <cryptex>/etc/profile
```

Once per *device*, not per install: both locate the cryptex through
`$CRYPTEX_MOUNT_PATH`, which `cryptex-run` exports, so they survive every later
reinstall. `rebuild_cryptex.sh` prints these two lines beside the
`srdtool cryptex install` line.

They have to be copied because the cryptex is **not** path-overlaid onto `/`:
measured, `<cryptex>/etc/profile` is present while `/etc/profile` is absent (and
so is `/bin/bash`, though the cryptex ships `bin/bash`), while `/etc/hosts` —
iOS's own — is there. `/private/preboot/Cryptexes/OS` is a *dyld* search prefix
for dylibs, not a filesystem overlay, and holds only `System` and `usr`.
`/private/etc` is read-only, so nothing can be dropped there either.

Two files rather than one, because the choice is not arbitrary: zsh never reads
`/etc/profile` (that is sh and bash), and `/etc/zshenv` is the right zsh hook
rather than `/etc/zshrc` because it is read on **every** invocation including
`zsh -c` — the failing case is non-interactive — and because it is read before
`~/.zshenv`, which matters since `ZDOTDIR` must be set before zsh looks for
`$ZDOTDIR/.zshenv`. `/etc/zprofile` and `/etc/zshrc` are deliberately not
shipped: they are read *after* `$ZDOTDIR/.zshenv` has reassigned
`ZDOTDIR=$HOME`, so setting it again there would send zsh looking for your own
`.zprofile` and `.zshrc` inside the cryptex.

`$HOME` (`/var/root`) is writable and the login shell reads `~/.profile`, so
that block in `~/.profile` makes it permanent for interactive sessions —
verified on device, after which a bare `curl https://apple.com` works. Note it
applies to **login** shells only, so `ssh <device> 'curl ...'` still gets
nothing: that is a non-interactive shell, which reads neither `~/.profile` nor
`~/.bashrc`. Export them in the command for scripted use.

There is no way to avoid the variables entirely. `/private/etc` is read-only, so
the files cannot be put where the tools already look, and the mount point's
random suffix means no absolute path can be compiled in.

| tool | needs | without it |
|---|---|---|
| `curl` | `CURL_CA_BUNDLE` | `curl: (77) error setting certificate verify locations: CAfile: /etc/ssl/cert.pem` |
| `openssl` | `SSL_CERT_FILE`, `OPENSSL_CONF` | handshake completes, chain verification fails |
| `perl` | `PERL5LIB` | `Can't locate POSIX.pm in @INC` |
| `ruby` | `RUBYLIB`, `SDKROOT` | `cannot load such file -- rubygems.rb` |
| `zsh` | `ZDOTDIR` | `failed to load module 'zsh/zle'`, no line editing |
| `expect` | nothing | — Tcl finds `lib/tcl8.5` relative to the interpreter by itself |

**curl and openssl** — iOS has no `/etc/ssl` at all. macOS's curated bundle is
staged at `share/ssl/cert.pem`. Note the two fail differently, and curl's is the
more confusing: openssl completes a TLS handshake and then reports `unable to
get local issuer certificate`, while curl refuses up front with error 77, which
reads like a broken build and is a missing file. `SSL_CERT_FILE` is not enough
for `openssl s_client`, which does not call `SSL_CTX_set_default_verify_paths`
unless given `-CAfile` — pass it explicitly there. `curl` honours
`CURL_CA_BUNDLE` on its own.

Ruby's `Net::HTTP` is a third case: it consults neither, so pass `ca_file`:

```sh
ruby -e 'require "net/https"; u=URI("https://apple.com/")
  h=Net::HTTP.new(u.host,443); h.use_ssl=true; h.ca_file=ENV["SSL_CERT_FILE"]
  puts h.get("/").code'                                          # 200
```

**perl** — the interpreter runs unaided, but `@INC` still points at
`/System/Library/Perl`, so anything that loads a module fails:

```sh
perl -e 'print "hi\n"'                 # works: no modules involved
perl -MPOSIX -e 'print POSIX::floor(3.7)'
#   Can't locate POSIX.pm in @INC (@INC contains: /Library/Perl/5.34/... )

export PERL5LIB=$CRYPTEX_MOUNT_PATH/share/perl5
$CRYPTEX_MOUNT_PATH/bin/perl -MPOSIX -e \
    'printf("uname=%s release=%s\n", (POSIX::uname())[0], (POSIX::uname())[2])'
#   uname=Darwin release=27.0.0
```

That also exercises the 51 XS `.bundle` modules, which are converted like any
other Mach-O.

**ruby** — the interpreter and its lifted `libruby` were always sound, but
nothing was staged for it, and `ruby -v` works without any of it, which is how
this went unnoticed for a while. `ruby -e 'puts 1'` needs three things:

```sh
export RUBYLIB=$CRYPTEX_MOUNT_PATH/share/ruby:$CRYPTEX_MOUNT_PATH/share/ruby/universal-darwin25
export SDKROOT=/
ruby -e 'require "digest"; puts Digest::MD5.hexdigest("abc")'
#   900150983cd24fb0d6963f7d28e17f72
```

`RUBYLIB` must name **both** directories: `rbconfig.rb` lives in the arch
subdir, and naming only the top gives `cannot load such file -- rbconfig`. And
`SDKROOT` must be set to *something*, because Apple's `rbconfig.rb` computes
`CONFIG["includedir"]` by backticking `xcode-select --print-path && xcrun
--show-sdk-path` at require time, and **iOS has no `/bin/sh`**, so the require
dies with `Errno::ENOENT`. The line short-circuits on `ENV['SDKROOT']`, so no
patch to Apple's file is needed.

All 96 native `.bundle` extensions are converted and load, which is not
optional: `rubygems/specification.rb` requires `stringio`, so without them even
`ruby -e 'puts 1'` fails. Only `--disable-gems` avoids it.

**zsh** — the shell runs, but three of its search paths are absolute macOS
paths *compiled into the binary*, so machomorph never sees them (they are C
strings in `__TEXT`, not load commands) and they cannot be patched either, since
the mount point is different every install:

```
/usr/lib/zsh/5.9              module_path   -> failed to load module 'zsh/zle'
/usr/share/zsh/5.9/functions  fpath         -> compinit and autoloads fail
/usr/share/zsh/site-functions fpath
```

The cryptex ships both trees plus a startup file that corrects the two
parameters at runtime, so one export is enough:

```sh
export ZDOTDIR=$CRYPTEX_MOUNT_PATH/share/zsh/zdotdir
zsh -c 'zmodload zsh/zle && echo ok'
```

`$ZDOTDIR/.zshenv` is read on every invocation, before any module is wanted. It
sets `module_path` and `fpath` from `$CRYPTEX_MOUNT_PATH` and then reassigns
`ZDOTDIR=$HOME`, so shipping it does not hide your own `.zshrc`.

Two things worth knowing if you do it by hand instead. These are zsh
*parameters*, not environment variables — exporting `MODULE_PATH` has no effect,
because `module_path` is not one of the arrays tied to one (`path`/`PATH` is).
And without the modules you lose interactive line editing — arrow keys,
completion, history — while scripting is unaffected:

```sh
zsh -c "module_path=($CRYPTEX_MOUNT_PATH/share/zsh/5.9); zmodload zsh/zle"
```

## What has been tested on device

SRD iPhone18,3, iOS 27.0 `24A5424a`. Everything below was launched and observed
working, not merely converted. Raw probe data in `measurements/`.

| | result |
|---|---|
| **Xcode reverse-engineering tools** | run: `otool -L`, `nm -mu`, `objdump`, `strings`, `lipo -info`, `size`, `strip`, `vtool -show-build`, `segedit`, `nmedit`, `install_name_tool`, `bitcode_strip`, `ctf_insert`, `codesign_allocate`, `dyld_info -platform`, `dyld_analyzer`, `dwarfdump`, `dsymutil`, `unwinddump`, `c++filt`, `swift-demangle`, `readtapi`, and their `llvm-*` originals |
| **memory and symbolication** (8) | all run: `atos`, `symbols`, `vmmap`, `heap`, `leaks`, `malloc_history`, `stringdups`, `filtercalltree`. `vmmap $$` gives real output against a live process |
| **zsh** | 5.9, all 37 modules load — needs `ZDOTDIR` (or `module_path=(...)`, **not** `MODULE_PATH`). `ztcp` opens a real socket and reads dropbear's SSH banner |
| **ruby** | 2.6.10, all 96 native extensions load — `socket`, `openssl`, `zlib`, `fiddle`, `ripper`; `net/https` to apple.com returns 200 |
| **expect** | 5.45, drives `openssl`'s interactive REPL over a pty |
| **perl** | 5.34, including XS modules from both the core and Extras trees (`Digest::MD5`, `JSON::PP`) with `PERL5LIB` set |
| **openssl** | LibreSSL 3.3.6; SHA-256, RSA and EC sign/verify, AES, TLSv1.3 to apple.com with `Verify return code: 0 (ok)` |
| **curl** | `https://www.apple.com/` → **200**, 254 KB, `ssl_verify_result 0` |
| **tcpdump** | captures and fully decodes; `--version` works |
| **dtrace** | **`-l` no longer crashes.** It reaches its own initialisation and reports `DTrace device not available on system` — the iOS kernel has no DTrace, which is as far as this tool can go |
| **bash** | the ported macOS bash runs, forks, and serves as dropbear's login shell |

### The whole-tree sweep

Every entry in the cryptex's `bin/` launched under a timeout and classified.

| outcome | first sweep (2026-08-30) | final |
|---|---|---|
| loads and runs | 379 | **399** |
| **fails: library missing** | **243** | **0** |
| fails: symbol missing | 70 | 39 |
| SIGKILLed | 83 | **0** |
| crash | — | 1 |
| blocked (daemon/interactive) | 64 | 16 |
| not run (denylisted) | 124 | 64 |

**Nothing fails on a library any more.** The remaining 39 are iOS genuinely not
exporting a symbol — confirmed from the crash reports, where
`termination.namespace` is `DYLD` and `indicator` is `Symbol missing` — led by
`_syslog$DARWIN_EXTSN` (7; see `next-session.md`). The single crash is `sntpd`'s
own `__assert_rtn`.

And the check that matters after all the shared-cache work: of the 40 crash
reports the final sweep produced, **none is `EXC_ARM_PAC_FAIL`**. Every lifted
library survives every path the sweep reaches.

### Four facts worth recording, because all were open questions

* **arm64 binaries run fine from a cryptex on an arm64e device.** The Xcode
  toolchain ships arm64 only, and everything else here is arm64e.
* **A locally built, non-platform arm64e dylib loads**, as long as it is inside
  the cryptex and so covered by its trust cache.
* **iOS ships no shell and no coreutils.** The whole of `/bin`, `/sbin`,
  `/usr/bin` and `/usr/sbin` on the device is daemons plus a handful of
  diagnostics (`data/ios_native_commands.txt`) — no `sh`, `ls`, `cat` or
  `sleep`. Everything a script uses has to come out of the cryptex.
* **A lifted library reserves 1–2 GB of address space**, because it keeps the
  cache's segment addresses (an ADRP immediate is a fixed PC-relative distance,
  so nothing can move). dyld reserves the whole span, and what runs out is the
  largest *contiguous* hole rather than a total: measured with perl's
  `DynaLoader`, 1972 MB then 1659 MB then 881 MB all load, while 1765–1887 MB
  do not once 1972 MB is taken. **Two or three lifted libraries per process.**
  That is why `systemstats`, which needs six, is blocklisted — though its real
  blocker is simpler: `CoreDisplay` and `IOPresentment` need symbols iOS does
  not export at all.

## Two things that break a library taken out of the shared cache

Both were found by `dlopen`-ing the staged libraries on the device and reading
the error, and both are now handled automatically.

**`incompatible platforms: iOS - macCatalyst`.** A macCatalyst-capable library
carries *two* `LC_BUILD_VERSION` load commands. Retargeting only the first
leaves the macCatalyst one behind and dyld rejects the image outright.
machomorph now drops the extras — nothing addresses `LC_BUILD_VERSION` by
ordinal, so removing them is safe.

**`__DATA_CONST segment missing SG_READ_ONLY flag`.** Images inside a dyld
shared cache do not carry `SG_READ_ONLY` on `__DATA_CONST`, because the cache
guarantees that protection itself. Pull one out with `ipsw dyld extract` and it
cannot be loaded as a standalone file until the flag is restored. machomorph now
restores it, on `__AUTH_CONST` too — a segment that only exists in cache images.

Neither is visible in `otool -L` output, and a weak reference hides both: dyld
skips the library silently and the process dies later with a confusing
`Symbol not found ... Expected in: <no uuid> unknown`. If you see that, the
library did not load, and `dlopen`-ing it directly is the fastest way to find
out why.

## Lifting a library out of the dyld shared cache

A library that exists only inside the cache is not a file, and what
`ipsw dyld extract` or Apple's `dsc_extractor.bundle` hand back is not a
loadable dylib either. machomorph repairs both reasons automatically — you only
need to notice it happening in the output:

    Relaid out 6 segments for a standalone image, rebuilt 93 exports

**The segments are unmappable.** They keep the addresses they had in the cache,
which are neither ascending nor page aligned — images share pages, so each
segment begins wherever it happens to:

| segment | vmaddr | offset within a 16K page |
|---|---|---|
| `__TEXT` | `0x19ce1e000` | `0x2000` |
| `__DATA_CONST` | `0x1e712a5a8` | `0x25a8` |
| `__AUTH_CONST` | `0x1f0987358` | `0x3358` |
| `__AUTH` | `0x1eddd38f8` | `0x38f8` |

dyld walks you through this one error at a time: `segment '__AUTH' vm address
out of order`, then `file offset out of order` once they are sorted, then a bare
`mmap … errno=22` once both orderings are fixed.

The repair moves **nothing**. Addresses are baked into the image in places no
rewrite could reach — every ADRP/ADD pair in the code is a PC-relative distance
to data — so instead each segment is grown *backwards* to the page boundary
below it and the gap zero-filled. Every address stays exactly where it was. A
uniform shift first makes `__TEXT` page aligned, which keeps the mach header at
file offset 0; the symbol table's absolute addresses follow that shift.

**The export trie is empty.** A cache holds export information centrally, so a
per-image `LC_DYLD_EXPORTS_TRIE` is present but zero-sized: the library loads
and exports nothing, and every import against it fails. The symbol table
survives extraction intact, so machomorph rebuilds the trie from it — as a radix
tree, which matters, because a flat one-child-per-symbol trie silently breaks
whenever one name is a prefix of another (`_foo` and `_foobar`).

**iOS checks `__LINKEDIT` alignment; macOS does not.** Its sub-tables must be
8-byte aligned, and a page-aligned relocation shifts them by whatever the
original offset happened to be — `mis-aligned LINKEDIT content 'symbol table'`.
machomorph pads *inside* the segment so the shift is a multiple of 16, which
preserves the original alignment, and 8-aligns the trie it appends. Worth
knowing because a library that loads perfectly on the Mac can still be rejected
on device for this alone.

**How far a raw extraction gets you.** `tcpdump` works properly — `tcpdump -i
lo0` captures and fully decodes traffic (TCP/IP dissection, port names, TCP
options, timestamps), and `tcpdump -D` lists interfaces. `dtrace` prints its
usage and real runtime output, then crashes on `-l` and `-n`. `curl` and
`openssl` crashed on every path tried. The difference is which code paths a
tool takes, for the reason below — and the reason a plain extraction is never
what you want to ship.

**The remaining limit, and how it was removed.** A cache-extracted library maps
and resolves symbols, and then crashes when a particular path dereferences an
unrebased pointer (`KERN_INVALID_ADDRESS at 0x7098993000100020` — a raw
chained-pointer bit pattern, not an address). Extracted images carry **no**
`LC_DYLD_CHAINED_FIXUPS`, because a shared cache does relocation centrally.

That is only half of it, and the other half is the half that matters: **the
cache builder uniques GOT entries cache-wide.** An image keeps its own `__got` /
`__auth_got` sections, but the builder zeroes them, clears their section type,
and rewrites the image's code to reach a shared GOT region that belongs to no
image at all. Extract the image and its every stub points outside its own
segments. That is a *code* problem, not just a metadata one, which is why no
extractor fixes it — Apple's and `ipsw`'s both reproduce the rewritten code
verbatim.

Everything needed to undo it survives, though. The indirect symbol table is
intact, `stub[i]` and `__auth_got[i]` name the same symbol, and the dead GOT
sections are exactly the right size. Only two things have to come from the
cache: which words in the image's data are pointers (its slide info) and which
symbol each cache-wide GOT slot held (its patch table). So:

An input that is not a file anywhere is a lift, not an error:

```sh
./machomorph.py /usr/lib/libxcselect.dylib -o out/libxcselect.dylib \
    -p ios -v 26.0 \
    --change /usr/lib/libxcselect.dylib \
             @loader_path/../lib/libxcselect.dylib
```

extracts, collects the facts, retargets, repoints every stub at the image's own
GOT, synthesises `LC_DYLD_CHAINED_FIXUPS`, repairs the ObjC metadata, refuses to
hand back anything still reaching the cache, and compacts the result.
`libxcselect` (58 stubs, 86 fixups) and `libdtrace` (2259 fixups) both run
afterwards. It is the same pipeline the closure pass uses, so there is one
implementation of it.

Seven stages, each its own module in `dsc/` with its own CLI — because when a
lift comes out wrong, the way to find out why is to run one stage by hand on the
intermediate:

| script | job |
|---|---|
| `dsc.gotscan` | diagnosis only — reports the damage and whether it is repairable |
| `dsc.facts` | pulls the slide-info and GOT-symbol facts out of the cache |
| `dsc.rebind` | repoints the code and synthesises the fixups |
| `dsc.objc` | rebases the ObjC selector, protocol and class references |
| `dsc.compact` | packs the segments, closing the 1.3–2.0 GB address-space hole |

That repair is what `curl` and `openssl` needed. Both were briefly rescued by
cross-compiling LibreSSL and curl for iOS instead; that route is gone.
**Everything this project ships is now the Apple binary, rewritten** — no
libraries compiled from source, no hand-written stubs. Lifting is strictly more
general: it works for `libdtrace` and `libxcselect`, which have no upstream to
build from and exist as a file nowhere, and it gives Apple's actual
implementation rather than a look-alike.

`--dry-run` applies it to a whole dependency closure and stops:

```sh
./machomorph.py /usr/bin/curl -o out/curl -p ios -v 26.0 --dry-run
```

Two ceilings it reports before you commit to anything. A lift only works if the
lifted library's *own* imports all exist on iOS — `CoreDisplay` needs
`_DSBrightnessExternalConvertLinearToUser`, which iOS does not export, so
`systemstats` can never work. And an *uncompacted* lift keeps the cache's
segment addresses, so dyld reserves its whole 1.3–2.0 GB span at load and what
runs out is the largest contiguous hole — two or three per process, never six.
Compaction is on by default and removes that ceiling; `--no-compact` puts it
back.

Use `native/` (a wrapper around Apple's extractor) to get the images out;
it must be built `-arch arm64e`, since the bundle ships only x86_64 and arm64e
and `dlopen` needs a matching slice. It extracts the whole cache at once —
several GB — so do it once and keep the tree. machomorph picks it up from
`/tmp/dsc_out` automatically, and builds the wrapper itself if `clang` is
around.

`native/dlopen_test`, `dlsym_test` and `dlcall_test` are worth knowing
about: a converted **macOS**-targeted library can be loaded on the Mac itself,
which is a far faster way to find layout problems than reinstalling a cryptex.
Pass `--no-cpusubtype-fix` for that, or the macOS arm64e ptrauth version
(`arm64e.v1`) will make it unloadable by an ordinary process. Use `dlcall_test`
in preference to the other two: a damaged extraction loads and resolves symbols
perfectly, and only faults once you actually call into it.


## How it works

Five edits to the Mach-O, and one call to `codesign`:

1. **Pick one architecture.** iOS will not load a universal binary that still
   carries an x86_64 slice, so the target slice is extracted.
2. **Retarget the platform.** `LC_BUILD_VERSION`'s `platform`, `minos` and `sdk`
   fields are rewritten. Older binaries carrying `LC_VERSION_MIN_*` instead are
   converted or retargeted in place.
3. **Fix the arm64e ptrauth ABI.** macOS refuses to run an arm64e binary whose
   pointer-authentication ABI version is 0, so `--platform macos` forces
   `cpusubtype` to `0x81000002`; for device platforms the version bits are
   cleared back to `0x80000002`.
4. **Fix framework paths.** macOS frameworks are versioned bundles
   (`CoreFoundation.framework/Versions/A/CoreFoundation`); on iOS they are flat
   (`CoreFoundation.framework/CoreFoundation`). The `Versions/X/` component is
   stripped from every `LC_LOAD_DYLIB`, `LC_ID_DYLIB` and `LC_RPATH`.
5. **Re-sign.** All of the above invalidate the signature. The binary's existing
   entitlements are read straight out of the embedded `CS_SuperBlob`, optionally
   extended, and handed back to `codesign` for an ad-hoc signature.

Some implementation notes:

* Load commands are **rebuilt**, not patched in place, so paths may grow as well
  as shrink. If the result no longer fits in the linker's header padding, the
  tool refuses to write rather than corrupt the binary, and tells you how many
  bytes short it is.
* **Nothing else in the file moves.** All file offsets are preserved, so chained
  fixups, the symbol table and `__LINKEDIT` need no adjustment.
* The SDK version is set to `major << 16` (minor and micro zeroed). Override it
  with `--sdk` if you need something exact.
* 64-bit little-endian Mach-O only (arm64/arm64e/x86_64). No 32-bit, no PPC —
  those error out explicitly rather than misparsing.

## Tests

`./test_machomorph.py` is a differential test suite: it runs the real `lipo`,
`cbv`, `install_name_tool` and `ldid` next to our implementations and compares
the results. Checks whose reference tool is missing are skipped.

```sh
./test_machomorph.py --cbv /path/to/cbv
```


## Repository layout

```
machomorph.py            the tool: convert a Mach-O for another Apple platform
                         and bring its libraries along -- the dependency
                         closure, the order of the lift and the output layouts
test_machomorph.py       its tests, diffed against the real toolchain

dsc/                     read and repair an image from a dyld shared cache
  image.py                 just enough Mach-O to reason about stubs and GOTs
  arm64.py                 the four instruction forms this project decodes
  extract.py               pull an image out of the cache, as the cache holds it
  facts.py                 what the cache knows and an extraction does not
  rebind.py                repair the uniqued GOT, synthesise chained fixups
  objc.py                  rebase the selector, protocol and class references
  compact.py               pack the segments, closing the address-space hole
  gotscan.py               judge a lifted library; modifies nothing
  index.py                 the loadable-path list, out of a cache or an IPSW

cryptex/                 build a cryptex, and check it before installing
  verify.py                pre-install gate over the staged tree
  symbols.py               the launch prediction, per binary
  blocklist.py             turn a probe result into the exclusion list below
  restage.py               superseded; kept for a tree built by an older version

scripts/                 shell, because it drives other programs
  rebuild_cryptex.sh       scrape the system, convert it all, copy the data
                           trees, check the result. Nothing else
  device_probe.sh          launch every ported binary on the device, classify

native/                  C, built by its own Makefile
  dsc_extract.c            wraps Apple's dsc_extractor.bundle
  dlopen_test.c            does it map?
  dlsym_test.c             does its export trie work?
  dlcall_test.c            does it RUN? The one that catches a damaged lift

data/                    measured inputs the build reads
  ios27_*_index.txt        what the target's dyld cache can load
  ios_native_commands.txt  what iOS already ships
  blocklist_symbols.txt    what dies on a missing symbol, and WHICH symbol.
                           Generated by cryptex.blocklist -- not by hand
  exclude_xcrun_shims.txt  the 95 xcrun shims, excluded by path
  no_compact.txt           images compaction must not touch
  ssl/openssl.cnf          the trust store's config

lifted/                  the lift cache: one library per basename, re-made
                         whenever any of the lifting code is newer (gitignored)
```

`machomorph.py` owns the conversion, the dependency closure and the order of
the lift; `dsc/` owns everything that knows what a shared cache is; `cryptex/`
owns the checks; `scripts/` drives other programs; `native/` is C. Each of
`dsc/` and `cryptex/` is a package whose modules import each other properly, so
there is no `sys.path` juggling and no importing a library out of a CLI.

Run a stage directly with `python3 -m`, from the repository root:

```sh
python3 -m dsc.gotscan  lifted/libcrypto.46.dylib
python3 -m dsc.compact  in.dylib -o out.dylib
python3 -m dsc.index    iPhone18,3_26.4_23E246_Restore.ipsw -o data/idx.txt
python3 -m dsc.symindex iPhone18,3_26.4_23E246_Restore.ipsw -o /tmp/syms.txt.gz
python3 -m cryptex.verify  --cryptex DIR --dylib-index data/ios27_*.txt
python3 -m cryptex.symbols --all --cryptex DIR
```

`cryptex.verify` and `cryptex.symbols` still print `verify_cryptex` and
`symbol_check:` as their own labels, so measurements recorded before the move
stay comparable.

### The two exclusion lists, and why they are separate

A scan applies both by default (`--no-exclude-defaults` opts out). They are
kept apart, rather than being one list, because they are believed for different
reasons.

`exclude_xcrun_shims.txt` is 95 **paths**. `/usr/bin` hard-links one inode under
78 names whose whole body is `xcselect_invoke_xcrun`: look up the active Xcode
and re-exec into it. There is no Xcode on a phone, and on iOS they are SIGKILLed
rather than merely useless. It has to match by path, not by name, because those
names exist twice -- `otool` is both a shim and, in the Xcode toolchain, the
real `llvm-otool`. A bare `otool` line would drop the tool you want; the
/usr/bin scan runs first, so an earlier build shipped `bin/otool -> DeRez`.

`blocklist_symbols.txt` is **generated** from a device probe, and each line
carries the symbol that blocked it:

```
date              # _syslog$DARWIN_EXTSN
jar               # _OBJC_CLASS_$_JLRuntime
postconf          # _sasl_client_init
```

Regenerate it after a probe rather than editing it:

```sh
cryptex/blocklist.py measurements/<latest>.tsv --cryptex <cryptex> \
    > data/blocklist_symbols.txt
```

Two things follow from generating it. A missing symbol is a snapshot rather than
a verdict -- it can be answered by a rename, a forwarding shim, or a newer iOS
-- so the symbol is recorded to make the exclusion reversible: delete the lines
naming it and re-probe. And the generator **holds back** a binary whose missing
symbol is imported by a library *this cryptex bundles*, because that failure is
ours to fix rather than a limit of iOS. It distinguishes the two by measurement,
since the probe output is identical either way: `date` imports
`_syslog$DARWIN_EXTSN` itself from libSystem and is excluded, while `openssl`,
`tcpdump` and `curl` never import it and inherit it from the bundled
`libcrypto`, so they are held back with the reason written into the file.

Everything under `data/` used to include a single hand-maintained
`blocklist_ios.txt`. It drifted from the measurements it claimed to encode and
excluded 480 binaries on reasoning that did not survive checking -- among other
things it blocked `ioreg`, whose native build is SIGKILLed on iOS while the port
dumps the whole registry. It is kept as evidence in `measurements/`, and
`next-session-blocklist.md` is the plan for rebuilding a defensible version.


## A note on how this was built

`machomorph` was vibe-coded with Claude (Claude Code, Opus 5). That is worth
saying out loud, because "an LLM wrote a Mach-O rewriter" should make you want
to see evidence before you point it at anything you care about.

So the output is verified rather than trusted:

* `cbv`'s behaviour was **reverse-engineered by byte-diffing** its output against
  the input on real system binaries, not guessed at from the blog post. It turns
  out to mutate exactly three fields plus `cpusubtype`; everything else that
  differs is `codesign`'s doing.
* [`test_machomorph.py`](test_machomorph.py) is a **differential** suite — it runs
  the real `lipo`, `cbv`, `install_name_tool`, `ldid` and `codesign` alongside our
  implementations and compares the results, rather than asserting against
  expectations we made up. Our thinning is byte-identical to `lipo -thin`; our
  entitlement parser agrees with both `ldid -e` and `codesign -d`.
* The tool was run across **1250 system binaries** from `/usr/bin`, `/usr/sbin`,
  `/usr/libexec`, `/usr/lib` and the system frameworks, with no failures; a
  sample of the results was checked with `codesign --verify` and `otool -l`.

Verification only goes so far, of course: it shows we match the tools we
replaced, on the binaries we tried. If something misbehaves, please open an
issue with the binary in question.

## Inspiration and acknowledgments

The platform-conversion trick is Jonathan Levin's, described in
[*Merging macOS and iOS*](https://www.df-f.com/blog/macosandiosmerge) along with
his `cbv` tool — including the `0x81000002` pointer-authentication workaround,
which is not documented anywhere else as far as we know. `machomorph`
reimplements `cbv`'s behaviour and is byte-for-byte verified against it.

Before this script, the workflow was:

```sh
lipo -thin arm64e /usr/sbin/ioreg -output /tmp/ioreg_thin
./cbv /tmp/ioreg_thin to ios 27.0
otool -L /tmp/ioreg_thin
install_name_tool -change \
    /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation \
    /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation \
    ... /tmp/ioreg_thin      # once per macOS-only path
ldid -e /tmp/ioreg_thin > ents.xml
# hand-edit ents.xml to add research.com.apple.license-to-operate
codesign --entitlements ents.xml -f -s - /tmp/ioreg_thin
```

`machomorph` folds all of that into one command:

| Step | Previously | Now |
|---|---|---|
| Pick one architecture out of a fat binary | `lipo -thin arm64e` | built in (`--arch`) |
| Rewrite `LC_BUILD_VERSION` platform/minos/sdk | `cbv <bin> to ios 27.0` | `-p ios -v 27.0` |
| Fix the arm64e ptrauth `cpusubtype` | `cbv` | automatic |
| Strip macOS-only `Versions/A/` from paths | `install_name_tool -change` × N | automatic |
| Arbitrary path rewrites | `install_name_tool -change` | `--change OLD NEW` |
| Inspect header, libraries, entitlements | `otool -hv`, `otool -L`, `ldid -e` | `--info` |
| Read the existing entitlements | `ldid -e` | automatic |
| Add the research entitlement | edit XML by hand | `--license-to-operate` |
| Re-sign ad hoc | `codesign -f -s -` | automatic |

Thanks also to `ldid` (Jay Freeman / ProcursusTeam) — not required any more, but
it is the reference our entitlement parser was checked against.
