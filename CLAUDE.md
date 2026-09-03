# macos-to-ios

A single, dependency-free Python tool (`machomorph.py`) that converts a Mach-O
binary from one Apple platform to another (typically macOS -> iOS) so it can be
run on a jailbroken device.

It replaces this multi-tool dance:

```sh
lipo -thin arm64e /usr/sbin/ioreg -output /tmp/ioreg_thin
./cbv /tmp/ioreg_thin to ios 27.0
otool -L /tmp/ioreg_thin
install_name_tool -change .../Versions/A/CoreFoundation .../CoreFoundation /tmp/ioreg_thin
ldid -e /tmp/ioreg_thin > ents.xml
codesign --entitlements ents.xml -f -s - /tmp/ioreg_thin
```

with one invocation:

```sh
./machomorph.py /usr/sbin/ioreg -o ioreg_ios --platform ios --version 27.0
```

## Design decisions

* **Pure stdlib Python 3.** No `lief`, no `macholib`. The Mach-O edits needed here
  are small and well understood; a hand-rolled `struct`-based reader/writer keeps
  the tool a single file with zero install story. (`lief` was considered and
  rejected: heavy dependency, and it rewrites/normalises more of the binary than
  we want.)
* **Binary rewriting only.** Every library this project ships is Apple's own
  binary, lifted out of the dyld shared cache and rewritten. Compiling a
  library from source and hand-writing a stub were both tried, both worked, and
  both have been **abandoned and deleted** (`ios-libs/`, `libxcselect-stub/`).
  Lifting is strictly more general: it works for `libdtrace` and `libxcselect`,
  which have no open-source upstream and exist as a file nowhere, and it gives
  Apple's actual implementation rather than a look-alike. Do not add a source
  build or a stub back; lift instead. The measurements from both routes are
  kept below because they are the evidence for the diagnosis, not because they
  describe what is shipped.
* **Only `codesign` is shelled out to.** Re-implementing CMS/ad-hoc code signing
  is out of scope; the user explicitly allowed assuming macOS + Xcode tools.
  `ldid` is *not* required — entitlement extraction is done by parsing the
  embedded `CS_SuperBlob` ourselves.
* **Load commands are rebuilt, not patched in place.** This handles dylib paths
  that grow as well as shrink. We check available header padding before writing
  and refuse rather than clobber `__text`.
* **Nothing else in the file moves.** All file offsets stay identical, so no
  fixups, symbol tables or LINKEDIT data need rewriting.
* **One binary at a time is the PRIMARY use, and a conversion includes the
  libraries.** `machomorph.py <one binary> -o <path>` produces a binary that
  runs, which means it also produces every library the target does not have,
  lifted out of the shared cache and staged beside it. The batch is the same
  mechanism pointed at a whole system, not a different tool. See "The
  architecture: one tool, and what is left outside it".

## What we reimplemented, and how it was verified

| External tool | Replacement | Verification |
|---|---|---|
| `lipo -thin` | `FatSlice` extraction in `machomorph.py` | byte-identical to `lipo -thin arm64e` |
| `cbv` | `set_platform()` + cpusubtype fix | byte-diffed cbv output vs ours (see below) |
| `install_name_tool -change` | `rewrite_paths()` | `otool -L` comparison |
| `ldid -e` | `extract_entitlements()` (CS_SuperBlob parser) | compared to `ldid -e` output |
| `ldid -S` / `codesign` | shells out to `/usr/bin/codesign` | n/a (intentional) |

### cbv reverse-engineered behaviour (verified by byte diff, 2026-08-30)

Running `cbv ioreg_thin to ios 27.0` changes exactly three things in the Mach-O:

1. `LC_BUILD_VERSION.platform` -> target platform id.
2. `LC_BUILD_VERSION.minos` -> requested `maj.min.micro`.
3. `LC_BUILD_VERSION.sdk` -> `maj << 16` (major only, minor/micro zeroed).

Plus, **for macOS targets only** on arm64e, `mach_header.cpusubtype` is forced to
`0x81000002` (PTRAUTH ABI version 1) — with version 0 XNU on macOS kills the
process. For iOS targets cbv leaves the subtype alone; macOS system arm64e
binaries already carry `0x80000002`, which is what iOS wants. We additionally
clear any stale ptrauth-version bits when targeting non-macOS, which cbv does not.

Everything else that differs between `cbv` input and output (the `__LINKEDIT`
segment `filesize`, `LC_CODE_SIGNATURE.datasize`, and the signature blob itself)
is the work of the `codesign` calls cbv makes, not cbv itself.

## Task list

- [x] Reverse-engineer exactly what `cbv` mutates (byte diff against real `ioreg`)
- [x] Write CLAUDE.md
- [x] Fat/universal parsing + slice extraction (replaces `lipo -thin`)
- [x] Mach-O header + load command parser
- [x] `LC_BUILD_VERSION` / `LC_VERSION_MIN_*` platform+version rewriting (replaces `cbv`)
- [x] arm64e cpusubtype handling
- [x] Dylib/rpath path rewriting incl. automatic `Versions/A/` stripping (replaces `install_name_tool -change`)
- [x] Load-command area rebuild with header-padding check
- [x] Entitlement extraction from `CS_SuperBlob` (replaces `ldid -e`)
- [x] Entitlement injection (`research.com.apple.license-to-operate`)
- [x] Ad-hoc re-signing via `codesign`
- [x] `--info` mode (replaces `otool -hv`, `otool -L`, `ldid -e`)
- [x] End-to-end verification against the real toolchain
- [x] README
- [x] `--license-to-operate` made opt-out: added by default when the binary
      already carries entitlements (an entitled binary is useless on an SRD
      without it), `--no-license-to-operate` to suppress
- [x] `dsc.index`: extract the loadable-path list (canonical + aliases) from
      a dyld shared cache
- [x] `machomorph --dylib-index`: resolve library paths against the target's
      real cache, incl. public<->PrivateFrameworks moves, and warn about
      libraries that are absent there
- [x] Device error analysis on the SRD (see below)
- [x] `machomorph --weak PATH` / `--weaken-missing`: rewrite `LC_LOAD_DYLIB` to
      `LC_LOAD_WEAK_DYLIB` (never delete it -- ordinals!) so a binary loads
      without an absent library
- [x] `libxcselect-stub/`: a from-scratch iOS `libxcselect.dylib`, so the
      binaries that need it load and skip the respawn-into-Xcode path.
      **Superseded and deleted** -- the real library is now lifted from the
      cache instead. Kept in the task list because the reverse engineering it
      required is what documented the callers' `cbz w0` guard
- [x] `machomorph --cryptex DIR` (+ `--cryptex-bindir` / `--cryptex-libdir`):
      stage converted binaries into a cryptex tree instead of a single `-o` path
- [x] `machomorph --provide-lib OLD FILE`: bundle a replacement dylib into the
      cryptex and repoint every reference at it via `@executable_path`
- [x] `machomorph --scan [DIR...]` / multiple inputs: convert a whole tree in
      one run, with a summary ranking the libraries that block the most binaries
- [x] Device test: `vmmap -pages 1` runs on the SRD against the stub, with no
      environment variable. All 106 libxcselect users rebuilt against it
- [x] Exercise the other seven of the 8: all run (`atos`, `symbols`, `vmmap`,
      `heap`, `leaks`, `malloc_history`, `stringdups`, `filtercalltree`)
- [x] `--provide-lib` symbol coverage: read a binary's imports per library from
      the symbol table, the replacement's exports from its trie, and warn on the
      gap. Reproduces the 94/9 libxcselect split automatically
- [x] Symlink aliases: an input that is a symlink to another input becomes a
      relative symlink in the cryptex, not a second copy
- [x] Port the real Xcode tools (105 of 108 resolve on iOS); `--scan-xcode`
      with a purpose-based blocklist keeps the 32 useful for reverse engineering
- [x] `--exclude GLOB` and `--list-skipped` to see and steer what a scan takes
- [x] `resolve_rpath()`: check an `@rpath` dependency against the binary's own
      LC_RPATHs and the staging directory, instead of reporting it as missing
- [x] Install and test the Xcode tools: arm64 runs fine from the cryptex, all
      32 work. Full device probe of 880 binaries in `device_probe_report.md`
- [x] Validated the static analysis against 880 real launches: 0 false negatives
- [x] `blocklist_ios.txt` + `--exclude-from`: never port what is measured broken
- [x] `ios_native_commands.txt`: do not port what iOS already ships (43 were)
- [x] Bundle real macOS dylibs to rescue `curl`, `dtrace`, `systemstats`
- [x] `rebuild_cryptex.sh`: the whole thing in one reproducible script
- [x] Fixed: hard-link dedup silently dropped 77 of 78 shim names; aliases could
      clobber real tools; writing through a stale symlink
- [x] Install the rebuilt cryptex and re-probe: `tcpdump` fully works, `dtrace`
      partially, `curl`/`openssl`/`systemstats` did not -- diagnosed to the
      missing chained fixups in cache-extracted libraries
- [x] `ios-libs/build.sh`: build LibreSSL 3.3.6, curl 8.7.1 and PCRE 8.44 for
      iOS from source, after identifying Apple's libcrypto/libssl as a LibreSSL
      fork. Vanilla builds are ABI-identical (0 missing across 1018 imports)
- [x] `bundle.py --prebuilt DIR` prefers a source build over a cache
      extraction, and warns `NO FIXUPS` on any library that is still extracted
- [x] Ship a trust store: iOS has no `/etc/ssl`, so `<cryptex>/share/ssl`
      plus `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`OPENSSL_CONF`
- [x] Device-confirmed: `openssl` (RSA, EC, AES, TLS 1.3 verify ok), `curl`
      (200 over HTTPS), `tcpdump --version`, zsh's `pcre` module
- [x] Asked whether the libxcselect stub can be replaced by a cache extraction:
      no. The extractor zeroes the GOT, so the real library faults on its first
      call, and on iOS it would return false anyway -- exactly what the stub
      does. `native/dlcall_test` is the harness that settles this class of
      question by actually calling into the library
- [x] Diagnosed the real reason a cache extraction crashes: not the missing
      LC_DYLD_CHAINED_FIXUPS on its own, but the cache-wide **uniqued GOT** the
      builder rewrites the image's code to reach. `dsc.gotscan` reports it
- [x] `dsc.facts` + `dsc.rebind` + `dsc_lift.sh`: repoint the stubs at the
      image's own GOT and synthesise LC_DYLD_CHAINED_FIXUPS from the cache's
      slide info and patch table. `libxcselect` and `libdtrace` both run
- [x] `native/dlcall_test`: dlopen, dlsym **and call**. The test that
      catches "loads, resolves, then faults"
- [x] Fixed: `relayout_for_standalone()` displaced every non-__TEXT segment's
      contents by 8 bytes relative to its own section table
- [x] `machomorph --reserve-header`: grow __TEXT downward so a load command can
      be added to an extraction later without moving any section
- [x] Ship the real `libxcselect` lifted from the cache instead of the stub;
      verified all 63 of its imports exist on iOS
- [x] Device-confirm the lifted `libxcselect`: **works on the SRD**, `vmmap`
      and `heap` both run against it. `libxcselect-stub/` deleted
- [x] Re-lift `libdtrace` and the `systemstats` closure now that the GOT repair
      exists. All seven lift clean (`libdtrace`, `CoreDisplay`, `CoreWLAN`,
      `IOPresentment`, `GPUWrangler`, `CrashReporterSupport`,
      `libDiagnosticMessagesClient`), so nothing is staged `NO FIXUPS` any more
- [x] `TrustEvaluationAgent` lifted: needed because Apple's `libcrypto` fork
      routes cert verification through it. Found the plain-`__got`-full case
      doing it, fixed with the segment-tail overflow pool
- [x] Closed "the one known gap": 15 of the 20 `INCOMPLETE` binds -- all of
      `libdtrace`'s, `CoreDisplay`'s and `IOPresentment`'s -- were one
      untrustworthy JSON field, not an unresolvable target. See rule 7
- [x] The three ObjC lifting gaps closed (2026-09-01): every lifted class had a
      NULL `superclass` (the cache names a class object with its bare name, not
      the mangled symbol), protocol conformance was a SIGSEGV rather than a
      silence, and every relative method list's selector reached the cache's
      uniqued pool. `DiskManagement` now has working superclasses, protocol
      conformance and method lists. See "Lifting an ObjC library out of the
      cache"
- [x] **The architecture: one tool.** The library closure, the seven-stage lift
      pipeline and the output layouts all live in `machomorph.py` now, so
      converting one binary produces the libraries it needs as well.
      `tools/bundle.py` and `tools/dsc_lift.sh` are deleted,
      `rebuild_cryptex.sh` is 664 lines down to 449 and holds no list of
      libraries, and the 33 hand-transcribed weakened symbols are derived.
      All 12 lifts re-verified **byte-identical**; csrutil's five-library mirror
      layout run against real dyld on macOS. See "The architecture"
- [x] Rebuild a whole cryptex through the new pass and device-probe it. 52
      libraries lifted by the closure (40 of them for the first time), 572
      binaries, 424 running on device with **0 symbol failures** -- and five
      bugs, four of which only a device could find. See "The first wide rebuild
      through the one-tool pipeline"
- [x] Reprobe the FIXED build: done by hand, and it found two more bugs, both
      regressions from the tree getting bigger. A lifted library's
      `__init_offsets` and `LC_FUNCTION_STARTS` are offsets from the mach
      header, which `--reserve-header` moves and nothing adjusted -- so dyld
      called `LDAP`'s initialiser a page early and took `curl`, `sendmail`,
      `postfix`, `httpd` and `checkgid` down with it. And the PrivateFramework
      blind spot returned `csrutil` to `_DAUnregisterApprovalCallback`, because
      the hand-written weakening list the refactor deleted was carrying
      knowledge the SDK stubs cannot reach. `dsc.symindex` closes it
- [x] Reprobe THIS build: done. **430 ok, 0 dylib, 0 symbol, 0 killed, 0 crash**
      out of 537 -- the first probe with no failure of any kind. Both fixes hold
      on device, `checkgid`'s two-session-old SIGSEGV is closed, and one new bug
      came out of it: every `CFSTR` literal in a lifted library had a NULL isa,
      because the cache names that class `__NSCFConstantString` while the image
      imports `___CFConstantStringClassReference`. One `ALIASES` line, 6628
      strings in 18 libraries
- [x] Reinstall and confirm `expect`. **Device-confirmed**: the SIGTRAP is
      gone, and `expect` then failed in its own `Tcl_Init` on a missing script
      library -- a staging gap, not a port problem. Staged into `lib/tcl8.5`,
      which Tcl finds by itself with no environment variable. `expect -v`,
      `expr` and a real `spawn` against a pty all work
- [x] Diagnosed the 81 unauthenticated `__text` leftovers: **all 81 are real**,
      and the "mostly decoding artefacts" story belonged to a second, looser
      decoder (`code_got_refs`) that never invalidated a pending ADRP. Strict
      finds 0 in 489 never-lifted binaries and 0 in `libLTO`; the survivors are
      all adjacent ADRP+use pairs. Two families: 8 in the cache's second GOT
      region, 73 direct selectors from its uniqued pool
- [x] `expect` and `ruby` both needed their script libraries staged, and both
      were hidden by a version flag passing. Tcl's goes in `lib/tcl8.5` (no env
      var; Tcl finds it itself), ruby's in `share/ruby` with `RUBYLIB` and
      `SDKROOT`. Both **device-confirmed**: `expect` drives a pty, and all 96
      ruby native extensions load with `socket`, `openssl`, `fiddle` and
      `net/https` at 200 doing real work
- [x] Converting a module staged its whole closure beside it -- 9 copies of
      `libruby`, 5 of `libcrypto`, 37 MB -- because the closure is the default
      and a module is not a tool in `bin/`. `retarget_module()` uses
      `--no-libraries` and derives the repoint set from the module's own load
      commands, replacing three hand-written `--change` flags. 473 -> 438 MB.
      **Device-confirmed**: `vmmap` on a live ruby shows one copy of each
      library, mapped from the cryptex's `lib/`
- [x] Three zsh modules (`zsh/net/tcp`, `zsh/net/socket`, `zsh/param/private`)
      had never been ported: the step used a non-recursive glob where perl's
      and ruby's use `find`, so they shipped as fat macOS binaries. 34 -> 37
      modules, all iOS. **Device-confirmed**: all 37 load, and `ztcp` opens a
      real socket and reads dropbear's SSH banner
- [ ] Repair those 73 direct selectors. Same optimisation `dsc.objc` already
      undoes for relative method lists, but here the pair must be re-encoded
      `adrp/add` -> `adrp/ldr` against the image's own `__objc_selrefs` slot.
      Needs the cache to name each address, a re-lift of 5 libraries and a
      device probe; nothing reaches these sites today
- [ ] `CoreWLAN`'s remaining 5: ObjC protocol references into the cache's
      canonical protocol tables. A third form of cache-wide uniquing, needing
      synthesised ObjC metadata rather than a repointed pointer.
      Narrowed, and no longer the blocker it looked like: `DiskManagement`
      loads and its classes, methods and protocols work (see "Lifting an ObjC
      library out of the cache"). What is left is repairing protocol references
      in `__objc_const` **by field rather than by name** -- so
      `class_conformsToProtocol` works -- and the protocols' relative method
      lists, whose selector offsets still reach the cache's uniqued pool
- [x] Device-probe the re-lifted set from the clean `machomorph-test` cryptex.
      **`dtrace -l` no longer faults** -- it reaches its own init and reports the
      iOS kernel has no DTrace device. Library failures across the whole tree
      went 243 -> 1
- [x] `usr/bin/cryptex-run` must be in the cryptex or the dropbear LaunchDaemon
      cannot start and there is no ssh. The cryptex installs and mounts anyway,
      so nothing warns
- [x] Exclude the 95 xcrun shims BY PATH: they are SIGKILLed on iOS and they
      were shadowing `otool`, `nm`, `objdump`, `dwarfdump`, `size`, `c++filt`
      with symlinks to `DeRez`. Needed `--exclude` to accept a path glob
- [x] Pull crash reports with `idevicecrashreport -e DIR`: it settled that the
      daemon crashes are jetsam `per-process-limit`, and that the 78 shim kills
      were `EXC_ARM_PAC_FAIL` inside a stale lift of our own -- not AMFI
- [x] Close the three "the file exists, so it is fine" holes that let a damaged
      lift ship: the rebuild's skip-if-present, `dsc_lift` not checking its own
      output, and `dsc_lift` reusing an empty `facts.json`
- [x] `systemstats`: blocklisted. `CoreDisplay` and `IOPresentment` need symbols
      absent from iOS, so it can never work, and its six lifted frameworks are
      no longer staged
- [x] **`_syslog$DARWIN_EXTSN`: solved by renaming the import, not by adding a
      library.** `machomorph --redirect-symbol OLD NEW` / `--darwin-extsn`
      rewrites the name in place in both tables that spell it. No ordinal
      rewrite, no stub dylib, no `LC_LOAD_DYLIB` -- see below
- [x] Compacting a lifted image (moving data segments relative to `__TEXT` and
      patching every ADRP that reaches them) lifts the two-or-three
      lifted-libraries-per-process ceiling. `dsc/compact.py`: all seven
      lifts go from 8262 MB of reserved address space to **3.9 MB**, and all
      seven still load and do real work locally. Not yet device-probed
- [x] A lifted library's **thread-local descriptors** carry the cache's own
      bookkeeping, and iOS dyld aborts the process before `main()` on one it
      cannot validate. `MachO.fix_tlv_descriptors()` repairs them,
      `malformed_tlv_descriptors()` gates them, and `cryptex.restage` will not
      repoint a weak reference at a library that fails the gate.
      **Device-confirmed:** `ssh-keygen`, `ssh-add` and `ssh-keyscan` go from
      `rc=134` to running, and all eight weak-linkers load
- [x] Close the three limitations in it. `offset = key >> 32` -- the cache
      records the answer -- takes the repair from 45 of 80 cache images to
      **80 of 80**, which matters because 213 of the 446 descriptors have no
      `$tlv$init` and a stripped library was unrepairable. Agrees with the
      linker's marker on **233 of 233** where both exist. The thunk no longer
      binds `__tlv_get_addr`, a name iOS does not export
- [x] Establish that **macOS dyld does not validate TLV offsets at all**, so no
      local `dlopen` can reproduce this class and the static gate is the only
      pre-device detection. Census in `measurements/tlv_census_2026-09-01.txt`

## Device findings (SRD, iPhone18,3, iOS 27.0 `24A5424a`, 2026-08-30)

Ported 843 macOS binaries into the research cryptex and analysed what actually
runs. Three failure classes, in descending order of how many binaries they hit.

### 1. Library genuinely absent from iOS -- 422 of 862

Not fixable by rewriting. The top offenders and what they are:
`libxcselect.dylib` (106, Xcode selection -- but 94 of those are `xcrun`
shims that are pointless to port, see below), `libcrypto.46`/`libssl.48` (55/28,
macOS ships OpenSSL, iOS does not), `OpenDirectory` (48), `libsasl2` (39),
`JavaLaunching` (36), `LDAP` (31), `ApplicationServices` (30),
`libswiftIOKit` (28, Swift IOKit overlay), `AppKit` (27), `Kerberos` (27),
`libcups` (26). Full list in `apple-cryptexes/rules_report.txt`.

### 2. Library exists on iOS but at a DIFFERENT path -- fixable, and now fixed

**This is the answer to "do we need rules beyond stripping `Versions/A`?": yes,
two more.**

* **iOS demotes several public macOS frameworks to `PrivateFrameworks`**:
  `DiskArbitration` (37 binaries), `SecurityFoundation` (12),
  `ServiceManagement` (5), `FSKit` (5), `LatentSemanticMapping` (1).
* **A dylib bundled inside a framework on macOS can ship loose in `/usr/lib`**:
  `WirelessDiagnostics.framework/Libraries/libprotobuf.dylib` ->
  `/usr/lib/libprotobuf.dylib`, likewise `libAWDProtobufBluetooth`.

Rather than hardcode these, `machomorph --dylib-index` resolves paths against a
real list of what the target cache can load (`dsc.index`), tries
Versions-flattening, public<->private framework moves and a unique-basename
match, and **warns about what it cannot resolve** -- so a binary's failure is
predicted before it is ever copied to the device.

### 3. Library present, SYMBOL missing -- 58 of the 372 tested

Invisible to static *path* analysis, and at the time this was written, thought
to need a device. It does not: `cryptex/symbols.py` predicts these on the Mac
(see "Predicting a symbol failure on the Mac"). iOS ships a
reduced surface of the *same* dylib. By frequency:
`syslog$DARWIN_EXTSN` (13 -- the macOS-only `$DARWIN_EXTSN` symbol variant),
`FSCloseFork`/`GetMacOSStatusCommentString` (Carbon), `wordexp` (2 -- absent
from iOS libc), `responsibility_get_*` (4 -- macOS process-responsibility API),
`AuthorizationCreate`/`AuthorizationCopyRights`/`CSSM_*`/`SecKeychain*`
(macOS-only Security APIs), `MDItemCopyAttribute*` (Spotlight),
`LSCopyApplicationForMIMEType` (LaunchServices), `SCPreferencesCreate`/
`SCDynamicStoreCreate`, `KextManagerLoadKextWithIdentifier`, `_qtn_*`
(quarantine).

### Verdict for the six reported broken

| tool | root cause | fix |
|---|---|---|
| `spindump` | needs `DebugSymbols` + `AppKit` -- absent | **use `/usr/sbin/spindump`, iOS ships one** |
| `kmutil` | needs 7 macOS-only libs (`KernelManagement`, `DiskManagement`, `SystemPolicy`, `libKernelCollectionBuilder`, `libbootpolicy`, `libxcselect`, `libswiftIOKit`) | none; iOS has no kext management |
| `taskinfo` | all libs fine; missing symbol `responsibility_get_attribution_for_audittoken` | **use `/usr/bin/taskinfo`** |
| `footprint` | all libs fine; missing symbol `responsibility_get_responsible_for_pid` | **use `/usr/bin/footprint`** |
| `heap` | needs `libxcselect.dylib` | **stub library bundled in the cryptex** -- see below |
| `vmmap` | needs `libxcselect.dylib` | **stub library bundled in the cryptex**, confirmed working on device |

### Native-vs-ported comparison (the ones iOS already ships)

iOS builds are *not* the macOS binary with a patched header -- they are compiled
against a smaller dependency set. The macOS `spindump` links 26 libraries, the
iOS one 22, and the seven extra (`AppKit`, `CoreGraphics`, `DiskArbitration`,
`IOKit`, `ServiceManagement`, `DebugSymbols`, `Sentry`) are exactly the reason
the port cannot load. `taskinfo` and `footprint` differ only by `libRosetta`
(macOS-only) plus IOKit path spelling. **Where iOS ships its own build, use it.**

### Two things that are NOT problems

* **`IOKit.framework/IOKit` vs `.../Versions/A/IOKit`.** Only the versioned
  spelling is a canonical cache image, but the flat one is a registered
  **alias**, so both load. Stripping `Versions/A` from IOKit is safe -- verified
  on device and in the cache's dylib trie.
* **arm64e ptrauth.** A converted Apple arm64e binary runs fine. What does *not*
  run is a locally compiled one, for a different reason (below).

### SRD execution constraints (cost real time, worth remembering)

* **Binaries must be installed via the cryptex.** Anything else is `Killed: 9`,
  including `/tmp`. The trust cache is keyed by **cdhash**, not path -- which is
  why copying an already-installed cryptex binary to `/tmp` *does* run, while a
  freshly built one never will, entitlements or not. So no dlopen/dlsym probe
  tool without a cryptex rebuild.
* **`DYLD_INSERT_LIBRARIES` is ignored** (AMFI), so it cannot be used to probe
  library availability either.
* `scp` needs `sftp-server`, which iOS lacks -- use `ssh root@localhost cat FILE`.
* The device's own dyld cache is readable at
  `/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/`; the main file is
  only ~768 KB and carries the whole image list. The **alias trie**, though,
  lives in the 676 MB `.dyldlinkedit` subcache, so for a complete index extract
  the cache from an IPSW instead (`ipsw extract --dyld`).

## The `/usr/lib/libxcselect.dylib` dependency

`libxcselect` is the most common missing library across the ported binaries
(106 of them). It is the "where is the active Xcode / Command Line Tools
install" resolver, and iOS neither has such a thing nor ships the library.

### Two very different groups of callers -- only 9 are worth porting

The earlier note in this file claimed 105 binaries as the prize. That was wrong,
and the correction matters, so here is the measurement. Classifying the 105 by
which `libxcselect` symbol they import (`nm -mu`):

| group | count | symbol | what the binary is |
|---|---|---|---|
| xcrun shims | **94** | `_xcselect_invoke_xcrun` | not a tool at all |
| real users | **9** | `_xcselect_get_developer_dir_path` | a real tool |
| neither | 2 | -- | `devicectl`, `sample` |

The 94 are **stubs whose entire body is the xcrun call**: they look up Xcode's
copy of themselves and `exec` it. `/usr/bin/otool`, `nm`, `lipo` and `strip` are
literally the same 118640-byte file (77 of the 94 share that exact size, 16
share 135200, 1 is 117104). `git`, `make`, `python3`, `clang`, `swift`, `ld` and
`xcodebuild` are in this group too. **Porting them to iOS achieves nothing** --
there is no Xcode on the device to re-exec into, so the "on-device toolchain"
idea does not follow from this list. The real `otool`/`nm`/`git` live inside
`Xcode.app` and were never the binaries being converted.

The 9 that genuinely call `xcselect_get_developer_dir_path` and do their own
work are:

```
atos filtercalltree heap leaks malloc_history stringdups symbols vmmap
xcode-select
```

`xcode-select` is meaningless on iOS, so the real prize is **8 tools** --
symbolication (`atos`, `symbols`) and memory analysis (`vmmap`, `heap`,
`leaks`, `malloc_history`, `stringdups`, `filtercalltree`). Worth having, but
not a hundred of them.

### The first fix: a hand-written stub (since deleted)

This is kept for the reverse engineering in it, not as instructions: the stub
has been deleted in favour of the real library lifted out of the cache. What
still matters is *why* returning false is the right answer, which is recorded
below and is equally true of the real library on iOS.

`libxcselect-stub/xcselect_stub.c` was a from-scratch iOS replacement exporting
all **12** symbols the real library exports, with the behaviour of a machine
that has no developer directory -- which is the truth on iOS. `build.sh` builds
it with the iPhoneOS SDK; it needs only `libSystem` and comes out as arm64e
cpusubtype `0x80000002`, the same ptrauth ABI as the converted Apple binaries.

Signatures were recovered by disassembling the arm64e `libxcselect` out of the
macOS shared cache (`ipsw dyld extract ... /usr/lib/libxcselect.dylib`). The
one that matters:

```c
bool xcselect_get_developer_dir_path(char *buf, int bufsize,
                                     bool *is_env_override,
                                     bool *is_command_line_tools,
                                     bool *unused);
```

The real one tries `DEVELOPER_DIR`, then the `/var/select/developer_dir`,
`/var/db/xcode_select_link` and `/usr/share/xcode-select/*` symlinks, and
returns false when it finds none. **The stub returns false**, and that is the
whole trick: every caller does

```
bl _xcselect_get_developer_dir_path
cbz w0, <skip the respawn>
```

so a false return is the clean "there is no Xcode here, carry on" answer. It
needs **no `DT_NO_RESPAWN` environment variable** -- the earlier weak-link plan
did, because a weak-linked absent symbol binds to NULL and calling it crashes
unless the env-var guard above the call is taken.

Returning a *path* (`/tmp`, as first suggested) would also avoid the crash, but
it makes the caller return true and then go looking for `/tmp/usr/bin/vmmap`.
False is strictly the better answer. `DEVELOPER_DIR` (or
`XCSELECT_STUB_DEVELOPER_DIR`) is still honoured if someone sets it, exactly as
the real library does.

`xcselect_invoke_xcrun` in the stub sets `errno = ENOENT` and returns -1 rather
than exec'ing. That does not rescue the 94 shims -- nothing can -- but it turns
their failure into an error instead of a crash.

### Why the load command is rewritten, never deleted

**Do not remove an `LC_LOAD_DYLIB`.** Chained-fixup binds address their library
by **ordinal** -- its 1-based position among the dylib load commands.
`libxcselect` is dylib #1 in both `heap` and `vmmap`, so deleting it shifts
every later ordinal down by one and silently re-points each import at the wrong
library (`CoreSymbolication` -> `Symbolication`, and so on). The binary would
load and then misbehave in ways that look nothing like a linking problem.

`machomorph --weak PATH` / `--weaken-missing` therefore **rewrites**
`LC_LOAD_DYLIB` (`0x0C`) to `LC_LOAD_WEAK_DYLIB` (`0x80000018`): same struct,
same `cmdsize`, same ordinal. `--provide-lib` likewise only rewrites the path
string, and additionally weakens it so a binary still launches if the bundled
library somehow fails to load.

### Can the stub be replaced by the real library from the cache? Yes (2026-08-30)

Once `machomorph` learned to lift a library out of the dyld shared cache, the
obvious question is whether the hand-written stub can be dropped in favour of
the real `/usr/lib/libxcselect.dylib`. The first attempt said no, and the
reason it gave was wrong in an instructive way. Both halves are recorded here,
because the wrong half is what most people would conclude and stop at.

**The first attempt.** Converted with `-p macos --no-cpusubtype-fix` and
exercised with `native/dlcall_test` -- the missing third step, since
`dlopen_test` proves an image is mappable and `dlsym_test` proves its export
trie works, but neither executes a single instruction of it:

```
$ native/dlcall_test /tmp/xcs_mac.dylib xcselect_get_developer_dir_path
loads
resolves xcselect_get_developer_dir_path = 0x7379800300000728
<SIGSEGV>

EXC_BAD_ACCESS, KERN_INVALID_ADDRESS at 0x0000000000000000
  xcselect_get_developer_dir_path + 60
```

The obvious reading is the fixup wall: no `LC_DYLD_CHAINED_FIXUPS`, so nothing
binds, so the first call through the GOT dies. The extracted `__auth_got` is
0x1d0 bytes of zeroes, which fits that story perfectly.

**Why that reading is wrong.** The zeroes are not a missing fixup table. They
are in the *cache* too -- `ipsw dyld dump` and a raw `dd` of
`dyld_shared_cache_arm64e.02.dylddata` both show `__auth_got` all zero for
`libxcselect`, for `libz`, for `libarchive`, for every image. Nothing was lost
in extraction, because there was nothing there to lose. See "The cache-uniqued
GOT" below for what is actually going on and how it is repaired.

**And the stub is genuinely replaceable.** The lifted real library now runs:

```
$ native/dlcall_test lifted/libxcselect_mac.dylib \
      xcselect_get_developer_dir_path
loads
resolves xcselect_get_developer_dir_path = 0xc46f800300000728
CALLS OK, returned 1, buf="/Applications/Xcode.app/Contents/Developer" out=0,0,1
```

-- the real lookup, finding this Mac's actual developer directory, out of a
cache extraction. `DEVELOPER_DIR=/tmp/zzz` is honoured too. On iOS there is no
developer directory to find, so it returns false, which is exactly the stub's
answer and exactly what makes the callers skip the respawn.

`rebuild_cryptex.sh` therefore ships the lifted library, and falls back to the
stub only on a machine without `ipsw`.

**Device-confirmed 2026-08-31.** Swapped the lifted library into
`apple-cryptexes/combined/usr/lib/libxcselect.dylib`, reinstalled the cryptex,
and `vmmap` and `heap` both run against it. So all 63 libSystem imports do
resolve on iOS 27, which was the one risk the SDK `.tbd` check could not settle.
`libxcselect-stub/` has been deleted.

Worth noting how small the swap was: the 12 binaries reference the library by
**path** (`@executable_path/../usr/lib/libxcselect.dylib`), not by cdhash, and
the lifted library carries the same `LC_ID_DYLIB`. So replacing the one file and
reinstalling was enough -- no rebuild, no re-converting binaries. The cdhash
keying applies to the trust cache, which `srdtool cryptex install` rebuilds from
the staged directory.

Two checks worth keeping:

* **The stub's ABI was right.** `libxcselect.tbd` in the MacOSX SDK lists 12
  `xcselect_*` symbols; the stub exported exactly those 12, and so does the
  lifted library. Diff-clean either way.
* **iOS exports all 63 of the library's imports.** Unlike the stub, the real
  library imports 63 libSystem symbols, and a single missing one would stop it
  loading -- taking all nine tools with it. Every one of them, including the
  private-looking `__xpc_runtime_is_app_sandboxed`, `_malloc_type_malloc`,
  `__os_assumes_log` and `_proc_pidpath`, appears as an exact token in the
  iPhoneOS SDK's 376 `.tbd` files.

`libxcselect` is Apple-proprietary with no upstream, and exists on disk
nowhere: `Xcode.app` and the Command Line Tools ship only the `.tbd` text stub,
which carries no code. The cache is the only copy, which is why lifting it had
to work.

### Who actually depends on the stub

Measured on the current cryptex (`apple-cryptexes/combined`) with
`imports_by_library()`, not on the pre-blocklist tree. Only **12** binaries
reference `libxcselect` now, not the 106 of the original scan, because the 94
xcrun shims were blocklisted:

| symbol imported | count | binaries |
|---|---|---|
| `_xcselect_get_developer_dir_path` | **9** | `atos`, `filtercalltree`, `heap`, `kmutil`, `leaks`, `malloc_history`, `stringdups`, `symbols`, `vmmap` |
| `_xcselect_invoke_xcrun` | 3 | `DeRez`, `actool`, `xcrun` |

So yes, `heap` is one of them. Eight of the nine are the memory-analysis and
symbolication tools and are the whole point of the stub. `kmutil` is in the list
but fails anyway on seven other macOS-only libraries. The remaining three are
leftover shims that now fail cleanly with `ENOENT` instead of failing to load.

### Never hardcode the cryptex mount path

The mount point carries a per-install random suffix
(`com.research.base-cryptex.Zbk8Q0`), so an absolute path breaks on the next
install. The stub's install name is
`@executable_path/../usr/lib/libxcselect.dylib`, which is stable for a binary in
`<cryptex>/bin`. `machomorph --provide-lib` derives the same relative name from
`--cryptex-bindir` / `--cryptex-libdir` and warns if the dylib's own
`LC_ID_DYLIB` disagrees.

**A dylib can only reach the device inside the cryptex.** Copying one over with
`scp`/`ssh` does not work and never will: the trust cache is keyed by cdhash and
is built by `srdtool cryptex install` from the staged directory, so anything not
in that directory at install time is unsigned as far as AMFI is concerned. The
whole flow is therefore: build the dylib locally -> `machomorph --provide-lib`
stages it into `<cryptex>/usr/lib` and repoints the binaries -> `srdtool cryptex
install <cryptex>`. Adding one library means reinstalling the cryptex. This is
also the only way a locally built binary ever loads on an SRD.

### How to rebuild the whole thing

```sh
./machomorph.py --scan -p ios -v 26.0 --cryptex /path/to/cryptex \
    --weaken-missing --keep-going --weaken-unresolvable
srdtool cryptex install /path/to/cryptex
```

The `--provide-lib` and separate-lift dance this used to need is gone: the scan
lifts `libxcselect` itself, because the nine tools that need it say so. See
"The architecture: one tool".

A full `--scan` of `/usr/bin /usr/sbin /bin /sbin` finds 733 executable Mach-Os
and converts them in one run, ending with a summary that ranks the still-missing
libraries by how many binaries each blocks.

### CONFIRMED ON DEVICE (2026-08-30)

**The stub works, and all eight tools run.** With
`combined/usr/lib/libxcselect.dylib` in place and the binaries repointed at
`@executable_path/../usr/lib/libxcselect.dylib`, **`atos`, `symbols`, `vmmap`,
`heap`, `leaks`, `malloc_history`, `stringdups` and `filtercalltree` all start
and print their usage** on the SRD (iPhone18,3, iOS 27.0 `24A5424a`) with **no
environment variable** -- `xcselect_get_developer_dir_path` returning false is
enough to skip the respawn, as predicted from the `cbz w0` at the call site.

The arm64e worry did not materialise: a locally built, non-platform arm64e dylib
loads fine into an arm64e process as long as it is inside the cryptex and thus
covered by the trust cache.

All **106** binaries that reference `libxcselect` have been rebuilt against the
stub and staged into `apple-cryptexes/combined` (verified: 0 still point at
`/usr/lib/libxcselect.dylib`, 106 point at the stub). Of those, the **8** that
actually call `xcselect_get_developer_dir_path` are the ones that gain anything
-- `atos`, `symbols`, `vmmap`, `heap`, `leaks`, `malloc_history`, `stringdups`,
`filtercalltree`. The 94 xcrun shims now load and fail cleanly with `ENOENT`
instead of failing to load, which is tidier but not useful.

Reproduce with:

```sh
xargs ./machomorph.py -p ios -v 26.0 --cryptex <cryptex> \
    --weaken-missing --keep-going --loader-path --cryptex-libdir lib \
    < list-of-macos-originals
srdtool cryptex install <cryptex>
```

Note BSD `xargs` has no `-a`; feed the list on stdin.

### machomorph derives the split itself now

The 94/9 classification above was originally done by hand with `nm -mu`.
`--provide-lib` now does it automatically: `MachO.imports_by_library()` reads
the two-level-namespace library ordinal out of each undefined `nlist_64`
(`n_desc >> 8`, indexing the dylib load commands -- still present in
chained-fixup binaries and far less work than walking the fixup chains), and
`export_trie_symbols()` walks the replacement's `LC_DYLD_EXPORTS_TRIE`. Verified
symbol-for-symbol against `nm -mu`. The batch report then prints:

```
symbols used from /usr/lib/libxcselect.dylib:
    94  _xcselect_invoke_xcrun
          DeRez, GetFileInfo, ResMerger, Rez, SetFile, SplitForks, +88 more
     9  _xcselect_get_developer_dir_path
          atos, filtercalltree, heap, kmutil, leaks, malloc_history, +3 more
     1  _xcselect_find_developer_contents_from_path, ... (7 symbols)
          xcode-select
```

and warns per binary when a bundled replacement does *not* export something the
binary imports -- "loads but crashes if it calls them", which is exactly the
failure mode weak-linking produces. So the next stub library does not need this
analysis repeated by hand.

## The `xcrun` shims are not a dead end -- ship the real tools

`xcselect_invoke_xcrun`, disassembled: it refuses under App Sandbox, calls
`xcselect_get_developer_dir_path`, and if that succeeds looks for
`<devdir>/usr/lib/libxcrun.dylib` to hand off to. If there is **no** developer
dir it falls back to searching absolute directories for `<dir>/<tool>` --
starting at `/usr/libexec/DeveloperTools` and walking a table of others -- and
`exec`s the first hit. Failing that it calls `xcselect_trigger_install_request`
and prints the familiar "no developer tools were found" error.
`/usr/libexec/DeveloperTools` does not exist even on macOS, and `/usr/libexec`
is not writable on iOS, so that fallback is not usable.

But the point is that the shim is only a resolver: **the real tools port fine.**
`otool` in the toolchain is a symlink to `llvm-otool` (72 KB), which links only
`/usr/lib/libc++.1.dylib` and `/usr/lib/libSystem.B.dylib` -- both in the iOS
cache. A survey of
`Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin`:
**105 of 108 executables resolve every dependency on iOS.** Only `ld-classic`
(`libxar.1.dylib`), `m4` and `yacc` (themselves xcselect shims) are blocked --
and `gm4`, `bison` and `byacc` are the real versions of the latter two.

Two things to know:

* They are **arm64, not arm64e**, unlike everything else ported so far.
* Several need `@rpath` dylibs from the toolchain's own `usr/lib`:
  `libcodedirectory.dylib` (8 tools), `libLTO.dylib` (`ld`, `libtool`,
  `dyld_info`) and `libtapi.dylib` (`ld`). Their rpath is
  `@executable_path/../lib/`, so they go in `<cryptex>/lib` and need **no**
  path rewriting -- stage them with `--cryptex <cx> --cryptex-bindir lib`.
  `machomorph --dylib-index` cannot validate an `@rpath` reference and reports
  it as missing; that warning is expected here.

### What is worth having on the device, and what is not

`--scan-xcode` converts the toolchain, applying a blocklist (`XCODE_SKIP` in
machomorph.py) built on one question: does the tool *inspect* a binary, or
*build* one? There is no source on the phone, so compilers are dead weight --
`clang` alone is 141 MB and `swift-frontend` 171 MB.

**The trap:** the tools worth keeping *are* llvm binaries. `otool` IS
`llvm-otool`, `nm` IS `llvm-nm`, `objdump` IS `llvm-objdump`. A blanket
`llvm-*` block removes exactly what you want. Block by purpose, never by prefix.
`XCODE_KEEP` exempts `swift-demangle` and `c++filt` from the `swift*`/`c++`
patterns for the same reason -- demangling is reverse engineering.

**Kept (32, of which 7 are symlink aliases), ~55 MB + 76 MB of libLTO:**

| group | tools |
|---|---|
| dump | `otool`/`llvm-otool`, `otool-classic`, `objdump`/`llvm-objdump`, `strings` |
| symbols | `nm`/`llvm-nm`, `nm-classic`, `c++filt`/`llvm-cxxfilt`, `swift-demangle` |
| Mach-O edit | `install_name_tool`, `strip`, `nmedit`, `segedit`, `vtool`, `lipo`, `bitcode_strip`, `ctf_insert`, `codesign_allocate` |
| dyld | `dyld_info`, `dyld_analyzer` |
| debug info | `dwarfdump`/`llvm-dwarfdump`, `dsymutil` (47 MB), `unwinddump` |
| other | `size`/`size-classic`/`llvm-size`, `readtapi`/`llvm-readtapi` |

**Dropped (54):** `clang*`, `swift*` (except `swift-demangle`), `sourcekit-lsp`,
`clangd`, `docc`, `tapi`, `metal*`, the asset compilers, the build-cache
helpers, coverage/profiling (`gcov`, `llvm-cov`, `llvm-profdata` -- useless
without an instrumented build), and the classic unix build tools (`ar`, `bison`,
`flex`, `m4`, `gperf`, `indent`, `ctags`, `rpcgen`, `unifdef`).

Also dropped: **`ld`, `libtool`, `ranlib`** -- linking and archiving is
building, not inspecting. That is worth noting because `ld` was the only user of
`libtapi.dylib` and of `libswiftDemangle.dylib`, so dropping it removes two
staging problems at once. `--no-xcode-blocklist` takes the lot (~+600 MB).

### The two `@rpath` dylibs that must come along

`libcodedirectory.dylib` (73 KB) is needed by 7 of the kept tools --
`install_name_tool`, `strip`, `segedit`, `nmedit`, `bitcode_strip`,
`ctf_insert`, `vtool`. `libLTO.dylib` (76 MB) is needed by `dyld_info`, and it
is worth its size: `dyld_info` imports `_LLVMCreateDisasm`,
`_LLVMCreateDisasmCPU`, `_LLVMDisasmInstruction` from it -- **libLTO carries
LLVM's disassembler**, which is squarely a reverse-engineering capability. That
was found with the new `imports_by_library()`, not by guessing.

Their rpath is `@executable_path/../lib/`, so they go in `<cryptex>/lib` and
need **no** rewriting:

```sh
./machomorph.py <toolchain>/usr/lib/libcodedirectory.dylib \
                <toolchain>/usr/lib/libLTO.dylib \
    -p ios -v 26.0 --cryptex <cx> --cryptex-bindir lib \
    --dylib-index ios27_24A5424a_index.txt
```

machomorph now resolves `@rpath/...` against the binary's own `LC_RPATH`
entries and checks whether the dylib is staged where they will look
(`resolve_rpath()`), so a correctly staged toolchain reports **25 of 25 ready,
zero warnings** instead of eight false "missing library" alarms. A cache index
can say nothing about `@rpath`; this is the part it can check.

### CONFIRMED ON DEVICE: arm64 is fine, all 32 run

Installed and probed 2026-08-30. **A plain arm64 binary runs from the cryptex on
this arm64e device** -- that worry is settled. `dyld_info -platform` on the
ported `otool` reports `otool [arm64] ... iOS 26.0`.

**All 32 Xcode RE tools run**, and so do all 8 memory/symbolication tools. Full
matrix in `device_probe_report.md`.

## Device probe: what actually runs (2026-08-30)

Every binary in the cryptex's `bin/` and `sbin/` was launched with no arguments
under a timeout. A binary that fails to load never reaches `main()`, so the load
classification is trustworthy; a binary that *does* load runs, which is why 124
were denylisted rather than launched -- power and disk changers (`reboot`,
`newfs_*`, `diskutil`), auth state (`unsetpassword`, `firmwarepasswd`), daemons
(`launchd`, `sshd`, `bluetoothd`) and interactive tools. The probe scripts are
in the report.

| outcome | count |
|---|---|
| loads and runs | 379 |
| loads, then blocks (daemon or interactive; still running at 10s) | 64 |
| fails: library missing | 243 |
| fails: symbol missing | 70 |
| not run (denylisted) | 124 |
| total | 880 |

A 5s timeout was too tight to distinguish "slow to start" from "hung", so the 64
were re-probed at 10s. All 64 still blocked -- they are daemons and interactive
tools, not slow starters. None of them is a load failure.

### The static analysis was validated, and it is sound

Comparing `machomorph --dylib-index` predictions against the 880 real launches:

| | count |
|---|---|
| failed on device, predicted | **243** |
| failed on device, **missed** | **0** |
| fine on device, predicted fine | 385 |
| fine on device, but flagged | 106 |

**Zero false negatives.** The 106 flagged-but-fine are not false alarms: 105 are
the libxcselect binaries, fine precisely because `--provide-lib` substituted the
stub, and the check was run against the unmodified macOS original. The 106th is
`swift-inspect`, which weak-links `libswiftRemoteMirror`.

What static analysis could not see *then* was the **symbol** level: all 70
symbol failures were invisible to it. That is no longer true -- see "Predicting
a symbol failure on the Mac", which flags 39 of 39 real failures and 0 of 384
working binaries. The sentence is left here because it was the honest reading of
this measurement, and because the correction is the interesting part.

### What blocks the most, and whether it is worth fixing

`JavaLaunching` (32 -- the whole JDK), `OpenDirectory` (28), `libcups.2` (25),
`libnetsnmp.25` (18), `libssl.48` (18), `libcrypto.46` (9), `Kerberos` (8),
`Cocoa`/`AppKit`/`ApplicationServices` (21 combined). None is fixable by path
rewriting -- iOS does not ship them. A stub is not an option either: stubbing
`libcups` or `JavaLaunching` means reimplementing them. The one plausible target
is **OpenSSL** -- a real `libssl`/`libcrypto` built for iOS would unblock 27
binaries including `openssl`, `tcpdump` and the postfix suite -- but that is a
port, not a shim.

Top repeat symbol failures: `_syslog$DARWIN_EXTSN` (11 -- the macOS-only
`$DARWIN_EXTSN` variant), a Swift `_stdlib_isOSVersionAtLeast` variant (6),
`__qtn_file_alloc` (3, quarantine), `_FSCloseFork` (3, Carbon),
`_AuthorizationCreate` (3, macOS-only Security).

## Device probe after the from-scratch rebuild (2026-08-31)

The whole tree rebuilt from an empty `lifted/` and an empty cryptex, installed,
and every binary in `bin/` launched. Raw data in
`measurements/device_probe_2026-08-31_rebuilt.tsv`.

| outcome | previous final probe | after the rebuild |
|---|---|---|
| loads and runs | 399 | **429** |
| fails: library missing | 0 | **0** |
| fails: symbol missing | **39** | **0** |
| SIGKILLed | 0 | **0** |
| crash | 1 | **0** |
| blocked (daemon or interactive) | 16 | 20 |
| skipped (denylist) | 64 | 76 |

**No binary in the cryptex fails to launch, for any reason.** That is the first
time, and it is not luck: `machomorph` refuses to port a binary the launch
prediction says cannot start, so the 45 that would have failed were never
staged. The probe is now a check on the prediction rather than a way of
discovering failures -- and it agreed with it exactly.

Of 384 crash reports on the device, **zero are `EXC_ARM_PAC_FAIL`**, so every
one of the seven freshly lifted libraries is sound on every path the probe
reached. The only crash generated by the probe itself is `nfsstat`, with
`SIGNAL Bad system call: 12` -- it loads and runs, then makes an NFS syscall iOS
does not implement. That is a runtime failure, not a linking one, and nothing
static can predict it.

Confirmed working on device from this clean build: `openssl` (LibreSSL 3.3.6,
correct digests), **`curl` at http=200 with `ssl_verify_result=0`**, `tcpdump`,
`dtrace -l` reaching its own initialisation, `perl` 5.034001 with `Digest::MD5`
and **`Sys::Syslog`** (the XS module the rename rescued -- it was silently being
skipped), `date`, `logger`, `scp`, `ssh-keygen`, the llvm tools (`otool -L`,
`nm -mu`, `dyld_info`), and `vmmap $$` giving real output, which confirms the
lifted `libxcselect` works from its new `lib/` location.

## Predicting a symbol failure on the Mac (2026-08-31)

This file used to say, in two places, that the symbol level was beyond static
analysis:

> What static analysis cannot see is the **symbol** level: all 70 symbol
> failures were invisible to it. Only launching finds those.

That is no longer true, and the thing that forced the issue was `curl`. Getting
it working took **four install-and-probe cycles**, each revealing the symbol
behind the one just fixed:

| round | error | actual cause |
|---|---|---|
| 1 | `_syslog$DARWIN_EXTSN` | iOS lacks the variant. Renamed |
| 2 | `_ASN1_STRING_get0_data` | `libcurl` named `/usr/lib/libcrypto.46.dylib` absolutely, so libcrypto never loaded under that name |
| 3 | `_GSS_C_NT_HOSTBASED_SERVICE` | `dsc.rebind` dropped `N_WEAK_REF`, making all 246 of libcurl's weak imports hard |
| 4 | `_SecCertificateCopyLongDescription` | iOS genuinely lacks 3 Security symbols. Weakened |

Each round cost a rebuild, an install and a reboot to learn one symbol. Every
one of the four was visible in the file the whole time.

### It is the default, not a report

`machomorph` runs the prediction on every conversion and **refuses to port a
binary that cannot launch**, because a binary that dies in dyld is not neutral:
it is dead weight in `bin/` that SHADOWS a working native tool of the same name
when the cryptex is earlier in PATH. That trap is already recorded in this file
-- it is why `ios_native_commands.txt` exists.

```
$ machomorph.py /usr/bin/logger -o logger_ios -p ios -v 26.0
skipped: /usr/bin/logger: will fail at launch on 1 symbol(s) the target does
not export: _syslog$DARWIN_EXTSN (from libSystem.B.dylib)   (--force to
convert anyway)

$ machomorph.py /usr/bin/logger -o logger_ios -p ios -v 26.0 --darwin-extsn
Output to                 logger_ios
```

That is the whole four-round curl story reduced to one line of output that also
says what to do about it.

| flag | effect |
|---|---|
| *(default)* | predict, and refuse to port what will not launch |
| `--force` | port anyway, with a warning. For when you know better than the SDK -- a private framework, or a newer OS than the stubs |
| `--no-symbol-check` | skip the prediction entirely |
| `--sdk-path PATH` | which SDK's stubs define the target surface. **Not** `--sdk`, which is the SDK *version* written into `LC_BUILD_VERSION` |

A batch reports the skipped set at the end, ranked by which symbol blocks the
most binaries -- the same shape as the missing-library summary, and the input
`data/blocklist_symbols.txt` used to need a device probe to produce.

### `cryptex/symbols.py`

    python3 -m cryptex.symbols --all --cryptex DIR --dylib-index FILE

Reads the two-level-namespace ordinal of every bind, and asks the iPhoneOS
SDK's `.tbd` stubs whether the target exports it. Run as step 8b of
`rebuild_cryptex.sh`.

**Validated against 423 real device launches** (`device_probe_2026-08-31_final.tsv`):

| | |
|---|---|
| died on device, predicted to fail | **39 of 39** (37 naming the same symbol) |
| ran fine, wrongly condemned | **0 of 384** |

It also flags the pre-fix `libcurl` from rounds 3 and 4 correctly; round 2 is
`verify_cryptex` check 3. So all four rounds were catchable before any install.

The analysis lives in `machomorph.py` (`TargetSymbols`, `MachO.bound_imports()`,
`unresolvable_imports()`) and `cryptex.symbols` is a thin CLI over it, so the
report and the conversion gate cannot drift apart.

### Four rules it took real errors to get right

**1. Only what the chained-imports table binds can fail.** An undefined
`nlist_64` with no entry there is never resolved. Apple's own `swift-inspect`
carries an undefined, absent `__swift_FORCE_LOAD_$_swiftIOKit` (a Swift
autolink marker) and runs fine on iOS; `appleh13camerad` has three absent
`AppleISPEmulator` constants and runs. Judging from the symbol table condemns
both -- that was 7 of the first 36 false positives.

**2. A weak-linked ABSENT library does not make its imports optional.** Only
the per-symbol `weak_import` bit does. `LC_LOAD_WEAK_DYLIB` tolerates the
library's absence; a *hard* import from it still kills the process. That is
exactly round 3 -- Kerberos is absent, and `_GSS_C_NT_HOSTBASED_SERVICE` was a
hard import from it.

**3. The chained table's weak bit, not the symbol table's `N_WEAK_REF`.** They
disagree in real binaries. Apple's `swift-inspect` marks 8 symbols weak in the
symbol table and 1 in the chained table, and it is the chained one dyld reads.

**4. `dyld_chained_import` comes in three sizes, and format 3 is 16 bytes.**

```
1 DYLIB_CHAINED_IMPORT           4 bytes   u32: ord:8  weak:1  name:23
2 DYLIB_CHAINED_IMPORT_ADDEND    8 bytes   the same u32, then i32 addend
3 DYLIB_CHAINED_IMPORT_ADDEND64 16 bytes   u64: ord:16 weak:1 pad:15 name:32
```

Reading format 3 as 8 bytes walks into the addends and yields library ordinals
in the thousands -- `dscl` decoded as ordinal 3589 of 6 dylibs. Only format 1 is
common, which is why the other two go unnoticed; `machomorph` now has one
`chained_import_fields()` that every caller uses.

### What it deliberately will not claim

The SDK ships stubs for `/usr/lib` and public frameworks only -- **no
PrivateFrameworks**, no `libpcap`, no `CoreSymbolication`. A symbol from a
library with no stub is reported `unknown` (with `--show-unknown`), never as a
failure. `tcpdump` imports 90 `libpcap` symbols and works perfectly, and
claiming those are broken would make the tool worse than useless. A false
positive is the expensive mistake here: it would have us weakening symbols that
are fine.

### Also fixed while doing this

* **`dsc.rebind` dropped `N_WEAK_REF`** when synthesising the imports table, so
  every weak import in *every* lifted library became hard. Fixed at source;
  `machomorph --fix-weak-imports` repairs an already-lifted file without a
  re-lift. Only `libcurl` (246) and `TrustEvaluationAgent` (1) were affected.
* **`machomorph --weaken-symbol SYM`** marks one import weak in both tables, so
  an absent symbol binds NULL instead of killing the process. It trades a
  certain failure for a conditional one -- the binary loads, and a path that
  calls the symbol crashes -- so it is only for a path the tool does not need.
  Used for curl's three Security symbols, all Secure Transport client-cert and
  verbose-cert-description paths.
* **`verify_cryptex` check 3 only walked `bin/`.** A bundled library
  referencing another bundled library absolutely was invisible, which is how
  round 2 shipped. It now checks the libraries too, and `cryptex.restage` scans the
  library directories as well.
* **Match on `(name, ordinal)`, never the name alone.** The same symbol name
  appears several times in an imports table with different ordinals and
  different weak flags -- Apple's `codesign` has three entries for one Swift
  dispatch thunk. Keying on the name alone would flip a deliberately-hard
  import in an untouched Apple binary.

### Still open

* Install and test the binutils. `otool -L`, `nm`, `lipo -info`, `size`,
  `strings` on a cryptex binary would cover it.
* Add a regression test for `--provide-lib`, `--scan` and the symlink aliases.

## Rebuilding the cryptex (2026-08-30, current procedure)

`./rebuild_cryptex.sh <cryptex-root>` does the whole thing. Read it before
changing anything -- the step order matters, see below.

Result: **460 converted + 131 aliases in `bin/`, 835 MB**, no binary that is
known to fail, nothing redundant with iOS.

### Three lists, and what each is for

* **`blocklist_ios.txt`** (399 names) -- fed to `--exclude-from`. Four sections:
  iOS ships its own build (88); fails to load, library absent; fails on a
  missing symbol; and the community iOS-native binaries already in the
  cryptex's `bin/` (14: `bash`, `vim`, `less`, `ldid`, `plutil`, ...).
* **`ios_native_commands.txt`** (88) -- what iOS actually ships, read off the
  device with `ls /bin /sbin /usr/bin /usr/sbin`. **This is not the same as the
  cryptex's contents.** The cryptex is what someone *added* to a device that
  has almost nothing: iOS has no `bash`, no `vim`, no `less`. Confusing the two
  is a mistake I made and had to undo.
* **`device_probe_report.md`** -- the measurements the blocklist is derived from.

**43 binaries were being ported redundantly**, including `ps`, `netstat`,
`ifconfig`, `route`, `mount`, `launchd`, `ioreg`, `taskinfo` and `spindump`.
A port is never better than the native build -- the iOS one is compiled against
the real iOS surface, the macOS one is merely retargeted -- and worse, a port in
the cryptex's `bin/` **shadows** the native one when the cryptex is earlier in
PATH.

### Three ordering traps, all hit for real

1. **A batch undoes `--provide-lib`.** `--scan` converts `/usr/bin/curl` too,
   and without the `--provide-lib` flags it leaves the reference at the absolute
   `/usr/lib/libcurl.4.dylib`, weak-linked -- so curl *loads* and then crashes
   on the first call. The rescued tools must be re-converted **after** the main
   batch. Step 5 of the script.
2. **Aliases clobbering real tools.** `/usr/bin` hard-links one xcrun shim
   inode under **78 names** -- `otool`, `nm`, `clang`, `git`, `make`, `python3`,
   `strings`, `lipo`, `strip`, `dyld_info`, `dsymutil` are all the *same file*
   (`ls -li` shows one inode, link count 78). machomorph converts the inode once
   and links the rest, but those link names collide with the real Xcode tools.
   Fixed: an alias is never created over a name a real conversion already
   claimed (`skipped 11 that a real binary already claims`).
3. **Writing through a stale symlink.** `open(output, "wb")` on an existing
   symlink writes into its *target*. machomorph now unlinks first.

Trap 2 also fixed a silent data-loss bug: `scan_binaries` used to deduplicate by
`(st_dev, st_ino)`, which dropped 77 of those 78 names without a word. Hard
links are now grouped and aliased instead, like symlinks.

### Rescued by bundling a library iOS does not have

`--provide-lib` is not only for stubs: the library can be the real macOS one,
pulled out of the shared cache with `ipsw dyld extract` and converted like any
other Mach-O. The dependency closure is what decides whether it is worth it:

| tool | extra libraries | size | verdict |
|---|---|---|---|
| `curl` | `libcurl.4.dylib` | 0.7 MB | ported |
| `dtrace` | `libdtrace.dylib` | 0.5 MB | ported; needs kernel support, untested |
| `systemstats` | CoreDisplay, CoreWLAN, IOPresentment, GPUWrangler, libDiagnosticMessagesClient | 3.1 MB | ported |
| `system_profiler` | 19, incl. **AppKit, SkyLight, HIToolbox, OpenGL** | 58.8 MB | **no** -- that is the macOS window server; it would load and have nothing to talk to |

A bundled library needs its own `LC_ID_DYLIB` rewritten to the
`@executable_path`-relative name, and any references *between* bundled libraries
rewritten too (`CoreDisplay` pulls in `GPUWrangler`, `IOPresentment` and
`libDiagnosticMessagesClient`). `--change` on the library itself does both.

**Still to try, same technique:** `zsh` needs only `libpcre.0.dylib`, and
`perl` only `libperl.dylib`. `openssl`/`tcpdump` and 25 others need a real
OpenSSL for iOS -- a port, not a shim, but it would unblock 27 binaries.

### `spindump`, `taskinfo`, `footprint`: use the native ones

All three exist on iOS already (`/usr/sbin/spindump`, `/usr/bin/taskinfo`,
`/usr/bin/footprint`), and the ports fail anyway -- `spindump` on absent
`DebugSymbols`, the other two on `responsibility_get_*` symbols iOS does not
export. Blocklisted.


## Lifting a library out of the dyld shared cache (solved 2026-08-30)

An earlier note in this file concluded this was impossible. That was wrong, and
the correction is the interesting part: the three errors dyld gives are three
separate problems, and stopping at the third one -- because `codesign` also
refused -- confused "codesign rejects my malformed output" with "this cannot be
signed". It could; the file simply had 0x9ac bytes of slack past `__LINKEDIT`.

The full chain, all now handled in `machomorph.py`:

1. `incompatible platforms: iOS - macCatalyst` -- a macCatalyst-capable library
   carries two `LC_BUILD_VERSION` commands. `set_platform()` drops the extras.
2. `__DATA_CONST segment missing SG_READ_ONLY flag` -- cache images do not carry
   it. `fix_data_const_flags()` restores it, on `__AUTH_CONST` too.
3. `segment '__AUTH' vm address out of order`, then `file offset out of order`,
   then `mmap ... errno=22` -- `relayout_for_standalone()`.
4. Loads but `dlsym` finds nothing -- the export trie is empty.
   `build_export_trie()` rebuilds it from the symbol table.

### Why the relayout does not move anything

Cache segments are non-monotonic *and* not page aligned (`__DATA_CONST` at
`...5a8`, `__AUTH_CONST` at `...358`) because images share pages. The instinct
is to rebase to a clean layout -- but addresses are baked into places nothing
could rewrite: every ADRP/ADD pair in the code encodes a PC-relative distance to
data, and none of that is in any relocation table.

So nothing moves. Each segment is grown **backwards** to the page boundary below
it, zero-filling the gap, which page-aligns the segment start while leaving
every byte at its original address. A uniform shift first makes `__TEXT` page
aligned so the mach header stays at file offset 0; the symbol table's absolute
`n_value`s follow that shift.

That is the right thing for the *lift*, and it is the whole reason a lifted
library spans 1.6-2.0 GB. It is not, however, permanent: "none of that is in
any relocation table" is true, and irrelevant, because the ADRPs can be found
by decoding rather than by looking them up. See "Compacting a lifted image",
which is a separate pass run after the lift has been judged sound.

### The export trie

Empty in a cache image -- the cache holds exports centrally. Rebuilt from
`LC_SYMTAB` (defined external symbols, addresses relative to the image base).
It must be a **radix tree**: a flat trie with one child per symbol is accepted
by the format but breaks lookup whenever one name is a prefix of another, since
dyld descends the first matching edge and never backtracks (`_foo` would
swallow `_foobar`).

### Two staging bugs the clean-cryptex rebuild exposed (2026-08-31)

Both were silent, both were in the *staging* rather than the conversion, and
both are the kind that only show up when you look at the finished tree.

### The hand-written tool list leaves binaries pointing at nothing

`bundle.py` is given its tools by name -- curl, openssl, tcpdump, dtrace,
systemstats, perl, zsh -- and repoints exactly those at the libraries it
bundles. The main `--scan` batch converts *every* binary in /usr/bin and
friends, though, and some of those link the same libraries. Those keep the
absolute macOS path, weak-linked, so they load and then crash on the first call
into a library that is not on the device. CLAUDE.md already recorded this as
"a batch undoes `--provide-lib`" -- what was missed is that the hand-written
list is *why it keeps happening*.

Measured on the first clean build: **14 binaries**, and the interesting ones are
not obscure:

| binaries | still naming |
|---|---|
| `ssh`, `scp`, `sftp`, `ssh-add`, `ssh-agent`, `ssh-keygen`, `ssh-keyscan`, `sshd` | `libcrypto.46` |
| `httpd`, `htpasswd` | `libcrypto.46`, `libssl.48` |
| `snmptrapd` | `libcrypto.46` |
| `networksetup` | `CoreWLAN` |
| `csrutil`, `securityd` | `libDiagnosticMessagesClient` |

A working `ssh` client on the device is worth having, and it was one `--change`
away the whole time. `cryptex.restage` now finds them by measurement -- any binary
naming a library absolutely that iOS lacks and this cryptex already bundles --
and rewrites just that reference.

**Do not hand them to `bundle.py`.** Tried it; it is wrong, because bundle.py
computes each tool's *whole closure*. Asking it to fix `ssh` also drags in
Kerberos and libHeimdalProxy, `httpd` brings libapr/libaprutil, `snmptrapd` the
four net-snmp libraries, and `networksetup` pulls **AppKit, SkyLight, HIToolbox
and OpenGL** -- 37 extra libraries and 130 MB of macOS window server, two of
which (`Cocoa`, `ApplicationServices`) extract to 4096-byte stubs that will not
even sign. The library those binaries need is already staged; the closure is not
the question being asked. So `cryptex.restage` edits the reference on the
**already-converted** binary in place, which also preserves the other
weakenings, any `--provide-lib` substitution and its entitlements.

### A lift flattens the library's own install name, so --change misses it

`bundle.py` rewrites each bundled library's `LC_ID_DYLIB` by passing
`--change <path the tool references> <@loader_path name>`. That silently does
nothing for a lifted library, because the lift ran `machomorph`, which flattened
`Versions/A` out of the library's *own* `LC_ID_DYLIB`:

```
systemstats asks for  .../CoreDisplay.framework/Versions/A/CoreDisplay
lifted CoreDisplay    .../CoreDisplay.framework/CoreDisplay      <- ID
--change keyed on the first  ->  never matches the second
```

So four of the sixteen bundled libraries shipped with their original absolute
install names while every binary asked for `@loader_path/../lib/X`:
`CoreDisplay`, `CoreWLAN`, `CrashReporterSupport`, `TrustEvaluationAgent`.
machomorph *did* warn (`has install name ..., but binaries will ask for ...`)
and the warning scrolled past in a 5785-line build log. `bundle.py` now keys the
rewrite on `mm.dylib_id(local)` as well as on the referenced path.

Note which four they were: exactly the lifted ones whose reference carried
`Versions/A`. `GPUWrangler` and `IOPresentment` came out right by luck -- they
are reached *through* the already-flattened `CoreDisplay`, so the referenced
path and the install name happened to agree.

### The lesson: check the tree, not the log

Both bugs were reported by the tools and lost in the noise. So there is now a
gate, `cryptex.verify`, run as the last step of `rebuild_cryptex.sh` and
exiting non-zero:

1. every Mach-O parses and is built for the target platform
2. cpusubtype is one iOS will run (arm64e ptrauth v0, or plain arm64)
3. no binary names a bundled library by absolute path
4. every bundled library's `LC_ID_DYLIB` is what binaries actually ask for
5. every `@loader_path` / `@executable_path` reference resolves to a real file
6. every bundled library carries `LC_DYLD_CHAINED_FIXUPS`
7. everything is code signed

Run it before an install cycle, not after.

## The clean test cryptex (2026-08-31)

`apple-cryptexes/machomorph-test` holds only `dropbear` and
`securityresearchd`, so nothing shadows a port and nothing hand-made is at risk.
That makes it the right target for a full-tree measurement -- and it changes one
assumption: **iOS itself ships no shell and no coreutils**. The whole of /bin,
/sbin, /usr/bin and /usr/sbin on the device is daemons plus a handful of
diagnostics (`ios_native_commands.txt`), with no `sh`, `ls`, `cat` or `sleep`.
Everything the probe uses therefore comes out of the cryptex being tested, which
is why `device_probe.sh` runs under `<cryptex>/bin/bash`.

Current state: **598 entries in bin/** (472 binaries + 126 symlink aliases),
16 bundled libraries, 402 MB, `cryptex.verify` clean.

Getting the probe onto the device: `scp` still does not work (iOS has no
sftp-server), but piping through `cat` does, and a shell script is data rather
than code so AMFI does not care:

```sh
ssh root@DEVICE 'cat > /tmp/device_probe.sh' < device_probe.sh
ssh root@DEVICE '<cryptex>/bin/bash /tmp/device_probe.sh <cryptex>' > probe.tsv
```

## Device probe on the clean cryptex (2026-08-31)

580 binaries launched on the SRD (iPhone18,3, iOS 27.0 `24A5424a`) from the
clean `machomorph-test` cryptex. Raw results in `device_probe_2026-08-31.tsv`.

| outcome | 2026-08-30 (old cryptex) | 2026-08-31 |
|---|---|---|
| loads and runs | 379 | **418** |
| fails: library missing | **243** | **1** |
| fails: symbol missing | 70 | 61 |
| SIGKILLed | not measured | 83 |
| blocked (daemon/interactive) | 64 | 16 |

**The 243 library failures are down to one.** That is the blocklist plus
`--dylib-index` plus the lifts doing their job: nothing is shipped that is
known to fail on an absent library. The one remaining is `systemstats`, for the
VM-span reason below.

### There is no ssh on the device, and no shell either

Testing had to go through `srdtool research spawn`, because `ssh` was refused at
the TCP level. The cause was in the cryptex: the dropbear LaunchDaemon's
`ProgramArguments[0]` is `/usr/bin/cryptex-run` -- resolved *inside* the cryptex
-- and `cryptex-run` was not there. It is a small Apple-signed helper that reads
`CRYPTEX_MOUNT_PATH`, sets `PATH` and execs the named binary; copy it from
`combined/usr/bin/cryptex-run` and dropbear starts. **That one missing file is
the whole reason ssh did not work**, and a cryptex whose daemon cannot start
still installs and mounts fine, so nothing else complains.

Two things worth knowing about the transport that replaced it:

* `srdtool research builtin scp` moves files both ways, which is the answer to
  "iOS has no sftp-server".
* `securityresearchd` crashes every few minutes and launchd's KeepAlive brings
  it back, so **every call needs a retry**, and a long-running probe has to be
  driven in slices from the Mac rather than detached on the device (a detached
  process is killed when the spawn's process group goes, `nohup` included).

`CRYPTEX_SHELL=/bin/bash` in the plist is resolved relative to the mount, so it
picks up `<cryptex>/bin/bash`. In `combined` that is a community iOS-native
build; **our ported macOS bash works too** -- confirmed, it runs and forks.

### What works, measured

| tool | result |
|---|---|
| `openssl version` | LibreSSL 3.3.6 |
| `openssl dgst -sha256` | `ba7816bf...` for "abc", correct |
| `curl https://www.apple.com/` | **http=200, ssl_verify_result=0**, 254322 bytes |
| `curl -V` | curl 8.7.1, LibreSSL/3.3.6, zlib/1.2.12 |
| `tcpdump --version` | works -- the path that used to SIGSEGV |
| `perl` + `Digest::MD5` | 5.034001, correct md5: libperl and the XS modules load |
| `zsh` + `zsh/pcre` | works, but see the MODULE_PATH note below |
| `llvm-otool -L`, `llvm-nm -mu`, `dyld_info -platform`, `lipo -info`, `vtool -show-build`, `llvm-cxxfilt`, `swift-demangle` | all work, on real iOS binaries |
| `vmmap`, `heap`, `leaks`, `malloc_history`, `stringdups`, `filtercalltree`, `atos`, `symbols` | all 8 reach their own usage, so the lifted `libxcselect` works |
| `vmmap $$` | **real output** -- introspects a live process, ARM64E/iOS/load address |
| **`dtrace -l`** | **no longer SIGSEGVs.** It now reports "DTrace device not available on system" -- its own error, past its own logic |
| `systemstats` | still fails: `vm_allocate(size=0x6CDC8000)` |

`dtrace -l` is the headline. It used to fault inside the cache-extracted
`libdtrace`; the lifted one runs, gets to dtrace's own initialisation, and the
only thing stopping it is that the iOS kernel has no DTrace. That is the correct
answer, and it is as far as this tool can go.

### `export MODULE_PATH=` was wrong advice

`zmodload zsh/pcre` failed with `dlopen(/usr/lib/zsh/5.9/zsh/pcre.so)` -- the
compiled-in path -- even with `MODULE_PATH` exported. **`module_path` is not one
of the zsh arrays tied to an environment variable** (`path`/`PATH` is,
`module_path`/`MODULE_PATH` is not), so the export does nothing. Setting the
array works:

```sh
module_path=($CRYPTEX_MOUNT_PATH/share/zsh/5.9)   # in ~/.zshenv
```

`PRIVILEGED` was off, so this is not the setuid-hardening path -- it is simply
not a tied variable. `rebuild_cryptex.sh` prints the correct form now.

### The xcrun shims do not just fail, they shadow the real tools

**83 SIGKILLs, and 78 of them are one file.** The 95 binaries in /usr/bin whose
whole body is `xcselect_invoke_xcrun` are a single hard-linked inode, and on iOS
they are killed outright rather than merely failing.

That was known to be useless cargo. What was not known is that they were
**taking the real tools' names with them**:

```
bin/otool -> DeRez        bin/nm -> DeRez         bin/objdump -> DeRez
bin/dwarfdump -> DeRez    bin/size -> DeRez       bin/c++filt -> DeRez
```

Six names, and exactly the six that are *symlinks* rather than real files in the
Xcode toolchain -- machomorph already refuses to alias over a real conversion,
which is why `strings`, `strip`, `lipo`, `install_name_tool`, `vtool`,
`dsymutil`, `dyld_info` and the rest were safe. When both sides are aliases,
the /usr/bin scan simply runs first and wins.

The capability was never missing (`llvm-otool`, `llvm-nm`, `llvm-objdump`,
`llvm-dwarfdump`, `llvm-size`, `llvm-cxxfilt` were all staged as real files), but
anyone typing `otool` got a shim that SIGKILLs.

**Fixed by excluding the shims by path**, which needed a new capability:
`--exclude` matched the basename only, and a bare `otool` line would have
dropped the toolchain's copy along with the shim. A pattern containing `/` is
now matched against the whole path, so `blocklist_ios.txt` carries
`/usr/bin/otool` and friends -- 95 entries, identified by symbol
(`_xcselect_invoke_xcrun`) rather than by hand. `bin/` goes 598 -> 520 and the
six names now point at the real tools.

### A lifted library reserves 1-2 GB of address space

`systemstats` is the last library failure, and the reason is not the lift being
wrong -- it is the relayout being *right*. A lifted library keeps the cache's
segment addresses, because an ADRP immediate is a fixed PC-relative distance and
nothing can rewrite it. So `__TEXT` stays near `0x18x` and `__LINKEDIT` at
`0x1ff96c000`, and dyld reserves the whole lowest-to-highest span at load:

| library | span |
|---|---|
| `CoreDisplay` | 2091 MB |
| `libDiagnosticMessagesClient` | 1972 MB |
| `CoreWLAN` | 1887 MB |
| `CrashReporterSupport` | 1844 MB |
| `IOPresentment`, `GPUWrangler` | 1826 MB |
| `libxcselect` | 1765 MB |
| `TrustEvaluationAgent` | 1659 MB |
| `libdtrace` | 881 MB |
| any source-built library | 0-77 MB |

**One of those loads; six do not.** `libxcselect` at 1765 MB is fine, and
`libdtrace` at 881 MB is fine -- both are a single lifted library in the
process. `systemstats` needs six at once and dies on the fifth:

```
Library not loaded: @loader_path/../lib/IOPresentment
  Referenced from: .../lib/CoreDisplay
  Reason: vm_allocate(size=0x6CDC8000) failed with result=3
```

`0x6CDC8000` is 1.8 GB, and `result=3` is KERN_NO_SPACE. So this is a hard
ceiling on how many lifted libraries one process can load, not a bug in any of
them. `cryptex.verify` now reports the spans so it is visible before an
install rather than as a runtime failure.

Compacting an image means moving data segments relative to `__TEXT` and patching
every ADRP that reaches them -- the cache-to-dylib converter that has been out
of scope throughout. `__LINKEDIT` alone could move freely (nothing ADRPs into
it, it is addressed by file offset) and would save ~285 MB, which is not enough
to matter. Left alone.

**That reading was too pessimistic, and the next section is the correction.**
It is true that compaction means patching every ADRP, and true that no table
records them. It does not follow that they cannot be found.

## Compacting a lifted image (2026-09-01)

`dsc/compact.py` closes the hole. Measured on the seven libraries this
project lifts:

| library | as lifted | compacted |
|---|---|---|
| `libxcselect` | 1683 MB | **0.14 MB** |
| `TrustEvaluationAgent` | 1582 MB | **0.09 MB** |
| `libpcre.0` | 1647 MB | **0.34 MB** |
| `libcurl.4` | 1579 MB | **0.72 MB** |
| `libdtrace` | 840 MB | **0.56 MB** |
| `libcrypto.46` | 471 MB | **1.61 MB** |
| `libssl.48` | 460 MB | **0.44 MB** |
| **all seven at once** | **8262 MB** | **3.90 MB** |

So the "two or three lifted libraries per process" ceiling is gone. Six at once
is 3.9 MB of reservation, which is what a normal dylib of that size costs.

### Why the ADRPs can be found, exactly rather than heuristically

The relayout note above says an ADRP immediate is a fixed PC-relative distance
recorded in no relocation table. Both halves are true. What makes it tractable
anyway is that an executable section of a lifted image is **pure instructions**
-- `LC_DATA_IN_CODE` is empty in all seven, checked, and refused if it is not --
so every 4-byte word can be decoded, and an ADRP is recognisable by opcode
alone.

The rule that turns this from a heuristic into an identity:

```
    target = page + imm12,  imm12 < 0x1000
    => page IS the 4 KB page of the address the pair computes
```

So an ADRP whose page target lands in a segment can only be reaching that
segment. **The paired ADD/LDR never has to be found**, or identified correctly,
or found at all -- which matters, because that pairing is exactly the part
`dsc.gotscan` gets wrong often enough to have a paragraph of apology about it.
Move a segment by a page multiple and add the same delta to the page target,
and every pair reaching it computes the same byte as before.

Measured, on the seven lifts: **every ADRP lands inside the image**, zero
outside, so the rewrite set is completely enumerable. libcrypto is the largest
at 3192 ADRPs repointed (4468 more point into `__TEXT`, which does not move).

The rest is bookkeeping over everything else that spells an address: segment
and section headers, `n_value` in the symbol table, the chained-fixup rebase
targets and each `dyld_chained_starts_in_segment.segment_offset`, and the
export trie.

### What it refuses, and why that list is short here

A **relative**-reference format encodes a distance between two segments rather
than an address, so a per-segment move breaks it and no ADRP scan would notice:
ObjC relative method lists (`__objc_const` -> `__objc_selrefs`) and Swift's
int32 relative pointers. `dsc.compact` refuses an image with `__objc*` or
`__swift*` sections. **None of the seven is ObjC or Swift**, which is why this
was cheap. `--rigid` is the fallback for one that is: it moves the data
segments as a single block, preserving every data-to-data distance, and
recovers much less (the `__TEXT`-to-`__DATA_CONST` jump is most of the span).

### The check that makes it safe to believe

Before writing anything out, `dsc.compact` builds `pc -> (segment, offset in
segment)` for every ADRP in the file, does the move, rebuilds the same map, and
**refuses to write output unless the two are identical**. That is not a
sample or a smoke test: it is every reference in the image, and it says the
thing that matters -- no ADRP changed which byte it names.

Two more checks, both from rules this file already records:

* `dyld_info -exports` against `nm` on the output. The export trie stores
  offsets from the image base, and a moved data export has to be re-encoded --
  the same class of bug `--reserve-header` had, where `dlsym` reports a wrong
  address without complaint. 3815 of 3815 agree on libcrypto.
* the addresses are re-encoded as **padded ULEB128** of the original byte
  length, so no node in the trie moves and nothing else in `__LINKEDIT` has to
  be repacked. In fact no byte in the file changes position at all: compaction
  edits instructions and address fields in place, and the file layout it
  inherits from the lift is already correct.

### Run it AFTER the gotscan verdict, not before

This ordering is real, and `dsc_lift.sh` enforces it. `dsc.gotscan` recognises
a leftover cache reference by the address landing **outside every segment** --
and compaction is precisely what fills that outside in. On a compacted
`libcrypto` one of its 11 known decoding artefacts stops being reported for
that reason alone, and an artefact and a real leftover would become
indistinguishable. Judge the lift first, then compact it.

### How to use it

```sh
./machomorph.py /usr/lib/libxcselect.dylib \
    -o lifted/libxcselect.dylib -p ios -v 26.0 --change ...

python3 -m dsc.compact lifted/libdtrace.dylib -o lifted/libdtrace.dylib
```

**It is the default as of 2026-09-01** (`--no-compact` opts out; the
`DSC_COMPACT=0` environment variable was the shell pipeline's spelling). It was opt-in while the local test loop
was the only evidence; the device probe of 2026-09-01 settled it -- 15
compacted libraries, 429 binaries, every one of them in the same bucket as the
uncompacted reference. Three things make the default cheap: compaction refuses
anything it cannot prove safe, it verifies every ADRP still names the same byte
before writing, and `dsc_lift.sh` treats a refusal as a warning that keeps the
uncompacted lift -- so the failure mode of having it on is the behaviour of
having it off. And for an ObjC image it is not an optimisation at all but a
requirement: dyld reads `__objc_imageinfo` by VM offset before mapping the
file, so an uncompacted ObjC lift does not load.

### Verified locally; NOT yet device-probed

All seven were retargeted to macOS and exercised through
`native/dlcall_test` plus a harness that does real work rather than
merely reaching the first import, and compacted output matches the lift
byte-for-byte in behaviour:

| library | before and after compaction |
|---|---|
| `libcrypto.46` | `LibreSSL 3.3.6`, `sha256("abc") = ba7816bf...15ad` |
| `libpcre.0` | `8.44 2020-02-12`, `^a(b+)c$` matches `abbbc`, rejects `axc` |
| `libcurl.4` | `libcurl/8.7.1 ... LibreSSL/3.3.6`, `curl_easy_escape("a b") = a%20b` |
| `libssl.48` | `SSL_CTX_new(TLS_client_method())` returns a context |
| `libxcselect` | the real developer dir, and honours `DEVELOPER_DIR` |
| `libdtrace` | `dtrace_open` returns without faulting |
| `TrustEvaluationAgent` | loads and calls |

Note which paths those are: the version strings are reads through globals,
which is the exact dereference an unrepaired extraction cannot survive, and
`sha256` is a real computation through the library's own data tables.

`codesign --verify` passes on all seven and `dsc.gotscan`'s verdict is
unchanged (`AUTHENTICATED_LEFTOVERS: 0`), with the one artefact-count change
explained above.

### Staged into a cryptex, and what that broke (2026-09-01)

Rebuilding `apple-cryptexes/machomorph-test` with compaction on -- from an
empty `lifted/` and an empty `bin/`, so every lift ran end to end -- took three
attempts, and the two failures are both worth keeping.

**1. `bundle.py --lift` was silently handing back stale EXTRACTIONS.**
`obtain()` asked "is there a cached copy?" before "was a lift asked for?", and
an earlier `--dry-run` had left plain extractions in
`/tmp/machomorph-extracted`. So `--lift` produced exactly the `NO FIXUPS`
libraries it exists to prevent, and said so in its own summary four screens
later. That is the **fourth** instance of the pattern this file already has
three of: *"the file is there" is not a check.* The cached copy is now reused
only when it actually carries `LC_DYLD_CHAINED_FIXUPS`.

**2. Compaction failing is not a lift failure -- but it was treated as one,**
and `set -e` took the whole build down with it after step 1 had already cleared
`bin/`. A refused compaction leaves the lift exactly as every lift was before
this step existed: good, just wide. `dsc_lift.sh` now warns and carries on, and
the csrutil step is explicitly non-fatal because it is an experiment.

Result: **528 in `bin/`, 15 bundled libraries, 407 MB, `verify: all checks
pass`, `symbol_check: 0 of 528`.**

### An ObjC image cannot be compacted, and `--rigid` does not rescue it

`DiskManagement` is the first ObjC library this project has lifted, and the
refusal fired on it:

```
__TEXT.__objc_methlist   __TEXT.__objc_stubs   __DATA_CONST.__objc_classlist
```

An ObjC **relative method list** stores int32 offsets from the entry to a
selector reference. `DiskManagement` keeps `__objc_methlist` in `__TEXT` and
its selrefs in `__DATA`, so those offsets span exactly the distance compaction
changes -- and `--rigid`, which preserves only data-to-data distances, is no
help either. That correction matters because the first version of this file
claimed `--rigid` was the ObjC-safe fallback. It is not. Patching relative
method lists is what an ObjC image would need, and nothing here does it.

So the cryptex ships a **mixed** case, which is the more interesting test
anyway: `DiskManagement` at 1628 MB uncompacted, and every other lift at 0.09
to 1.61 MB.

### An ADRP pointing outside the image is left alone, not refused

`libcsfde` has two of `dsc.gotscan`'s tolerated unauthenticated leftovers, and
the first version of the compactor aborted on them -- it cannot tell an
ADRP-with-no-matching-ADD artefact from a real unrepaired cache reference.
It does not have to. Leaving the instruction untouched leaves it naming the
address it already named, so an artefact stays an artefact and a real leftover
stays exactly as broken as the lift handed it over. The division of labour is:
`dsc.gotscan` judges the lift, `dsc_lift.sh` refuses an AUTHENTICATED leftover
before compaction runs, and `dsc.compact` preserves whatever survives that.
`libcsfde` then compacts 1579 MB -> 0.19 MB with one site left alone.

## csrutil: the multi-lift test case (2026-09-01)

`bundle.py --lift --loader-path /usr/bin/csrutil` stages **five** libraries iOS
does not have, none of which exists as a file anywhere:

| library | as lifted | staged |
|---|---|---|
| `DiskManagement` | 1707 MB | **1628 MB** (ObjC, not compacted) |
| `libCoreStorage` | 1757 MB | **0.69 MB** |
| `libcsfde` | 1579 MB | **0.19 MB** |
| `libbootpolicy` | 1274 MB | **0.39 MB** |
| `libDiagnosticMessagesClient` | 1881 MB | **0.12 MB** |

8198 MB of contiguous reservation becomes 1629 MB, and `bundle.py`'s verdict
goes from `TOO MANY  5 at once will not fit` to `1 library reserves over
537 MB`. That is the whole point of the exercise: this is the closure the
previous session measured as impossible for address-space reasons, and the
only thing left above the line is the one library compaction refuses.

### Thirty weakened symbols, and why that is defensible ONLY here

`DiskManagement` (7) and `libcsfde` (23) import macOS-only Security APIs that
iOS has no equivalent of at all -- Authorization Services, `SecKeychainOpen`,
the `SecTransform` pipeline, and the FileVault recovery-key calls -- plus
`_KextManagerCreateURLForBundleIdentifier` and `_SCDynamicStoreCreate`. They
are weakened in `rebuild_cryptex.sh` step 2c, which binds them NULL: the
libraries load, and any path that reaches one crashes.

That is a far larger judgement than libcurl's three, and it is acceptable only
because of what is being tested. **csrutil reports SIP status and iOS has no
SIP**, so this was never going to be a useful tool. The question is whether
five lifted libraries LOAD in one process, which is a question about dyld, not
about FileVault. Do not copy this pattern to something meant to be used.

### DEVICE-CONFIRMED: the address-space ceiling is gone (2026-09-01)

Installed on the SRD and run by hand. The result is the third of the three
outcomes that were possible, and it is the good one:

```
dyld[82313]: Symbol not found: _DAUnregisterApprovalCallback
  Referenced from: .../com.research.base-cryptex.SqAYNU/lib/DiskManagement
  Expected in:     /System/Library/PrivateFrameworks/DiskArbitration.framework/DiskArbitration
Abort trap: 6
```

**Read what that is not.** It is not `vm_allocate ... result=3`. dyld maps every
image before it binds a single symbol, so reaching a symbol-binding error means
**all five lifted libraries mapped into one process** -- one 1628 MB ObjC lift
plus four compacted ones. The same closure uncompacted died in `vm_allocate` on
the fifth. That is compaction confirmed on device, which is the one thing the
local dlopen loop could not settle.

The remaining failure is an ordinary absent symbol, and it is the class of
thing this file has a whole section about.

### The PrivateFramework blind spot, closed with the iOS cache

`symbol_check` said `0 of 528` and was wrong here -- for a reason it documents
about itself: *"The SDK ships stubs for /usr/lib and public frameworks only --
no PrivateFrameworks."* `DiskArbitration` is a PrivateFramework on iOS, so all
45 symbols `DiskManagement` imports from it were `unknown`, and `unknown` never
fails a binary. The gate did exactly what it promises; the promise has a hole.

The hole is closable, because the iOS cache is on disk (an `ipsw extract
--dyld` of the IPSW) and it knows what every image really exports:

```sh
ipsw dyld symaddr --image /System/Library/PrivateFrameworks/DiskArbitration.framework/DiskArbitration \
     dyld_shared_cache_arm64e | grep -v 'private|' | awk '{print $3}'
```

Two things to get right, both of which bit on the first attempt:

* **Drop the `private|` rows.** `symaddr` prints local symbols beside exported
  ones, and only exported ones are bindable.
* **`MachO.bound_imports()` yields `(name, weak)` tuples, not names.** Comparing
  the tuple against a set of names reports *every* symbol as missing --
  including `_DASessionCreate`, which iOS obviously has. A result that says
  "45 of 45 missing" is a bug in the checker, not a finding.

Done correctly, across the whole csrutil closure -- `DiskManagement`,
`libcsfde`, `libCoreStorage`, `libbootpolicy`, `libDiagnosticMessagesClient`
and `csrutil` itself, over `DiskArbitration`, `APFS`, `MediaKit`,
`CoreAnalytics` and `ProtectedCloudStorage` -- there is **exactly one** hard
import iOS does not export:

```
HARD MISSING  lib/DiskManagement  DiskArbitration  _DAUnregisterApprovalCallback
```

The one the device reported. So the check reproduces the device's answer
exactly, on the Mac, before an install -- which is the whole four-round curl
lesson applied to a surface the SDK cannot see.

`_DARegisterDiskUnmountApprovalCallback` *is* present on iOS; only the
unregister half is missing. It is weakened (step 2c), so DiskManagement loads
and would crash only if it ever tore down an approval callback -- a path
`csrutil status` has no reason to take.

Checked against an iOS **26.5** cache while the device runs 27.0 `24A5424a`, so
this is a close proxy rather than the exact surface. It named the real failure,
which is the evidence that matters, but a 27.0 cache would be better.

**Built, 2026-09-01: `dsc.symindex`.** The paragraph that used to stand here
proposed exactly this and called it not yet needed. It was needed one session
later, by the same symbol, and it is now the default in a build with `--ipsw`.
See "The PrivateFramework blind spot, closed" below.

Note `device_probe.sh` denylists `csrutil` (on macOS it changes SIP state), so
it has to be run by hand. Anything it prints about SIP is a bonus, not the test.

### Round 2: past dyld, into libobjc -- and the ObjC gap is worse than recorded

With `_DAUnregisterApprovalCallback` weakened, csrutil gets further and dies
differently:

```
EXC_BAD_ACCESS, SIGSEGV, KERN_INVALID_ADDRESS at 0xfffffffefc0e2758
  libobjc.A.dylib +0x12114
  libobjc.A.dylib +0x11d90
  dyld            +0x4df34        <- image registration, before main()
```

`idevicecrashreport -e <dir>` again, and the crash report settles three things
at once:

* **All six images are in `usedImages`**, so every one of them mapped. The
  compaction result from round 1 holds.
* The frames are `dyld -> libobjc`, i.e. `map_images`/`load_images` walking
  DiskManagement's ObjC metadata at launch. Nothing of csrutil's own code ran.
* The lift said so in advance, and it was in the build log the whole time:

```
warning: __AUTH_CONST.__objc_const+0x1140 binds an unnamed target (0x1ff918739);
         left NULL -- this library is INCOMPLETE
warning: __AUTH_CONST.__objc_const+0x11b0 binds an unnamed target (0x1ff918719);
         left NULL -- this library is INCOMPLETE
```

`0x1ff918739` and `0x1ff918719` are unaligned addresses in the cache's
`.dyldreadonly` ObjC optimisation region -- **the same signature as CoreWLAN's
remaining 5**, the one item still open in the task list above. So
`DiskManagement` is the second library to hit it, and csrutil is blocked by it.

**The scarier hypothesis was checked and is wrong.** A literal zero written
into a slot that is part of a fixup chain would set `next = 0` and silently
orphan every later fixup on that 16 KB page. It is not in a chain: walking the
blob, neither offset appears among the 12592 chained slots, and 464 slots after
them on the same page are still linked and applied. They are two honest NULLs.

**Superseded, and read the next section instead.** The diagnosis below --
that this crash is the open ObjC-uniquing task -- is wrong. It was a reasonable
read of the two INCOMPLETE warnings, and it is what the lift log invited, but
the crash had three other causes and all three are now fixed. See "Lifting an
ObjC library out of the cache". The two `__objc_const` NULLs are real and are
still unrepaired; they are simply not what was killing the process.

**What this corrects.** This file records the blast radius of the ObjC gap as
"small and specific: `conformsToProtocol:` and `@protocol()` for those five
protocols in CoreWLAN". That was the reasoning from CoreWLAN, which is bundled
for a tool that never got that far. DiskManagement shows the real radius: the
ObjC runtime walks this metadata **at image registration**, so a NULL protocol
reference is not a dormant hole in one API, it is a **SIGSEGV before `main()`
for the whole process**. An ObjC library with an unrepaired protocol reference
does not load, full stop.

## Lifting an ObjC library out of the cache (2026-09-01)

`DiskManagement` is the first ObjC library this project has lifted, and it hit
**three separate bugs**, none of which is the one this file predicted. The
prediction was that the open ObjC-uniquing task was the blocker; it was not.
The reproduction loop that found all three is the local one: retarget the lift
to macOS and `dlopen` it, which reproduces the device's crash in two seconds
and gives you lldb.

### 1. dyld reads `__objc_imageinfo` by VM offset BEFORE mapping the file

```
EXC_BAD_ACCESS at 0x151cbcb9d
  dyld`dyld3::MachOAnalyzer::hasSwiftOrObjC(bool*) const + 136
  dyld`dyld4::JustInTimeLoader::makeJustInTimeLoaderDisk(...)
```

`hasSwiftOrObjC` walks the section table of the file **as mapped for
inspection**, and finds a section's content at its *VM offset from the image
base*. That is correct for a normal dylib, whose segments tile the file. In an
uncompacted lift `__DATA_CONST` is 1.3 GB above `__TEXT` in VM and 49 KB into a
1.4 MB file, so the read lands far off the end.

**Only an image with `__objc_imageinfo` is ever inspected that way**, which is
exactly why every non-ObjC lift has always worked and this one could not.

**So compaction is not optional for an ObjC lift, it is the fix.** `dsc.compact`
used to *refuse* ObjC images; it now compacts them and says why. The cost is
real but narrow, and is stated in the next-but-one section.

### 2. libobjc believes the image is still in the shared cache

With that fixed, the crash moves to where the device's crash was:

```
EXC_BAD_ACCESS at 0xfffffffef935af20
  libobjc.A.dylib`map_images_nolock + 724
    ->  ldr x9, [x8]        ; x8 = getPreoptimizedHeaderRW(hi)
```

`getPreoptimizedHeaderRW` looks the image up in the **cache's** preoptimized
header tables, by pointer arithmetic against the cache's own header array. A
lifted image is not in that array, so the index is nonsense and the result is a
wild pointer. libobjc only does this when the image says it was optimised by
dyld -- a flag in `__objc_imageinfo`.

Measured rather than assumed, by building a reference dylib with `clang`:

| image | `objc_image_info.flags` |
|---|---|
| a locally built ObjC dylib | `0x50` |
| `DiskManagement` from the cache | `0x59` |

So the cache adds `OPTIMIZED_BY_DYLD` (1<<3) and (1<<0).
`machomorph.fix_objc_imageinfo()` clears exactly those two during the
standalone relayout, beside `fix_data_const_flags()`, and reports
`Cleared dyld-optimised ObjC flags 0x0059 -> 0x0050`.

### 3. Every selector reference was bound as a C symbol, to NULL

This is the big one, and it is a `dsc.rebind` bug this file had already
half-documented. Its rule -- *"a bind the image's own symbol table does not list
gets a weak flat lookup, so a missing one binds to NULL instead of failing the
load"* -- is right for a C library, where the only casualties are C++ vtable
slots nothing calls. For an ObjC library it is catastrophic:

* a slot in `__objc_selrefs` points into the cache's uniqued **selector string**
  pool, and asked what lives there the cache answers with the selector text;
* a slot in `__objc_protorefs` points at a canonical **protocol** object, and
  the cache answers with the protocol name.

So `dsc.rebind` emitted, in DiskManagement, **948 weak binds for "symbols"
spelled `DADiskToUUID:`** and 2 for `SK_DM_Client2DaemonProtocol`, all against
libSystem, all NULL at runtime -- 953 of 1497 imports. `dyld_info -imports` on a
lift makes this obvious once you look:

```
0x002C  SK_DM_Client2DaemonProtocol [weak-import] (from libSystem)
```

**Neither reference needs the cache at all**, because the image carries its own
copy of both things. `dsc/objc.py` rewrites each bogus bind in place as a
rebase:

* a selref -> the selector text in this image's `__TEXT.__objc_methname`;
* a protoref -> the protocol object in this image's own `__objc_protolist`.

A chained bind and a chained rebase are both one word in the same chain, so the
11-bit `next` field is carried across and nothing moves. It runs in
`dsc_lift.sh` as step 4a, after `dsc.rebind` and before compaction.

### Result: ObjC works out of a cache lift

Verified locally on the pipeline-built library (`dsc/objc.py` reports
948 selector and 2 protocol references rebased, 0 unresolved):

```
loads
  class DMAppleRAID             23 methods   first selector: initWithManager:
  class DMCoreStorage           58 methods   first selector: initWithManager:
  protocol SK_DM_Client2DaemonProtocol    found
  protocol SK_DM_Daemon2ClientProtocol    found
  [DMManager sharedManager] -> <DMManager: 0x1054c73f0>
```

That last line is a real ObjC message send into a library that exists as a file
nowhere, returning a live object. Classes register, method lists carry the right
selectors, protocols resolve.

### Every lifted ObjC class had a NULL superclass, and that is `no class for metaclass`

The previous session read the `csrutil` abort as the open ObjC-uniquing task and
looked for it in csrutil's own image, because the metaclass address ended in
`0xfc8` and the slide put it there. That inference was wrong. The fault was in
`DiskManagement`, it was one field, and it reproduces locally in two seconds:

```
$ /tmp/msg /tmp/dm_old/lib/DiskManagement          # the lift as shipped
DMManager = 0x10991cfa0
objc[30316]: no class for metaclass 0x10991cfc8   <- the device's error, on the Mac
```

Note the address still ends in `0xfc8`. It is DMManager's metaclass, 0x28 above
the class, and it was never in csrutil at all.

**What the cache does.** A class object carries two names in the cache: the
mangled symbol `_OBJC_CLASS_$_NSObject` and the bare class name the ObjC
metadata spells it with. `dsc.rebind` asks the cache what lives at an address
and the lookup answers with the **bare** one, which the image does not import.
So the rule this file already records for `__platform_memchr` applies verbatim,
and the casualty is every class's `superclass` field:

| field | what the cache named it | bindable? |
|---|---|---|
| `class_t.superclass` | `NSObject` | **no**, flat weak bind, NULL |
| `metaclass.isa` / `.superclass` | `_OBJC_METACLASS_$_NSObject` | yes |

The metaclass side came out right on its own, because the mangled spelling is
the only name at *that* address. That asymmetry is the whole tell.

**Why it does not fail the load.** libobjc reads a NULL `superclass` as "this is
a root class", so the image registers and the classes appear. The damage shows
only when something walks the class/metaclass pair,
which is `getMaybeUnrealizedNonMetaClass` giving up and aborting inside
`objc_msgSend`. Measured on DiskManagement: **22 of 22 classes** had a NULL
superclass.

**The fix is in two places, and it needs both.** `resolve_alias` gains the
candidate `_OBJC_CLASS_$_<name>` for a bare name, so the correct spelling
reaches the synthesised imports table at all. Then `dsc.objc` re-checks each
reference **by field** and corrects the mangling if the position disagrees,
walking `__objc_classlist` to each `class_t` and the metaclass its `isa` names.
The name alone can never decide this, since `NSObject` is also a protocol and is
one in `__objc_const`. Position is authoritative, so the field pass is
deliberately prefix-tolerant rather than skipping anything already spelled as a
symbol.

Measured before and after, on the same eight classes:

```
BEFORE   DMManager  super=(NULL)     DMAPFS  super=(NULL)    ... all 22
AFTER    DMManager  super=NSObject   DMAPFS  super=NSObject  ... all 22
```

The same bug hits **constant objects**, whose `isa` is a bind on the bare name
in `__objc_arrayobj`, `__objc_intobj` and `__objc_dictobj`: 335 + 2 + 1 in
DiskManagement, all NULL. Those names were not in the imports table at all,
which is why the source fix in `resolve_alias` was needed rather than an
ordinal rewrite alone.

**Result: a lift with zero unrepaired ObjC references.** `dsc.objc` on the
re-lifted DiskManagement reports nothing left, where before it reported 367.

Checked before believing it, because a hard bind on a symbol iOS lacks is a load
failure rather than a NULL:

| symbol | iOS 27.0 export trie | ordinal in the lift resolves to |
|---|---|---|
| `_OBJC_CLASS_$_NSObject` | libobjc.A.dylib | libobjc.A.dylib |
| `_OBJC_CLASS_$_NSConstantArray` | CoreFoundation | CoreFoundation |
| `_OBJC_CLASS_$_NSConstantDictionary` | CoreFoundation | CoreFoundation |
| `_OBJC_CLASS_$_NSConstantIntegerNumber` | Foundation | Foundation |

Read off the real 27.0 cache from the IPSW rather than the SDK stubs, since
`_OBJC_CLASS_$_` symbols are not in the `.tbd` files. Note `ipsw dyld symaddr`
labels all four `(local|regular)`, which reads like "not exported" and is not
the right question. The export **trie** is, and `machomorph.export_trie_symbols`
answers it.

**And a checker bug worth recording, because it nearly became a false alarm.**
Mapping those ordinals to library names first said `NSConstantArray` binds
against libSystem, which would be a shipped load failure. The enumeration was
wrong: two-level ordinals count `LC_LOAD_DYLIB` and friends but **not**
`LC_ID_DYLIB`, and including it shifts every ordinal by one. The giveaway was
`_OBJC_CLASS_$_NSArray` resolving to libSystem too, which is obviously false.
Same shape as the `bound_imports()` tuple bug this file already records: a
result that indicts something obviously fine is a bug in the checker.

### Protocol conformance: repaired by field, and it was a SIGSEGV not a silence

This file recorded the 7 `__objc_const` binds as survivable, on the reasoning
that "a NULL baseProtocols means conforms to nothing". That is wrong. The list
itself is present and only its *entries* are NULL, so libobjc walks into them:

```
BEFORE   class_copyProtocolList(DMUDSWrapper)  -> SIGSEGV (rc=139)
AFTER    DMUDSWrapper  super=NSObject  protocols=1 NSSecureCoding
                       conformsTo(NSCoding)=YES
```

`dsc.objc` now walks `__objc_classlist` to each `class_ro_t.baseProtocols` and
`__objc_protolist` to each `protocol_t.protocols`, and rebases the entries of
those `protocol_list_t` arrays to the image's own protocol objects. All 5
protocols DiskManagement needs are defined locally, so nothing has to come from
the cache. `conformsTo(NSCoding)` being YES through `NSSecureCoding` shows the
`protocol_t.protocols` half works too, not just `baseProtocols`.

### Relative method lists: solved, and they were never only the protocols'

This file said the relative-method-list problem was the protocols', and that
"class method lists are pointer-based and are fine, which is why
`class_copyMethodList` works". Both halves are wrong. Every method list in
DiskManagement is relative, and every entry's `name` dangles:

```
DMUDSWrapper   methlist@0x199e2f088 (__TEXT.__objc_methlist)
               entsizeAndFlags=0xc000000f  count=9  relative=yes
   [0] name -> OUTSIDE the image
       types -> 0x199e7105f  '@16@0:8'     inside, correct
       imp   -> 0x199db02f8                inside, correct
```

`types` and `imp` are image-local and correct. Only `name` was rewritten, which
is the cache-uniquing signature exactly. The consequence is total: **no method
on a lifted ObjC class can be found by selector.** `class_copyMethodList`
returns the right count with `<null selector>` for every entry, and
`+[DMManager sharedManager]` is an unrecognized selector even once the class
hierarchy is sound.

**The offset is not relative to its own field.** That is the assumption that
wasted the most time here. Decoded as `&field + offset` the targets land in
unrelated frameworks' `__TEXT` (`libIPTelephony`,
`EmbeddedAcousticRecognition`, confirmed against the cache `.map`), and the
cache base does not work either. The list carries
`relativeMethodSelectorsAreDirectFlag` (0x40000000) beside the small-list flag
(0x80000000), and objc4 then takes the offset from a single **cache-wide
selector base**.

**That base is the start of the uniqued selector pool**, and it is one command:

```sh
ipsw dyld objc sel <cache>        # 1322244 selectors, addr: name
```

The minimum address in that dump is the base. On this Mac it is `0x1faa4dda0`,
the pool runs 48.7 MB to `0x1fdb0cb6b`, and with it **390 of 390** class and
metaclass entries decode to a real selector. `initWithManager:`, `dealloc`,
`DADiskToUUID:lookupMembers:lookupSpares:` -- the names the previous session
saw and could not explain.

Worth recording how the base was found, because guessing it did not work.
`ipsw dyld objc sel` was reached for only after a plain string search for
`initWithManager:` in the cache found *some other image's local copy* at
`0x182d4349f` and solving from it gave a base that validated 0 of 15. The
canonical copy is at `0x1fb3c57a0`, in the `.dyldreadonly` subcache, and only
the ObjC optimisation tables know that.

**The repair points `name` at one of the image's own `__objc_selrefs` slots,**
not at the string. Outside the shared cache objc4 reads a relative method name
as a pointer to a selector *reference*, and `fix_objc_imageinfo()` deliberately
clears the dyld-optimised flag, so a lifted image is always on that path. The
direct-selectors flag is cleared to match.

The worry this raised -- that a selector appearing only in a method list has no
selref, and there is no room to add one without moving a section -- **does not
materialise**: all 361 distinct selectors DiskManagement's method lists name
already have a selref, because the image sends them too. 0 missing. If one ever
is missing it is reported rather than guessed at.

Measured, on the same class:

```
BEFORE   DMCoreStorage  class_copyMethodList -> SIGBUS
AFTER    DMCoreStorage  INSTANCE methods (58): initWithManager: init dealloc
                        isEncryptedDiskForLogicalVolume:encrypted:locked:type:
                        logicalVolumeForDisk:logicalVolume: ...
```

### It must run AFTER compaction, and that is not optional

The repair makes `name` a `__TEXT` -> `__DATA_CONST` relative reference, which
is precisely the kind of cross-segment distance compaction changes. This file
already names that hazard when explaining what `dsc.compact` refuses. Running
the repair at step 4a, before compaction, produces a library whose method lists
decode to nothing at all -- which is how the ordering was learned, and it looked
exactly like the repair not working.

So `dsc_lift.sh` splits the ObjC work in two:

| step | pass | why there |
|---|---|---|
| 4a | selrefs, protorefs, class and protocol references | they are rebases, and compaction remaps rebases |
| 7 | relative method lists | they are inter-segment distances, valid only on the final layout |

`dsc.objc` is idempotent, so running it in both places is safe: the method-list
pass skips any list whose direct-selectors flag is already cleared. Without that
guard a second run decodes the repaired selrefs as pool offsets and reports all
515 entries as naming no selector.

### DEVICE-CONFIRMED: csrutil's ObjC subcommands run (2026-09-01)

Installed on the SRD and probed. Identity established first, as this file's own
rule requires: a fresh mount suffix (`QksHcd`), and `lib/DiskManagement` and
`bin/csrutil` hashed **on the device** with the cryptex's own `openssl dgst`
match the staged copies exactly. `shasum` is not in this cryptex, which is worth
knowing before reading an empty hash as a mismatch.

The staged tree was then re-derived from the final code and came back
byte-identical, so the build measured is the build described here rather than an
older one that happened to be lying around.

| subcommand | before | now |
|---|---|---|
| `csrutil` | usage, rc=64 | usage, rc=64 |
| `csrutil status` | its own SIP error, rc=69 | its own SIP error, rc=69 |
| `csrutil authenticated-root status` | **`no class for metaclass`, SIGABRT rc=134** | **`No macOS installations found`, rc=71** |
| `csrutil allow-research-guests status` | **same abort** | **`No macOS installations found`, rc=71** |

`No macOS installations found` is csrutil's **own** message from its own logic.
It reached `main()`, registered its ObjC, called through DiskManagement and
answered truthfully, which on an iPhone is the correct answer and the ceiling
this tool was always going to hit. The two subcommands that used to die inside
`libobjc` before `main()` now do not.

`csrutil clear` was not run. It is the third of the three that aborted, but it
is state-changing and `libbootpolicy` is in this closure, so it is not worth
poking at to confirm a fix the two read-only ones already demonstrate.

Nothing else moved. `openssl` (LibreSSL 3.3.6, correct SHA-256), `tcpdump`
(4.99.1 / libpcap 1.10.1 / LibreSSL 3.3.6), `dtrace -l` reaching its own
initialisation, `vmmap $$` against a live process, and `otool -L` all behave
exactly as recorded. Crash reports pulled with `idevicecrashreport -e`:
**0 `EXC_ARM_PAC_FAIL`**, and no csrutil or DiskManagement report at all.

So of the four independent reasons csrutil could not be ported, reason 4 (the
ObjC lifting bugs) is closed. Reason 1 stands and always will: iOS has no SIP.

## The wide port: 815 binaries, and what 44 ObjC lifts showed (2026-09-01)

Built `apple-cryptexes/machomorph-wide` by converting every system Mach-O whose
closure of iOS-absent libraries is 7 or fewer, ignoring the failure-based
blocklist so that anything newly fixed gets another chance.

| stage | count |
|---|---|
| Mach-O executables in /usr/bin, /usr/sbin, /bin, /sbin, /usr/libexec | 1282 |
| closure <= 7 libraries | 1170 |
| minus the 95 xcrun shims | 1075 |
| staged by bundle.py | 770 |
| plus the toolchain and ssh family carried over | **815** |

The 303 that did not make it were blocked by a **library** the symbol gate
refused, not by themselves: 36 libraries, led by `OpenDirectory` (54 tools),
`libcups.2` (24), `Kerberos` (22) and `LDAP` (17). Every one fails on macOS-only
Authorization Services and `SecKeychain*` calls, so none was ever going to work.

The 95 shims stay excluded even with the blocklist otherwise ignored, and the
reason is worth restating because it is not "they fail": they are one
hard-linked inode that owns the names `otool`, `nm`, `objdump`, `dwarfdump`,
`size` and `c++filt` in /usr/bin. Staging them takes those names away from the
real llvm tools. The two are mutually exclusive and the toolchain is the side
worth having, confirmed on device with `otool -hv /usr/lib/dyld` reading a
**native iOS** binary.

### The ObjC repairs generalise

This is the measurement the ObjC work was waiting for. Before today the project
had lifted exactly one ObjC library. This build lifted **44**, of which 21 are
staged:

| | |
|---|---|
| ObjC libraries lifted | 44 of 113 |
| relative method names repointed | **16192** |
| libraries reporting anything unrepaired | **0** |
| OBJC-namespace crashes in 103 device crash reports | **0** |
| `EXC_ARM_PAC_FAIL` | **0** |

`dsc.objc` re-run over `OpenDirectory`, `CoreWLAN`, `SkyLight`, `IOBluetooth`,
`SystemPolicy` and `login` reports nothing outstanding in any of them. So the
three fixes were not `DiskManagement`-specific.

Note the log does **not** show this on its own: `dsc_lift.sh` runs the step-4a
pass with `--quiet`, so the class and protocol counts never reach it and an
aggregate over the logs reads a misleading `0 class references repointed`. The
re-run is what actually confirms the repair.

### The remaining ObjC gap now has five instances, not one

`CoreWLAN`'s unnamed-target binds into the cache's canonical ObjC tables are no
longer a single odd library:

```
OpenDirectory       8 unnamed-target binds   0x1ff913b71 ...
CoreWLAN            5                        0x1ff915389
IOBluetooth         3                        0x1ff916559
SkyLight            3                        0x1ff911d51
libruby.2.6.dylib   1                        0x18050d90c   <- a different region
```

20 binds across 5 of 44 ObjC libraries, so it is rare rather than systemic. All
but `libruby`'s land in the `0x1ff91xxxx` ObjC optimisation region, the same
signature recorded for CoreWLAN. `libruby`'s outlier address is in the ordinary
TEXT range and may be a different cause wearing the same warning.

### Device probe: 814 binaries

Raw data in `measurements/device_probe_2026-09-01_wide.tsv`.

| outcome | count |
|---|---|
| loads and runs | 547 |
| skipped (denylist) | 83 |
| blocked (daemon or interactive) | 80 |
| crash | 62 |
| fails: symbol missing | 36 |
| fails: library missing | 4 |
| SIGKILLed | 2 |

**The 62 crashes are almost all one thing**: 37 SIGSEGV, and 36 of those are the
JDK launchers (`java`, `javac`, `jar`, `jshell`, ...) going through
`JavaLaunching`. That is the JDK not being present, not a lifting fault.

## A lifted library's thread-local variables, found and repaired

The most valuable thing the wide probe found, because it is a **new class of
lifting gap** that had been there all along and only fired once a library with
TLVs was bundled.

```
ssh-keygen: EXC_CRASH / SIGABRT, namespace DYLD
  failed to set up thread local variables for '.../lib/libEndpointSecuritySystem.dylib':
  malformed thread-local, offset=0xC800000000 is larger than total size=0xC8
```

A thread-local descriptor is `{ thunk, key, offset }`, three 64-bit words, and
`offset` is the variable's position in the TLV template. dyld validates it at
load and aborts the process before `main()` if it is out of range.

**The raw extraction already has it wrong**, so the lift does not break this. It
is how the cache stores the descriptors: dyld fills `key` and `offset` in for a
cache image from the cache's own TLV tables and never reads what is in the file.
`dsc.rebind` rewrites the `thunk`, because the slide info covers it, and leaves
the other two words alone because they are plain data.

### The reference that made the layout obvious

Guessing at the malformed words got nowhere. What settled it was diffing against
a **real, non-cache dylib that has TLVs** -- `libLTO.dylib`, from the Xcode
toolchain, which is a file on disk rather than a lift:

```
libLTO   desc: [thunk][key=0][offset=0x80]        <- 24 valid descriptors
libESS   desc: [thunk][0xc8][0xc800000000]        <- the cache's own bookkeeping
```

### The offsets are recoverable exactly, with no guessing

The linker emits a local `<symbol>$tlv$init` at each variable's storage:

```
__ZN4spar14sigbus_jmp_setE$tlv$init  @ 0x28418fd10   = __thread_bss + 0
__ZN4spar14sigbus_jmp_bufE$tlv$init  @ 0x28418fd14   = __thread_bss + 4
```

So `offset = addr(<symbol>$tlv$init) - start of the TLV template`, and `key` is
zero for dyld to assign. `MachO.fix_tlv_descriptors()` does exactly that, in the
same place as `fix_data_const_flags()` and `fix_objc_imageinfo()`.

**The template is a SPAN, not a sum of section sizes.** `__thread_bss` is
aligned after `__thread_data` and the gap counts. Summing the two sizes makes
the template look too small and condemns valid descriptors: libLTO has five
whose offsets fall in exactly that gap, and the first version of this reported
all five as malformed.

### The cache records the answer, and a stripped image needs it (2026-09-01)

The `$tlv$init` route above is exact, and it is not enough: the markers are
**local** symbols, so a stripped image has none. That was written down as a
known limitation with the note that it "will fire". Measured over the whole
macOS shared cache -- every one of its 3649 images -- it fires on nearly half:

| | |
|---|---|
| images with `__thread_vars` | **80** of 3649 |
| descriptors in them | 446 |
| descriptors malformed in the cache's way | **446 of 446** |
| descriptors with a usable `$tlv$init` | 233 |
| **images repairable by the symbol alone** | **45 of 80** |

So 35 images -- `libmecabra` with 44 descriptors, `libFosl_dynamic` with 31,
`libaxis` and `libusd_ms` with 27 each, `libncurses.5.4`, `libSparse`,
`Lexicon` -- could not be repaired at all, and would have shipped as libraries
that abort every process that loads them.

**The cache carries the offset itself**, and the previous session's reading of
those two words was one field out. Decoding all 446:

```
key    = (the real offset << 32) | <the cache's TLV key index, constant per image>
offset = (the template size << 32) | <unused>
```

so

```
    offset = key >> 32
```

Measured against the linker's own `$tlv$init` wherever it survives: **233 of
233 agree, across 45 images.** And `key >> 32` is in range for all 446, so it
repairs every one of the 80 images -- verified, `fix_tlv_descriptors()` now
reports 80 of 80 fully repaired with zero warnings, where it managed 45 before.

The docstring used to say `key` holds the *template size* in its low half. It
does not; that was a coincidence of the one library measured, whose template is
200 bytes = `0xc8` and whose cache key index also happens to be `0xc8`. The
size lives in the **offset** field's high half, and only 2 of 446 descriptors
make that coincidence.

`$tlv$init` still wins where it exists, because it is the linker's own ground
truth and because keeping it means the repair reproduces the bytes already
confirmed on device. The cache's copy is the fallback, and a disagreement
between the two -- never yet observed -- is reported loudly rather than
silently resolved.

**A free independent check came out of this.** `offset >> 32` is the cache's own
record of the template size, so it arbitrates the span-versus-sum question
above without needing a reference dylib at all: the span agrees in **80 of 80**
images, the sum in 75. Where the two disagree the cache's bookkeeping is not
laid out the way this code believes, so `key >> 32` is barred and only the
symbol is trusted.

### macOS dyld does not validate this at all, so the local loop cannot see it

The single most important thing to know about this bug class, and it inverts the
project's usual habit of proving things locally first.

The exact library, converted with the repair suppressed, carrying the exact
descriptors iOS refused (`offset=0xC800000000`, template `0xC8`):

```
$ native/dlopen_test ess.notlv
LOADS
```

**macOS dyld loads it.** So does it load an unrepaired `libncurses.5.4`. There
is no local test -- no `dlopen`, no `dlsym`, no `dlcall` -- that can reproduce
this failure, which is why it survived every check the project had until a
device probe found it.

That makes `MachO.malformed_tlv_descriptors()` and the `verify_cryptex` check
over it the **only** pre-device detection for this class, rather than a
convenience. Widening the local sample, as the previous session proposed, would
never have found it; the static census above is what widening actually looks
like here.

### The thunk bound a symbol iOS does not export

The third known limitation, and it turned out to be substantive rather than
cosmetic. A descriptor's first word is its resolver thunk, and `dsc.rebind`
names it from the cache, which pre-resolves it to libsystem's *implementation*:

| | thunk binds | in the image's symbol table? |
|---|---|---|
| the lift, as shipped | `__tlv_get_addr` `[weak-import]` | **no** |
| `libLTO`, a real linker's output | `__tlv_bootstrap` | yes |

`__tlv_get_addr` appears in **0** of the iPhoneOS SDK's 705 `.tbd` stubs;
`__tlv_bootstrap` appears in 13 of them, `libSystem.B.tbd` among them -- which
is the very library the bind names. So the shipped thunk was a weak flat bind
resolving to **NULL**, and the library worked only because dyld overwrites that
word during `setUpTLVs` before anything reads it. That is the same
"cache names the implementation, image imports the public name" rule this file
already records for `__platform_memchr`, and it belongs in the same place:
`ALIASES` in `dsc.gotscan` now maps `__tlv_get_addr` -> `__tlv_bootstrap`,
resolving only when the image actually imports the latter.

Re-lifted, the thunk binds `libSystem/__tlv_bootstrap` with no `[weak-import]`,
the descriptors come out byte-identical to the device-confirmed ones, and
`__tlv_get_addr` is gone from the image entirely.

**Device-confirmed on a second install** (mount `iPIX55`, the staged library
hashed on the device as `34a02906...`, matching): all eight weak-linkers still
run, `vmmap` still shows six segments mapped into a live `ssh-agent`, and there
are zero crash reports from that mount. Nothing else in the tree moved --
`openssl` (LibreSSL 3.3.6, correct SHA-256), `curl` (**http=200 verify=0**),
`tcpdump` 4.99.1, `dtrace -l` reaching its own initialisation, `vmmap $$`,
`otool -L` on a native iOS binary, and `perl` with `Digest::MD5` and
`Sys::Syslog` all behave as recorded. So the thunk change is a no-op on
behaviour, which is what it should be -- dyld overwrites that word either way.
The point of making it is that the image no longer carries a NULL weak bind
whose harmlessness depends on dyld's ordering.

The full census is `measurements/tlv_census_2026-09-01.txt`.

### DEVICE-CONFIRMED: the eight go from SIGABRT to running (2026-09-01)

Identity established first: fresh mount `rrUXjT`, 815 in `bin/` and 84 in
`lib/`, and `lib/libEndpointSecuritySystem.dylib` hashed **on the device** with
the cryptex's own `openssl dgst -sha256` matching the staged copy exactly
(`41982d9f...`).

| binary | before | now |
|---|---|---|
| `ssh-keygen` | **crash rc=134** | rc=1, its own getopt error; bare invocation starts generating a key |
| `ssh-add` | **crash rc=134** | rc=2, "Could not open a connection to your authentication agent" |
| `ssh-keyscan` | **crash rc=134** | rc=1, its own usage |
| `scp`, `sftp`, `ssh-agent`, `sshd`, `login` | denylisted, unprobed | all five reach their own getopt |

All eight of the weak-linkers load. The before-figures are
`measurements/device_probe_2026-09-01_wide.tsv`, and the device's own crash
reports carry the matching evidence from the **previous** mount (`4HsKym`):

```
namespace DYLD, code 9
failed to set up thread local variables for
  '.../com.research.base-cryptex.4HsKym/lib/libEndpointSecuritySystem.dylib':
  malformed thread-local, offset=0xC800000000 is larger than total size=0xC8
```

-- and **zero** reports from the current mount.

**And dyld really did load it, rather than skipping a weak reference.** That
distinction is the whole result, since all eight reference the library
`LC_LOAD_WEAK_DYLIB`, so `vmmap` on a live `ssh-agent`:

```
__TEXT       1040ec000-1040fc000  .../rrUXjT/lib/libEndpointSecuritySystem.dylib
__DATA_CONST 1040fc000-104100000  ...
__AUTH_CONST 104108000-10410c000  ...
__DATA       104100000-104104000  ...
__AUTH       104104000-104108000  ...
__LINKEDIT   10410c000-104118000  ...
```

Six segments mapped, spanning 176 KB -- so the image is loaded, its TLV
descriptors were validated and accepted, and compaction is holding.

### `xprotect` is not actually in this tree

Worth correcting, because the reasoning above rests on it. This file says
blocklisting `libEndpointSecuritySystem` "would break `xprotect`". In
`machomorph-wide` there is no `xprotect` and no `XprotectFramework`: the binary
is blocklisted on `_OBJC_CLASS_$_XProtectUpdate`
(`data/blocklist_symbols.txt`), so the symbol gate dropped it after `bundle.py`
had already pulled the library into the closure through it.

So nothing in the tree links the library strongly, and the only references are
the eight weak ones `cryptex.restage` repointed. The net effect is that eight
binaries now load a library none of them needs, for the sake of a tool that is
not shipped. Harmless now that the library is sound -- and it is what made the
device confirmation above possible -- but the sharper rule is that
`cryptex.restage` has no reason to repoint a weak reference when no staged binary
links that library strongly. Not changed here.

### It is self-detecting, not lift-only

The repair runs on every conversion and rewrites **only** a descriptor whose
offset is already outside the template, so an ordinary macOS binary is never
touched. Verified: libLTO's `__thread_vars` is byte-identical before and after,
and `/usr/bin/zsh` reports nothing.

That matters because the alternative -- gating on `needs_relayout()` like the
ObjC fix -- does not work here. This library's raw extraction does **not** need
relaying out, so it would have been skipped.

### And the gate

`verify_cryptex` fails on a bundled library with a malformed descriptor, so one
can never ship again. Tested by corrupting a descriptor back to the cache's
value and confirming it is caught, then restored and clean.

### Bundling a library can be worse than not bundling it

Worth keeping as a rule in its own right. These eight binaries reference
`libEndpointSecuritySystem` **weakly**:

```
login  scp  sftp  ssh-add  ssh-agent  ssh-keygen  ssh-keyscan  sshd
```

In `machomorph-test` the library was not bundled, the weak reference went
unsatisfied, dyld skipped it, and `ssh-keygen` worked. In `machomorph-wide` it
entered the closure through `XprotectFramework`, which links it **strongly**, so
`cryptex.restage` repointed all eight at the bundled copy -- and every one of them
then aborted in dyld before `main()`.

So `cryptex.restage` repointing a weak reference at a bundled library trades a
harmless absence for a hard dependency on a library that has to be correct. That
is right when the library works and strictly worse when it does not. The answer
is not to blocklist the library, which would break `xprotect`: it is to make the
library correct and to have a gate that proves it.

### The rule restage now follows

**A weak reference stays weak and absolute unless the bundled library is shown
to be loadable.** `library_is_sound()` checks the three things that have
actually bitten:

| check | what it catches |
|---|---|
| the file parses | a 4096-byte umbrella stub |
| carries `LC_DYLD_CHAINED_FIXUPS` | a raw cache extraction, which loads and then crashes on the first global |
| no malformed TLV descriptor | this bug |

`--repoint-weak` overrides it. Tested both ways: with the corrupted library
staged, restage reports

```
bin/ssh-keygen: left libEndpointSecuritySystem.dylib weak and absolute --
  malformed thread-local descriptor: descriptor at 0x28418fce0 has offset
  0xc800000000, template is 0xc8 bytes
```

and with the repaired one it repoints as before. Note this is deliberately a
**property of the library**, not a list of names. A name list is what this file
already records going wrong four times.

A strong reference is still always repointed, because there is nothing to
preserve: the binary cannot load without that library either way.

### Installing the cryptex can hang with no output

Worth recording because it cost most of a session and looks like nothing.
`srdtool cryptex install machomorph-test` sat for 18 minutes, then on a second
attempt another 8, producing **zero bytes** on stdout and leaving the device on
its old mount and old hashes throughout. Both were killed. The same command run
by hand by the user completed. So a silent `srdtool` is not progress, and the
device's mount suffix plus a hash of one changed file is the only way to tell
whether an install landed.

### A zero word is NULL, not a rebase to the image base

Found while walking the method lists, and worth keeping because it produced a
completely misleading error. `rebase_target()` returned `lay.base` for a word of
zero, so `DMManager`, whose `baseMethods` genuinely is NULL, handed the walker
the **mach header** dressed as a method list. It reported `entsize 64204`, which
is the low half of `0xfeedfacf`. The fix is one line, and the lesson is the
usual one: a struct field read out of a NULL pointer produces a plausible number
rather than an obvious failure.

### What is still broken, precisely

**Protocol conformance is not wired up.** 7 binds in `__AUTH_CONST.__objc_const`
-- a class's `baseProtocols` and a protocol's own `protocols` list -- are left
as weak binds and resolve NULL, so `class_conformsToProtocol()` returns 0 and
`class_copyProtocolList()` returns nothing. Everything else works.

Repairing them **by name was tried and is wrong**, and the reason is worth
keeping: in `__objc_const` a name is ambiguous. `protocol_t.name` is a `char *`
to the string `"NSObject"`, while a `baseProtocols` entry is a `protocol_t *` --
same spelling, two completely different targets. Rebasing a name field to the
protocol object earns:

```
EXC_BAD_ACCESS (code=261) libobjc`readClass + 216
  x8 = "NSObject"   x21 = "DMUDSWrapper"
```

Telling them apart needs structure parsing rather than name matching: walk
`__objc_classlist` to each `class_ro_t` and `__objc_protolist` to each
`protocol_t`, and repair **by field**. `dsc.objc` reports what it skipped
instead of guessing.

**Protocol method lists dangle.** The relative method lists in
`__TEXT.__objc_methlist` are the *protocols'*, and their `name` fields are int32
offsets the cache rewrote to reach its uniqued selector pool -- 20 MB outside
the image, broken before compaction touches them. Class method lists are
pointer-based and are fine, which is why `class_copyMethodList` works. Anything
that introspects a protocol's methods -- `NSXPCInterface interfaceWithProtocol:`
above all -- would read a dangling pointer.

That last point is also why compaction makes nothing worse here: these offsets
already point outside the image.

### DEVICE-CONFIRMED: compaction is a no-op on behaviour, and csrutil runs

Installed and probed 2026-09-01, over ssh (`ssh -p 2222 root@localhost`, password
`PASSWORD` -- much better than `srdtool research spawn`, which needs a retry every
few minutes because jetsam keeps killing `securityresearchd`). Raw data in
`measurements/device_probe_2026-09-01_compacted.tsv`.

Identity established first, as the cleanup session's lesson requires: all 16
files that changed are byte-identical between the local tree and the device.
Resolve the mount from the live shell (`$CRYPTEX_MOUNT_PATH`) rather than by
globbing `mnt/` -- there were **eight** stale mountpoints there, all reporting
an empty `bin/`, and the live one was none of them.

| outcome | reference (uncompacted) | now (all 15 compacted) |
|---|---|---|
| loads and runs | 429 | **429** |
| fails: library missing | 0 | **0** |
| fails: symbol missing | 0 | **0** |
| SIGKILLed | 0 | **0** |
| crash | 0 | **0** |
| blocked (daemon/interactive) | 20 | **20** |
| skipped (denylist) | 76 | 77 (+csrutil) |

**Zero binaries changed bucket**, and the only difference in the whole run is
csrutil, which is new and which the probe denylists. 0 `EXC_ARM_PAC_FAIL` in
the crash reports. So compaction -- 15 libraries, 8262 MB of reservation down to
83 MB, of which 73 is libLTO -- changes nothing about what runs.

Every compacted library exercised on real work, not just a usage message:

| library (compacted size) | on device |
|---|---|
| `libxcselect` (0.14 MB) | all 8 memory/symbolication tools reach their own usage; **`vmmap $$` gives real output** |
| `libdtrace` (0.56 MB) | `dtrace -l` reaches its own init: "system integrity protection is on", then "DTrace device not available" |
| `libcrypto`/`libssl`/`TrustEvaluationAgent` | `openssl version` = LibreSSL 3.3.6; `dgst -sha256` correct |
| `libcurl` (0.72 MB) | **`http=200 verify=0`** against apple.com |
| `libperl` (2.98 MB) | perl 5.034001, `Digest::MD5("abc")` correct, `Sys::Syslog` loads |
| `libpcre` (0.34 MB) | `zsh/pcre` compiles and matches |
| `libcrypto` via tcpdump | `tcpdump version 4.99.1 -- Apple version 158`, libpcap 1.10.1 |
| the llvm tools | `otool -L`, `nm -mu`, `dyld_info -platform`, `lipo -info` all work on a lifted library |

### csrutil: it runs, and three of five subcommands still abort in ObjC

```
$ csrutil                       -> usage, rc=64          the tool's own output
$ csrutil status                -> "failed to retrieve system integrity
                                    configuration", rc=69
$ csrutil authenticated-root status  -> objc[...]: no class for metaclass
$ csrutil allow-research-guests status  -> same
$ csrutil clear                 -> same, rc=134 (SIGABRT)
```

The first two are **success**: the binary loads, its ObjC registers, `main()`
runs, and `status` reaches its own logic and fails with its own message because
iOS has no SIP to report. That was the predicted ceiling and it is reached.

The other three abort, and the crash report localises it precisely:

```
exception:   EXC_CRASH / SIGABRT
termination: namespace OBJC, code 1
  csrutil +0x1b64 -> objc_msgSend -> libobjc +0x18dbc -> abort
```

`no class for metaclass` is libobjc's `getMaybeUnrealizedNonMetaClass` giving
up: a metaclass whose corresponding class it cannot find, scanning every
registered class. What is *not* the cause, each checked:

* **not a missing symbol.** Every `_OBJC_CLASS_$_` import of csrutil and of all
  five libraries exists in the iOS cache -- `NSTask` included, which was the
  obvious suspect and is present. 0 hard imports absent.
* **not an unrepaired lift.** DiskManagement is the only lifted library with
  ObjC sections at all, its `__objc_imageinfo` is the correct `0x50`, and it has
  no ObjC-name binds left.
* **not reproducible on macOS.** The same csrutil against the same libraries
  runs `authenticated-root status` fine locally, so it is specific to iOS's
  libobjc or its Foundation.

The metaclass address ends in `0xfc8` across runs, and the slide puts it in
**csrutil's own image**, not in a lifted library -- so the next place to look is
csrutil's own ObjC metadata after `machomorph` converted it, not the lifting.
Left open; the two working subcommands are as far as csrutil can usefully go
anyway.

### So csrutil cannot be ported today, for four independent reasons

Worth listing, because each was found by a different mechanism and only the
last one needed a device:

| # | wall | found by |
|---|---|---|
| 1 | iOS has no SIP for it to report | reading what the tool does |
| 2 | DiskManagement + libcsfde need 30 macOS-only Security symbols | `symbol_check` on the Mac |
| 3 | `_DAUnregisterApprovalCallback` absent from iOS DiskArbitration | the iOS cache, after the device named it |
| 4 | three ObjC lifting bugs (see the section above) | local `dlopen` + lldb |

Reasons 2 and 3 were worked around with weakenings. **Reason 4 turned out to be
three fixable bugs rather than the open ObjC-uniquing task**, and all three are
fixed: DiskManagement now loads and its classes, methods and protocols work.
What remains of it is protocol *conformance* and protocol *method lists*, which
csrutil is unlikely to need -- so csrutil is worth a device probe again.
Reason 1 still stands, and always will: iOS has no SIP to report.

**But the exercise did its job.** The question was whether compaction lifts the
two-or-three-lifted-libraries-per-process ceiling, and the answer is yes,
measured on the device: five lifted libraries, 8198 MB of reservation as
lifted, mapped into one process. csrutil was only ever the vehicle.

**The device is what settles it**, as it has been every other time in this
file: iOS dyld is stricter than macOS dyld, and a segment layout that macOS
accepts is exactly the kind of thing it has rejected before (`mis-aligned
LINKEDIT content` appeared only on device). The probe to run is a rebuild with
compaction on, an install, and `device_probe.sh` -- the eight memory tools
for `libxcselect`, `dtrace -l`, `openssl`/`curl`/`tcpdump` for the crypto
stack, and `cryptex.verify` going quiet about spans.

### The biggest remaining lever: `_syslog$DARWIN_EXTSN`

Of the 61 symbol failures, **16 are the same symbol**:

```
  16  _syslog$DARWIN_EXTSN          <- one shim would unblock all of these
   4  _OBJC_CLASS_$_JLRuntime       (JavaLaunching)
   2  _wordexp                       2  _pam_acct_mgmt
   2  _ODNodeCopyRecord              2  _KextManagerLoadKextWithIdentifier
   2  _DMUnlocalizedTechnicalErrorString
```

`syslog$DARWIN_EXTSN` is the macOS-only variant symbol; iOS libc exports plain
`syslog` and nothing else. It blocks `scp`, `sshd`, `date`, `logger` and 12 more
-- more than a quarter of all remaining symbol failures, and it is a pure
forwarding stub, not a reimplementation.

The catch is that it cannot be fixed by adding a library: the symbol is bound in
the **two-level namespace** to libSystem specifically, so a shim exporting it
would never be consulted. Redirecting it to a shim would mean editing the
import's library ordinal (the high byte of `n_desc`, and the chained-imports
table) and adding an `LC_LOAD_DYLIB`.

## `_syslog$DARWIN_EXTSN`: fixed by a string edit (2026-08-31)

None of that machinery was needed, and the reason is worth keeping, because the
expensive plan above was the obvious one and it was wrong.

**Plain `_syslog` is present on iOS, and the name is shorter.** So the import
does not have to be redirected to another library at all -- it can be *renamed*
inside its own storage. `_syslog$DARWIN_EXTSN` is 20 bytes, `_syslog` is 7, both
live in libSystem, and therefore:

* nothing moves -- no table is repacked, no segment relaid out, no load command
  added, no header room needed;
* the two-level-namespace ordinal is **unchanged**, which was the entire reason
  the other plan was hard.

`machomorph --redirect-symbol OLD NEW` does it, with `--darwin-extsn` as the
shorthand for the measured case. `rebuild_cryptex.sh` passes it to the main
batch, to the toolchain dylibs, to `bundle.py` and to `dsc_lift.sh`.

### Check the family before assuming it is missing

`$DARWIN_EXTSN` is a family and the instinct is that all of it is absent from
iOS. It is not -- measured against the iPhoneOS SDK's `.tbd` stubs:

| symbol | importers | on iOS? |
|---|---|---|
| `_realpath$DARWIN_EXTSN` | 73 | **present** |
| `_syslog$DARWIN_EXTSN` | 64 | **ABSENT** |
| `_fopen` / `_popen` / `_fdopen` / `_select` `$DARWIN_EXTSN` | 5 | present |

So the scope is exactly one symbol, which is what makes this cheap:

```sh
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
grep -rF '_syslog$DARWIN_EXTSN'   $SDK/usr/lib/*.tbd   # no hits
grep -rF '_realpath$DARWIN_EXTSN' $SDK/usr/lib/*.tbd   # hits
```

### The name lives in exactly two places, and both must be patched

Verified on `/usr/bin/logger`, and the shape is the same in every importer:

```
0xc12a  the LC_DYLD_CHAINED_FIXUPS symbols pool   <- what dyld binds through
0xc436  the LC_SYMTAB string table                <- what nm reads, and what
                                                     n_desc's ordinal pairs with
```

The fixups pool is the one that decides whether the process launches. The symtab
one keeps `nm -mu` and `MachO.imports_by_library()` honest -- and that function
is what `--provide-lib`'s symbol-coverage check and `cryptex.restage` rely on, so
letting the two disagree would quietly poison later analysis.

Both are uncompressed (`symbols_format=0`) in every binary and every lift
measured. A compressed pool is refused rather than mangled.

### Three things that had to be got right

* **Only whole, NUL-terminated strings count.** The match checks the preceding
  byte is NUL and the following byte is NUL, so a name merely *ending* in the
  needle can never be hit.
* **Refuse when names share storage.** String tables may overlap by sharing a
  suffix, so before writing, every `nlist_64.n_strx` and every chained-import
  name offset is checked: if one lands strictly inside the bytes about to be
  overwritten, the edit refuses instead of silently truncating a neighbour.
  `libcrypto` imports `_vsyslog` right beside `_syslog$DARWIN_EXTSN`, which is
  the case this protects.
* **An old-style `LC_DYLD_INFO` bind stream cannot be shortened**, because it
  spells names inline and is parsed sequentially -- the NUL padding after a
  shortened name would be read as `BIND_OPCODE_DONE` and truncate the binds.
  That is refused too. It never fires here: all 96 importers use chained
  fixups.

### On a lifted library it must run AFTER the rebind

This is the trap in `dsc_lift.sh`, and it is not obvious. `dsc.rebind` names
each cache GOT slot from the *cache* and then matches that name against the
image's own undefined symbols (`resolve_alias`). Rename the symtab first and the
cache's `_syslog$DARWIN_EXTSN` matches nothing, so the slot is left NULL --
trading a load failure for a null-pointer call, which is strictly worse.

So `dsc_lift.sh` holds `--darwin-extsn` / `--redirect-symbol` back from the
machomorph step and applies them after `dsc.rebind`, before `codesign`.

### Why it was worth more than the 7-to-9 binaries it was scoped at

The cryptex stopped source-building LibreSSL and now lifts Apple's `libcrypto`
out of the cache instead -- and **Apple's libcrypto imports the variant**. So
the library failed to load on device and took three working tools with it:

| tool | source-built | lifted, before the fix | after |
|---|---|---|---|
| `openssl version` | LibreSSL 3.3.6 | `Symbol not found: _syslog$DARWIN_EXTSN` | to be probed |
| `tcpdump --version` | works | same | to be probed |
| `curl https://...` | 200, verify=0 | `Symbol not found: _ASN1_STRING_get0_data` | to be probed |

The `curl` line reads like a separate bug and is not: that symbol is a *weak*
import from `libcrypto.46`, and `"Expected in: <no uuid> unknown"` is dyld
saying the expected image never loaded. **One root cause, three tools.**

### Measured after the change, on the Mac

* All **96** binaries in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` that import
  the variant convert with `--darwin-extsn`: 96 renamed, **0** left carrying it,
  0 refusals, `codesign --verify` clean.
* `nm -mu` shows `_syslog`, and `dyld_info -fixups` shows the bind as
  `libSystem/_syslog` -- same library, so the ordinal really did not move.
* Byte-diffing a converted binary against the same conversion without the flag:
  **identical file size**, and exactly two 13-byte differences (the two string
  regions) plus the code signature. Nothing else moved.
* Same on the lifted `libcrypto.46.dylib`, whose `__LINKEDIT` was repacked and
  whose fixups this project synthesised -- and `dsc.gotscan`'s verdict is
  unchanged by the edit.

`data/blocklist_symbols.txt` had 16 entries held back on this symbol; they are
retired (285 -> 269) by the file's own documented procedure. `cryptex.verify`
gained a check that nothing staged still imports it, since "the rename ran" is
exactly the sort of thing this project has shipped wrong before.

**Not yet device-probed.** That is the one thing that settles it.

### The semantics that are given up

`syslog$DARWIN_EXTSN` is the variant-symbol form macOS uses for the extended
behaviour; plain `syslog` is the same call with the older semantics. For a
command-line tool writing log lines that is a nuance, not a correctness
problem -- but it is a real difference, not a no-op. If some tool's logging
turns out to depend on it, the fallback is the forwarding shim described above,
and only then is the ordinal-rewriting machinery worth building.

### restage worked, and it was not enough on its own

The 14 binaries `cryptex.restage` repointed at the bundled libcrypto no longer fail
on a library -- they now fail on a *symbol*, which is progress but not a rescue:

| binary | now blocked by |
|---|---|
| `scp`, `sshd` | `_syslog$DARWIN_EXTSN` |
| `ssh` | `_gss_delete_sec_context` (Kerberos/GSS) |
| `httpd` | `_apr_base64_decode` (libapr, deliberately not bundled) |
| `csrutil` | `_DMUnlocalizedTechnicalErrorString` (DiskManagement) |
| `networksetup` | `_SCBondInterfaceCopyAll` |
| `snmptrapd` | `_init_netsnmp_trapd_auth` (net-snmp) |

So repointing removed a latent crash-on-first-call in every one of them, and in
no case was libcrypto the only thing missing. Fixing `syslog$DARWIN_EXTSN`
should take `scp` and `sshd` the rest of the way -- it is fixed as of
2026-08-31 (see "fixed by a string edit"), pending a device probe.

### A bug in the probe script itself, worth recording

`device_probe.sh`'s denylist is written several names to a line, and the first
version matched against `"\n$1\n"` -- which only ever hits a name alone on its
line. **The denylist silently never fired**, so the whole of it was launched:
`reboot`, `halt`, `shutdown`, `newfs_*`, `dd`, `rm`. Nothing came of it, because
they need arguments and most fail to load on iOS anyway, but that was luck. It
now flattens the list and matches on whitespace.

## Crash reports settle what a SIGKILL actually was (2026-08-31)

`idevicecrashreport -e <dir>` pulls the device's `.ips` reports over usbmux, and
it turned two guesses into facts. An `.ips` is one JSON header line followed by a
JSON body, so `json.loads` twice.

### The daemon crashes were jetsam, not a bug

`srdtool research spawn` fails every few minutes with "the daemon appears to be
offline". `JetsamEvent-*.ips` names it exactly:

```
securityresearchd  pid 37507  reason: per-process-limit  rpages: 511
securityresearchd  pid 37570  reason: per-process-limit  rpages: 510
```

So it is jetsam enforcing `securityresearchd`'s own memory limit while it is
parenting a probe that forks hundreds of children -- not a crash in it, and
nothing to fix. **Every call through it needs a retry**, and a long probe has to
be driven in slices from the Mac.

### The 78 SIGKILLs were EXC_ARM_PAC_FAIL, and the cause was ours

`DeRez-*.ips` -- 27 of them, timestamped exactly when the probe ran:

```
exception:   EXC_BAD_ACCESS, SIGKILL, EXC_ARM_PAC_FAIL at 0x00000000d73f0a11
termination: PAC_EXCEPTION
triggered thread:
   libxcselect.dylib  +0x2090  xcselect_trigger_install_request
   libxcselect.dylib  +0x1918  xcselect_invoke_xcrun
   DeRez              +0x778   main
```

`0xd73f0a11` is not an address, it is the `blraa x16, x17` opcode -- the
signature this file already records. So the shims were **not** killed by AMFI or
by jetsam. They died inside **our own lifted `libxcselect`**, at one
authenticated GOT site that was never repointed, on the one code path the nine
tools that matter never take.

`dsc.gotscan` had been reporting it all along, and dismissing it:

```
(2 out-of-image __text loads remain; dsc.facts rejects an address that does
 not name an import, so these are ADRP/LDR decoding false positives)
```

One of the two was real: `pc=0x196692084 (add) -> 0x1ee59ca08 AUTHENTICATED`,
which is `___chkstk_darwin` once the **code shift** (-0x1000, not the image-base
shift) is applied. Re-lifting with the current rebinder gives **0** out-of-image
sites and binds it into `__auth_ptr`.

### Three ways a bad lift shipped silently, all now closed

The library was right in `dsc.facts`' own output the whole time. Three separate
"if it exists, it's fine" checks conspired:

1. **`rebuild_cryptex.sh` skipped the lift when the file existed** (`if [ ! -f
   "$XCSELECT" ]`), so a lift produced before the rebinder could allocate an
   authenticated overflow slot was shipped session after session. It now
   re-lifts when `dsc.rebind`, `dsc.facts`, `dsc.gotscan` or
   `machomorph.py` is newer than the lift -- a make-style dependency, since a
   lift is a build product of those four.
2. **`dsc_lift.sh` never checked its own output.** A run whose facts came out
   empty printed "0 instructions repointed" and 58 `__auth_stubs[N] has no
   symbol in the facts` warnings, **exited 0**, and handed back a damaged
   library. It now runs `dsc.gotscan` and fails unless the verdict is
   `repaired`, deleting the output.
3. **`dsc_lift.sh` reused a cached `facts.json` on a bare `-f` test.** An empty
   or truncated one from an interrupted run is what produced the damaged library
   above -- the cache queries were fine. It now discards a facts file with no
   `stub_got` in it.

And the diagnostics stopped lying:

* `dsc.gotscan`'s verdict is now **`stubs repaired, but INCOMPLETE`** whenever a
  `__text` site still reaches outside the image, listing each one with its pc and
  whether it is authenticated. It no longer claims to know which are artefacts,
  because it does not.
* `cryptex.verify` **fails** on an authenticated leftover in any bundled
  library, and reports unauthenticated ones as a note. It catches the exact file
  that shipped:

```
FAIL  lifted library has an AUTHENTICATED __text site still reaching the cache
        libxcselect.dylib pc=0x196692084 -> 0x1ee59ca08
```

The lesson is narrow and worth keeping: **a lift is only as good as its facts,
and "the file is there" is not a check.** Every one of these three was a
freshness assumption, and the failure they produced was invisible on every path
anyone happened to test.

## systemstats cannot be ported, for two independent reasons

The earlier note blamed the VM span alone. Measured properly with perl's
`DynaLoader` on the device -- loading the lifted libraries one at a time and
watching where it breaks -- there are two separate walls, and **the symbol one is
final**:

**1. Two of its frameworks need symbols iOS does not have.**

```
CoreDisplay    Symbol not found: _DSBrightnessExternalConvertLinearToUser
IOPresentment  Symbol not found: _IOAccelDisplayPipeCopyCapabilities
                 Expected in: IOAccelerator.framework
```

No amount of lifting fixes that, so `systemstats` is now blocklisted and its six
frameworks are no longer staged. That removes the cryptex's last library failure.

**2. The address-space limit is real, but it is the largest free hole, not a
total.** This is the correction to the earlier reading. Loading largest-first:

```
libDiagnosticMessagesClient  1972 MB   ok
CoreWLAN                     1887 MB   FAIL vm_allocate
CrashReporterSupport         1844 MB   FAIL vm_allocate
GPUWrangler                  1826 MB   FAIL vm_allocate
libxcselect                  1765 MB   FAIL vm_allocate
TrustEvaluationAgent         1659 MB   ok      <- smaller, so it still fits
libdtrace                     881 MB   ok
```

A cumulative cap would not let 1659 MB and 881 MB through after 1972 MB has been
taken. What runs out is a **contiguous** span: after the first ~2 GB reservation
the largest remaining hole is somewhere between 1659 and 1765 MB. In a different
order, four lifted libraries load happily (881 + 1659 + 1765 + 1826 MB).

So the practical rule is not "one lifted library per process" but **two or three,
depending on their sizes** -- which is plenty for `libxcselect` (nine tools) and
`libdtrace` (one), and never going to be enough for six.

## Final device probe (2026-08-31)

All 519 entries in `bin/`, on the cryptex with the shims excluded, systemstats
dropped and libxcselect re-lifted. Raw data in `device_probe_2026-08-31_final.tsv`.

| outcome | old cryptex | first clean probe | final |
|---|---|---|---|
| loads and runs | 379 | 418 | **399** |
| **fails: library missing** | **243** | 1 | **0** |
| fails: symbol missing | 70 | 61 | **39** |
| SIGKILLed | -- | 83 | **0** |
| crash | -- | 1 | 1 |
| blocked | 64 | 16 | 16 |
| skipped (denylist) | 124 | 0 (bug) | 64 |

**Nothing fails on a library any more**, and all 83 SIGKILLs are gone. `ok` reads
lower than the first probe only because the denylist works now and skips 64
rather than launching them.

Every remaining failure is accounted for and none of them is ours:

* **39 symbol failures** are iOS not exporting a symbol. Confirmed from the
  crash reports rather than inferred -- `termination.namespace` is `DYLD`,
  `indicator` is `Symbol missing`, `details` says "terminated at launch; ignore
  backtrace". Led by `_syslog$DARWIN_EXTSN` (7).
* **1 crash**, `sntpd`, is its own `__assert_rtn`.
* **16 blocked** are daemons and tools that wait on something.

And the check that matters after a session spent on lifted libraries: of the 40
crash reports this probe produced, **zero are `EXC_ARM_PAC_FAIL`**. Every lifted
library survives every path the probe reaches.

Confirmed working, on device: the six rescued names (`otool -L`, `nm -mu`,
`objdump --version`, `size`, `c++filt`, `dwarfdump`) now run the real llvm tools;
`dyld_info -platform`, `lipo -info`, `vtool -show-build`, `swift-demangle`;
`openssl`, `curl` (200 + verify=0), `tcpdump --version`, `perl` with XS modules,
`zsh` + `zsh/pcre`; all eight memory tools, with `vmmap $$` giving real output;
and **`dtrace -l` reaching its own initialisation**.

Remaining symbol failures are led by `_syslog$DARWIN_EXTSN` (7 of 39 now that the
denylist no longer launches `date`, `logger` and friends), then
`_OBJC_CLASS_$_JLRuntime` (4, the JDK) and `_KextManagerLoadKextWithIdentifier`
(2). The syslog variant was the one worth fixing. It did **not** need
import-ordinal rewriting in the end -- plain `_syslog` exists on iOS and is
shorter, so `--darwin-extsn` renames it in place. See "fixed by a string edit".

## The cleanup verified: a no-op on the output (2026-09-01)

`48edb37` refactored `machomorph.py`'s symbol-table handling -- collapsing three
near-identical walks into one `MachO.undefined_symbols()`, keeping
flat-namespace imports under `FLAT_NAMESPACE` instead of dropping them, and
fixing a `NameError` in `weaken_symbol`. It touched the code path that decides
which binaries get ported at all, and the cryptex on the device had been built
before it. So the question was whether the refactor changed the output.

**It did not, at the strongest resolution available: byte identity.**

| check | result |
|---|---|
| `test_machomorph.py` | 70 passed, 0 failed, 0 skipped |
| the 39 binaries a device probe measured dying on a symbol | **39 of 39** flagged `WILL FAIL` |
| the 384 that ran fine | **0 of 384** wrongly condemned |
| from-scratch rebuild: the 7 lifts | **all 7 byte-identical** to the pre-cleanup lifts |
| whole cryptex, `diff -rq` | **0 differing files**, identical tree structure |
| device probe, 525 binaries | **429 ok / 76 skipped / 20 blocked**, and every binary in the same bucket as the reference |
| crash reports | **0 `EXC_ARM_PAC_FAIL`** |

The rebuild was from an empty `lifted/` and an empty cryptex, so `dsc_lift.sh`
ran end to end for all seven libraries. `bin/` came back at the same 527 names,
`lib/` at 10, 404 MB, `verify_cryptex` clean, `symbol_check: 0 of 527`.

### Why the flat-namespace change could not move the gate

Worth recording as reasoning rather than only as a measurement, because it is
the one piece of the cleanup that genuinely changes what
`unresolvable_imports()` sees. A flat-namespace import lands in `unknown`, never
in `fail`:

* before, ordinal-0 imports were dropped, so they failed nothing;
* after, they are reported `unknown`, which also fails nothing.

So the *fail* set is unchanged by construction, and the 39/0 result and the
byte-identical tree are what that predicts. What the change buys is that a
flat-namespace binary no longer looks import-free -- all 155 of `postalias`'s
undefined symbols carry ordinal 0 and were previously invisible.

### The device was verified to be running the build under test, not assumed

This mattered, and it nearly produced a wrong answer. The first probe was run
against the **`combined`** cryptex rather than `machomorph-test`: `bin/` held 535
names instead of 527, the extra 8 being the community iOS-native binaries
(`ldid`, `less`, `login`, `mksh`, `passwd`, `trustcache`, `uicache`, `zstd`).
Two symptoms said so before the count did, and both are worth recognising again:

* **the mount suffix changed between two consecutive ssh calls**
  (`...O97SPc` -> `...PnuQyB`), because the cryptex was being swapped underneath;
* the probe **died at 395 of 525 lines with rc=255** -- an ssh drop, which looks
  nothing like a probe failure and everything like one.

After the reinstall, identity was established by hashing **every** file rather
than a sample: all **488** real files in `bin/` and `lib/` (the other 39 entries
are symlinks) are byte-identical between the device and the local tree. Only
then is a probe result evidence about the cleanup.

`ls -1 <dir> | wc -l` over ssh is fine, but piping a **long** listing through a
local `tr`/`sort` silently returned nothing twice. Resolve the mount and do the
work in one remote command; do not carry `$CX` across calls.

### Two dangling aliases in `bin/`, pre-existing

`diff -rq` could not read two files, on **both** sides:

```
bin/more        -> less        (less is a community binary, not in this cryptex)
bin/parldyn5.34 -> parldyn     (parldyn was not staged)
```

They are alias symlinks whose targets are absent, so they are inert rather than
harmful -- and they are why the tree has 527 names but the probe reports 525.
`cryptex.verify` check 5 resolves `@loader_path` / `@executable_path`
references but does not check that a plain alias symlink has a target, so
nothing flags them. Not caused by the cleanup, and not fixed here.

### Verdict

`48edb37` is a no-op on every byte the project ships. It is kept.

## Testing without reinstalling a cryptex

`native/dlopen_test` and `dlsym_test` load a converted library on the Mac.
Convert with `-p macos --no-cpusubtype-fix` (without that flag the macOS arm64e
ptrauth version becomes `arm64e.v1`, which an ordinary process cannot load).
This turned a 20-minute install cycle into a two-second one and is how all four
errors above were found. SIP does not get in the way -- ad-hoc signing a file in
/tmp works.

### Extraction

`native/` wraps Apple's `/usr/lib/dsc_extractor.bundle`; build it
`-arch arm64e`, since the bundle ships only x86_64 and arm64e and `dlopen` needs
a matching slice. It extracts the entire cache (3649 images, 5.3 GB) in one go,
so keep the tree; `bundle.py` prefers `/tmp/dsc_out` when it exists. Apple's
extractor and `ipsw dyld extract` produce the same segment addresses -- neither
rebases -- but Apple's gives a complete symbol table, which is what the trie is
rebuilt from.

### __LINKEDIT has to be repacked, not just shifted

`rebuild_linkedit()` relays every table in __LINKEDIT at an 8-byte aligned
offset. Preserving the original alignment is not enough -- a cache extraction
arrives with tables that were *never* aligned (`function starts` at `...004`),
and dyld rejects those too. Each table is addressed by an explicit
(offset, size) pair in a load command, so moving them is bookkeeping.

The repack deliberately drops LC_CODE_SIGNATURE: the Apple signature is dead
weight once anything has moved, and `codesign -f -s -` writes a fresh ad-hoc one
afterwards. Two traps found doing this:

* __LINKEDIT must *not* get the 16-byte alignment padding the other segments
  need. Its contents are freshly packed and carry their own alignment, so the
  padding only knocks the segment base off the page boundary.
* Its `filesize` has to include the page pad, not just the blob length.
  Getting that wrong leaves the segment under-covering its own contents, and
  `codesign` reports it only as `main executable failed strict validation`.

That message means "your Mach-O is malformed", not "this cannot be signed" --
worth remembering, since reading it the other way is what produced the wrong
"cache-only libraries cannot be ported" conclusion earlier.

### Mapped segments must tile the file

The last thing standing between a relaid-out library and the device was
`code signature invalid ... (errno=1)` -- reported for every relaid-out library
and for none of the others, while `codesign --verify` passed on the Mac.

It was not a trust-cache problem. A normal dylib's mapped segments have a
**page-aligned filesize**, so they tile the file end to end. The relayout was
keeping each segment's original (unaligned) filesize while starting the next one
on a page boundary, which left a gap after every segment: file pages that the
code signature covers but no segment claims. codesign(1) does not care; the
kernel does.

Rounding each mapped segment's filesize up to a page fixes it. __LINKEDIT keeps
its exact size, as in a normal dylib, and the signature ends the file.

### iOS dyld is stricter than macOS dyld

The local `dlopen` loop is fast but not sufficient: iOS rejects things macOS
accepts. `mis-aligned LINKEDIT content 'symbol table', fileOffset=0x000968BC`
appeared only on device. `__LINKEDIT` sub-tables must be 8-byte aligned, and
moving the segment to a page boundary shifts every one of them by whatever the
original (arbitrary) offset happened to be.

The fix is padding *inside* the segment rather than before it: the segment start
must stay page aligned, so the slack that makes the shift a multiple of 16 goes
after `fileoff`. That preserves whatever alignment the tables originally had.
The rebuilt export trie is separately 8-aligned, since it is appended rather
than shifted.

So: prove layout on the Mac, but only the device settles it.

### Partial success: cache-extracted libraries work, but only on some paths

**`tcpdump` and `dtrace` genuinely work.** Measured on device:

| invocation | result |
|---|---|
| `tcpdump -D` | **rc=0**, lists every interface |
| `tcpdump -c 1 -i lo0` | **rc=0**, captures |
| `tcpdump -i lo0` | **full protocol decode** -- see below |
| `tcpdump` (bare) | **captures live**; a non-zero rc here was only a test timeout |
| `tcpdump -h`, `--version` | SIGSEGV |
| `dtrace` (bare) | **rc=2**, full usage -- its normal no-args behaviour |
| `dtrace -l`, `-n '...'` | prints real runtime output, then SIGSEGV |
| `curl` (every path tried) | SIGSEGV -- **fixed, see "Building the library from source"** |
| `openssl` (every path tried) | SIGKILL -- **fixed, same way** |
| `systemstats` | `vm_allocate(size=0x6CDC0000)` -- a 1.8 GB sparse span |

The `tcpdump --version`, `curl` and `openssl` rows above are the *extracted*
measurement. All three now work, because those libraries are no longer
extracted -- they are built from source. The table is kept because it is the
evidence for the diagnosis, not because it still describes the cryptex.

`tcpdump -i lo0` is not limping, it is doing the whole job:

```
listening on lo0, link-type NULL (BSD loopback), snapshot length 524288 bytes
22:56:29.301567 IP localhost.ssh > localhost.52804: Flags [P.],
    seq 211860833:211861021, ack 1555966279, win 6327,
    options [nop,nop,TS val 2542253599 ecr 2865644570], length 188
```

Capture, BPF, TCP/IP dissection, port-name resolution, TCP option parsing and
timestamping all work. It gets away with it because its missing libraries are
`libssl` and `libcrypto`, which tcpdump only reaches for ESP/IPsec decryption --
not on any path a normal capture takes.

This is what the missing-fixup diagnosis predicts, and it is worth stating
precisely rather than writing the libraries off. An unrebased pointer only
crashes when something *dereferences* it. Argument parsing, local logic and
anything PC-relative runs correctly; code reaching through a global pointer
table (GOT entries, vtables, string tables) reads garbage. Note which paths
fail for tcpdump: `--version` and `-h`, the ones that print version strings out
of globals. The capture paths, which are the point of the tool, are fine.

So a cache-extracted library is not dead, it is **partially functional**, and
how far a tool gets depends entirely on which paths it takes. For tcpdump that
is far enough to be useful. For curl and openssl it is not.

### The real wall: the cache-uniqued GOT (diagnosed and fixed 2026-08-30)

Underneath the partial success, the libraries **load** and then crash:

    EXC_BAD_ACCESS, KERN_INVALID_ADDRESS at 0x7098993000100020
      libcurl.4.dylib +0x64358 <- +0x14e4c <- curl +0x98b8

`0x7098993000100020` is not an address. It is a raw chained-pointer bit pattern
read as if it were a pointer.

The first diagnosis was "extracted images carry no `LC_DYLD_CHAINED_FIXUPS`, and
synthesising them means walking the cache slide info -- a cache-to-dylib
converter, much larger than a retargeter". The load-command half is true:

    extracted libcurl:  LC_SYMTAB LC_DYSYMTAB LC_FUNCTION_STARTS
                        LC_DYLD_EXPORTS_TRIE LC_DATA_IN_CODE ...
    normal dylib:       LC_DYLD_CHAINED_FIXUPS   <-- absent from every extraction

But it is not the whole story, and the missing part is the one that decides
whether this is fixable. **The cache builder uniques GOT entries cache-wide.**
Each image keeps its own `__got` / `__auth_got` sections at the original size,
but the builder zeroes them, clears their section *type* (`S_NON_LAZY_SYMBOL_-
POINTERS` becomes `0`), and rewrites the image's code to reach a shared GOT
region that belongs to no image at all. `libxcselect`'s own `__auth_got` is at
`0x1f005b380`; every one of its 58 stubs is

```
adrp x17, 0x1ee57d000        ; a region ipsw reports as  dylib=  (none)
add  x17, x17, #0x820        ; ipsw names the slot _ptr.__NSGetProgname
ldr  x16, [x17]
braa x16, x17
```

and the handful of GOT-relative data loads in `__text` -- the stack guard,
`___stderrp`, the block runtime classes -- reach a second such region at
`0x1e61c2xxx`. Extract the image and those addresses point outside every one of
its segments, at whatever happens to be mapped, usually zero. That is a **code**
problem, not merely a metadata one, which is why no extractor fixes it: Apple's
`dsc_extractor` and `ipsw dyld extract` both reproduce the rewritten code
verbatim.

Stopping at "no fixups" is what produced the earlier "not fixable by rewriting"
conclusion. Measuring where the code actually points is what undid it.

### Everything needed to undo it survives

Three facts, each verified on `libxcselect` and then on `libdtrace`:

* **The indirect symbol table is intact.** 119 entries: 58 stubs, 3 `__got`,
  58 `__auth_got`. Every slot is still named.
* **`stub[i]` and `__auth_got[i]` name the same symbol**, for all 58. So a stub
  can be repointed at its own image's GOT slot with *no cache lookup at all*.
* **The dead GOT sections are exactly the right size**, so the repair needs no
  new space -- only the section type restored.

Only two things genuinely have to come from the cache:

* **which words in the image's data are pointers, and what they target.** A
  cache image's data is covered by the cache's slide info rather than by a
  fixup command of its own. `ipsw dyld slide --json` emits one record per
  pointer for the whole cache (27M of them); streaming it and keeping the ones
  inside the image gives 24 for `libxcselect`, 2006 for `libdtrace`, with
  target, ptrauth key, diversity and address-diversity for each.
* **which symbol each cache-wide GOT slot held.** Those slots *are* populated
  in the cache, so reading the value and asking what is exported at that
  address names them. `ipsw dyld patches` gives the same answer for function
  slots, with the ptrauth key -- `key: IA, diversity 0x0000, auth: true`, which
  is what `braa x16, x17` needs.

### The tools

| script | job |
|---|---|
| `dsc.gotscan` | diagnosis only. Reports the damage and whether it is repairable. Modifies nothing |
| `dsc.facts` | the two things above, out of the cache, into a small JSON |
| `dsc.rebind` | repoints stubs and code loads at the image's own GOT, restores the section type, synthesises `LC_DYLD_CHAINED_FIXUPS` |
| `machomorph.lift_library()` | all of it plus extract, retarget and `codesign`, in one call. Was `dsc_lift.sh`, which is gone |
| `dsc.objc` | after the rebind: rebases the ObjC selector and protocol references the rebinder mistook for C symbols |
| `dsc.compact` | afterwards: packs the segments together so the image reserves its own size instead of 1.6-2.0 GB (on by default; `DSC_COMPACT=0` opts out). REQUIRED for an ObjC image |
| `native/dlcall_test` | the test that catches this: dlopen, dlsym **and call** |

```sh
./machomorph.py /usr/lib/libxcselect.dylib -o out/libxcselect.dylib \
    -p ios -v 26.0 --no-libraries \
    --change /usr/lib/libxcselect.dylib \
             @loader_path/../lib/libxcselect.dylib
```

An input that is not a file anywhere is a lift, not an error -- the cache is the
only copy, so the request is unambiguous.

The slide pass is over the whole cache and takes a couple of minutes. It is
paid **once**: `facts_dump_args()` saves both cache-wide dumps -- the slide info
and the patch table -- on the first lift, keyed by the cache's own size and
mtime, and every later lift reads them instead of the cache. `DSC_SLIDE_JSON`
and `DSC_PATCHES_TXT` still override with a dump of your own.

Each is written to a per-process `.part` and renamed only once dsc.facts has
succeeded, and a dump of **0 bytes is refused with a warning** wherever it comes
from. That matters more than it looks: an empty dump is read by dsc.facts
without complaint and simply yields no records, so the lift comes out with
nothing repointed, loads, and PAC-faults -- the sixth instance of "the file is
there is not a check", and the one that actually happened, when
`rebuild_cryptex.sh`'s `[ -f /tmp/slide.jsonl ]` accepted a dump that was still
being written.

### Details that cost time, and are easy to get wrong again

* **Emit the format a real arm64e iOS dylib uses, do not guess it.** Decoding
  our own source-built `libcrypto.46.dylib` settled it:
  `DYLD_CHAINED_PTR_ARM64E_USERLAND24` (12) with `DYLD_CHAINED_IMPORT` (1),
  page size 0x4000, `next` in units of 8 bytes, plain-rebase `target` an offset
  from the image base. Its GOT slots are `AUTH BIND key=IA addrDiv=1 div=0` --
  the same shape the cache's patch table reports, which is a good cross-check.
* **`dyld_chained_starts_in_segment` is `size, page_size, pointer_format,
  segment_offset, max_valid_pointer, page_count, page_start[]`.** Getting
  `max_valid_pointer` and `page_count` the wrong way round yields `page_count=0`
  and a blob that parses cleanly and does nothing.
* **`segment_offset` is a VM offset from the mach header, not a file offset.**
  In a relaid-out extraction the two differ by tens of megabytes.
* **Carry the real library ordinal.** The chained imports table stores a
  1-based dylib ordinal per symbol; it is in the high byte of each undefined
  `nlist_64`'s `n_desc`. Hardcoding 1 works for a single-dylib library like
  `libxcselect` and silently breaks a multi-dylib one -- `libdtrace` failed to
  load with `Symbol not found: _CFRelease, Expected in: CoreSymbolication`,
  which is dyld looking in the wrong library, not a missing symbol.
* **A bind the image's own symbol table does not list** -- a C++ ABI vtable
  slot the cache resolved for it, say -- gets a weak flat lookup, so a missing
  one binds to NULL instead of failing the load.
* **Not every out-of-image `ADRP`+`LDR` is a GOT reference.** A register reused
  between an unrelated `ADRP` and a later `LDR` produces a plausible address
  that resolves to some unrelated cache symbol. `dsc.facts` keeps a slot only
  when the symbol it names is one the image actually imports; that took
  `libxcselect` from 5 candidates to the 3 real ones.
* **A cache extraction has ~100 spare bytes of header**, not enough for a new
  load command, and a section cannot simply move: its address is baked into
  every `ADRP` that reaches it. `machomorph --reserve-header N` grows `__TEXT`
  *downward* by whole pages instead -- the mach header stays at file offset 0,
  the slack goes after the load commands, and because the segment base moved
  by the same amount every section keeps the address it had.

### Lifting the ios-libs set: five more things that only show up at scale

`libxcselect` (58 stubs) and `libdtrace` (2259 fixups) worked with the first
version of the rebinder. Doing `libcrypto.46`, `libssl.48`, `libcurl.4` and
`libpcre.0` -- the four `ios-libs/` builds from source -- broke it five separate
ways. Each is a rule, not a special case.

**1. The indirect symbol table cannot be trusted at all.** The first version
named every GOT slot from it, having verified on `libxcselect` that `stub[i]`
and `__auth_got[i]` agree. Then:

| library | its indirect symbol table |
|---|---|
| `libxcselect`, `libdtrace`, `libpcre.0` | intact and correct |
| `libcrypto.46` (305 entries), `libssl.48` (731) | **all zeroes** |
| `libcurl.4` (959 entries) | non-zero and **in a different order** |

All-zeroes is the dangerous one: index 0 is a valid index, so every slot
silently resolves to symbol 0 and the whole GOT binds to `_Camellia_Ekeygen`.
For `libcurl` slot 0 reads `_SSLClose` where the stub demonstrably points at
`_ASN1_STRING_get0_data`'s slot -- confirmed by two independent cache routes
(`a2s` on the slot, and `a2s` on the value the slot holds). Both symbols really
are imported, so it is an ordering difference, and an extraction's dysymtab is
regenerated with no obligation to match the GOT.

So the naming comes from the cache, always: the stub's own `adrp`/`add` says
which cache-wide slot it wants, and the cache says what is in that slot. The
indirect symbol table is now only a cross-check, printed and ignored.

**2. The cache names the implementation; the image imports the public name.**
One address carries several exported names and the cache reports whichever the
lookup finds first. Binding the wrong one of a pair is the subtle failure:
`__platform_memchr` is not bindable by name, so the slot ends up NULL and the
library dies on its first `memchr`. This is what NULLed `libpcre`'s first call.

| the cache says | the image imports |
|---|---|
| `__platform_memchr`, `__platform_bzero`, ... | `_memchr`, `_bzero`, ... |
| `__platform_memmove` (for a memcpy slot) | `_memcpy` |
| `___recvfrom`, `___sendto` | `_recvfrom`, `_sendto` |
| `____chkstk_darwin` (four underscores) | `___chkstk_darwin` (three) |
| `_ptr.<symbol>` (a slot pointing at another slot) | `<symbol>` |
| `__NSGlobalBlock__` | `__NSConcreteGlobalBlock` |

`resolve_alias()` tries the candidates in that order against the image's own
undefined symbols. Note the underscore rule has to try *each* depth rather than
assuming one: `____chkstk_darwin` loses one, `___recvfrom` loses two.

**3. The cache inlines some stubs straight into `__text`, and those need an
AUTHENTICATED slot.** Two forms reach a GOT slot, and a scanner that only knows
the first will mis-decode the second:

```
adrp x8,  P  /  ldr x8, [x8, #off]        a data symbol. Slot is P+off,
                                          the pair to patch is (adrp, ldr)

adrp x17, P  /  add x17, x17, #off        an inlined stub. Slot is P+off,
ldr  x16, [x17] / blraa x16, x17          the pair to patch is (adrp, add)
```

An `ldr`-only scanner sees the third instruction of the second form, computes
`P+0`, finds nothing, and leaves the site alone. The result is
`EXC_ARM_PAC_FAIL at 0x00000000d73f0a11` inside `formatf+52`, five frames below
`curl_version` -- and `0xd73f0a11` is not an address, it is the `blraa x16, x17`
opcode, which is the giveaway. `scan_got_sites()` now tracks the register value
through `adrp`/`add`/`ldr` and reports which form each site is and whether the
use is an authenticated branch.

**4. `__auth_ptr` is the pool for the authenticated overflow.** The GOT sections
come out *exactly* full -- `__auth_got` has one slot per stub, and `__got` one
per distinct data symbol, in all five libraries measured -- so an inlined stub
has nowhere to go. `__auth_ptr` does: it is dead space in the same way (zeroed
in the cache, named by neither the indirect symbol table nor the slide info),
and 1 to 10 slots of it, where each library needs exactly one. Slots that *are*
named by the slide info are reserved and never allocated.

**5. `--reserve-header` moves the base further than it moves the code.** Two
bugs, both from that one page:

* The export trie stores offsets from the image base, and it was being built
  before `text_gap` lowered that base -- so every exported symbol landed one
  page early. `dlsym` reports such an address without complaint and the call
  goes into the middle of another function. Compare `dyld_info -exports`
  against the symbol table; they must agree exactly.
* An `ADRP` immediate is fixed, so a target decoded from the converted image is
  displaced by however far the *code* moved. With `--reserve-header` the base
  moves by 0x6000 and the code by 0x2000. Using the base shift to translate
  addresses found nothing, which showed up only as "repointed 148 stubs and
  **0** code GOT loads". The facts now record the original section addresses so
  the code shift is derived from `__text` itself.

### Two more, found lifting the systemstats and dtrace set (2026-08-31)

Doing the seven libraries that have no open-source upstream -- `libdtrace`, and
the `CoreDisplay` / `CoreWLAN` / `IOPresentment` / `GPUWrangler` /
`CrashReporterSupport` / `libDiagnosticMessagesClient` closure `systemstats`
needs -- plus `TrustEvaluationAgent`, broke the rebinder two further ways. Both
are rules, and one of them closes the gap the previous session left open.

**6. The plain `__got` can come out exactly full too, and it had no overflow
pool.** Rule 4 gave the authenticated side `__auth_ptr` as the pool for stubs
the cache inlined into `__text`. The plain side got nothing, because in the five
libraries measured then it never needed any. `TrustEvaluationAgent` needs one:
it reaches four data symbols from code (`_bootstrap_port`, `_mach_task_self_`,
`_NDR_record`, `_voucher_mach_msg_set`) and its `__got` is exactly three slots.
The fourth was reported and skipped:

```
warning: no free GOT slot for _voucher_mach_msg_set;
         0x19cb35070 left pointing at the cache
```

-- which is one `ldr` still reaching a cache-wide address, on the path that
sends the MIG message, i.e. all of `TEAVerifyCert`.

`__auth_ptr` is a thin answer anyway: 1 to 10 slots, and TEA's is exactly 1. So
both pools now also draw on **the segment's spare tail** -- the 8-aligned space
between a data segment's last section and its end. A relaid-out image
page-aligns each segment and rounds its filesize up to a page, so `__DATA_CONST`
and `__AUTH_CONST` end in padding that no section claims: 660 and 1193 slots in
TEA's case. Nothing in the image can reach it, since a section is the only thing
that gives an address meaning there, and it is mapped and writable-at-load like
the rest of the segment. Crucially **nothing moves** -- every existing section
keeps its address, which is the constraint the whole lift is built around.

`dyld_info` shows such a slot with an empty section column, which is how to
recognise one:

```
__DATA_CONST  __got   0x1E70EAB58  bind  libSystem/_NDR_record
                      0x1E70EAB60  bind  libSystem/_voucher_mach_msg_set
```

The tail is appended *after* the real pools, so a library that already fitted
allocates exactly as before -- verified: all four ios-libs lifts reproduce their
previous fixup and instruction counts to the digit.

**7. `ipsw dyld slide --json` reports the target twice, and the two disagree.**
Each record carries a `target` and a `pointer.value`, where `value` is the same
address as an offset from the cache base. They agree for almost every record.
Where they do not, **`value` is the one that is right**:

```
{"cache_vm_address":8296703592, "target":2205516226624,
 "pointer":{"value":50520128,"next":1}}

  target                -> 0x2018302e040   200x past the end of a 5 GB cache
  value + 0x180000000   -> 0x18302e040     CoreDisplay's own __TEXT.__const
```

`0x18302e040` holds `NSt3__120__packaged_task_funcIPFvjPfS1_...` -- a C++ RTTI
type-name string, which is exactly what the `std::type_info` in
`__AUTH_CONST.__const` that points at it should point at. So the record is an
ordinary **rebase inside the image**, and reading `target` made it a *bind* to
an address nothing in the cache could name, which was then left NULL:

```
warning: __AUTH_CONST.__const+0x758 binds an unnamed target (0x2018302e040);
         left NULL -- this library is INCOMPLETE
```

`dsc.facts` now computes the target as `pointer.value + cache_base(cache)`,
reading the base from the first mapping in the cache header rather than assuming
`0x180000000`. That accounted for **15 of the 20** warnings:

| library | INCOMPLETE before | after | what changed |
|---|---|---|---|
| `CoreDisplay` | 12 | **0** | rebases 2350 -> 2362, binds unchanged |
| `IOPresentment` | 2 | **0** | rebases 532 -> 534, binds unchanged |
| `libdtrace` | 1 | **0** | rebases 2006 -> 2007, binds unchanged |
| `CoreWLAN` | 5 | 5 | a different problem -- below |

`libdtrace` was "the one known gap" the previous session left open, and it is
closed. In every case the bind count is unchanged and the rebase count rises by
exactly the number of warnings, which is the shape to expect: each was always a
rebase and was being misfiled.

**The 5 that remain are not the same bug.** With the target decoded correctly
they land at `0x1ff915329`, `0x1ff915341`, ... -- inside the cache after all,
in the `.03.dyldreadonly` READ_ONLY_DATA region, at unaligned addresses on a
0x18 stride, referenced from `__AUTH_CONST.__objc_const`. Reading the bytes
there gives binary structures rather than symbols or strings. That region holds
the cache's **ObjC optimisation tables** -- the canonical selector, class and
protocol metadata -- so these are an ObjC framework's protocol references
pointing at cache-canonical protocol objects that belong to no image.

So it *is* a third form of the same cache-wide uniquing the GOT suffers, just
not the one the wrong addresses first suggested, and it needs synthesising ObjC
metadata rather than repointing a pointer. Left NULL and reported. The blast
radius is small and specific: `conformsToProtocol:` and `@protocol()` for those
five protocols in `CoreWLAN`, which is bundled only for `systemstats`.

Worth recording what the wrong reading looked like, because it was plausible: an
address 200x outside the cache, unaligned, on a repeating stride reads
convincingly as a uniqued *string* pool. The check that settled it was masking
the high bits and asking whether the result landed in the image, and what was
written there -- `0x18302e040` is in `CoreDisplay`'s own `__TEXT.__const` and
holds `NSt3__120__packaged_task_func...`, so a `std::type_info` pointing at its
own type name. One field of a JSON dump was simply less trustworthy than the
field beside it.

### `TrustEvaluationAgent`: a dependency the source build does not have

A detail that matters when choosing between the two mechanisms. Apple's
`libcrypto.46` is a LibreSSL *fork*, and its `crypto/apple/` layer routes
certificate-chain verification through `TrustEvaluationAgent`: the lifted
library imports 7 symbols from it (`_TEAVerifyCert`,
`_TEACertificateChainCreate`, ...). Vanilla LibreSSL imports none, so
`ios-libs/`'s build has no such dependency.

iOS does not ship `TrustEvaluationAgent` either (0 hits in the cache index), so
lifting `libcrypto` means lifting TEA too, and TEA in turn talks to a daemon
over MIG. **So the two routes are not interchangeable on the verify path**, and
the source build is the safer default there: it verifies chains itself.

### Result: all six libraries run

Verified with `native/dlcall_test` on macOS-targeted lifts:

| library | fixups | instructions repointed | call |
|---|---|---|---|
| `libxcselect` | 86 | 93 | `xcselect_get_developer_dir_path` -> the real developer dir |
| `libcrypto.46` | 7361 | 1614 | `SHA256_Init` -> 1, `OpenSSL_version_num` -> 0x20000000 |
| `libssl.48` | 1300 | 841 | `SSLv23_method` -> a method table |
| `libcurl.4` | 2231 | 795 | `curl_version`, `curl_global_init` -> 0, `curl_easy_init` -> a handle |
| `libpcre.0` | 42 | 32 | `pcre_version` -> a version string |
| `libdtrace` | 2256 | 673 | `dtrace_open` |

`OpenSSL_version_num` returning `0x20000000` is LibreSSL's number, which is a
nice independent confirmation that the right code is running.

Every cache GOT slot is named in all six (`named 246 of 246`, `496 of 496`, ...).
The one remaining gap is a single bind in `libdtrace` whose target
(`0x201cb205460`) nothing in the cache names; it is left NULL and reported as
`this library is INCOMPLETE`.

**Not yet staged or device-tested.** These are macOS-targeted lifts for the
local test loop. See `next-session.md`.

### The relayout was displacing every data segment by 8 bytes

Found while chasing why the synthesised fixups were read from the wrong slots,
and worth calling out separately because it was silently corrupting **every**
library the relayout had ever produced.

`relayout_for_standalone()` padded each segment so that its file-offset delta
stayed a multiple of 16, on the theory that this preserved the alignment of the
segment's contents. It did the opposite. VM addresses do not move in this
relayout -- only the uniform page `shift`, itself a multiple of 16 -- so their
alignment was never at risk, while the extra pad displaced the *contents* of
every non-`__TEXT` segment by 8 bytes relative to its own section table:

```
  __DATA_CONST.__got     addr=0x1e6f21f28  off=0x9f30  expected=0x9f28   +8
  __AUTH_CONST.__auth_got addr=0x1f005a380 off=0x12388 expected=0x12380  +8
```

dyld maps `file[fileoff, +filesize)` at `vmaddr`, so a section's recorded
address and its recorded file offset must agree. They did not. `dlopen`
succeeded, `codesign` was happy, and every data address the code computed was
off by 8. Removing the pad is the whole fix, and it is very likely part of why a
cache-extracted library used to work on one path and not another.

### Result

`libxcselect` -- 58 stubs, 65 binds, 21 rebases, 92 instructions repointed --
runs its real code out of the cache. `libdtrace` -- 253 binds, 2006 rebases,
617 instructions repointed -- loads and calls too, and it is the other library
the source-build route could not rescue because it has no open-source upstream.

### What the relayout work did achieve

It is not wasted: everything short of the fixups is now correct, and the same
code is what makes a *real file* extracted from anywhere load cleanly. The
sequence of four device-only errors it fixed (platform, SG_READ_ONLY, segment
layout, __LINKEDIT alignment, segment tiling) all had to be solved regardless.

### Result

All 15 bundled libraries now carry a rebuilt export trie, one iOS
`LC_BUILD_VERSION`, and ascending page-aligned segments. Locally, the relaid-out
`libcurl`, `libpcre`, `libdtrace`, `libcrypto` and `libssl` all `dlopen` and
resolve symbols.

On device, the relayout is necessary but not sufficient: `tcpdump` and `dtrace`
run, `curl` and `openssl` did not. The four whose upstream is open source
(`libcrypto`, `libssl`, `libcurl`, `libpcre`) have since been replaced by
source builds and are no longer extracted at all. `libdtrace` and the five
`systemstats` frameworks remain extracted, and remain path-dependent --
`bundle.py` now prints `NO FIXUPS` for exactly those.

## Building the library from source (2026-08-30) -- SUPERSEDED, do not revive

**This route is abandoned.** `ios-libs/` is deleted and nothing is built from
source any more; the four libraries below are lifted out of the cache like
everything else. Kept because it is the evidence that the fixup diagnosis was
right -- a source-built library has real `LC_DYLD_CHAINED_FIXUPS` and it fixed
exactly the paths a raw extraction broke -- and because the ABI measurement and
the two configuration traps are worth not rediscovering. The fixups a source
build gave for free are now synthesised by `dsc.rebind`, so the reason to
build is gone.


The fixup wall above is real, but it is only a wall for libraries that exist
*nowhere else*. Three of the four that mattered are Apple forks of open source,
and `strings` names the version in each:

| Apple library | really is | how it was identified |
|---|---|---|
| `libcrypto.46` / `libssl.48` | **LibreSSL 3.3.6** | build root `.../Sources/libressl/libressl-3.3/crypto/...`, banner `LibreSSL 3.3.6` |
| `libcurl.4` | curl 8.7.1 | `libcurl/8.7.1` |
| `libpcre.0` | PCRE 8.44 | `8.44 2020-02-12` |

So they can be compiled for iOS instead of extracted, and a compiled library
has real `LC_DYLD_CHAINED_FIXUPS`. `ios-libs/build.sh` does all three.

### Why the ported macOS binaries link against a vanilla build

This is the part that could easily have failed and did not. Upstream LibreSSL
3.3.6 picks **the same dylib version numbers Apple ships** -- `libcrypto.46`,
`libssl.48`, current version 47.2.0 and 49.2.0 -- so dyld's compatibility
version check passes and `/usr/bin/openssl` links against the vanilla build
unmodified. No shim, no rebuild of the tool.

Apple's fork *does* differ: a `crypto/apple/` directory routes AES, RSA, ECDH
and HMAC through corecrypto, and it links `TrustEvaluationAgent`. Those are
implementation swaps behind the same API. What matters is the exported surface,
so `build.sh` measures it rather than assuming, reusing `imports_by_library()`
and `export_trie_symbols()`:

```
  /usr/bin/openssl  <- libcrypto.46.dylib: 847 imports, 0 missing
  /usr/bin/openssl  <- libssl.48.dylib:    103 imports, 0 missing
  /usr/sbin/tcpdump <- libcrypto.46.dylib:  14 imports, 0 missing
  /usr/bin/curl     <- libcurl.4.dylib:     54 imports, 0 missing
ABI check: OK, nothing missing
```

Zero gaps across 1018 imports. Run that check before an install cycle, not
after.

### CONFIRMED ON DEVICE (2026-08-30)

Everything the extraction route could not do:

| invocation | result |
|---|---|
| `openssl version` | **LibreSSL 3.3.6** |
| `openssl dgst -sha256` | correct digest |
| `openssl genrsa` + sign + verify | **Verified OK** |
| `openssl ecparam prime256v1` + sign + verify | **Verified OK** |
| `openssl enc -aes-256-cbc -pbkdf2` roundtrip | correct |
| `openssl s_client -connect apple.com:443 -CAfile ...` | TLSv1.3, AEAD-CHACHA20-POLY1305, **Verify return code: 0 (ok)** |
| `openssl x509` on a live Apple EV cert | parses subject, issuer, dates |
| `curl -sSL https://www.apple.com/` | **200**, `ssl_verify_result 0`, 254322 bytes |
| `curl -V` | `libcurl/8.7.1 LibreSSL/3.3.6 zlib/1.2.12` |
| `tcpdump --version` | **works** -- this is the path that used to SIGSEGV |
| `tcpdump -c 3 -i lo0` | full TCP handshake captured and decoded |
| `zsh -c 'zmodload zsh/pcre; pcre_match'` | match and non-match both correct |

`tcpdump --version` is the single most useful line here. It reads a version
string out of a global, which is precisely the dereference an unrebased
extracted library cannot survive -- and it is fine now. The fixup diagnosis was
right, and source-building is the cure.

### Two configuration traps, both device-only

**OPENSSLDIR is compiled in from `--prefix`.** Without `--with-openssldir`,
every `openssl` invocation on the phone printed

    WARNING: can't open config file: /Users/.../ios-libs/build/libressl-prefix/etc/ssl/openssl.cnf

-- the build machine's path, baked into the library. Configure with
`--with-openssldir=/etc/ssl`. Then `make install` fails, because LibreSSL's
`install-exec-hook` writes `openssl.cnf` and `cert.pem` to that *absolute*
path and tries to touch the Mac's real `/etc/ssl`. The hook honours `DESTDIR`,
so install through one -- and then **move the prefix back to where it was
configured to be**, because the installed `.pc` files record the configured
prefix and leaving the tree under `DESTDIR` makes pkg-config hand curl a `-L`
that does not exist (`--with-openssl was given but OpenSSL could not be
detected`).

**iOS has no `/etc/ssl` at all.** So curl and openssl complete a TLS handshake
and then fail the chain: `unable to get local issuer certificate`. That is
configuration, not a port problem -- worth recognising, because it looks like a
crypto failure and is not. macOS's curated bundle at `/etc/ssl/cert.pem`
(333 KB) is staged into `<cryptex>/share/ssl/`. The mount point carries a
per-install random suffix, so the path cannot be compiled in; it comes from the
environment, like `PERL5LIB` and `module_path` already do:

```sh
export SSL_CERT_FILE=$CRYPTEX_MOUNT_PATH/share/ssl/cert.pem
export CURL_CA_BUNDLE=$SSL_CERT_FILE
export OPENSSL_CONF=$CRYPTEX_MOUNT_PATH/share/ssl/openssl.cnf
```

`SSL_CERT_FILE` is not enough for `openssl s_client`, which does not call
`SSL_CTX_set_default_verify_paths` unless given `-CAfile`. Pass it explicitly
there. `curl` honours `CURL_CA_BUNDLE` on its own.

### Two cross-compile traps that cost real time

**`-isysroot` must be in `CPPFLAGS`, not only `CFLAGS`.** Autoconf's "is this
function prototyped" checks run the preprocessor alone, which never sees
`CFLAGS`. Without it every such check fails with `'string.h' file not found`
and configure concludes, silently, that the function is unavailable. That is
not cosmetic: it is how curl ends up compiling a stale `!HAVE_GETSOCKNAME`
branch that references struct members which no longer exist and does not build,
and how LibreSSL loses `sys/random.h`.

**curl's release tarball ships a top-level `Makefile` of its own.** So
`[ -f Makefile ] || ./configure ...` skips our configure entirely and lets that
Makefile run a *native* one -- the giveaway is `host_alias=''` in `config.log`
plus `cannot run C compiled programs`. Use `config.status` as the
already-configured sentinel.

### A bundled library links its dependencies by the path recorded in the file

The linker records whatever install name it finds *inside* the library it links
against. Build curl against a LibreSSL whose `LC_ID_DYLIB` still says
`.../libressl-prefix/lib/libcrypto.46.dylib`, and libcurl references that --
a path that exists on no device, and one `bundle.py` then dutifully bundles a
*second* copy of under its own name. Normalise the install names to Apple's
`/usr/lib/...` spelling **in the prefix, before anything links against it**,
not just in the copies. `build.sh` then asserts no build path survives.

### `bundle.py --prebuilt DIR` and the `NO FIXUPS` warning

`--prebuilt` looks in a directory by basename before falling back to extracting
from the cache, so a source build is preferred wherever one exists. And because
"loads but crashes on some paths" is invisible until you hit the path,
`bundle.py` now reports which bundled libraries lack fixups:

```
=== curl: 3 extra libraries, 2.7 MB            (no warnings -- all source-built)
=== dtrace: 1 extra library, 0.5 MB
      NO FIXUPS  libdtrace.dylib  (cache-extracted: loads, but crashes on any
                                   path that dereferences a global)
```

That reproduces the observed behaviour statically: `dtrace` runs until `-l` or
`-n`, and `systemstats` flags all five of its extracted frameworks.

### What is still extracted, and therefore still fragile

`libdtrace` (dtrace), and CoreDisplay, CoreWLAN, GPUWrangler, IOPresentment and
libDiagnosticMessagesClient (systemstats). None has an open-source upstream to
build from.

**That is no longer a dead end.** "Synthesising fixups" is now implemented --
see "The real wall: the cache-uniqued GOT" -- and `libdtrace` already loads and
executes after `dsc_lift.sh`. These six need re-lifting and re-probing on the
device; until then `bundle.py` still prints `NO FIXUPS` for them, which remains
the correct warning for anything staged the old way.

## The index is the rule, and it is now the default (2026-09-01)

`csrutil` converted with a bare `-o` reached the device asking for
`/System/Library/Frameworks/DiskArbitration.framework/DiskArbitration` and died
on `Library not loaded`. The conversion had reported `Rewrote 9 path(s)` and no
warnings.

**Not a missing rule -- a missing flag.** `DylibIndex.resolve()` has had the
public->private move since the day this file recorded it. Without
`--dylib-index` none of it runs, and `auto_fix_path()` alone knows only that
iOS frameworks are flat. For a framework iOS demoted, flattening turns a
*correct* macOS path into a *plausible* iOS path that does not exist -- and
reports it as a successful rewrite. That is worse than not rewriting: the
failure looks like a missing library rather than a wrong path.

It silently disabled two checks as well:

* the missing-library warning, which needs the index to know what iOS has;
* **half the launch prediction.** `unresolvable_imports()` marks a library
  `absent` only when `index is not None` (machomorph.py:1786). `DiskManagement`
  is a PrivateFramework, so the SDK ships no `.tbd` for it, so with no index its
  22 imports fall through to `unknown` and the gate never fires. csrutil was
  converted, signed and declared fine.

### The fix is not a better regex

A regex cannot know. `DiskArbitration.framework/DiskArbitration` is a perfectly
well-formed iOS path; nothing about its *shape* says iOS keeps it in
`PrivateFrameworks`. A hardcoded table of the moves would be a guess about one
iOS version, and this file's own design note already rejected it: "rather than
hardcode these, `--dylib-index` resolves paths against a real list of what the
target cache can load."

So the index stays the only source of truth, and instead it stops being
optional. `machomorph.py` ships `data/ios27_24A5424a_index.txt` and uses it
whenever `--platform` is in `BUNDLED_INDEX` and `--dylib-index` was not given,
announcing which index is in play. `--dylib-index` overrides it,
`--no-dylib-index` opts out, and a non-macOS target with neither now warns that
paths are being rewritten by rule and nothing can be said about the target.
Add an index for a new iOS version to `BUNDLED_INDEX` rather than to the rules.

The user's original command now behaves exactly like the `--dylib-index` one:
`[public->private]`, three missing-library warnings, and `skipped: will fail at
launch on 22 symbol(s)`.

### An index for another build comes out of its IPSW (2026-09-01)

The shipped index is one build's, and the shipping of it makes the wrong one
easy to use without noticing: a bare run announces `data/ios27_24A5424a_index.txt`
whatever the device is running, and an index from a different build is not a
neutral approximation -- it is the same failure the flag-less run had, one
version removed. A library the target moved between builds resolves to the old
spelling and is reported as a successful rewrite.

So `dsc.index` takes the IPSW itself, and runs the extraction:

```sh
python3 -m dsc.index iPhone18,3_26.4_23E246_Restore.ipsw -o data/ios264_23E246_index.txt
./scripts/rebuild_cryptex.sh --ipsw iPhone18,3_26.4_23E246_Restore.ipsw <cryptex>
```

It also takes the directory `ipsw extract --dyld` wrote, or the cache file
itself, so the manual route still works and nothing had to be re-learned.
`--arch` picks the slice (default `arm64e`); `--extract-dir` and `--re-extract`
control the cache of the extraction, which is keyed by IPSW and arch and lives
under `/tmp/machomorph-ipsw`.

Reusing an extraction is a freshness assumption, and this file records four
times one shipped a stale artefact -- but an IPSW is immutable, so the cache
really is the same bytes the extraction would produce. It says so out loud
anyway, and `rebuild_cryptex.sh` rebuilds the index when the IPSW or
`dsc.index` is newer than it.

Verified on both routes: the directory form over the already-extracted 27.0
cache reproduces `data/ios27_24A5424a_index.txt` **byte for byte** (4776 paths,
4691 canonical + 85 aliases), and the IPSW form on
`iPhone18,3_26.4_23E246_Restore.ipsw` extracts and indexes 26.4 from scratch
(4391 paths, 4315 + 76), with the reuse pass giving an identical file.

`rebuild_cryptex.sh` grew the options this needs, and it is now the only place
the target build is named: `--ipsw`, `--dylib-index` for one already built,
`--arch`, and `--os-version` for the minos that was hardcoded at 26.0. Making
the generated index a *default* is still a deliberate act -- copy it into
`data/` and add it to `BUNDLED_INDEX` -- because that is what a bare
`machomorph.py` run picks up, and it should change when someone decides it
does.

One test changed meaning rather than breaking: `test_roundtrip`'s "no
/Versions/ paths left" now runs with `--no-dylib-index`, because with the index
a versioned path can legitimately survive -- the iOS cache carries **IOKit**
under its versioned spelling, so leaving it is resolution working. See
`test_bundled_index`.

## When to lift a library, and when to give up

The question csrutil raises is why `DiskManagement`, `libbootpolicy` and
`libDiagnosticMessagesClient` are not simply lifted out of the cache like
`libxcselect` was. The ladder, cheapest first:

| the library is | do |
|---|---|
| on iOS, another path | rewrite the path. Free, no staging |
| absent, open-source upstream | build it for iOS. Real fixups, ~0 MB VM span |
| absent, no upstream | lift it out of the **macOS** cache -- automatic, or name it as machomorph's input |
| absent, and its own closure fails | nothing works |

The two costs that decide the third row against the fourth, both measured:

* **The lift's own imports must exist on iOS.** A lift retargets a macOS
  library; it does not port it. `CoreDisplay` needs
  `_DSBrightnessExternalConvertLinearToUser` and `IOPresentment` needs
  `_IOAccelDisplayPipeCopyCapabilities`, neither of which iOS exports, so
  `systemstats` can never work and is blocklisted.
* **Each lift reserves 1.6-2 GB of contiguous address space**, because the
  relayout deliberately keeps the cache's segment addresses. Two or three per
  process, never six.

Measured for csrutil's three, against `data/ios27_24A5424a_index.txt`:

```
DiskManagement -> libcsfde        ABSENT
                  libCoreStorage  ABSENT
                  DiscRecording   ABSENT
                  MediaKit, CoreAnalytics, APFS, Security, IOKit   on iOS
```

So lifting `DiskManagement` means lifting four libraries plus `libbootpolicy`
and `libDiagnosticMessagesClient` -- six, past the address-space ceiling before
any of their own symbol closures are checked. And csrutil reports **SIP**
status, which iOS does not have. Both walls, and the second one alone settles
it.

**Where the distinction lives: nowhere automatic.** `machomorph` predicts *that*
a binary will fail; the decision to lift is a human one, and
`rebuild_cryptex.sh` step 2b holds a hand-written list of six images. This file
already records that a hand-written list is what keeps going wrong (see
"The hand-written tool list leaves binaries pointing at nothing"). What would
close it is a closure-cost report -- for each blocking library, how many
libraries the lift would need, whether every one of their imports exists on iOS,
and the total VM span -- so the answer is measured rather than remembered.
Nothing needs it today; the set of interesting blockers is small and already
decided.

## `bundle.py --lift`: port a binary with its whole closure (2026-09-01)

`bundle.py` has always computed the recursive closure of libraries iOS lacks
and staged them. What it could not do was get them out of the cache *properly*:
`obtain()` copied from `/tmp/dsc_out` or ran `ipsw dyld extract`, so everything
it bundled was a raw extraction -- the `NO FIXUPS` warning it printed about its
own output. Lifting was only ever done by hand, in `rebuild_cryptex.sh` step 2b,
against a hand-written list of six images, and reached `bundle.py` through
`--prebuilt`.

`--lift` closes that: `obtain()` runs `dsc_lift.sh` for any image that is
cache-only. A library that is a real file on disk is still copied, since it
already carries its own fixups and there is nothing for a lift to repair. It
passes `--darwin-extsn` through, and treats a `dsc_lift.sh` failure as
unobtainable -- the script deletes its own output when the gotscan verdict is
not `repaired`, so "the file is there" stays a valid test for the caller.

It saves both cache-wide dumps on the first lift and reads them thereafter, so
the whole-cache pass is paid once rather than once per library; `DSC_SLIDE_JSON`
and `DSC_PATCHES_TXT` override with your own.

### The dry run now reports both ceilings

`--dry-run` printed size, which was never the thing that decides. The two
things that do:

* **the lifted library's own imports must exist on iOS** -- the `CoreDisplay` /
  `IOPresentment` wall that makes `systemstats` impossible;
* **each lift reserves 1.3-2.0 GB of contiguous address space**, and what runs
  out is the largest free hole, so two or three per process and never six.

The second is now measured and printed. On csrutil, which is what raised the
question:

```
=== csrutil: 5 extra libraries, 2.9 MB
          1.48 MB  .../DiskManagement.framework/Versions/A/DiskManagement
          0.71 MB  /usr/lib/libCoreStorage.dylib
          0.41 MB  /usr/lib/libbootpolicy.dylib
          0.18 MB  /usr/lib/libcsfde.dylib
          0.12 MB  /usr/lib/libDiagnosticMessagesClient.dylib
      5 libraries reserve over 537 MB of contiguous address space each:
          1972 MB  libDiagnosticMessagesClient.dylib
          1842 MB  libCoreStorage.dylib
          1707 MB  DiskManagement
          1656 MB  libcsfde.dylib
          1336 MB  libbootpolicy.dylib
      TOO MANY      5 at once will not fit; measured ceiling is two or three
```

So the closure is *cheap* -- 2.9 MB, five libraries, and all five lift clean
with zero `NO FIXUPS` -- and it still cannot work, for a reason size never
showed. Worth noting `DiscRecording` is absent from iOS and correctly not in
the closure: `DiskManagement` links it `LC_LOAD_WEAK_DYLIB`, so its absence is
tolerated. And csrutil reports SIP, which iOS does not have.

**Compaction is what lifts that ceiling** (see "Compacting a lifted image"),
and this is the first thing that would actually benefit from it: the five
reserve 8513 MB between them as lifted, and compaction takes a library down to
its own size, so the address-space wall stops being the reason csrutil cannot
work. Its *other* reason -- iOS has no SIP to report -- still settles it, and
these five have never been lifted, so that is a prediction rather than a
measurement.

## The default index regressed the lift, and the gate caught it (2026-09-01)

Making the dylib index the default broke `dsc_lift.sh` in two ways at once, and
the first from-scratch rebuild after it refused to build at all:

```
skipped: lifted/libcrypto.46.dylib: will fail at launch on 7 symbol(s) the
  target does not export: _TEACertificateChainAddCert (from
  TrustEvaluationAgent); ... (--force to convert anyway)
LIFT FAILED: /usr/lib/libcrypto.46.dylib
LIFT FAILED: /usr/lib/libssl.48.dylib
one or more lifts failed -- refusing to build a degraded cryptex
```

**1. `LC_ID_DYLIB` is not a dependency.** The path-resolution loop excluded only
`LC_RPATH`, so a library's own install name was resolved against the target
index and reported missing -- every lifted library told "1 library is missing on
the target; this binary will fail at load" about its own name. It now falls
through to `auto_fix_path()` as before, which flattens `Versions/` out of it,
which is behaviour `bundle.py` depends on.

**2. A lift is not a staging decision.** Step 4b of `dsc_lift.sh` ran the launch
prediction with no `--no-symbol-check`, harmless while there was no index and
everything came back `unknown`. With one, Apple's `libcrypto` "fails" on 7
`TrustEvaluationAgent` symbols and `libssl` on 330 `libcrypto` ones -- both of
which this project bundles right beside them, and `dsc_lift` has no way to know
that. The gate belongs where the answer is known: `--provide-lib` at staging
time, then `cryptex.symbols` and `cryptex.verify` over the finished tree.

Worth recording that **the failure was loud**. `dsc_lift.sh` deleted its own
damaged output, and `rebuild_cryptex.sh` refused rather than shipping a cryptex
missing `libcrypto` and `libssl` -- which would have surfaced on device as an
`openssl` that does not load. Those two checks were added in an earlier session
precisely because the alternative had happened.

### Verified on device

Rebuilt from scratch into `apple-cryptexes/machomorph-test-rebuild`, installed,
and probed. Raw data in `measurements/device_probe_2026-09-01_index_default.tsv`.

| check | result |
|---|---|
| the 7 lifts | all `VERDICT: repaired`, **all 7 byte-size-identical** to the pre-change lifts |
| `cryptex.verify` | all checks pass; 478 binaries, 10 libraries, 49 aliases |
| `symbol_check` | **0 of 527** will fail at launch |
| `diff -rq` vs the previous tree | **526 of 527 binaries and 9 of 10 libraries byte-identical** |
| device probe, 525 binaries | **429 ok / 76 skipped / 20 blocked**, every binary in the same bucket as the reference, and **0 name differences** |
| failures of any kind | **0** dylib, **0** symbol, **0** killed, **0** crash |
| crash reports | 3 files, **0 `EXC_ARM_PAC_FAIL`**. One `nfsstat` SIGSYS (the known NFS syscall iOS lacks) and one unrelated jetsam |

The one file that is not byte-identical is `lib/libcurl.4.dylib`, 416 bytes in
two strings:

```
before:  /System/Library/Frameworks/LDAP.framework/LDAP              (weak)
after:   /System/Library/Frameworks/LDAP.framework/Versions/A/LDAP   (weak)
```

Same for `Kerberos`. Both are absent from iOS and weak, so dyld skips them under
either spelling. Cause: with an index, `resolve()` returns None for an absent
library and leaves the path alone, where `auto_fix_path()` used to flatten it.
Inert, and `verify_cryptex` and `symbol_check` are clean on it.

### Device identity was established before believing the probe

The same discipline the previous session needed. `srdtool cryptex list` gave a
fresh mount suffix (`...SOy163`), `bin/` counted 527 and `lib/` 10, and
`openssl dgst -sha256` **on the device** returned `aefa6335...` for
`lib/libcurl.4.dylib` -- the rebuild's hash, not the previous tree's
(`192527e9...`). That file being the only one that differs made it the right
one to hash.

Two transport notes. `ssh -p 2222 root@localhost` works (password `PASSWORD`,
through `iproxy 2222 22`) and is far better than driving everything through
`srdtool research spawn`, but **dropbear intermittently refuses an auth that
then succeeds**, so every call needs a retry just as the spawn route does. The
probe is still driven in slices from the Mac.

### Functional results, all reproduced from this build

`openssl` (LibreSSL 3.3.6, correct SHA-256, TLSv1.3 to apple.com with
`Verify return code: 0 (ok)`), `curl` (**http=200, verify=0**, 254322 bytes),
`tcpdump --version` (4.99.1 / libpcap 1.10.1), `dtrace -l` reaching its own
initialisation, `vmmap $$` against a live process, all eight memory tools,
`perl` 5.34.1 with `Digest::MD5`, **`Sys::Syslog`** and `JSON::PP` (needs
`PERL5LIB=$CRYPTEX_MOUNT_PATH/share/perl5`), `zsh` + `zsh/pcre`, and the llvm
tools (`otool -L`, `nm -mu`, `dyld_info -platform`, `lipo -info`,
`vtool -show-build`, `objdump`, `size`, `c++filt`, `dwarfdump`, `strings`,
`swift-demangle`).

## The architecture: one tool, and what is left outside it (2026-09-01)

The trigger was a fair complaint: `machomorph.py /usr/bin/csrutil -o /tmp/csrutil
-p ios -v 27.0 --force` produced a binary and three warnings about libraries it
had not brought along, and the answer to "how do I also get the libraries" was
"use a different program, with a different flag, against a hand-written list".
That is the wrong shape. A conversion whose output cannot load is not a
conversion.

### What moved, and what did not

| was | is |
|---|---|
| `tools/bundle.py` -- closure, obtain, stage | `machomorph.py`: `library_closure()`, `obtain_library()`, `obtain_libraries()` |
| `tools/dsc_lift.sh` -- the 7-stage lift pipeline | `machomorph.py`: `lift_library()` |
| `cryptex/cryptex.restage` run by the build | not run; the closure is per binary, so the bug it retrofitted cannot occur |
| `rebuild_cryptex.sh` steps 2, 2a, 2b, 2c, 5, 6b | gone -- 664 lines to 449 |
| `dsc/facts.py`, `dsc.rebind`, `dsc.objc`, `dsc.compact`, `dsc.gotscan` | **unchanged**, imported as modules |

The five stage scripts stay separate files and keep their CLIs, and that is
deliberate rather than lazy: when a lift comes out wrong the way to find out why
is to run one stage by hand on the intermediate, which is how every bug in
"Lifting an ObjC library out of the cache" was found. They gained `main(argv)` so
they can be called in-process; nothing else about them changed.

`machomorph.py` grew from 3469 to about 4500 lines. What it owns now is the
*orchestration* -- which is the part that was duplicated, and the part that had
the hand-written lists in it.

### The layout: libraries beside the binary, at the target's own path

`-o out/csrutil` gives:

```
out/csrutil
out/System/Library/PrivateFrameworks/DiskManagement.framework/DiskManagement
out/usr/lib/libCoreStorage.dylib
out/usr/lib/libbootpolicy.dylib
out/usr/lib/libcsfde.dylib
out/usr/lib/libDiagnosticMessagesClient.dylib
```

Three things about that are decisions rather than defaults:

* **The TARGET's spelling, not the macOS one.** `auto_fix_path()` runs on the
  destination too, so `DiskManagement.framework/Versions/A/DiskManagement`
  becomes the flat iOS spelling. Mirroring `Versions/A` would carry a macOS-ism
  into the tree and cost 11 bytes in every reference to it.
* **`@loader_path`, always, computed per referrer.** For a main executable it
  means the same as `@executable_path`, and it is the one that is also right
  inside a bundled library referencing another one -- which is the common case
  (`DiskManagement` references `libcsfde` four directories away, as
  `@loader_path/../../../../usr/lib/libcsfde.dylib`). A library's own
  `LC_ID_DYLIB` is set to the spelling a *binary* uses, since the two differ
  under a mirror layout and dyld resolves either to the same file.
* **A cryptex is still flat**, into `--cryptex-libdir`, with one spelling for
  every referrer. `verify_cryptex` check 4 and `cryptex.restage` both assume that,
  and the shorter name is load-bearing: `tcpdump` has 16 bytes of load-command
  slack for its two references and failed the build by exactly 8 once.

`--lib-layout flat`, `--lib-subdir` and `--libs-into` steer it; `Cryptex` and
`DirStaging` are the two implementations of the same three-method interface
(`library_dest`, `install_name_for`, `reference_name`).

### Three phases, because the cost gate has to come before the cost

A lift is minutes. So the closure is enumerated from cheap *extractions*
(`probe_library()`), the gates are applied, and only then is anything lifted.
An extraction is worthless as a library and perfectly good as a source of load
commands, which is the whole reason the split works.

`--max-libs 7` is the gate. A larger closure means the binary is dragging in a
whole macOS subsystem that cannot work on iOS anyway -- `system_profiler` wants
AppKit, SkyLight, HIToolbox and OpenGL, which is the macOS window server. Such
a binary is still converted and simply reports its libraries as missing, which
is the truth. `--dry-run` prints every closure with its size and its
address-space cost and stops.

### The 33 weakened symbols are now derived, not written down

`rebuild_cryptex.sh` step 2c used to carry 30 symbol names by hand for
`DiskManagement` and `libcsfde`, plus 3 for `libcurl`. They are gone.
`--weaken-unresolvable` runs the existing launch prediction over the bundled
library and weakens exactly what the target does not export, naming every one.

**It stays opt-in, and that is the point.** Weakening turns a certain load
failure into a crash on any path that reaches the symbol, so it is a judgement
about what the tool needs. `rebuild_cryptex.sh` makes that judgement for the
cryptex, in one flag with the reasoning beside it, which is what a
hand-transcribed list of 33 names was pretending to be.

### An input that is not a file is a lift

`machomorph.py /usr/lib/libxcselect.dylib -o lifted/libxcselect.dylib` used to
be `cannot read: No such file or directory`. It is now the lift, because the
library exists as a file nowhere and the cache is the only copy -- so the
request is unambiguous. Same pipeline as the closure pass uses.

### Verified: byte-identical lifts, and a real run

The refactor's whole risk is that the pipeline changed while moving from shell
to Python. So all **12** libraries this project has ever lifted were re-lifted
through the new in-process path and compared against the shipped ones:

| library | |
|---|---|
| `libxcselect`, `libdtrace`, `libpcre.0`, `libcrypto.46`, `libssl.48` | **byte-identical** |
| `TrustEvaluationAgent`, `libCoreStorage`, `libbootpolicy`, `libDiagnosticMessagesClient` | **byte-identical** |
| `libcurl.4` (3 weakened symbols) | **byte-identical** |
| `libcsfde` (23), `DiskManagement` (7, and the only ObjC one) | **byte-identical** |

Two differences that were *not* the pipeline, and both are worth knowing:

* **`codesign` derives the signing identifier from the output filename**, so
  lifting to `/tmp/xcs.dylib` instead of `libxcselect.dylib` legitimately
  changes 16 bytes. Compare with the same basename or the diff is noise.
* **The lift's internal `machomorph` call needs `--no-libraries`.** Without it
  the lifted `libssl` came out pointing at `@loader_path` copies of `libcrypto`
  and `TrustEvaluationAgent` that had been bundled into the work directory. A
  lift is one image; where its own absent dependencies go is the *caller's*
  decision, and only the staging pass knows it. Found by byte-diff, which is
  exactly what that check is for.

And the layout was run against real dyld rather than reasoned about. The
csrutil closure was lifted for **macOS** (`-p macos --no-cpusubtype-fix`, the
local test loop this file already documents), staged into the mirror layout, and
executed:

```
$ ./csrutil                      -> its full usage, rc=0
$ ./csrutil status               -> "System Integrity Protection status: enabled."
```

Real output, through five lifted libraries reached by relative paths four
directories deep. Note what that also settles: the mirror layout's differing
spellings between the binary's reference, a sibling library's reference and the
`LC_ID_DYLIB` are all resolved to the same file, which was the one thing about
it that could not be checked statically.

Two harness details cost time and are worth recording:

* **`--no-cpusubtype-fix` has to reach the lift, not just the conversion.** The
  first attempt produced `arm64e.v1` libraries and `csrutil` died in dyld with
  `incompatible architecture (have 'arm64e.v1', need 'arm64e')` -- the trap this
  file already records for the local loop, one level deeper than where it was
  recorded.
* **An entitled binary ad-hoc signed on macOS is SIGKILLed** (`rc=137`), which
  looks like a load failure and is not. Sign the test copy with empty
  entitlements (`--entitlements` an empty plist, `--no-license-to-operate`).

Also checked: `test_machomorph.py` 96 passed / 0 failed (up from 88 -- two new
sections, the closure and the cache-only input), and a three-binary cryptex
(`openssl`, `tcpdump`, `vmmap`) built in **one** command that previously needed
`rebuild_cryptex.sh` steps 2a, 2b, 3, 5 and 6b: 4 libraries lifted and staged,
`verify_cryptex: all checks pass`, `symbol_check: 0`.

### A scan's defaults are the tool's, not the script's

The batch invocation was five flags of boilerplate that every caller had to
repeat, and a caller who forgot one got a quietly worse cryptex:

```sh
machomorph.py --scan --scan-xcode \
    --exclude-from data/exclude_xcrun_shims.txt \
    --exclude-from data/blocklist_symbols.txt ...
```

All four are now what a scan does by default, alongside the dylib index which
already worked this way:

| default | why it is not a preference |
|---|---|
| the Xcode toolchain is scanned too | `/usr/bin/otool`, `nm`, `lipo`, `strip` are one hard-linked xcrun stub, not tools. A sweep that takes those and leaves the real llvm binaries behind has picked the wrong half -- and the stubs then own those names in `bin/` |
| `data/exclude_xcrun_shims.txt` | 95 paths, identified by symbol. On iOS they are SIGKILLed, and `bin/otool -> DeRez` shipped once because of it |
| `data/blocklist_symbols.txt` | 269 binaries a device probe measured dying at launch. Complementary to the launch prediction, not redundant: the SDK ships no PrivateFramework stub, so those symbols fall through to `unknown` and fail nothing |

`--no-scan-xcode`, `--no-exclude-defaults` and `--exclude-from` (which adds
rather than replaces) are the overrides, and each default announces itself the
way the index does.

**The exclusion lists apply ONLY to what a scan finds.** A path named on the
command line is always converted. That distinction is the whole reason this is
safe to default: `/usr/bin/otool` is on the shim list, and
`machomorph.py /usr/bin/otool -o out` silently doing nothing would be
indefensible. `main()` now tracks a `scanned` set for exactly this.

Checked for equivalence rather than assumed: a bare `--scan` and the old
five-flag invocation both come out at **572 convert / 418 skip**, and
`--no-exclude-defaults` takes it to 632 -- so the lists are doing what they did
and nothing else changed.

### The layout: four packages, and the dependency inversion inside one of them

Everything used to sit in one `tools/` directory -- lifting stages, cryptex
checks, shell scripts and C programs, thirteen files with no relationship
expressed between them. Now:

```
machomorph.py     the conversion, the closure, the order of the lift
dsc/              read and repair an image from a dyld shared cache
cryptex/          build a cryptex, and check it before installing
scripts/          shell, because it drives other programs
native/           C, with a Makefile
data/  lifted/
```

The move fixed a real problem rather than only tidying. `Image`, `adrp`, `u32`,
`add_imm64` and `ldr_uimm64` -- the Mach-O reader and the instruction decoders
that four modules depend on -- lived in **`dsc_gotscan.py`**, the *diagnostic*
tool. So `facts`, `rebind` and `compact` each did a `sys.path.insert` and
imported their library out of the CLI that judges their output. They are now
`dsc/image.py` and `dsc/arm64.py`, and **all 7 `sys.path.insert` hacks and the
`__import__()`-by-string in `machomorph.py` are gone**.

Two other things stopped being in the wrong file:

* `_extract_from_cache()` and its inlined `clang -arch arm64e` line were cache
  knowledge inside `machomorph.py`. They are `dsc/extract.py` and
  `native/Makefile`, next to the C program they build.
* The stage ORDER -- `objc` before `compact`, `compact` after `gotscan`, method
  lists last -- is the most error-prone thing in this repo and existed only as
  prose in this file. It is `dsc/__init__.py` now, beside the code it governs.

Each stage keeps its CLI, reached as `python3 -m dsc.gotscan FILE` from the
repository root. That is not decoration: every ObjC lifting bug in this file was
found by running one stage by hand on an intermediate.

**`cryptex.verify` and `cryptex.symbols` still print `verify_cryptex` and
`symbol_check:`** as their own labels. Deliberate: those strings appear in
dozens of measurements recorded above, and renaming them would make older
evidence read as if it came from something else.

Verified after the move: all 12 lifts still **byte-identical**, 94 tests pass
(the lift test needs `--change` to match the shipped libxcselect's install name,
or it legitimately differs), `python3 -m` works for all nine module CLIs, and
the three-binary cryptex still comes out `verify: all checks pass`.

### NOT yet done

* **No full cryptex rebuild, and no device probe.** The batch now computes a
  closure for every binary in the scan, so a from-scratch build lifts on the
  order of a hundred libraries at minutes each. That is the run that would
  settle whether the wide port still comes out the same, and it is the next
  thing to do.
* `cryptex.restage` is superseded but not deleted, and `cryptex.verify` still
  assumes the cryptex's flat layout -- it has nothing to say about a mirror
  tree.

## The first wide rebuild through the one-tool pipeline (2026-09-01)

The rebuild the restructure was waiting for: `machomorph-test` from an empty
`lifted/` and an empty `bin/`, with the library closure choosing the library set
for the first time instead of a hand-written list of twelve.

**It found five bugs, and four of them only a device could find.** That is the
result worth recording -- not the counts.

### The build, and what the device said about it

| | first build | after the fixes |
|---|---|---|
| libraries lifted | **52** (40 never lifted before) | 37 |
| binaries staged | 572 | 539 |
| bundled libraries | 54, 462 MB | 39, 427 MB |
| `symbol_check` | 0 of 572 | **0 of 539** |
| `cryptex.verify` | **FAILED**, 1 check + 1 note | **all checks pass** |

Device probe of the first build (mount `OCWg9R`, identity established by hashing
three libraries on the device with the cryptex's own `openssl dgst`):

| outcome | count |
|---|---|
| loads and runs | **424** |
| skipped (denylist) | 119 |
| blocked (daemon or interactive) | 22 |
| fails: library | **6** |
| crash | **1** |
| fails: symbol | **0** |
| SIGKILLed | **0** |

Zero symbol failures across 572 binaries, so the closure port works. Every one
of the seven failures was a real bug.

### 1. A per-binary closure DOES leave absolute references

The commit that moved the closure into `machomorph` claimed: "A closure computed
from the binary in front of us cannot have that gap." That is wrong, and
`cryptex.verify` check 3 said so before the device did -- 30 references across 7
binaries (`asr`, `automount`, `bless`, `kextcache`, `kextload`, `kextutil`,
`networksetup`) naming `/usr/lib/libCoreStorage.dylib`, `OpenDirectory`,
`KernelManagement` absolutely **while those libraries sat in `lib/`**.

The mechanism: `--max-libs 7` refused *their* closure, so nothing was bundled
*for them* -- and another binary brought the same library in anyway. So this is
"a batch undoes `--provide-lib`" in a third costume, and `restage.py` existed to
retrofit exactly it.

**Fix, and the rule behind it:** a binary is repointed at every library that
ended up staged, not at the ones from its own accepted closure. Rewriting a
reference to a library that IS there is free and always right; **`--max-libs` is
about what to pay to lift, not about what a binary is allowed to see.**

### 2. `--weaken-unresolvable` was weakening the binaries too

1281 symbols across 48 files, and **30 of those files were binaries**:
`screencapture` 155, `profiles` 65, `networksetup` 49, `softwareupdate` 46,
`spctl` 42, `mDNSResponder` 19.

Not what the flag was for, and it contradicts this file's own rule. For a
bundled **library** weakening is the difference between the whole closure loading
and none of it, because iOS has no equivalent of Authorization Services or the
`SecTransform` pipeline at all. For a **binary** the same trade turns a clean
skip into a crash later -- and a port that dies is dead weight that shadows a
native tool of the same name, which is why `ios_native_commands.txt` exists.

Now scoped to the library staging pass (`libargs._weaken_unresolvable_here`);
`--force` remains the way to ask for it on a binary. `bin/` went 572 -> 539,
which is the 30 plus fix 4's effect, and that shrinkage is the fix working.

### 3. The lift cache was also a default `--prebuilt` directory

`obtain_library()` checks the `--prebuilt` directories **first and
unconditionally**, and `default_prebuilt()` put the lift cache in that list. So
`lift_is_stale()` -- the make-style rule this file documents at length, added
after a stale `libxcselect` shipped with a PAC-faulting GOT site -- was **dead
code in the default case**, and a cached lift was handed back at any age.

**The fifth instance of "the file is there is not a check."** Reuse now goes
through `lift_is_stale()`, which is what it is for. An explicit `--prebuilt`
still wins over everything: trusting what the user points at is reasonable in a
way that trusting our own leftovers is not.

### 4. `dylib_deps()` ignored `LC_REEXPORT_DYLIB`

`assetutil` and `layerutil` died on

```
Library not loaded: .../ApplicationServices.framework/Versions/A/Frameworks/ATSUI.framework/Versions/A/ATSUI
```

and **nothing static had reported it**, because as far as the closure was
concerned there was nothing to report. An umbrella framework is nothing *but*
re-exports: `ApplicationServices` and `Cocoa` export **zero** symbols of their
own. The closure followed only `LC_LOAD_DYLIB`, so it bundled the umbrella, saw
no dependencies, and shipped a hard reference to a library iOS does not have.

`LC_REEXPORT_DYLIB` and `LC_LOAD_UPWARD_DYLIB` are dependencies and are followed
now. The effect is not that the umbrellas got fixed -- it is that their closures
grew past `--max-libs 7`, so **they are dropped rather than shipped broken**, and
`ATSUI` (which `QD` needs) is lifted and staged instead. `lib/` went 54 -> 39.

### 5. `needs_relayout()` missed a non-page-aligned segment FILESIZE

The most valuable of the five, and it cost four working tools.

```
Library not loaded: @loader_path/../lib/libHeimdalProxy.dylib
  Referenced from: .../lib/Kerberos
  Reason: tried: '.../lib/libHeimdalProxy.dylib' (code signature invalid
          (errno=1) sliceOffset=0x0, codeBlobOffset=0x3480, codeBlobSize=0x4780)
```

`libHeimdalProxy`, `ApplicationServices` and `Cocoa` are 4-20 KB umbrellas whose
only segments are `__TEXT` and `__LINKEDIT`. Both page-aligned, both in VM
order -- so `needs_relayout()`'s two conditions said nothing, the relayout never
ran, and `__TEXT` kept the extraction's filesize of `0x3f8`:

```
__TEXT      vm=0x19d78c000+0x3f8    file=0x0+0x3f8
__LINKEDIT  vm=0x1ff96c000+0x8000   file=0x3f8+0x7808     <- starts mid-page
```

So the mapped segments did not tile the file, the signature covered file pages no
segment claimed, and **the kernel refused it**. This file already records the
rule ("Mapped segments must tile the file") and its trap -- the message reads as
a trust problem and is not one, `codesign --verify` passes because codesign(1)
does not care. What was missing is that `needs_relayout()` did not detect the
condition, only the two VM-layout ones.

dyld then refused `libHeimdalProxy` and took **`curl`, `ssh-add`, `ssh-keygen`
and `ssh-keyscan`** with it -- all four of which worked in the previous build.
So bundling Kerberos's closure was a regression, and it is the second instance
of "bundling a library can be worse than not bundling it".

**One predicate fixed both symptoms.** `needs_relayout()` now also returns True
when a mapped segment's filesize is not page-aligned (`__LINKEDIT` excepted, as
in a normal dylib), and the existing device-proven relayout does the rest:

| | before | after |
|---|---|---|
| `__TEXT` filesize | `0x3f8` | `0x8000` |
| VM span | 1570 MB | **0.06 MB** |

The span collapsed because the regular layout is also what `dsc.compact`'s
page-alignment assertion needs -- so the `NOTE  3 bundled libraries reserve over
256 MB` line is gone too. Checked against 305 ordinary macOS Mach-Os: **0** are
now relaid out that were not before, so the predicate discriminates.

### And the gate, because the kernel should not be the first to notice

`cryptex.verify` grew a check: a bundled library whose mapped segments do not
tile the file, with the kernel's exact error in the message. Validated the only
way that means anything -- it named **exactly those three** out of 54, and
nothing else.

### What this says about the checks

Worth stating plainly, because it cuts against this project's habit of proving
things on the Mac first. Of the five bugs:

* **1** was caught by `cryptex.verify` before the install. Good.
* **2** and **3** were caught by reading the build's own output -- 1281 weakened
  symbols and a lift file whose mtime had not moved. Both were *in the log*.
* **4** and **5** were caught **only by the device**, and neither was
  detectable by anything that existed: 4 because the closure could not see a
  dependency it did not follow, 5 because `codesign --verify` passes and only
  the kernel checks tiling.

Both now have static gates. That is the pattern this file keeps recording: the
device does not find bugs the Mac could have found, it finds the bugs whose
*check did not exist yet*, and the fix is the check as much as the code.

### Reprobed by the user, and it found two more (2026-09-01)

The fixed build was installed and three failures reported by hand, which is
worth more than the whole automated probe because all three were on paths the
probe cannot reach. Two independent bugs, both in the sections below:

| reported | cause |
|---|---|
| `csrutil` dies on `_DAUnregisterApprovalCallback` | the PrivateFramework blind spot. It used to be worked around by a hand-written list this session's refactor deleted |
| `sendmail` segfaults | the lifted `LDAP`'s initialiser, at a base-relative offset nothing adjusted |
| `curl` segfaults, and it worked before | the same `LDAP`. `libcurl` weak-links it, and LDAP was bundled for the first time in this build |

Both were regressions in the honest sense: the tree got *bigger* and two things
that worked stopped. `curl` is the second time this file has had to record
"bundling a library can be worse than not bundling it", and `csrutil` is the
second time a derived answer replaced a hand-written list that was carrying
knowledge the derivation could not reach.

## A base-relative offset the relayout did not move (2026-09-01)

`sendmail` and `curl` both segfaulted before `main()`. The crash report says
where, and it is not either of them:

```
EXC_BAD_ACCESS, SIGSEGV, KERN_INVALID_ADDRESS at 0xf803880103042590
  libsystem_platform.dylib   _platform_memchr
  LDAP                       +0x125a8
  dyld  invocation function for block in
        dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const
```

`0xf803880103042590` is not an address, it is a raw chained-pointer bit pattern
read as one, which is the signature this file already records for an unrepaired
lift. That reading is wrong here, and `dsc.gotscan` said so: `VERDICT: repaired,
AUTHENTICATED_LEFTOVERS: 0`. The garbage is downstream of the real fault.

**The real fault is one 32-bit field.** `__init_offsets`
(`S_INIT_FUNC_OFFSETS`, the modern spelling of `__mod_init_func`) holds each
initialiser as an **offset from the mach header** rather than as a pointer. A
pointer-based `__mod_init_func` is carried by the chained fixups and comes out
of a lift correct. A 32-bit offset is carried by nothing.

And `--reserve-header` moves the header. That is its whole purpose: it lowers
`__TEXT`'s vmaddr by whole pages and pushes the segment's contents the same
distance further into the file, so every section keeps the address it had and no
ADRP has to be rewritten. The consequence is that the image base moves and the
code does not, so every distance recorded from the base is now that much too
small. This file already records the class:

> **`--reserve-header` moves the base further than it moves the code.** The
> export trie stores offsets from the image base, and it was being built before
> `text_gap` lowered that base, so every exported symbol landed one page early.

The export trie was fixed then. `__init_offsets` and `LC_FUNCTION_STARTS` are
the other two and were missed. Measured on `LDAP`:

| | stored | dyld computes | truth |
|---|---|---|---|
| before | `0x12594` | `0x19cb06594` | |
| after | `0x16594` | `0x19cb0a594` | a `paciza` + `__cxa_atexit` static-init thunk |

So dyld called a page short of the initialiser, landing mid-function with
garbage in every register, and the first thing that code did was call `memchr`
on whatever was in `x20`.

### Why it hid for every lift this project has ever shipped

**`LC_FUNCTION_STARTS` is base-relative too, and was wrong by exactly the same
0x4000.** So `dyld_info -function_starts` on a lifted library reported the bad
initialiser address *as a function start* -- the two errors agreed with each
other, and every tool that reads one of them corroborated the other. Chasing
this, the first check run was "is the address dyld jumped to a function start",
the answer was yes, and that nearly closed the investigation.

The tell that breaks the tie costs nothing: **the first entry of
`LC_FUNCTION_STARTS` is the first function in `__text`**, so it has to land
inside `__text`. On every lifted library it landed one page below it, at an
address inside the load-command padding. On `libxcselect`: `0x728` where
`__text` begins at `0x4728`.

### Blast radius, measured

| | |
|---|---|
| lifted libraries in the tree | 33 of 39 |
| whose `LC_FUNCTION_STARTS` was a page low | **33 of 33** |
| which also carry `__init_offsets`, i.e. fatal | **2** -- `LDAP`, `ATSUI` |
| binaries `LDAP` takes down | `curl` (through `libcurl`), `sendmail`, `postfix`, `httpd`, `checkgid` |

`checkgid` is worth calling out: this file lists its SIGSEGV under "known-open,
do not re-diagnose, unknown whether it is ours". It is ours, it is this, and its
crash report faults at **the same byte offset in the same region** as
sendmail's. Two reports of one bug, filed as one open question and one mystery.

`LC_FUNCTION_STARTS` on its own is not fatal -- it is symbolication and unwind
bookkeeping -- but a wrong one makes every crash report and every `dyld_info`
reading of a lifted library quietly wrong, which is how this bug stayed hidden.
Both are repaired together in `MachO.header_relative_offsets()`, beside
`fix_data_const_flags()` and `fix_tlv_descriptors()`.

### This one IS reproducible on the Mac, and that is the lesson

The previous session established that macOS dyld does not validate TLV offsets
at all, so no local `dlopen` could reproduce that class. The opposite is true
here, and it is a two-second test, because **dyld runs initialisers on
`dlopen`**:

```
$ native/dlopen_test lifted-for-macos/LDAP            # repaired
LOADS
$ native/dlopen_test LDAP.broken                      # the offset put back
<SIGABRT>
```

Same library, one field, and the local loop separates them immediately. Nothing
was missing but the test: no lifted library carrying an initialiser had ever
been handed to `dlopen_test`, because the libraries the local loop was built for
(`libxcselect`, `libcrypto`, `libdtrace`) have none. `dlcall_test` exists
precisely because `dlopen` proving an image mappable is not enough -- and here
`dlopen` alone was enough and was not run.

### And the gate

`MachO.stray_header_offsets()`, checked by `cryptex.verify` on every bundled
library: no `__init_offsets` entry and no `LC_FUNCTION_STARTS` start may land
outside an executable section. Validated the only way that means anything --
it names **33 of 39** libraries in the build that shipped, **0 of 39** in the
rebuilt one, and **0 of 489** binaries in either.

Two things it took a wrong version to get right:

* **The base is `__TEXT`'s vmaddr, not `segments[0]`'s.** In a main executable
  `segments[0]` is `__PAGEZERO` at 0, so the first version reported every
  binary on the system, 490 of 490.
* **The `__init_offsets` check alone would have missed this.** A page below the
  real initialiser is still inside `__text`, so only the
  `LC_FUNCTION_STARTS` half fires on `LDAP`. `ATSUI` is the reverse: its
  initialiser is the first function in `__text`, so a page below it is outside
  and both halves fire. Neither check subsumes the other.

## The PrivateFramework blind spot, closed (2026-09-01)

`csrutil` on the device:

```
Symbol not found: _DAUnregisterApprovalCallback
  Referenced from: <...>/lib/DiskManagement
  Expected in: /System/Library/PrivateFrameworks/DiskArbitration.framework/DiskArbitration
```

which is the failure this file has a whole section about, reappearing after it
was fixed. The fix, the first time, was `rebuild_cryptex.sh` step 2c: 33 symbol
names written out by hand, `_DAUnregisterApprovalCallback` among them. This
session's refactor replaced that list with `--weaken-unresolvable`, which
derives the set from the launch prediction -- and the launch prediction reads
the target's surface from the SDK's `.tbd` stubs, which cover **no
PrivateFramework**. So `DiskArbitration` was `unknown`, `unknown` fails nothing
and weakens nothing, and the gate reported `0 of 539` while shipping a library
that cannot load.

Both halves did exactly what they promise. The derivation was strictly more
correct than the list *and* strictly less informed, and nothing said so.

### `dsc.symindex`

The cache knows, and the cache is on disk. `dsc.symindex` reads what every
image in a shared cache exports, the companion to `dsc.index` reading what it
can load:

```sh
python3 -m dsc.symindex iPhone18,3_27.0_24A5424a_Restore.ipsw -o ios27_symbols.txt.gz
./machomorph.py ... --target-symbols ios27_symbols.txt.gz
./scripts/rebuild_cryptex.sh --ipsw <ipsw> <cryptex>      # builds and uses it
```

**The exports really are in the cache**, which is not obvious given that this
file records the opposite for an *extraction*: "Loads but `dlsym` finds nothing
-- the export trie is empty", which is why a lift rebuilds the trie from the
symbol table. The trie is there, in the `.dyldlinkedit` subcache, reached
through the image's own `__LINKEDIT` (vmaddr, fileoff) pair. So a device's bare
cache head is not enough and an IPSW is, exactly as for `dsc.index`.

Two things to get right, both of which this file's earlier hand-measurement of
the same question also had to:

* **Follow `LC_REEXPORT_DYLIB`.** An umbrella framework exports nothing of its
  own -- `ApplicationServices` and `Cocoa` export zero symbols -- so a
  trie-only answer would condemn every binary that uses one. 138 of the 4691
  images gain symbols this way.
* **Union with the SDK, do not prefer the cache.** `TargetSymbols._symbols()` is
  deliberately coarse, a regex over a whole `.tbd`, so it can name things that
  are not exports. Unioning keeps every SDK-covered library behaving exactly as
  it was measured (39 of 39 real failures, 0 of 384 wrongly condemned) and lets
  the index only ever add knowledge where there was none.

### It reproduces the device's answer, and it costs one binary

The validation that matters, run before rebuilding anything:

| | |
|---|---|
| iOS 27.0 cache | 4691 libraries, 4.68M exported symbols, 5.25M after re-exports |
| libraries the SDK describes | 623. **The index adds 4068** |
| `DiskManagement` | `WILL FAIL AT LAUNCH: _DAUnregisterApprovalCallback` -- the device's exact answer |
| `_DARegisterDiskUnmountApprovalCallback`, `_DASessionCreate` | present, as the earlier hand-measurement found |
| binaries in the shipped tree newly condemned | **1 of 490** |

The one is `diskutil`, on `_DAApprovalSessionCreate` and three
`_OBJC_CLASS_$_SK*` StorageKit classes. It is denylisted by `device_probe.sh`
(on macOS it changes disk state), so the device had never been asked, and it
would have died at launch. So the index costs one binary that never worked and
buys four libraries that could not load:

```
ATS            _CreateFontForScaler, _ReleaseFontForScaler      (libFontParser)
HIServices     _kTCCServiceAccessibility, +2                    (TCC)
OpenDirectory  _OBJC_CLASS_$_SFAuthorization                    (SecurityFoundation)
DiskManagement _DAUnregisterApprovalCallback                    (DiskArbitration)
```

All four now weaken and load.

**The change to what gets weakened is tiny, and that is the point.** Diffing the
two builds' logs, `--weaken-unresolvable` went from 371 symbols across 14
libraries to 376 across the same 14 -- **seven added and two removed**:

```
ATS            + _CreateFontForScaler _ReleaseFontForScaler   (libFontParser)
HIServices     + _kTCCServiceAccessibility _kTCCServicePostEvent
                 _kTCCServiceScreenCapture                    (TCC)
OpenDirectory  + _OBJC_CLASS_$_SFAuthorization                (SecurityFoundation)
DiskManagement + _DAUnregisterApprovalCallback                (DiskArbitration)
ATS            - _CGFontCreateWithPlatformFont
HIServices     - _CGContextDrawPDFDocument
```

So this is not a wholesale loosening of the judgement -- those libraries were
already being weakened on the symbols the SDK *does* describe, and 209 of
`HIServices`'s 209 NULL imports were there before. It is five symbols that
decided whether four libraries load, and one of them decided whether `csrutil`
runs.

**And the two removals are the union earning its keep.** iOS 27's real
CoreGraphics exports `_CGFontCreateWithPlatformFont` and
`_CGContextDrawPDFDocument`; the SDK's `CoreGraphics.tbd` does not mention them.
So the index does not only turn `unknown` into an answer, it retires false
positives in a library the SDK already covered -- which is only possible because
the two sources are unioned rather than the cache merely consulted as a
fallback.

### The rebuild, and the check that it is the build described

From an empty `lifted/` and the cryptex's own manifest, with both fixes in:
**538 in `bin/`, 39 in `lib/`, 426 MB, `verify: all checks pass`,
`symbol_check: 0 of 538`.** `bin/` is one name down from 539, and the name is
`diskutil`. `test_machomorph.py`: 96 passed, 0 failed.

Then re-derived a second time from the final code -- the `_by_base` refinement
below landed after the first rebuild -- and diffed by hash rather than by
listing: **528 of 528 files byte-identical, and all 33 lifts byte-identical.**
So the tree on disk is the tree this section describes.

One refinement worth recording, because it was a silent loss rather than a
visible one. Recomputing `TargetSymbols._by_base` over the union dropped **31**
basename resolutions the SDK alone had -- `IOKit`, `UIKit`, `AVFoundation`,
`WebKit` among them -- because a basename unique across 625 stubs need not be
unique across 4691 cache images, and a library that stops resolving stops being
judged. The SDK's answers are kept and only non-colliding cache basenames are
added, which takes it to 0 lost and 4298 resolvable. None of the 31 is reached
through the fallback in practice, since a macOS binary spells `IOKit` versioned
and the iOS cache carries that spelling verbatim. The point is that nothing
would have said so.

### Not shipped in `data/`, and why that is a real cost

37 MB gzipped, 371 MB of text, 4.7 million symbols. Filtering does not rescue
it: restricted to libraries that also exist on macOS it is 30 MB, and dropping
Swift-mangled names (3.8M of the 5.25M) is 10 MB and would make a Swift symbol
look absent rather than unjudged. So there is no `BUNDLED_SYMBOLS` to match
`BUNDLED_INDEX`, and **a bare `machomorph.py` run is still blind to
PrivateFrameworks** -- it says so, and `rebuild_cryptex.sh` says so when built
without `--ipsw`. That is the one thing this fix does not close, and it is the
shape of trap CLAUDE.md's own "The index is the rule, and it is now the default"
section was written about.

## Device probe of the two fixes, and a third bug it found (2026-09-01)

Installed and probed. Identity first: fresh mount `zoDf3r`, `bin/` 538 and
`lib/` 39, and `LDAP`, `ATSUI`, `DiskManagement` and `QD` hashed **on the
device** with the cryptex's own `openssl dgst -sha256` all matching the staged
copies. Every library in `lib/` changed in this build, so any two of them are a
valid identity check.

### Both fixes hold

| | before | now |
|---|---|---|
| `curl -V` | SIGSEGV | curl 8.7.1 / LibreSSL 3.3.6, and `http=200 verify=0` |
| `sendmail -h` | SIGSEGV | its own `fatal: open /etc/postfix/main.cf` |
| `postfix -v`, `httpd -v`, `checkgid` | SIGSEGV / crash | all reach their own output (`Apache/2.4.67`) |
| `assetutil`, `layerutil` | died twice, on two different bugs | both print their own usage |
| `csrutil` | **SIGABRT in dyld** | usage rc=64; `status` its own SIP error; `authenticated-root status` and `allow-research-guests status` both `No macOS installations found` |

`assetutil` and `layerutil` are the sharpest of these: they died on device in one
build because `QD` named `ATSUI` absolutely, and in the next because `ATSUI`'s
initialiser was at a base-relative offset nothing had moved. Both are fixed, and
they run.

### The probe: the first run with no failures of any kind

537 binaries, in nine slices of 60. Raw data in
`measurements/device_probe_2026-09-01_initfix.tsv`.

| outcome | 2026-09-01 (5 bugs) | now |
|---|---|---|
| loads and runs | 424 | **430** |
| skipped (denylist) | 119 | 85 |
| blocked (daemon/interactive) | 22 | 22 |
| fails: library | **6** | **0** |
| fails: symbol | 0 | **0** |
| SIGKILLed | 0 | **0** |
| crash | **1** | **0** |

**`checkgid` is `ok, rc=0`.** Its SIGSEGV was carried in this file for two
sessions as "unknown whether it is ours". It was ours, it was the `LDAP`
initialiser, and its crash report faults at the same byte offset in the same
region as `sendmail`'s -- two reports of one bug, filed as one open question and
one mystery.

The whole probe produced exactly **one** crash report, `nfsstat`, which is the
known SIGSYS on an NFS syscall iOS does not implement. It is classified `ok`
because it loads and runs; nothing static can predict it.

Confirmed doing real work, not just launching: `openssl` (`ba7816bf...15ad` for
"abc"), `curl` (200/verify=0), `tcpdump --version` **and `tcpdump -D` listing
live interfaces**, `dtrace -l` reaching its own initialisation, all eight
memory/symbolication tools, **`vmmap $$` against a live process with 345 mapped
library lines**, `otool -hv` on a native iOS `/usr/lib/dyld`, `nm -mu` and
`size` and `strings` on a lifted library, `c++filt`, `swift-demangle`,
`dwarfdump`, `objdump`, `lipo -info`, `dyld_info`, perl with `Digest::MD5`,
`Sys::Syslog` and `JSON::PP`, `zsh` + `zsh/pcre`, `ruby 2.6.10` (**`-v` only
-- see "`ruby -v` is not a test"**), and -- the two
libraries the symbol index rescued -- **`dsmemberutil getuuid -u 0`** returning
a real UUID through `OpenDirectory`/`CFOpenDirectory` and **`kcc --version`**
through `Kerberos`/`KerberosHelper`.

## Every constant CFString in a lifted library had a NULL isa (2026-09-01)

The one thing the probe found, and it was found only because `expect` is on the
probe's denylist and had to be run by hand:

```
$ expect -v
Trace/BPT trap: 5
```

The crash report, which is unusually informative:

```
EXC_BREAKPOINT (SIGTRAP)
  CoreFoundation  __CF_IS_OBJC.cold.1        <- "CF objects must have a non-zero isa"
  CoreFoundation  CFHash
  CoreFoundation  CFSetGetValue
  CoreFoundation  __CFRunLoopCopyMode
  CoreFoundation  CFRunLoopAddSource
  Tcl             Tcl_InitNotifier
  Tcl             Tcl_CreateInterp
```

Read naively that is iOS's own CoreFoundation trapping, i.e. not our problem.
**It reproduces locally in two seconds**, which settles that immediately:

```
$ native/dlcall_test lifted-for-macos/Tcl Tcl_CreateInterp
loads / resolves / <SIGTRAP>
```

and under lldb the register that matters is `x1 =
@"com.tcltk.tclEventsOnlyRunLoopMode"` -- **Tcl's own constant string**, with
`x8 = "CF objects must have a non-zero isa"`.

### It is the alias rule, for the fourth time

Every `CFSTR("...")` literal is a `__cfstring` record whose first word is the
class of a constant CFString. A compiler emits that as a bind to
`___CFConstantStringClassReference`, which CoreFoundation exports and which the
lifted image's own symbol table **already imports**. The cache holds the word
pre-resolved, and asked what lives at that address the cache answers with the
ObjC class name:

```
lift, before:  __AUTH_CONST __cfstring  auth-bind  libSystem/__NSCFConstantString [weak-import]
lift, after:   __AUTH_CONST __cfstring  auth-bind  CoreFoundation/___CFConstantStringClassReference
```

The ptrauth schema is identical either way (`div=0x6AE1 ad=1 key=DA`), because
only the name was wrong. This is exactly the split this file already records for
`__NSGlobalBlock__` -> `__NSConcreteGlobalBlock`, `__platform_memchr` ->
`_memchr` and `__tlv_get_addr` -> `__tlv_bootstrap`, and the fix is one line in
the same `ALIASES` table. `Tcl_CreateInterp` then returns a live interpreter.

### Blast radius: 18 of 33 lifted libraries, 6628 strings

| library | strings | | library | strings |
|---|---|---|---|---|
| `DiskManagement` | 4189 | | `KerberosHelper` | 108 |
| `HIServices` | 743 | | `OpenDirectory` | 96 |
| `CFOpenDirectory` | 704 | | `libcsfde` | 116 |
| `ATS` | 366 | | `libCoreStorage` | 82 |
| `LDAP` | 69 | | `AppleShareClientCore` | 76 |
| + `ATSUI`, `DirectoryService`, `KernelManagement`, `QD`, `Tcl`, `libbootpolicy`, `libcurl.4`, `ColorSyncLegacy` | | | | |

Latent rather than fatal, which is why it survived: the string has to actually
be *used*. `csrutil` reaches `No macOS installations found` through a
`DiskManagement` holding 4189 of them without touching one, and `curl` works
with three. `Tcl` has **three**, and hands one to `CFRunLoopAddSource` in its
initialiser, so it could not miss.

### And the gate: a cache-only name must never survive as an import

`cryptex.verify` now fails on any bundled library importing a key of
`dsc.gotscan.ALIASES`. The predicate is exact -- a real linker never emits those
names, and `libLTO.dylib` (a genuine toolchain file) has none -- and it
discriminated 19 of 39 libraries before the fix, 0 of 39 after.

## `ruby -v` is not a test, and three things stood between it and working

Found by exercising `ruby` properly while confirming `expect`, and it is the
same lesson twice in one session: a version flag touches almost none of a
tool. This file recorded `ruby 2.6.10` as device-confirmed. It was, for
`ruby -v`. `ruby -e 'puts 1'` died before running a line of the program:

```
<internal:gem_prelude>:2: cannot load such file -- rubygems.rb (LoadError)
```

`ruby --disable-gems -e` worked throughout, so the interpreter and the lifted
`libruby.2.6.dylib` were always sound. Nothing was staged for it at all -- no
`share/ruby`, where perl has had `share/perl5` since it was ported.

Three walls, each only visible once the one before it fell:

| # | error | cause |
|---|---|---|
| 1 | `cannot load such file -- rubygems.rb` | no module tree staged |
| 2 | `cannot load such file -- rbconfig` | `RUBYLIB` named the stdlib but not its **arch subdir**, where `rbconfig.rb` lives |
| 3 | `Errno::ENOENT - xcode-select --print-path ... && xcrun --show-sdk-path` | Apple's `rbconfig.rb` backticks the developer tools at require time, and **iOS has no `/bin/sh`** |
| 4 | `cannot load such file -- stringio` | the native `.bundle` extensions are required on the **bootstrap** path |

Wall 3 needs no patch to Apple's file: the line is
`ENV['SDKROOT'] || (... %x(xcode-select ...))`, so setting `SDKROOT` to anything
short-circuits the backtick. Wall 4 is the one that decides the shape of the
fix -- `rubygems/specification.rb` requires `stringio`, so the extensions are
not an optional extra for exotic modules, they are needed for `puts 1`.

So the step is perl's, exactly: copy the tree into `share/ruby`, retarget every
`.bundle` and repoint it at the staged `libruby`. **96 retargeted, 0 skipped**,
all thinned to arm64e, and 0 still naming `Ruby.framework` absolutely. 45 MB,
against perl's 132 -- most of it is decompression, since macOS system files are
`decmpfs`-compressed in place and `du` on the source undercounts them.

```sh
export RUBYLIB=$CRYPTEX_MOUNT_PATH/share/ruby:$CRYPTEX_MOUNT_PATH/share/ruby/universal-darwin25
export SDKROOT=/
```

### DEVICE-CONFIRMED (2026-09-02)

Installed (mount `oopUQu`, `stringio.bundle` and `digest.bundle` hashed on the
device against the staged copies -- both match) and exercised:

| | |
|---|---|
| `ruby -e 'puts RUBY_VERSION'` | `2.6.10` -- the invocation that used to die in gem_prelude |
| `require 'digest'` | `900150983cd24fb0d6963f7d28e17f72`, correct |
| **all 96 native extensions `require`d** | **96 loaded, 0 failed** |
| `socket` | `Socket.gethostname` -> `SRDs-iPhone`, the real device |
| `openssl` | `SHA256('abc')` = `ba7816bf...`, correct |
| `zlib`, `etc`, `pty`, `fiddle`, `ripper`, `psych`, `bigdecimal`, `objspace`, `io/console`, `nkf`, `date`, `fcntl` | all load and do real work |
| `net/https` to apple.com with an explicit `ca_file` | **code=200, 254738 bytes** -- the same byte count curl gets |

`fiddle` working means libffi; `ripper` means Ruby's own parser. So this is a
usable scripting language on the device, not a binary that starts.

One caveat, and it is configuration rather than a port problem -- the same one
this file records for curl and openssl. Ruby's compiled-in
`OpenSSL::X509::DEFAULT_CERT_FILE` is `/private/etc/ssl/cert.pem`, which iOS
does not have, and `Net::HTTP` does not consult `SSL_CERT_FILE` on its default
path. Pass `ca_file` explicitly, or set `http.ca_file = ENV['SSL_CERT_FILE']`.
Verification itself is fine, which the 200 proves.

## Converting a module staged its whole closure beside it (2026-09-02)

Found by reading `otool -L` on a working ruby extension, which named
`@loader_path/usr/lib/libcrypto.46.dylib` -- a path that looks wrong and was.

Since the one-tool refactor made the library closure the **default**,
`machomorph module.bundle -o module.new` also stages every library that module
needs next to the output. For a tool in `bin/` that is the whole point. For a
loadable module buried in `share/`, it writes a private copy of the library into
whatever directory the module happens to sit in:

```
share/ruby/universal-darwin25/racc/System/Library/Frameworks/
    Ruby.framework/usr/lib/libruby.2.6.dylib
```

Measured across the staged tree: **9 copies of `libruby`, 5 of `libcrypto`, 5 of
`libssl`, 37 MB in 25 files.** And it went unnoticed for the most dangerous
reason -- **it worked.** perl and ruby were both device-confirmed while reaching
into those scratch copies, because a private copy beside the module is a
perfectly loadable library.

### The fix derives the library list instead of carrying one

`retarget_module()` in `rebuild_cryptex.sh` converts with `--no-libraries` and
repoints every reference to a library the cryptex **already has in `lib/`** at
that copy, reading the set from the module's own load commands. That subsumes
the three hand-written `--change` flags the perl, zsh and ruby steps each
carried (`libperl`, `libruby`, `libpcre` -- each basename is in `lib/`) and picks
up the six they never mentioned: `libssl`, `libcrypto`, `libapr`, `libaprutil`,
`libsasl2`, `libHeimdalProxy`. A hand-written list of libraries is what this
file records going wrong four times.

**`@executable_path`, not `@loader_path`.** The interpreter is
`<cryptex>/bin/ruby`, so `../lib` is right whatever depth the module sits at --
and they sit at four different depths. That is also why `--libs-into` is not the
answer even though it looks like it: it emits `@loader_path/lib/X`, which for a
module in `universal-darwin25/digest/` means a directory that does not exist.

### The check that made it safe to believe

The risk of `--no-libraries` is a module that referenced a library iOS lacks
which is *not* in `lib/` -- it would have had a closure copy and now has
nothing. Over all **296** modules in the three trees:

| | |
|---|---|
| references to a library absent from iOS and not in `lib/` | **0** |
| `@executable_path` references that do not resolve to a real file | **0 of 150** |
| stray staged libraries left under `share/` | **0** (the one `libperl` at the CORE path is deliberate) |

| tree | before | after |
|---|---|---|
| `share/ruby` | 45 MB | **18 MB** |
| `share/perl5-extras` | 90 MB | **82 MB** |
| whole cryptex | 473 MB | **438 MB** |

`verify: all checks pass`, `symbol_check: 0 of 489`, 96/0 tests.

### DEVICE-CONFIRMED, and it proves where the libraries come from

Reinstalled (mount `dfSPrW`, `md5.bundle` and `pcre.so` hashed on the device
against the staged copies -- both match, and only the one deliberate `libperl`
remains under `share/`). All four interpreters work: ruby's digest, openssl and
socket, perl's `Digest::MD5`, `Sys::Syslog` and `JSON::PP`, `zsh/pcre` matching
and rejecting correctly, `expect 5.45`. **96 of 96 ruby native extensions load.**

The check that settles it is `vmmap` on a live ruby that has required
`openssl`, `digest` and `zlib`:

```
__TEXT ... <mount>/lib/libruby.2.6.dylib
__TEXT ... <mount>/lib/libssl.48.dylib
__TEXT ... <mount>/lib/libcrypto.46.dylib
__DATA_CONST ... /usr/lib/libz.1.dylib        <- iOS's own, correctly
```

One copy of each, mapped from the cryptex's real `lib/`, not from a copy beside
a module -- which is the whole point of the change. `libz` coming from iOS is
right, since iOS has it.

## Three zsh modules had never been ported, and a glob is why (2026-09-02)

Found while re-confirming the above. `zmodload zsh/zftp` fails on a missing
`_tcp_close`, which reads as a broken zftp and is nothing of the kind -- dyld's
message says so if you read to the end of it:

```
dlopen(.../share/zsh/5.9/zsh/net/tcp.so): tried: '...' (mach-o file ...,
    but incompatible platform (have 'macOS', need 'iOS'))
```

The zsh step iterated `"$C"/share/zsh/5.9/zsh/*.so`, a **non-recursive glob**,
while perl's and ruby's steps use `find`. zsh keeps three modules in
subdirectories -- `zsh/net/tcp`, `zsh/net/socket`, `zsh/param/private` -- so
those three shipped as untouched **fat macOS** binaries for as long as the step
has existed. The tell is the magic: `0xbebafeca` is a universal binary, and a
converted module is always thin.

`find` instead of the glob takes it from 34 modules to **37, all iOS, none
fat**. `zsh/zftp` needs `zmodload zsh/net/tcp` first and `zsh/deltochar` needs
`zsh/zle` first -- both are ordinary flat-namespace load order in zsh, not
faults, and both then load.

### DEVICE-CONFIRMED (2026-09-02)

Mount `0g2sDk`, `net/tcp.so` and `param/private.so` hashed on the device
against the staged copies -- both match. **All 37 modules load, 0 failed**, with
`zsh/zle` and `zsh/net/tcp` preloaded for the two that resolve against them.

The three that had never been ported do real work, which is the point -- loading
is not the test:

| module | |
|---|---|
| `zsh/net/tcp` | `ztcp 127.0.0.1 22` opens a real socket and reads back `SSH-2.0-dropbear_202...` |
| `zsh/param/private` | `private foo=bar` declares the parameter, `$foo` reads `bar` |
| `zsh/zftp` | registers as a builtin (`whence -w zftp` -> `zftp: builtin`) |

A live TCP connection out of a zsh module that shipped as a fat macOS binary for
as long as the step existed is about as clear a confirmation as this gets.

Nothing else moved: `openssl` LibreSSL 3.3.6 with the correct SHA-256, `curl`
**http=200 verify=0**, `tcpdump` 4.99.1, `dtrace -l` reaching its own
initialisation, `vmmap $$` giving 500 lines of live process map, `otool -hv` on
a native iOS `/usr/lib/dyld`, ruby and perl both `900150983c...`, `expect`
5.45, `dsmemberutil getuuid` a real UUID, `kcc` Heimdal.



## curl needs `CURL_CA_BUNDLE`, and the variables are now documented in one place

Reported from the device:

```
# curl https://apple.com
curl: (77) error setting certificate verify locations:  CAfile: /etc/ssl/cert.pem
```

Not a new bug -- it is the `/etc/ssl` gap this file already records, and the
answer is the documented `CURL_CA_BUNDLE` export. Worth keeping for two reasons.

**curl and openssl fail differently, and curl's is the more misleading.**
openssl completes a handshake and reports `unable to get local issuer
certificate`, which reads as a chain problem. curl refuses up front with error
77, which reads as a broken build. Both are one missing file.

**It cannot be fixed without a variable**, and that was checked rather than
assumed: `/private/etc` is read-only on the device (`touch` -> `Operation not
permitted`), so the bundle cannot be placed where curl already looks, and the
mount's random suffix rules out compiling any absolute path in.

What *can* be made permanent is the environment. Measured on device:
`CRYPTEX_MOUNT_PATH` is already exported by `cryptex-run`, `$HOME`
(`/var/root`) is writable, and no profile file exists. A `~/.profile` is read by
the **login** shell -- confirmed with a marker, after which a bare
`curl https://apple.com` returns `http=301 verify=0` (301 is apple.com's own
redirect; `verify=0` is the point). A **non-login** shell, which is what
`ssh <device> 'cmd'` gives, reads neither `~/.profile` nor `~/.bashrc`, so
scripted use still needs the exports inline.

The five sets of variables were only ever printed by `rebuild_cryptex.sh`, one
hint per step, and `README.md` documented two of them. They are now one block
plus a failure-mode table in README's "Running the ported tools on the device",
and the whole block is verified end to end on device: curl 301/verify=0,
`openssl s_client` `Verify return code: 0 (ok)`, `perl -MPOSIX` release=27.0.0,
ruby's digest, `zmodload zsh/zle`, `expect` 5.45.

### And the cryptex now ships them as real startup files (2026-09-02)

Step 7b writes `etc/profile` and `etc/zshenv` into the cryptex, holding the
exports themselves rather than a pointer to them, all derived from
`$CRYPTEX_MOUNT_PATH`.

**MEASURED: the cryptex's `etc/` is NOT read.** Shipped and installed, and both
files stay invisible at `/etc`:

| path | |
|---|---|
| `<cryptex>/etc/profile`, `<cryptex>/etc/zshenv` | present, 2148 bytes each |
| `/etc/profile`, `/etc/zshenv` | **ABSENT** |
| `/etc/hosts` (iOS's own) | present, 213 bytes |
| `/bin/bash` (the cryptex ships `bin/bash`) | **ABSENT** |

So the research cryptex is mounted only at its own path and is not
path-overlaid onto `/` for arbitrary files. `/private/preboot/Cryptexes/OS` is a
**dyld** search prefix for dylibs -- it holds only `System` and `usr` -- and the
research cryptex is not in it. Behaviourally confirmed too: a bash login shell
and `zsh -c` both report `CURL_CA_BUNDLE=UNSET`, and `curl` still fails with
error 77.

**The files are still the right artefact**, they just have to be copied to the
device once. `$HOME` (`/var/root`) is writable and both `~/.profile` and
`~/.zshenv` are read, so:

```sh
ssh -p 2222 root@localhost 'cat > ~/.zshenv'  < <cryptex>/etc/zshenv
ssh -p 2222 root@localhost 'cat > ~/.profile' < <cryptex>/etc/profile
```

That is **once per device, not per install**: both files locate the cryptex
through `$CRYPTEX_MOUNT_PATH`, which `cryptex-run` exports, so they survive
every later reinstall unchanged. `rebuild_cryptex.sh` prints these two lines
beside the `srdtool cryptex install` line.

The *content* is already proven, so the install tests only the overlay
question. Pushed to `/tmp` and sourced on device with nothing else set, it
resolves all seven variables and then: curl `http=301 verify=0` (301 is
apple.com's own redirect), `perl -MPOSIX` release=27.0.0, ruby's digest
`900150983c...`, `zmodload zsh/pcre` ok, openssl `ba7816bf...`.

**Two files, and which two is not arbitrary.** zsh never reads `/etc/profile`
at all -- that is sh and bash -- and bash never reads `/etc/zshenv`:

| file | read by |
|---|---|
| `/etc/profile` | bash, **login** shells. A non-login interactive bash reads `~/.bashrc` and no `/etc` file at all |
| `/etc/zshenv` | zsh, **always** -- interactive, login, `zsh -c`, scripts -- and **first**, before `~/.zshenv` |

`/etc/zshenv` rather than `/etc/zshrc` for two reasons, both decisive: the
failing case is `zsh -c 'zmodload zsh/pcre'`, which is non-interactive so
`/etc/zshrc` would never fire; and `ZDOTDIR` has to be set before zsh goes
looking for `$ZDOTDIR/.zshenv`.

**`/etc/zprofile` and `/etc/zshrc` are deliberately NOT shipped**, and the
reason is a bug avoided rather than a preference. They are read *after*
`$ZDOTDIR/.zshenv`, which reassigns `ZDOTDIR=$HOME` precisely so the cryptex
does not hide the user's own dotfiles -- so setting `ZDOTDIR` again there would
send zsh looking for the user's `.zprofile` and `.zshrc` inside the cryptex.
The first version of this shipped the same content to all five files and had
exactly that fault.

### The `ZDOTDIR` asymmetry, which is load-bearing

`etc/profile` sets `ZDOTDIR`; `etc/zshenv` must **not**, and instead sets
`module_path` and `fpath` directly. Both halves matter:

* an sh-compatible file **cannot** set zsh arrays, so `etc/profile` points a
  zsh started from a bash login at the shipped `zdotdir/.zshenv`, which sets
  them and hands `ZDOTDIR` back to `$HOME` on the way out;
* a copy of `etc/zshenv` at `~/.zshenv` is read **before** `.zprofile` and
  `.zshrc` are looked for, and the `zdotdir/.zshenv` that would have reset
  `ZDOTDIR` is never reached -- so setting it there sends zsh hunting for the
  user's own dotfiles inside the cryptex. Setting the arrays directly is what
  makes the file work as a plain copy.

Verified on device, both paths, with a marker `~/.zshrc`:

```
zsh -c            ZDOTDIR unset,  module_path=<cx>/share/zsh/5.9, pcre MATCH
zsh -i -c         MY_MARKER=own-zshrc-read   <- own .zshrc still read
bash -l -c 'zsh'  MY_MARKER=own-zshrc-read, module_path set via ZDOTDIR
bash -l -c        curl 301/verify=0, perl release=27.0.0, ruby 900150983c...
```

`expect` is the one entry that needs nothing, and that is worth stating
explicitly rather than by omission: Tcl finds `lib/tcl8.5` relative to the
interpreter by itself.

Ruby's `Net::HTTP` is a third case again -- it consults neither `SSL_CERT_FILE`
nor `CURL_CA_BUNDLE`, because its compiled-in
`OpenSSL::X509::DEFAULT_CERT_FILE` is `/private/etc/ssl/cert.pem` and it does
not call `set_default_paths` on that path. Pass `ca_file` explicitly.

## The 81 leftovers are real, and the artefact story was the other decoder (2026-09-02)

This file has said for several sessions that the unauthenticated `__text`
leftovers are "mostly ADRP/LDR decoding artefacts". Measured, that is wrong in
an instructive way: **it was true of one decoder and never of the other, and
the two were being quoted interchangeably.**

`dsc/gotscan.py` had two independent scanners for the same thing:

| | invalidates a pending ADRP? | used by |
|---|---|---|
| `scan_got_sites()` | **yes**, on any other write to the register | `cryptex.verify`'s gate |
| `code_got_refs()` | **no** -- a pending ADRP lived forever | `dsc.gotscan`'s own CLI |

So `verify`'s count was already the strict one, while its message explained the
loose one's behaviour, and `python3 -m dsc.gotscan` over-reported against the
gate that judges it.

### The measurement

Distinct out-of-image targets over the 39 bundled libraries: **63 loose, 19
strict**, and `only-strict` is **0** in every library -- strict is a subset, so
the invalidation loses nothing. Three independent controls, each a file that
cannot contain a cache leftover by construction:

| control | loose | strict |
|---|---|---|
| 489 never-lifted binaries in `bin/` (ordinary macOS Mach-Os) | **123** | **0** |
| `libLTO.dylib`, a genuine Xcode toolchain dylib | 3 | **0** |
| `libcrypto.46`, whose "11 artefacts" this file cited as the evidence | 10 | **0** |
| `Tcl`, whose one artefact was hand-decoded last session | 2 | **0** |

and both hand-decoded REAL sites (`ATS`, `CFOpenDirectory`) survive.

**The register invalidation IS the adjacency test.** No separate distance rule
is needed: every one of the 81 surviving sites has its ADRP and its use
**exactly one instruction apart**, and every site it drops was a stale register
paired across an arbitrary gap. `code_got_refs()` is now a thin index over
`scan_got_sites()` rather than a second decoder, and the docstring says not to
reintroduce one.

### So the 81 are latent, not benign

They are real loads and address-materialises that fault on the path that
reaches them. Two families, and neither is on a path anything probed reaches:

| family | sites | shape |
|---|---|---|
| the cache's **second GOT region** `0x1e61xxxxx` | 8 | `adrp`/`ldr` -- the region this file names for `___stderrp`, the stack guard and the block classes. `ATS` 3, `HIServices` 2, `ATSUI`, `Kerberos`, `libcsfde` 1 each |
| the cache's **uniqued selector pool** `0x1faa4dda0..0x1fdb0cb6b` | 73 | `adrp`/`add` straight into an argument register: a direct selector, the same cache optimisation `dsc.objc` already undoes for relative method lists |

The selector family is the larger and the better understood: the repair is the
one `dsc.objc` performs on a method list's `name`, which is to reach the
image's own `__objc_selrefs` slot rather than the pool. Here it additionally
means re-encoding the pair `adrp/add` as `adrp/ldr` against the selref's page,
so it is an instruction rewrite rather than a pointer edit. Not attempted:
it needs the cache to name each address, a re-lift of five libraries, and a
device probe, and nothing reaches these sites today.

### And the wording is fixed in all three places

`cryptex.verify`'s NOTE, `dsc.gotscan`'s VERDICT prose, and the comment on
`machomorph`'s lift gate all said "almost always an ADRP with no matching
add/ldr". The gate itself is unchanged -- it keys on
`AUTHENTICATED_LEFTOVERS`, and accepting an unauthenticated one is a judgement
that the path is not needed, not a claim the site is imaginary. `libcrypto`,
`Tcl`, `libLTO`, `libCoreStorage` and `libruby` now report `VERDICT: repaired`
where they used to report `INCOMPLETE`; all 12 lifts stay byte-identical
(`test_machomorph.py` 96 passed, 0 failed).

### Two more silently-disabled gates in verify.py

The previous session found `except Exception` hiding the ALIASES check for four
rounds. Three more were doing the same: `malformed_tlv_descriptors()`,
`stray_header_offsets()` and -- worst -- the leftover scan itself, whose
`except Exception: pass` would have switched off the check that exists because
a stale `libxcselect` cost 78 `EXC_ARM_PAC_FAIL` SIGKILLs. All three now catch
`(mm.MachOError, struct.error, OSError)` and **report** rather than skip. The
two that already called `rep.bad()` were left alone: a catch-all that reports
is not a disabled gate.

## `expect` needs Tcl's script library, and it goes in `lib/` (2026-09-02)

The CFString fix is **device-confirmed**: `expect` no longer traps. What it did
instead was fail in its own `Tcl_Init`:

```
Tcl_Init failed: Can't find a usable init.tcl in the following directories: ...
```

Tcl keeps its script library outside the framework binary, and no interpreter is
usable until `init.tcl` is sourced -- so this reads like a broken port and is
purely a staging gap, the same shape as `share/ssl` for openssl and `PERL5LIB`
for perl.

**It is staged into `lib/tcl8.5`, and that spelling is the point.** Tcl searches
`<dir of the executable>/../lib/tcl8.5` on its own, so unlike perl's `PERL5LIB`
and zsh's `module_path` -- both compiled-in absolutes needing an export -- this
needs **no environment variable**, and the mount point's random suffix does not
matter because the path is derived at runtime. `cryptex.verify` walks `lib/`
with `os.path.isfile`, so a directory there is skipped rather than parsed:
confirmed, still 39 bundled libraries and `all checks pass`.

Verified on the device by pushing the 1.4 MB script tree ahead of the next
install -- Tcl scripts are data, so AMFI does not care, and the cryptex has
`cpio` and `gzip` (no `tar`), which is the transport when `scp` is unavailable:

```
expect -v                        -> expect version 5.45          rc=0
echo 'puts [expr 6*7]' | expect - -> 42                           rc=0
spawn echo hello / expect hello   -> OK-SPAWN                     rc=0
```

`spawn` working means a live interpreter driving a pty, which is the whole
point of `expect` and well past anything the crash allowed.

## The verify gate had been silently off since the restructure

Found while adding the check above, and worse than the bug it was added for.
`cryptex/verify.py` carried:

```python
try:
    import dsc_gotscan as gotscan
except Exception:       # "the gate still works without it"
    gotscan = None
```

`dsc_gotscan` is the **pre-restructure** module name. It stopped existing in
`ba06351`, so the fallback set `gotscan = None` and turned off the check for a
`__text` site still reaching the cache -- the check that exists because a stale
`libxcselect` shipped with one authenticated site and cost 78 `EXC_ARM_PAC_FAIL`
SIGKILLs on the device. It has been reporting nothing for two sessions, and the
comment on the `except` said it was fine.

**A tolerant import of a module that is not optional is not tolerance, it is a
disabled gate.** It is a hard import now, and the accompanying lesson is that my
own `except Exception` around the new check hid the resulting `AttributeError`
for four debugging rounds -- so it catches `(MachOError, struct.error, OSError)`
instead.

### What the re-enabled check reports: 81 leftovers, and some are real

With it back on: **0 authenticated** (the fatal class -- nothing PAC-faults) and
**81 unauthenticated** `__text` sites reaching outside their image, across the
lifted set. This file's standing wording is that most are ADRP/LDR decoding
artefacts. Both halves of that are now measured, on three examples:

```
Tcl        add x9, x9, #0xf4, lsl #12 / add x9, x9, #0x240      ARTEFACT
           0xf4000 + 0x240 = 1000000. It is `usec += 1000000`, a timeval
           borrow next to _Tcl_GetTime -- no ADRP in the context at all.

ATS        adrp x8, 0x1e6143000 / ldr x8, [x8, #0x6c0] / ldr x23, [x8]   REAL
           the cache's second GOT region -- the one this file names for
           ___stderrp, the stack guard and the block classes. It loads a
           pointer and dereferences it, so any path reaching it faults.

CFOpenDir  adrp x8, 0x1fb518000 / add x1, x8, #0x7a0            REAL
           0x1fb5187a0 is in the cache's uniqued SELECTOR pool
           (0x1faa4dda0..0x1fdb0cb6b), passed straight into x1 as an
           objc_msgSend selector. otool says as much one line earlier:
           "Objc class ref: bad class ref".
```

So the artefacts are real artefacts and the leftovers are real leftovers, and
the tell is whether the ADRP is adjacent to a load or add that uses the same
register. Neither of the two real ones is on a path anything probed reaches --
`dsmemberutil getuuid` works through `CFOpenDirectory` -- but they are latent
faults, and they are the same cache-uniquing family as the open `CoreWLAN` item.

## Testing

`./test_machomorph.py` diffs our output against the real toolchain
(`lipo`/`cbv`/`install_name_tool`/`ldid`) on system binaries. It skips
individual checks when a reference tool is missing.
