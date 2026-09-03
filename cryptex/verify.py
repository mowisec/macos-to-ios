#!/usr/bin/env python3
"""verify_cryptex -- check a staged cryptex before installing it.

    ./verify_cryptex.py --cryptex DIR --dylib-index FILE [-p ios -v 26.0]

An install cycle on an SRD costs minutes and a device reboot, and several of the
mistakes this project has actually made are visible in the staged tree before
any of that: an install name that does not match what binaries ask for, a
reference left pointing at an absolute macOS path, a bundled library with no
chained fixups, an unsigned binary. Each one was found the slow way at least
once. This is the fast way.

Checks, in the order they tend to matter:

  1. every Mach-O parses, and is built for the target platform
  2. cpusubtype is one iOS will run (arm64e ptrauth v0, or plain arm64)
  3. nothing references a library this cryptex bundles by absolute path -- not
     a binary in bin/, and not another bundled library (the "a batch undoes
     --provide-lib" trap -- see restage.py). Checking only bin/ is how a
     libcurl pointing at /usr/lib/libcrypto.46.dylib shipped and broke curl
  4. every bundled library's LC_ID_DYLIB is what binaries actually ask for
     (a mismatch makes dyld register the image under the wrong name)
  5. every @loader_path / @executable_path reference resolves to a real file
  6. every bundled library carries LC_DYLD_CHAINED_FIXUPS (a cache extraction
     without them loads and then crashes on any path touching a global)
  7. everything is code signed
  8. no lifted library has a __text site still reaching outside itself. An
     AUTHENTICATED one is a blraa through an unbound slot: it PAC-faults on any
     path that reaches it, which is how a stale libxcselect shipped and killed
     78 binaries in xcselect_trigger_install_request
  9. no bundled library has chained imports that lost N_WEAK_REF, and nothing
     staged still imports a symbol iOS does not export. Only
     _syslog$DARWIN_EXTSN so far, and it is fatal at launch rather than on
     the path that calls it -- see machomorph --darwin-extsn
 10. how much VM each bundled library reserves. A library lifted out of the
     shared cache keeps the cache's addresses, so it spans ~1-2 GB and dyld
     reserves that whole range; one such library loads fine, but a tool needing
     six of them (systemstats) dies on vm_allocate

Exit status is non-zero if any check fails, so it can gate an install.
"""
import argparse
import os
import struct
import subprocess
import sys

import machomorph as mm       # the package __init__ puts the repo root on the path
# gotscan for two things: ALIASES, the names only the shared cache uses, and
# scan_got_sites, which finds a __text site still reaching the cache.
#
# This used to be `try: import dsc_gotscan ... except: gotscan = None`, a
# pre-restructure module name that stopped existing when it became dsc/gotscan.py
# -- so the fallback silently set it to None and TURNED OFF the check for an
# authenticated leftover, which exists because a stale libxcselect shipped with
# one and cost 78 SIGKILLs on the device. A tolerant import of a module that is
# not optional is not tolerance, it is a disabled gate. It is a hard import now.
from dsc import gotscan

PLATFORMS = {"ios": 2, "macos": 1, "tvos": 3, "watchos": 4}
LC_DYLD_CHAINED_FIXUPS = 0x80000034
# Anything above this is a lifted library carrying cache addresses. A normal
# dylib starts at 0 and spans its own size.
VM_SPAN_WARN = 256 << 20
# arm64e with ptrauth ABI version 0 is what iOS wants; plain arm64 is
# cpusubtype 0 and is fine too (the Xcode toolchain is arm64).
OK_SUBTYPES = {0x80000002, 0x00000002, 0x00000000}


class Report:
    def __init__(self):
        self.fail = {}
        self.counts = {}

    def bad(self, check, detail):
        self.fail.setdefault(check, []).append(detail)

    def note(self, key, n=1):
        self.counts[key] = self.counts.get(key, 0) + n

    def show(self, verbose):
        for k in sorted(self.counts):
            print(f"  {self.counts[k]:6}  {k}")
        if not self.fail:
            print("\nverify: all checks pass")
            return 0
        print()
        for check, items in self.fail.items():
            print(f"FAIL  {check}: {len(items)}")
            for d in items[: (None if verbose else 12)]:
                print(f"        {d}")
            if not verbose and len(items) > 12:
                print(f"        ... and {len(items) - 12} more (-v for all)")
        return 1


def absent_variant_imports(m) -> list[str]:
    """Imported symbols the target is known not to export.

    Only one so far: iOS libc has plain `_syslog` but not
    `_syslog$DARWIN_EXTSN`, and dyld kills the process at launch over it --
    before main(), so nothing in the binary gets a chance to cope. machomorph
    --darwin-extsn renames it in place; this is the check that the rename
    actually reached everything staged, including a library lifted before the
    flag existed.
    """
    absent = {old for old, _new in mm.DARWIN_EXTSN_REDIRECTS}
    found = set()
    for syms in m.imports_by_library().values():
        found |= absent.intersection(syms)
    return sorted(found)


def load(path):
    with open(path, "rb") as fh:
        return mm.MachO(mm.thin(fh.read(), None)[0])


def signed(path) -> bool:
    r = subprocess.run(["/usr/bin/codesign", "-v", "--no-strict", path],
                       capture_output=True)
    return r.returncode == 0


def resolve_at_path(ref, binpath, cryptex) -> str | None:
    """Where a @loader_path/@executable_path reference actually points."""
    if ref.startswith("@loader_path/"):
        base = os.path.dirname(binpath)
        rest = ref[len("@loader_path/"):]
    elif ref.startswith("@executable_path/"):
        base = os.path.dirname(binpath)
        rest = ref[len("@executable_path/"):]
    else:
        return None
    return os.path.normpath(os.path.join(base, rest))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="verify_cryptex")
    ap.add_argument("--cryptex", required=True, metavar="DIR")
    ap.add_argument("--dylib-index", required=True, metavar="FILE")
    ap.add_argument("-p", "--platform", default="ios")
    ap.add_argument("-v", "--version", dest="osversion", default="26.0")
    ap.add_argument("--bindir", action="append", default=["bin", "sbin"])
    ap.add_argument("--libdir", action="append", default=["lib", "usr/lib"])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--skip-sign", action="store_true",
                    help="skip the codesign check (it is the slow one)")
    args = ap.parse_args(argv)

    C = args.cryptex
    index = mm.DylibIndex.load(args.dylib_index)
    want_platform = PLATFORMS.get(args.platform)
    rep = Report()

    # What this cryptex bundles, and under what install name a binary in bindir
    # would have to ask for it.
    bundled = {}
    spans = []
    unrepaired = []
    for d in args.libdir:
        p = os.path.join(C, d)
        if not os.path.isdir(p):
            continue
        for f in sorted(os.listdir(p)):
            fp = os.path.join(p, f)
            if os.path.isfile(fp) and not os.path.islink(fp):
                bundled.setdefault(f, fp)

    # 6. fixups, and 4. install names, on the bundled libraries.
    for base, fp in bundled.items():
        rep.note("bundled libraries")
        try:
            m = load(fp)
        except Exception as e:
            rep.bad("library does not parse", f"{base}: {e}")
            continue
        # A cache image's thread-local descriptors carry the cache's own
        # bookkeeping in the `key` and `offset` words. dyld validates `offset`
        # against the TLV template and aborts the whole process before main()
        # if it is out of range -- which is how a lifted
        # libEndpointSecuritySystem killed ssh-keygen, ssh-add and ssh-keyscan.
        # machomorph repairs these; this is the gate that says it happened.
        try:
            bad_tlv = m.malformed_tlv_descriptors()
        except (mm.MachOError, struct.error, OSError) as e:
            rep.bad("could not check thread-local descriptors", f"{base}: {e}")
            bad_tlv = []
        for where in bad_tlv:
            rep.bad("bundled library has a malformed thread-local descriptor "
                    "(dyld refuses the image at load: 'malformed thread-local, "
                    "offset=... is larger than total size=...')",
                    f"{base}: {where}")
        # Every MAPPED segment's filesize must be page-aligned, so the
        # segments tile the file end to end. A normal dylib does; a relaid-out
        # cache image only does if something rounded them up.
        #
        # The kernel is the only thing that checks this, and it says
        # `code signature invalid ... (errno=1)` -- which reads as a trust
        # problem and is not one: codesign --verify passes on the Mac, because
        # codesign(1) does not care that the signature covers file pages no
        # segment claims. The kernel does. This shipped: libHeimdalProxy,
        # ApplicationServices and Cocoa are 4-20 KB umbrella images whose only
        # segments are __TEXT and __LINKEDIT, __TEXT's filesize came out 0x3f8,
        # and dyld then refused libHeimdalProxy -- taking curl, ssh-add,
        # ssh-keygen and ssh-keyscan with it, all four of which had worked in
        # the build before.
        segs = [s for s in m.segments() if s[0] != "__PAGEZERO"]
        for n, seg in enumerate(segs[:-1]):
            if seg[4] % 0x4000:
                rep.bad("bundled library's mapped segments do not tile the "
                        "file: a filesize that is not page-aligned leaves file "
                        "pages the signature covers and no segment claims, and "
                        "the KERNEL refuses it as 'code signature invalid "
                        "(errno=1)' while codesign --verify passes",
                        f"{base}: {seg[0]} filesize {seg[4]:#x} at {seg[3]:#x}")
        # Anything stored as an offset from the mach header has to have grown
        # by --reserve-header's page, because the base moved and the code did
        # not. `__init_offsets` is the fatal one: dyld calls base + offset, and a
        # page short of the real initialiser is the middle of another function.
        # The lifted LDAP shipped that way and took curl and sendmail down with
        # a SIGSEGV inside memchr, under findAndRunAllInitializers -- while the
        # file parsed, signed and read back perfectly, because
        # LC_FUNCTION_STARTS was wrong by exactly the same amount and the two
        # errors agreed with each other. That is why this checks both.
        try:
            stray = m.stray_header_offsets()
        except (mm.MachOError, struct.error, OSError) as e:
            rep.bad("could not check base-relative offsets", f"{base}: {e}")
            stray = []
        for where in stray:
            rep.bad("bundled library has a base-relative offset that does not "
                    "land in code (an __init_offsets entry is an initialiser "
                    "dyld will CALL; the file is well-formed and signs fine, "
                    "and the process dies before main())",
                    f"{base}: {where}")
        # A cache-only spelling must never survive into a lifted library's
        # imports table. `dsc.gotscan.ALIASES` maps each name the CACHE answers
        # with to the public name the image actually imports -- the block
        # classes, the TLV thunk, and the constant-CFString class. A key of that
        # table appearing as an import means the alias did not fire, so the slot
        # is a flat weak bind that resolves NULL.
        #
        # That is not cosmetic. `__NSCFConstantString` unaliased gives every
        # CFSTR literal in the library a NULL isa, and CoreFoundation traps the
        # first time one is used -- EXC_BREAKPOINT in `__CF_IS_OBJC`, "CF
        # objects must have a non-zero isa". `expect` died on Tcl's own
        # @"com.tcltk.tclEventsOnlyRunLoopMode", and 18 of the 33 lifted
        # libraries carried 6628 such strings between them.
        try:
            aliased = sorted({sym for _lib, syms in m.bound_imports().items()
                              for sym, _w in syms if sym in gotscan.ALIASES})
        except (mm.MachOError, struct.error, OSError):
            aliased = []
        for sym in aliased:
            rep.bad("bundled library imports a name only the shared cache uses "
                    "(the alias did not fire, so the slot binds NULL -- for "
                    "__NSCFConstantString that is every CFSTR literal in the "
                    "library, and CoreFoundation traps on the first one used)",
                    f"{base}: {sym} -> {gotscan.ALIASES[sym]}")
        for sym in absent_variant_imports(m):
            rep.bad("bundled library imports a symbol iOS does not export "
                    "(it will not load, and takes every tool behind it down)",
                    f"{base}: {sym}")
        # A synthesised chained-imports table can lose N_WEAK_REF, which turns
        # every weak import hard -- so a weak-linked library the target does
        # not have fails the load instead of binding NULL. dsc_rebind dropped
        # it, and the lifted libcurl weak-links Kerberos, which iOS has none
        # of: _GSS_C_NT_HOSTBASED_SERVICE killed curl before main().
        try:
            n_weak, weak_names = m.sync_weak_imports()
        except mm.MachOError:
            n_weak, weak_names = 0, []
        if n_weak:
            rep.bad("bundled library has chained imports that lost their "
                    "weak flag (a weak-linked absent library will fail the "
                    "load instead of binding NULL; machomorph "
                    "--fix-weak-imports)",
                    f"{base}: {n_weak}, e.g. {', '.join(weak_names[:3])}")
        # 3, again -- on the libraries themselves, not just on bin/.
        # This is how a broken curl shipped: libcurl referenced
        # /usr/lib/libcrypto.46.dylib absolutely and weakly, so on iOS the
        # library silently did not load and every libcrypto symbol came out
        # unbound ("Expected in: <no uuid> unknown"). The tools in bin/ were
        # all correct, so checking only bin/ saw nothing wrong. A bundled
        # library reaching another bundled library is the same trap and needs
        # the same check.
        for lc, ref in m.paths():
            if lc.cmd not in (mm.LC_LOAD_DYLIB, mm.LC_LOAD_WEAK_DYLIB):
                continue
            if ref.startswith("/") and os.path.basename(ref) in bundled \
                    and index.resolve(ref)[0] is None:
                rep.bad("bundled library references another bundled library "
                        "by absolute path (it will not load there, and every "
                        "symbol from it comes out unbound)",
                        f"{base} -> {ref}")
        if not any(lc.cmd == LC_DYLD_CHAINED_FIXUPS for lc in m.commands):
            # An @rpath toolchain dylib built by Apple has them; a cache
            # extraction that was never repaired does not.
            rep.bad("bundled library has no LC_DYLD_CHAINED_FIXUPS "
                    "(loads, then crashes on any path touching a global)", base)
        # A lifted library keeps the cache's segment addresses -- __TEXT down
        # near 0x18x and __LINKEDIT up at 0x1ff96c000 -- so its lowest-to-
        # highest span is 1-2 GB, and dyld reserves the whole range at load.
        # One of those loads; six at once do not. Reported, not failed: the
        # lift is still the only way to get these libraries at all.
        lo = hi = None
        for seg in m.segments():
            name, a, vs = seg[0], seg[1], seg[2]
            if name == "__PAGEZERO":
                continue
            lo = a if lo is None else min(lo, a)
            hi = a + vs if hi is None else max(hi, a + vs)
        if lo is not None and hi - lo > VM_SPAN_WARN:
            spans.append((hi - lo, base))
        # A lifted library whose code still reaches a cache-wide GOT slot is
        # not finished. An authenticated one is fatal on the path that reaches
        # it, and the failure is a PAC trap a long way from its cause -- so it
        # is worth failing the gate rather than discovering it in a crash log.
        if gotscan is not None:
            try:
                img = gotscan.Image(open(fp, "rb").read())
                for site in gotscan.scan_got_sites(img):
                    if img.owns(site["target"]) or site["target"] % 8:
                        continue
                    where = f"{base} pc={site['first_pc']:#x} -> " \
                            f"{site['target']:#x}"
                    if site.get("auth"):
                        rep.bad("lifted library has an AUTHENTICATED __text "
                                "site still reaching the cache (will "
                                "EXC_ARM_PAC_FAIL on that path)", where)
                    else:
                        unrepaired.append(where)
            except (mm.MachOError, struct.error, OSError) as e:
                # Silently passing here would switch the gate off, which is how
                # the tolerant `import dsc_gotscan` disabled this very check for
                # two sessions. Report instead.
                rep.bad("could not scan for leftover cache references",
                        f"{base}: {e}")

    # 1/2/3/5/7 over the binaries, and collect which install names are asked for.
    asked = {}
    for d in args.bindir:
        dd = os.path.join(C, d)
        if not os.path.isdir(dd):
            continue
        for name in sorted(os.listdir(dd)):
            p = os.path.join(dd, name)
            if os.path.islink(p):
                rep.note("symlink aliases")
                continue
            if not os.path.isfile(p) or name.endswith(".plist"):
                continue
            rep.note("binaries")
            try:
                m = load(p)
            except Exception as e:
                rep.bad("does not parse", f"{d}/{name}: {e}")
                continue
            bv = m.build_version()
            if want_platform is not None and (bv is None or bv[0] != want_platform):
                rep.bad(f"not built for {args.platform}", f"{d}/{name}: {bv}")
            if m.cpusubtype not in OK_SUBTYPES:
                rep.bad("cpusubtype iOS will not run",
                        f"{d}/{name}: {m.cpusubtype:#x}")
            for lc, ref in m.paths():
                if lc.cmd not in (mm.LC_LOAD_DYLIB, mm.LC_LOAD_WEAK_DYLIB):
                    continue
                if ref.startswith("/"):
                    b = os.path.basename(ref)
                    if b in bundled and index.resolve(ref)[0] is None:
                        rep.bad("references a bundled library by absolute path "
                                "(weak-links to a library that is not there)",
                                f"{d}/{name} -> {ref}")
                elif ref.startswith("@loader_path/") or \
                        ref.startswith("@executable_path/"):
                    asked.setdefault(os.path.basename(ref), set()).add(ref)
                    target = resolve_at_path(ref, p, C)
                    if target and not os.path.exists(target):
                        rep.bad("@path reference does not resolve to a file",
                                f"{d}/{name} -> {ref}")
            for sym in absent_variant_imports(m):
                rep.bad("imports a symbol iOS does not export "
                        "(dyld kills it at launch; use --darwin-extsn)",
                        f"{d}/{name}: {sym}")
            if not args.skip_sign and not signed(p):
                rep.bad("not code signed", f"{d}/{name}")

    # 4. Does each bundled library call itself what binaries ask for?
    for base, refs in sorted(asked.items()):
        fp = bundled.get(base)
        if fp is None:
            continue
        actual = mm.dylib_id(fp)
        for ref in sorted(refs):
            if actual != ref:
                rep.bad("install name is not what binaries ask for "
                        "(dyld registers it under the wrong name)",
                        f"{base}: is {actual!r}, asked for {ref!r}")

    print(f"verify_cryptex {C}")
    rc = rep.show(args.verbose)
    if unrepaired:
        # NOT "mostly decoding artefacts". That wording stood here and was
        # measured wrong: this check already uses scan_got_sites, whose
        # register invalidation drops stale-register pairs, and every site
        # that survives it in the shipped tree is an ADRP and its use one
        # instruction apart. The same decoder finds 0 in 489 never-lifted
        # binaries, so these are real references, latent rather than benign:
        # each faults on the path that reaches it.
        print(f"\nNOTE  {len(unrepaired)} unauthenticated __text site(s) still "
              f"reach outside their image. These are adjacent ADRP+use pairs, "
              f"not decoding artefacts -- each faults if its path is taken.")
        for u in unrepaired[:8]:
            print(f"        {u}")
    if spans:
        print(f"\nNOTE  {len(spans)} bundled librar"
              f"{'y' if len(spans) == 1 else 'ies'} reserve over "
              f"{VM_SPAN_WARN >> 20} MB of address space each (lifted from the "
              f"shared cache, so they keep its addresses).")
        for span, base in sorted(spans, reverse=True):
            print(f"        {span / 1e6:7.0f} MB  {base}")
        print("      One loads; a tool needing several can die on vm_allocate.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
