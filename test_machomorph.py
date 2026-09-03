#!/usr/bin/env python3
"""Differential tests: machomorph vs. the real toolchain.

Each check that needs an external reference tool (lipo / cbv / otool /
install_name_tool / ldid) is skipped when that tool is not installed.

    ./test_machomorph.py [--cbv /path/to/cbv]
"""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import machomorph as mm  # noqa: E402

PASS, FAIL, SKIP = [], [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))


def skip(name, why):
    SKIP.append(name)
    print(f"  skip  {name}   ({why})")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def have(tool):
    return shutil.which(tool) is not None


def morph(*args):
    return run([sys.executable, os.path.join(os.path.dirname(__file__),
                                             "machomorph.py"), *args])


# ---------------------------------------------------------------------------


def test_thin(tmp, binary):
    print(f"\n[lipo] {binary}")
    if not have("lipo"):
        return skip("thin == lipo -thin", "lipo missing")
    ref = os.path.join(tmp, "ref_thin")
    r = run(["lipo", "-thin", "arm64e", binary, "-output", ref])
    if r.returncode != 0:
        return skip("thin == lipo -thin", "no arm64e slice")
    with open(binary, "rb") as fh:
        ours, arch = mm.thin(fh.read(), "arm64e")
    with open(ref, "rb") as fh:
        expected = fh.read()
    check("thin == lipo -thin", ours == expected,
          f"{len(ours)} vs {len(expected)} bytes")
    check("thin picks arm64e", arch == "arm64e", arch)


def test_cbv(tmp, binary, cbv):
    print(f"\n[cbv] {binary}")
    if not cbv:
        return skip("platform rewrite == cbv", "cbv not available")
    if not have("lipo"):
        return skip("platform rewrite == cbv", "lipo missing")

    for target, version in (("ios", "27.0"), ("macos", "15.0"), ("tvos", "18.2")):
        src = os.path.join(tmp, f"cbv_{target}")
        if run(["lipo", "-thin", "arm64e", binary, "-output", src]).returncode:
            return skip("platform rewrite == cbv", "no arm64e slice")
        # cbv always writes to /tmp/<basename> and re-signs. Run it there.
        r = run([cbv, src, "to", target, version])
        cbv_out = os.path.join("/tmp", os.path.basename(src))
        if r.returncode != 0 or not os.path.exists(cbv_out):
            skip(f"platform rewrite == cbv ({target})", "cbv run failed")
            continue

        ours = os.path.join(tmp, f"ours_{target}")
        m = morph(binary, "-o", ours, "-p", target, "-v", version,
                  "--no-auto-paths", "--no-sign", "-q")
        if m.returncode != 0:
            check(f"platform rewrite == cbv ({target})", False, m.stderr.strip())
            continue

        a = mm.MachO(open(cbv_out, "rb").read())
        b = mm.MachO(open(ours, "rb").read())
        check(f"build version matches cbv ({target})",
              a.build_version() == b.build_version(),
              f"{a.build_version()} vs {b.build_version()}")
        check(f"cpusubtype matches cbv ({target})",
              a.cpusubtype == b.cpusubtype,
              f"{a.cpusubtype:#x} vs {b.cpusubtype:#x}")
        # Everything outside the load commands and the signature must be
        # untouched by both tools.
        sig = a.code_signature()
        end = sig[0] if sig else len(a.data)
        start = 32 + max(a.sizeofcmds, b.sizeofcmds)
        check(f"file body untouched ({target})",
              bytes(a.data[start:end]) == bytes(b.data[start:end]))
        os.unlink(cbv_out)


def test_paths(tmp, binary):
    print(f"\n[install_name_tool] {binary}")
    if not have("otool"):
        return skip("paths == otool -L", "otool missing")
    with open(binary, "rb") as fh:
        macho = mm.MachO(mm.thin(fh.read(), "arm64e")[0])
    ours = [p for lc, p in macho.paths() if lc.cmd != mm.LC_RPATH]
    ref = []
    for line in run(["otool", "-arch", "arm64e", "-L", binary]).stdout.splitlines()[1:]:
        line = line.strip()
        if line.startswith("/") or line.startswith("@"):
            ref.append(line.split(" (compatibility")[0])
    check("dylib list == otool -L", ours == ref, f"{ours}\n        vs {ref}")

    if not have("install_name_tool"):
        return skip("rewrite == install_name_tool", "install_name_tool missing")
    if not ref:
        return skip("rewrite == install_name_tool", "no dylibs")

    old = ref[0]
    new = "/System/Library/Frameworks/ZZ.framework/ZZ"
    ref_out = os.path.join(tmp, "int_ref")
    run(["lipo", "-thin", "arm64e", binary, "-output", ref_out])
    r = run(["install_name_tool", "-change", old, new, ref_out])
    if r.returncode != 0:
        return skip("rewrite == install_name_tool", "install_name_tool failed")
    our_out = os.path.join(tmp, "int_ours")
    m = morph(binary, "-o", our_out, "-p", "macos", "-v", "26.6.0",
              "--no-auto-paths", "--no-sign", "-q", "--change", old, new)
    check("morph --change succeeds", m.returncode == 0, m.stderr.strip())
    a = [p for _lc, p in mm.MachO(open(ref_out, "rb").read()).paths()]
    b = [p for _lc, p in mm.MachO(open(our_out, "rb").read()).paths()]
    check("rewrite == install_name_tool -change", a == b, f"{a}\n        vs {b}")


def test_auto_paths():
    print("\n[auto path fixup]")
    cases = [
        ("/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
         "/System/Library/Frameworks/IOKit.framework/IOKit"),
        ("/usr/lib/libSystem.B.dylib", None),
        ("/System/Library/PrivateFrameworks/X.framework/Versions/B/X",
         "/System/Library/PrivateFrameworks/X.framework/X"),
        ("@rpath/Foo.framework/Versions/A/Foo", "@rpath/Foo.framework/Foo"),
    ]
    for src, want in cases:
        got = mm.auto_fix_path(src)
        check(f"auto_fix_path({src.split('/')[-1]})", got == want, f"{got!r}")


def test_bundled_index(tmp):
    """The shipped index is used by default, and it is what resolves the
    frameworks iOS demoted to PrivateFrameworks.

    Without it, /Versions/A flattening turns a correct macOS path into a
    plausible-looking iOS path that does not exist -- reported as a successful
    rewrite. That is how a converted csrutil reached the device asking for
    /System/Library/Frameworks/DiskArbitration.framework/DiskArbitration.
    """
    print("\n[bundled dylib index]")
    path = mm.bundled_index(mm.PLATFORMS["ios"])
    if path is None:
        SKIP.append("bundled index not present")
        print("  skip  no bundled index shipped")
        return
    check("bundled for iOS, not for macOS",
          mm.bundled_index(mm.PLATFORMS["macos"]) is None)
    index = mm.DylibIndex.load(path)
    da = "/System/Library/Frameworks/DiskArbitration.framework/Versions/A/DiskArbitration"
    got, why = index.resolve(da)
    check("DiskArbitration resolves to PrivateFrameworks",
          got == "/System/Library/PrivateFrameworks/DiskArbitration.framework"
                 "/DiskArbitration" and why == "public->private", f"{got} ({why})")
    check("a library iOS does not have resolves to None",
          index.resolve("/usr/lib/libbootpolicy.dylib")[0] is None)

    # And it is on by default: the flattening rule alone would have written the
    # public path, so a default conversion that still says "public" is the bug.
    src = "/usr/bin/csrutil"
    if not os.path.exists(src):
        return
    out = os.path.join(tmp, "idx")
    m = morph(src, "-o", out, "-p", "ios", "-v", "27.0", "--force")
    check("default conversion uses the bundled index", m.returncode == 0
          and "public->private" in m.stdout, m.stdout[-300:] + m.stderr[-300:])
    if m.returncode == 0:
        paths = [p for _lc, p in mm.MachO(open(out, "rb").read()).paths()]
        check("no public DiskArbitration path survives",
              not any(p.startswith(mm.PUBLIC_FW + "DiskArbitration.")
                      for p in paths), str(paths))
    m = morph(src, "-o", out + "2", "-p", "ios", "-v", "27.0",
              "--no-dylib-index")
    check("--no-dylib-index falls back to the rule",
          "public->private" not in m.stdout and "flattened" in m.stdout,
          m.stdout[-300:])


def test_versions():
    print("\n[version parsing]")
    check("parse '27'", mm.parse_version("27") == (27, 0, 0))
    check("parse '16.4'", mm.parse_version("16.4") == (16, 4, 0))
    check("parse '16.4.1'", mm.parse_version("16.4.1") == (16, 4, 1))
    check("encode 16.4.1", mm.encode_version((16, 4, 1)) == 0x00100401)
    for bad in ("", "a", "1.2.3.4", "-1"):
        try:
            mm.parse_version(bad)
            check(f"reject {bad!r}", False)
        except ValueError:
            check(f"reject {bad!r}", True)


def find_entitled_binary():
    for cand in ("/usr/libexec/lsd", "/usr/sbin/spindump", "/usr/bin/log",
                 "/usr/libexec/amfid", "/usr/sbin/systemstats",
                 "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"):
        if os.path.exists(cand):
            with open(cand, "rb") as fh:
                data = fh.read()
            try:
                macho = mm.MachO(mm.thin(data, None)[0])
            except mm.MachOError:
                continue
            if mm.extract_entitlements(macho):
                return cand
    return None


def test_entitlements(tmp):
    print("\n[ldid -e]")
    binary = find_entitled_binary()
    if binary is None:
        return skip("entitlements == ldid -e", "no entitled binary found")
    print(f"  using {binary}")
    with open(binary, "rb") as fh:
        macho = mm.MachO(mm.thin(fh.read(), None)[0])
    ours = mm.extract_entitlements(macho)
    check("entitlements found", bool(ours))
    ours_dict = plistlib.loads(ours)
    check("entitlements parse as plist", isinstance(ours_dict, dict),
          f"{len(ours_dict)} keys")

    if have("ldid"):
        thinned = os.path.join(tmp, "ent_thin")
        run(["lipo", "-thin", mm.MachO(mm.thin(open(binary, 'rb').read(), None)[0]).arch,
             binary, "-output", thinned])
        src = thinned if os.path.exists(thinned) else binary
        r = run(["ldid", "-e", src])
        if r.returncode == 0 and r.stdout.strip():
            ref = plistlib.loads(r.stdout.encode())
            check("entitlements == ldid -e", ref == ours_dict,
                  f"ours {sorted(ours_dict)}\n        ldid {sorted(ref)}")
        else:
            skip("entitlements == ldid -e", "ldid produced nothing")
    else:
        skip("entitlements == ldid -e", "ldid missing")

    if have("codesign"):
        r = run(["codesign", "-d", "--entitlements", ":-", binary])
        if r.returncode == 0 and r.stdout.strip():
            ref = plistlib.loads(r.stdout.encode())
            check("entitlements == codesign -d", ref == ours_dict)
        else:
            skip("entitlements == codesign -d", "codesign produced nothing")

    # Round trip: convert + inject, and read the entitlements back out.
    out = os.path.join(tmp, "ent_out")
    m = morph(binary, "-o", out, "-p", "ios", "-v", "27.0",
              "--license-to-operate", "-q")
    check("convert with --license-to-operate", m.returncode == 0, m.stderr.strip())
    if m.returncode == 0:
        back = mm.extract_entitlements(mm.MachO(open(out, "rb").read()))
        back_dict = plistlib.loads(back) if back else {}
        check("license-to-operate present after signing",
              back_dict.get(mm.LICENSE_TO_OPERATE) is True)
        check("original entitlements preserved",
              all(back_dict.get(k) == v for k, v in ours_dict.items()),
              f"{sorted(set(ours_dict) - set(back_dict))} missing")


def test_roundtrip(tmp, binary):
    print(f"\n[end-to-end] {binary}")
    out = os.path.join(tmp, "e2e")
    # --no-dylib-index so this exercises auto_fix_path()'s rule. With the
    # bundled index a versioned path may legitimately survive -- the iOS cache
    # carries IOKit under its versioned spelling -- which is resolution working,
    # not the rule failing. See test_bundled_index.
    m = morph(binary, "-o", out, "-p", "ios", "-v", "27.0", "--no-dylib-index")
    check("full conversion succeeds", m.returncode == 0, m.stderr.strip())
    if m.returncode != 0:
        return
    macho = mm.MachO(open(out, "rb").read())
    check("platform is iOS 27.0", macho.build_version()[:2] == (2, 27 << 16),
          str(macho.build_version()))
    check("no /Versions/ paths left",
          not any(mm.auto_fix_path(p) for _lc, p in macho.paths()))
    if have("codesign"):
        r = run(["codesign", "--verify", "--no-strict", out])
        check("codesign --verify passes", r.returncode == 0, r.stderr.strip())
    if have("otool"):
        r = run(["otool", "-l", out])
        check("otool can parse the result", r.returncode == 0
              and "LC_BUILD_VERSION" in r.stdout)
    # Idempotency
    out2 = os.path.join(tmp, "e2e2")
    m2 = morph(out, "-o", out2, "-p", "ios", "-v", "27.0", "-q")
    check("re-running is idempotent", m2.returncode == 0
          and mm.MachO(open(out2, "rb").read()).build_version()
          == macho.build_version())


def test_header_overflow(tmp, binary):
    print("\n[header padding guard]")
    with open(binary, "rb") as fh:
        macho = mm.MachO(mm.thin(fh.read(), "arm64e")[0])
    paths = [(lc, p) for lc, p in macho.paths()]
    if not paths:
        return skip("refuses to overflow header", "no dylibs")
    lc, _p = paths[0]
    macho.set_path(lc, "/" + "A" * 100000)
    try:
        macho.build()
        check("refuses to overflow header", False, "no error raised")
    except mm.MachOError as exc:
        check("refuses to overflow header", "header padding" in str(exc), str(exc))


def test_bad_input(tmp):
    print("\n[error handling]")
    junk = os.path.join(tmp, "junk")
    with open(junk, "wb") as fh:
        fh.write(b"not a macho at all, really" * 10)
    m = morph(junk, "-o", os.path.join(tmp, "x"), "-p", "ios", "-v", "27.0")
    check("rejects non-Mach-O", m.returncode != 0 and "not a Mach-O" in m.stderr,
          m.stderr.strip())
    m = morph("/nonexistent-file", "--info")
    check("rejects missing file", m.returncode != 0)
    m = morph("/usr/sbin/ioreg", "-o", os.path.join(tmp, "y"),
              "-p", "ios", "-v", "not.a.version")
    check("rejects bad version", m.returncode != 0)



def _extsn_importer():
    """A system binary that imports _syslog$DARWIN_EXTSN, or None."""
    for d in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        for name in ("logger", "date", "ssh-keygen", "ssh-keyscan"):
            path = os.path.join(d, name)
            if not os.path.exists(path):
                continue
            out = run(["nm", "-mu", path]).stdout
            if "_syslog$DARWIN_EXTSN" in out:
                return path
    return None


def test_redirect_symbol(tmp):
    print("\n[--redirect-symbol / --darwin-extsn]")
    src = _extsn_importer()
    if src is None:
        skip("redirect round-trip", "no binary here imports _syslog$DARWIN_EXTSN")
        return

    plain = os.path.join(tmp, "redir_plain")
    fixed = os.path.join(tmp, "redir_fixed")
    # --no-symbol-check: the un-redirected baseline imports a symbol iOS does
    # not export, which machomorph now refuses to port by default. That refusal
    # is tested separately (test_symbol_gate); here we just want the two files.
    morph(src, "-o", plain, "-p", "ios", "-v", "26.0", "-q",
          "--no-symbol-check")
    m = morph(src, "-o", fixed, "-p", "ios", "-v", "26.0", "-q",
              "--darwin-extsn")
    check("--darwin-extsn converts", m.returncode == 0, m.stderr.strip()[:120])
    if not os.path.exists(fixed):
        return

    # The name is gone from every table that spells it, and the plain one is
    # there in its place -- bound against the same library.
    names = run(["nm", "-mu", fixed]).stdout
    check("symbol table says _syslog",
          "_syslog$DARWIN_EXTSN" not in names and "_syslog " in names + " ")
    info = run(["dyld_info", "-fixups", fixed]).stdout
    if info:
        check("chained fixups bind libSystem/_syslog",
              "libSystem/_syslog " in info + " "
              and "_syslog$DARWIN_EXTSN" not in info)
    else:
        skip("chained fixups bind libSystem/_syslog", "dyld_info unavailable")

    # Nothing moved: same size, and the only differences are the two string
    # regions plus the signature codesign rewrote.
    a, b = open(plain, "rb").read(), open(fixed, "rb").read()
    check("nothing moved (same file size)", len(a) == len(b),
          f"{len(a)} vs {len(b)}")

    mo = mm.MachO(b)
    regions = mo._symbol_string_regions()
    check("both string regions are patched", len(regions) == 2,
          f"{[r[0] for r in regions]}")
    for _what, off, size in regions:
        check(f"no _syslog$DARWIN_EXTSN left in the {_what}",
              b"_syslog$DARWIN_EXTSN" not in b[off:off + size])

    check("codesign --verify passes",
          run(["codesign", "--verify", fixed]).returncode == 0)

    # A longer replacement cannot be written in place.
    mo2 = mm.MachO(open(plain, "rb").read())
    try:
        mo2.redirect_symbol("_syslog$DARWIN_EXTSN",
                            "_syslog_something_far_longer")
        check("refuses a longer name", False)
    except mm.MachOError as exc:
        check("refuses a longer name", "longer than" in str(exc))

    # A symbol nothing imports is a no-op, not an error.
    mo3 = mm.MachO(open(plain, "rb").read())
    check("absent symbol is a no-op",
          mo3.redirect_symbol("_no_such_symbol_at_all", "_x") == [])


def test_redirect_shared_suffix(tmp):
    """The refuse-on-shared-suffix path, on a synthesised string table.

    Two symbols share storage: `_ab_syslog$DARWIN_EXTSN` and, four bytes in,
    `_syslog$DARWIN_EXTSN` itself. Shortening the second would truncate
    nothing, but shortening the *first* would eat the second, so an nlist
    pointing inside the range must make the edit refuse.
    """
    print("\n[redirect: shared-suffix guard]")
    src = _extsn_importer()
    if src is None:
        skip("refuses to truncate a neighbour", "no importer available")
        return
    plain = os.path.join(tmp, "suffix_plain")
    morph(src, "-o", plain, "-p", "ios", "-v", "26.0", "-q",
          "--no-symbol-check")
    mo = mm.MachO(open(plain, "rb").read())

    symtab = mo.find(mm.LC_SYMTAB_CMD)
    _c, _s, symoff, nsyms, stroff, strsize = struct.unpack_from(
        "<6I", symtab.data, 0)
    needle = b"_syslog$DARWIN_EXTSN\0"
    at = bytes(mo.data[stroff:stroff + strsize]).find(needle)
    if at < 0:
        skip("refuses to truncate a neighbour", "name not in the string table")
        return

    # Point an existing undefined nlist at the *middle* of the name, as a
    # suffix-sharing string table legitimately may.
    inside = at + 7
    for i in range(nsyms):
        off = symoff + i * 16
        n_strx, n_type, _sect, _desc = struct.unpack_from("<IBBH", mo.data, off)
        if not (n_type & mm.N_STAB) and (n_type & mm.N_TYPE) == mm.N_UNDF:
            struct.pack_into("<I", mo.data, off, inside)
            break

    try:
        mo.redirect_symbol("_syslog$DARWIN_EXTSN", "_syslog")
        check("refuses to truncate a neighbour", False,
              "the edit went ahead anyway")
    except mm.MachOError as exc:
        check("refuses to truncate a neighbour",
              "share suffixes" in str(exc), str(exc)[:100])



def test_symbol_gate(tmp):
    """Refuse, by default, to port a binary that cannot launch on the target."""
    print("\n[launch prediction gate]")
    src = _extsn_importer()
    if src is None:
        skip("refuses a binary that cannot launch", "no importer available")
        return
    out = os.path.join(tmp, "gated")

    m = morph(src, "-o", out, "-p", "ios", "-v", "26.0", "-q")
    check("refuses a binary that cannot launch", not os.path.exists(out),
          m.stderr.strip()[:110])
    check("says which symbol", "_syslog$DARWIN_EXTSN" in m.stderr)

    m = morph(src, "-o", out, "-p", "ios", "-v", "26.0", "-q", "--force")
    check("--force ports it anyway", os.path.exists(out))
    check("--force still warns", "will fail at launch" in m.stderr)

    # Fixing the actual problem makes the gate pass on its own.
    out2 = os.path.join(tmp, "gated_fixed")
    m = morph(src, "-o", out2, "-p", "ios", "-v", "26.0", "-q",
              "--darwin-extsn")
    check("--darwin-extsn satisfies the gate", os.path.exists(out2),
          m.stderr.strip()[:110])

    # A binary with nothing missing is untouched by any of this.
    out3 = os.path.join(tmp, "gated_ok")
    m = morph("/usr/bin/true", "-o", out3, "-p", "ios", "-v", "26.0", "-q")
    check("a clean binary is unaffected", os.path.exists(out3),
          m.stderr.strip()[:110])



def test_weaken_symbol(tmp):
    """--weaken-symbol, in both tables. Untested until it broke in a refactor."""
    print("\n[--weaken-symbol]")
    src = _extsn_importer()
    if src is None:
        skip("weakens a hard import", "no suitable binary")
        return
    plain = os.path.join(tmp, "weak_plain")
    morph(src, "-o", plain, "-p", "ios", "-v", "26.0", "-q", "--no-symbol-check")
    if not os.path.exists(plain):
        skip("weakens a hard import", "baseline conversion failed")
        return

    m = mm.MachO(open(plain, "rb").read())
    sym = "_syslog$DARWIN_EXTSN"
    n_sym, n_imp = m.weaken_symbol(sym)
    check("weakens the symbol table entry", n_sym == 1, f"{n_sym}")
    check("weakens the chained import", n_imp == 1, f"{n_imp}")
    check("the symbol table now says weak", sym in m.weak_ref_symbols())
    bound = [w for syms in m.bound_imports().values()
             for s, w in syms if s == sym]
    check("the chained table now says weak", bound == [True], f"{bound}")

    # Idempotent, and a symbol that is not imported is a no-op rather than an
    # error -- a batch weakens the same name across many binaries.
    check("re-weakening changes nothing", m.weaken_symbol(sym) == (0, 0))
    check("absent symbol is a no-op", m.weaken_symbol("_nope_") == (0, 0))

    # It must survive a real conversion and stay signed.
    out = os.path.join(tmp, "weak_cli")
    r = morph(src, "-o", out, "-p", "ios", "-v", "26.0", "-q",
              "--weaken-symbol", sym)
    check("--weaken-symbol satisfies the launch gate", os.path.exists(out),
          r.stderr.strip()[:110])
    if os.path.exists(out):
        check("still passes codesign --verify",
              run(["codesign", "--verify", out]).returncode == 0)


def test_flat_namespace(tmp):
    """A flat-namespace binary is unjudgeable, and must say so."""
    print("\n[flat namespace]")
    flat = None
    for cand in ("/usr/sbin/postalias", "/usr/sbin/postmap", "/usr/sbin/postconf"):
        if not os.path.exists(cand):
            continue
        m = mm.MachO(mm.thin(open(cand, "rb").read(), None)[0])
        if mm.FLAT_NAMESPACE in m.bound_imports():
            flat = (cand, m)
            break
    if flat is None:
        skip("flat-namespace imports are kept", "no flat-namespace binary here")
        return
    path, m = flat
    n = len(m.bound_imports()[mm.FLAT_NAMESPACE])
    check("flat-namespace imports are kept, not dropped", n > 0,
          f"{os.path.basename(path)}: {n}")

    sdk = run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"]).stdout.strip()
    if not sdk or not os.path.isdir(sdk):
        skip("reported as unknown, never as a failure", "no iPhoneOS SDK")
        return
    target = mm.TargetSymbols(sdk)
    fail, unknown = mm.unresolvable_imports(m, target)
    check("reported as unknown, never as a failure",
          not fail and len(unknown) > 0, f"fail={len(fail)} unknown={len(unknown)}")


def test_tlv_descriptors(tmp):
    """A lifted image's thread-local descriptors, and the gate on them.

    dyld validates each descriptor's `offset` against the TLV template span at
    load and aborts the process before main() if one is out of range -- which is
    what killed the eight ssh binaries. macOS dyld does NOT validate this, so
    the local dlopen loop cannot see the bug at all and this check is the only
    thing standing between a bad lift and a device.
    """
    print("\n[thread-local variables]")
    raw = "/tmp/dsc_out/usr/lib/libEndpointSecuritySystem.dylib"
    if not os.path.exists(raw):
        return skip("cache-form TLV descriptors are repaired",
                    "no extracted cache at /tmp/dsc_out")

    m = mm.MachO(open(raw, "rb").read())
    tv = m._section(b"__thread_vars")
    if tv is None:
        return skip("cache-form TLV descriptors are repaired",
                    "no __thread_vars in the extraction")

    bad_before = m.malformed_tlv_descriptors()
    check("a cache extraction's descriptors are all malformed",
          len(bad_before) == tv[1] // 24, f"{len(bad_before)} of {tv[1] // 24}")

    # The cache records the answer twice over, and both must agree with the
    # linker's own $tlv$init marker where that survives.
    n = tv[1] // 24
    keys = [struct.unpack_from("<QQQ", m.data, tv[2] + i * 24) for i in range(n)]
    data, bss = m._section(b"__thread_data"), m._section(b"__thread_bss")
    present = [x for x in (data, bss) if x is not None]
    base = min(x[0] for x in present)
    span = max(x[0] + x[1] for x in present) - base
    check("offset's high half records the template size, and it is the SPAN",
          all((o >> 32) == span for _t, _k, o in keys), f"span {span:#x}")

    fixed, notes = m.fix_tlv_descriptors()
    check("every descriptor is repaired", fixed == n, f"{fixed} of {n}")
    check("with no complaints", not notes, str(notes))
    check("and the gate is then quiet", not m.malformed_tlv_descriptors())

    offs = [struct.unpack_from("<Q", m.data, tv[2] + i * 24 + 16)[0]
            for i in range(n)]
    check("each repaired offset is inside the template",
          all(0 <= o < span for o in offs), str([hex(o) for o in offs]))
    check("key is left zero for dyld to assign",
          all(struct.unpack_from("<Q", m.data, tv[2] + i * 24 + 8)[0] == 0
              for i in range(n)))

    # key >> 32 is what makes a STRIPPED image repairable: 213 of the 446
    # descriptors in the cache have no $tlv$init to fall back on.
    check("the repaired offset is what the cache's key recorded",
          offs == [k >> 32 for _t, k, _o in keys],
          f"{offs} vs {[k >> 32 for _t, k, _o in keys]}")

    # Self-detecting: a descriptor that is already in range is never touched,
    # so an ordinary macOS binary and a real linker's dylib come out identical.
    before = bytes(m.data)
    again, _ = m.fix_tlv_descriptors()
    check("re-running is a no-op", again == 0 and bytes(m.data) == before)


def test_compact(tmp):
    """dsc.compact closes the address-space hole without changing meaning.

    It needs a lifted library to work on, which only exists on a machine that
    has run dsc_lift, so it skips rather than requiring the cache.  What it
    checks is the property the compactor is built around: every ADRP resolves
    to the same (segment, offset) before and after, and the export trie still
    agrees with the symbol table.
    """
    print("\n[address-space compaction]")
    here = os.path.dirname(os.path.abspath(__file__))
    lifted = os.path.join(here, "lifted")
    cands = ([os.path.join(lifted, f) for f in sorted(os.listdir(lifted))]
             if os.path.isdir(lifted) else [])
    cands = [c for c in cands if os.path.isfile(c)]
    if not cands:
        skip("compaction shrinks the span", "no lifted/ library to compact")
        return

    sys.path.insert(0, here)
    try:
        from dsc import compact as dc
    except Exception as e:                                  # noqa: BLE001
        skip("compaction shrinks the span", f"dsc.compact unimportable: {e}")
        return

    # Take the first library that compacts at all. A refusal is not a failure:
    # an ObjC image (DiskManagement) is refused by design, because its relative
    # method lists encode a __TEXT-to-__DATA distance that a per-segment move
    # changes. Fail only if every candidate is refused.
    out = os.path.join(tmp, "compacted.dylib")
    src = why = None
    for cand in cands:
        r = run([sys.executable, "-m", "dsc.compact", cand, "-o", out],
                cwd=here)
        if not r.returncode:
            src = cand
            break
        why = f"{os.path.basename(cand)}: {r.stderr.strip().splitlines()[0][:70]}"
    if src is None:
        skip("compaction packs the image and never widens it",
             f"every candidate refused ({why})")
        return

    # The property, stated so it holds whether or not the input was already
    # compacted (rebuild_cryptex compacts lifted/ in place, so it usually is):
    # the output is PACKED -- its span is the sum of its own segments, with
    # nothing reserved that it does not use -- and never wider than the input.
    a0, b0 = dc.Layout(src), dc.Layout(out)
    before, after = a0.span(), b0.span()
    packed = sum(s["vmsize"] for s in b0.segs)
    check("compaction packs the image and never widens it",
          after <= packed and after <= before,
          f"{os.path.basename(src)}: {before / 2**20:.2f} MB -> "
          f"{after / 2**20:.2f} MB, segments total {packed / 2**20:.2f} MB")

    # The exactness claim: an ADRP still names the same byte of the same
    # segment.  This is the check dsc.compact refuses to write output without,
    # so it is really asserting that the guard is wired up.
    check("every ADRP resolves to the same segment and offset",
          dc.resolved_targets(a0) == dc.resolved_targets(b0))

    # The export trie stores offsets from the image base, so a moved data
    # export has to be re-encoded.  Getting this wrong puts a symbol at an
    # address dlsym reports without complaint -- the bug --reserve-header had.
    if not have("nm") or not have("dyld_info"):
        skip("export trie agrees with the symbol table", "no nm / dyld_info")
        return
    base = min(s["vmaddr"] for s in b0.segs)
    trie = {}
    for line in run(["dyld_info", "-exports", out]).stdout.splitlines():
        f = line.split()
        if len(f) >= 2 and f[0].startswith("0x") and f[1].startswith("_"):
            trie[f[1]] = int(f[0], 16)
    bad = []
    for line in run(["nm", "-gU", out]).stdout.splitlines():
        f = line.split()
        if len(f) == 3 and f[1] in "TSDBC" and f[2] in trie:
            if trie[f[2]] != int(f[0], 16) - base:
                bad.append(f[2])
    check("export trie agrees with the symbol table", not bad and trie,
          f"{len(trie)} exports, {len(bad)} disagree")


def test_library_closure(tmp):
    """A binary and the libraries the target lacks, from one invocation.

    This is the primary use of the tool, and what it replaced: the closure used
    to be a second program (bundle.py) driven by a hand-written list of tools,
    which is why a batch kept leaving binaries pointing at an absolute macOS
    path they could not reach.

    csrutil is the case worth testing because its closure is five libraries,
    none of which exists as a file anywhere -- so it exercises the whole path
    (probe the cache, lift, compact, stage, repoint) rather than a copy. It
    needs libraries lifted earlier, so it skips rather than spending minutes on
    a cache pass.
    """
    print("\n[library closure]")
    tool = "/usr/bin/csrutil"
    if not os.path.exists(tool):
        skip("closure", f"no {tool}")
        return
    here = os.path.dirname(os.path.abspath(__file__))
    lifted = os.path.join(here, "lifted")
    want5 = ["DiskManagement", "libCoreStorage.dylib", "libcsfde.dylib",
             "libbootpolicy.dylib", "libDiagnosticMessagesClient.dylib"]
    if not all(os.path.isfile(os.path.join(lifted, w)) for w in want5):
        skip("closure", "lifted/ does not hold csrutil's five (run a build)")
        return
    out = os.path.join(tmp, "closure", "csrutil")
    # --lift-cache into tmp, so this reads lifted/ and can never write it: the
    # repo's cache is a build artefact of a real build, not of a test run.
    # --darwin-extsn and --weaken-unresolvable because that is how a build
    # stages a library, and without them these five are correctly refused --
    # DiskManagement alone imports _syslog$DARWIN_EXTSN and 7 macOS-only
    # Security symbols.
    r = run([sys.executable, os.path.join(here, "machomorph.py"), tool,
             "-o", out, "-p", "ios", "-v", "27.0", "--prebuilt", lifted,
             "--lift-cache", os.path.join(tmp, "liftcache"),
             "--darwin-extsn", "--weaken-unresolvable", "-q"])
    if r.returncode:
        skip("closure", "conversion failed (no lifted/ and no cache?)")
        return
    root = os.path.dirname(out)
    check("the binary is written", os.path.isfile(out))
    # The five, at the TARGET's spelling of their path -- iOS frameworks are
    # flat, so mirroring Versions/A/ would carry a macOS-ism into the tree.
    want = ["System/Library/PrivateFrameworks/DiskManagement.framework/"
            "DiskManagement",
            "usr/lib/libCoreStorage.dylib", "usr/lib/libcsfde.dylib",
            "usr/lib/libbootpolicy.dylib",
            "usr/lib/libDiagnosticMessagesClient.dylib"]
    missing = [w for w in want if not os.path.isfile(os.path.join(root, w))]
    check("every library in the closure is staged, at the target's path",
          not missing, ", ".join(missing) or f"{len(want)} of {len(want)}")
    check("no Versions/ in the staged tree",
          not any("/Versions/" in os.path.join(dp, f)
                  for dp, _d, fs in os.walk(root) for f in fs))

    # Every relative reference in the tree must resolve to a real file. This is
    # the check the mirror layout is worth having: the relative spelling from a
    # library four directories deep is not the one a binary at the root uses,
    # and getting it wrong is invisible until dyld refuses to load.
    bad = []
    for dp, _d, fs in os.walk(root):
        for f in fs:
            path = os.path.join(dp, f)
            lines = run(["otool", "-L", path]).stdout.splitlines()[1:]
            if not lines:
                continue
            for line in lines[1:] if path != out else lines:   # skip an ID
                ref = line.strip().split(" (")[0]
                if not ref.startswith("@loader_path/"):
                    continue
                base = os.path.dirname(path)
                if not os.path.exists(os.path.normpath(
                        os.path.join(base, ref.split("/", 1)[1]))):
                    bad.append(f"{os.path.relpath(path, root)} -> {ref}")
    check("every @loader_path reference resolves to a staged file", not bad,
          "; ".join(bad[:3]))

    ids = {}
    for w in want:
        ids[w] = run(["otool", "-D", os.path.join(root, w)]
                     ).stdout.strip().splitlines()[-1]
    check("each library's install name is what a binary asks for",
          all(v.startswith("@loader_path/") and not v.startswith("/")
              for v in ids.values()), str(sorted(ids.values())[0]))
    check("everything is signed",
          all(run(["codesign", "--verify", os.path.join(root, w)]).returncode
              == 0 for w in want + [os.path.basename(out)]))


def test_lift_from_cache(tmp):
    """An input that is not a file is lifted out of the shared cache.

    /usr/lib/libxcselect.dylib exists on disk nowhere: Xcode ships only a .tbd
    text stub, and the cache is the only copy of the code. So `machomorph.py
    /usr/lib/libxcselect.dylib` is not an error to report, it is a lift to run.
    Checked against a lift made earlier, which is the regression this protects:
    the pipeline moved from a shell script into this file and must still
    produce the same bytes.
    """
    print("\n[lifting an input that only exists in the cache]")
    here = os.path.dirname(os.path.abspath(__file__))
    ref = os.path.join(here, "lifted", "libxcselect.dylib")
    if not os.path.isfile(ref):
        skip("lift", "no lifted/libxcselect.dylib to compare against")
        return
    out = os.path.join(tmp, "lift", "libxcselect.dylib")
    # The same arguments a build lifts with, and no more: the install name is
    # set when the library is STAGED, not when it is lifted, so a --change here
    # would legitimately produce different bytes from the cached lift.
    r = run([sys.executable, os.path.join(here, "machomorph.py"),
             "/usr/lib/libxcselect.dylib", "-o", out, "-p", "ios", "-v", "26.0",
             "--darwin-extsn", "--no-libraries", "-q"])
    if r.returncode or not os.path.isfile(out):
        skip("lift", "no shared cache to lift out of")
        return
    check("a cache-only input is lifted rather than refused",
          os.path.isfile(out))
    with open(out, "rb") as a, open(ref, "rb") as b:
        same = a.read() == b.read()
    # The output basename has to match the reference: codesign derives the
    # signing identifier from it, so a different name is a different signature
    # and a legitimately different file.
    check("byte-identical to the lift the shell pipeline produced", same)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cbv", default=os.path.expanduser(
        "~/Documents/ios_tools/cbv"))
    ap.add_argument("--binary", default="/usr/sbin/ioreg")
    args = ap.parse_args()
    cbv = args.cbv if os.path.exists(args.cbv) and os.access(args.cbv, os.X_OK) else None

    with tempfile.TemporaryDirectory() as tmp:
        test_versions()
        test_auto_paths()
        test_thin(tmp, args.binary)
        test_cbv(tmp, args.binary, cbv)
        test_paths(tmp, args.binary)
        test_entitlements(tmp)
        test_roundtrip(tmp, args.binary)
        test_header_overflow(tmp, args.binary)
        test_bad_input(tmp)
        test_redirect_symbol(tmp)
        test_redirect_shared_suffix(tmp)
        test_symbol_gate(tmp)
        test_weaken_symbol(tmp)
        test_flat_namespace(tmp)
        test_bundled_index(tmp)
        test_tlv_descriptors(tmp)
        test_compact(tmp)
        test_library_closure(tmp)
        test_lift_from_cache(tmp)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
