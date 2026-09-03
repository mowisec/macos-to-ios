#!/usr/bin/env python3
"""SUPERSEDED, and kept only for a tree built by an older version of this repo.
machomorph computes every binary's library closure itself now, so a batch can no
longer leave one of them pointing at an absolute macOS path -- which is the
whole bug this script existed to retrofit. rebuild_cryptex.sh no longer runs it.

restage -- repoint cryptex binaries that still name an absent macOS library.

    ./restage.py --cryptex DIR --dylib-index FILE            # report
    ./restage.py --cryptex DIR --dylib-index FILE --apply     # fix

Finds every binary in the cryptex that references a library by absolute path
when

  * iOS does not have that library (the dylib index cannot resolve it), and
  * this cryptex already bundles a copy of it,

and rewrites the reference to point at the bundled copy.

Why this exists
---------------
`bundle.py` is given its tools by hand -- curl, openssl, tcpdump, dtrace,
systemstats, perl, zsh -- and repoints exactly those at the libraries it
bundles. But the main `--scan` batch converts *every* binary in /usr/bin and
friends, and some of those link the same libraries. Those keep the absolute
macOS path, weak-linked, so they load and then crash on the first call into a
library that is not on the device. CLAUDE.md records this as "a batch undoes
--provide-lib"; the hand-written list is what makes it keep happening.

Measured on the first clean-cryptex build: 14 binaries, including the whole ssh
family (ssh, scp, sftp, ssh-add, ssh-agent, ssh-keygen, ssh-keyscan, sshd) on
libcrypto, httpd and htpasswd on libcrypto/libssl, and snmptrapd on libcrypto.

Why not just hand these to bundle.py
------------------------------------
Tried, and it is wrong. bundle.py computes each tool's *whole* closure, so
asking it to fix `ssh` also drags in Kerberos and libHeimdalProxy, `httpd`
brings libapr/libaprutil, `snmptrapd` the four net-snmp libraries, and
`networksetup` pulls AppKit, SkyLight, HIToolbox and OpenGL -- 37 extra
libraries, 130 MB of macOS window server, two of which ("Cocoa",
"ApplicationServices") extract to 4096-byte stubs that do not even sign. The
library those binaries need is *already staged*; the closure is not the
question being asked.

So this edits the reference and nothing else, and it edits the **already
converted** binary in place rather than re-converting the macOS original --
which preserves everything the main batch did to it (the other weakenings, any
--provide-lib substitution, its entitlements).
"""
import argparse
import os
import subprocess
import sys
import tempfile

import machomorph as mm       # the package __init__ puts the repo root on the path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)          # machomorph.py lives at the repo root


def bundled(cryptex: str, libdirs) -> dict:
    """basename -> relative directory, for the libraries this cryptex carries."""
    out = {}
    for d in libdirs:
        p = os.path.join(cryptex, d)
        if not os.path.isdir(p):
            continue
        for f in os.listdir(p):
            out.setdefault(f, d)
    return out



def library_is_sound(local: str) -> tuple[bool, str]:
    """Is this bundled library safe to turn a WEAK reference into a real one?

    A weak reference to a library the target lacks is harmless: dyld skips it
    and the binary runs. Repointing it at a bundled copy removes that escape
    hatch -- the library now has to load, and if it cannot, the process dies in
    dyld before main().

    That is not hypothetical. `libEndpointSecuritySystem` is weak-linked by
    login, scp, sftp, sshd and the four ssh-* tools, and it worked on device for
    exactly as long as it was NOT bundled. Once it entered the closure (through
    XprotectFramework, which links it strongly) restage repointed all eight, and
    every one of them then aborted on its malformed thread-local descriptors.

    So a weak reference is only worth repointing at a library we can show is
    loadable. The checks are the ones that have actually bitten:
    """
    try:
        with open(local, "rb") as fh:
            m = mm.MachO(mm.thin(fh.read(), None)[0])
    except (OSError, mm.MachOError) as e:
        return False, f"does not parse ({e})"
    if m.find(mm.LC_DYLD_CHAINED_FIXUPS) is None:
        # A raw cache extraction. It loads and then crashes on the first
        # dereference of a global, which is worse than not loading at all.
        return False, "no LC_DYLD_CHAINED_FIXUPS (a cache extraction, not a lift)"
    try:
        bad = m.malformed_tlv_descriptors()
    except Exception:
        bad = []
    if bad:
        return False, f"malformed thread-local descriptor: {bad[0]}"
    return True, ""


def stale(path: str, have: dict, index, cryptex: str | None = None,
          repoint_weak: bool = False) -> tuple[list, list]:
    """[(reference, basename)] this binary should not still be using.

    Two kinds, and the second was added after the blocklist was retired:

    1. An ABSOLUTE macOS path to a library iOS does not have but this cryptex
       bundles. Left alone the binary loads (the reference is weakened) and then
       crashes on its first call into it.
    2. An @-RELATIVE reference to a bundled library spelled differently from
       that library's own LC_ID_DYLIB. dyld registers an image under its install
       name, so a mismatch is at best inconsistent and at worst a second copy.
       This is what a wrong --anchor produces, and it is invisible to (1)
       because the reference is no longer absolute.
    """
    try:
        with open(path, "rb") as fh:
            macho = mm.MachO(mm.thin(fh.read(), None)[0])
    except (OSError, mm.MachOError):
        return [], []
    out, held = [], []
    for lc, ref in macho.paths():
        if lc.cmd not in (mm.LC_LOAD_DYLIB, mm.LC_LOAD_WEAK_DYLIB):
            continue
        base = os.path.basename(ref)
        if base not in have:
            continue
        if not ref.startswith("/"):
            # (2) an @-relative reference: right library, possibly wrong name.
            if not (ref.startswith("@") and cryptex):
                continue
            local = os.path.join(cryptex, have[base], base)
            ident = mm.dylib_id(local) if os.path.exists(local) else None
            if ident and ident.startswith("@") and ident != ref:
                out.append((ref, base))
            continue
        # A library iOS really has is fine to name absolutely -- that is the
        # normal case. Only an unresolvable one is a problem.
        if index.resolve(ref)[0] is not None:
            continue
        if lc.cmd == mm.LC_LOAD_WEAK_DYLIB and not repoint_weak:
            # Leave a weak reference weak unless the bundled library is known
            # to work. Absent, it is skipped and the binary runs; repointed at
            # a broken library, the binary dies in dyld.
            local = os.path.join(cryptex, have[base], base) if cryptex else None
            ok, why = (library_is_sound(local) if local and os.path.exists(local)
                       else (False, "not staged"))
            if not ok:
                held.append((ref, base, why))
                continue
        out.append((ref, base))
    return out, held


def install_name(base: str, reldir: str, anchor: str, depth: int,
                 cryptex: str | None = None) -> str:
    """The name to point a binary at for bundled library `base`.

    Prefer the library's OWN LC_ID_DYLIB. dyld registers a loaded image under
    its install name, so a dependent that asks for it by any other spelling is
    at best inconsistent and at worst loads a second copy -- which is why
    verify_cryptex checks the two agree.

    This used to construct the name from --anchor alone, and that broke as soon
    as the blocklist was retired: bundle.py deliberately stages libperl and
    libpcre with @executable_path (perl's and zsh's module trees sit at varying
    depths under share/, where @loader_path would mean a different directory for
    every module), while this defaulted to @loader_path. The postfix suite,
    perl5.34 and parldyn came into scope, were repointed with the wrong anchor,
    and verify_cryptex failed the build. Same lesson as bundle.py keying its
    rewrite on mm.dylib_id(): ask the library, do not assume.
    """
    if cryptex:
        local = os.path.join(cryptex, reldir, base)
        if os.path.exists(local):
            ident = mm.dylib_id(local)
            # Only an @-relative id is usable; an absolute one is a macOS path
            # that exists on no device, and constructing our own is right there.
            if ident and ident.startswith("@"):
                return ident
    return f"{anchor}/{'../' * depth}{reldir}/{base}"


def repoint(path: str, refs, have: dict, args) -> bool:
    """Rewrite this binary's references. True on success."""
    cmd = [os.path.join(ROOT, "machomorph.py"), path,
           "-p", args.platform, "-v", args.osversion, "-q"]
    if args.dylib_index:
        cmd += ["--dylib-index", args.dylib_index]
    for ref, base in refs:
        name = install_name(base, have[base], args.anchor, args.depth,
                            args.cryptex)
        cmd += ["--change", ref, name, "--weak", name]
    # -o to a temp file, then replace: machomorph refuses to write over its own
    # input, and an interrupted rewrite must not leave a half-written binary in
    # a cryptex that is about to be signed and installed.
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".restage-")
    os.close(fd)
    try:
        r = subprocess.run(cmd + ["-o", tmp], capture_output=True, text=True)
        if r.returncode:
            sys.stderr.write(r.stdout + r.stderr)
            return False
        os.chmod(tmp, 0o755)
        os.replace(tmp, path)
        return True
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="restage")
    ap.add_argument("--cryptex", required=True, metavar="DIR")
    ap.add_argument("--dylib-index", required=True, metavar="FILE")
    ap.add_argument("--bindir", action="append", default=["bin", "sbin"],
                    metavar="REL")
    ap.add_argument("--libdir", action="append", default=["lib", "usr/lib"],
                    metavar="REL")
    ap.add_argument("-p", "--platform", default="ios")
    ap.add_argument("-v", "--version", dest="osversion", default="26.0")
    ap.add_argument("--anchor", default="@loader_path",
                    choices=["@loader_path", "@executable_path"],
                    help="four bytes shorter than @executable_path, and means "
                         "the same thing for a binary in bin/")
    ap.add_argument("--depth", type=int, default=1,
                    help="directories from the binary up to the cryptex root")
    ap.add_argument("--repoint-weak", action="store_true",
                    help="also repoint WEAK references at a bundled library "
                         "that fails the soundness check. The default leaves "
                         "them weak and absolute, because dyld skips an absent "
                         "weak library and the binary runs, where a bundled "
                         "one that cannot load kills it before main()")
    ap.add_argument("--apply", action="store_true",
                    help="rewrite them; without this, only report")
    args = ap.parse_args(argv)

    index = mm.DylibIndex.load(args.dylib_index)
    have = bundled(args.cryptex, args.libdir)

    found = failed = 0
    # The library directories are scanned too, not just bin/ and sbin/. A
    # bundled library reaching another bundled library by absolute path is the
    # same bug with the same cause, and it is the one that shipped: libcurl
    # named /usr/lib/libcrypto.46.dylib weakly, so on iOS libcrypto silently did
    # not load under that name and every symbol from it came out unbound --
    # `Symbol not found: _ASN1_STRING_get0_data, Expected in: <no uuid>
    # unknown`. Every binary in bin/ was correct, so scanning only bin/ found
    # nothing. bundle.py could not have caught it either: it builds each tool's
    # closure from LC_LOAD_DYLIB only, and Apple's libcurl links libcrypto
    # *weakly*, so libcrypto was never in curl's closure to be rewritten.
    kept = []
    for d in list(args.bindir) + list(args.libdir):
        dd = os.path.join(args.cryptex, d)
        if not os.path.isdir(dd):
            continue
        for name in sorted(os.listdir(dd)):
            p = os.path.join(dd, name)
            # A symlink is an alias of a binary listed in its own right.
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            refs, held = stale(p, have, index, args.cryptex,
                               args.repoint_weak)
            for ref, base, why in held:
                kept.append(f"  {d}/{name}: left {base} weak and absolute "
                            f"-- {why}")
            if not refs:
                continue
            found += 1
            libs = ", ".join(sorted({b for _, b in refs}))
            if not args.apply:
                print(f"  {d}/{name}: {libs}")
                continue
            if repoint(p, refs, have, args):
                print(f"  repointed {d}/{name} at bundled {libs}")
            else:
                print(f"  FAILED to repoint {d}/{name} ({libs})",
                      file=sys.stderr)
                failed += 1

    if kept:
        print(f"\nrestage: {len(kept)} weak reference(s) left alone, because a "
              f"weak reference to an absent library is harmless and repointing "
              f"it at a library that cannot load is not (--repoint-weak to "
              f"override):")
        for line in kept[:12]:
            print(line)
        if len(kept) > 12:
            print(f"  ... and {len(kept) - 12} more")

    if not found:
        print("restage: nothing stale")
    elif not args.apply:
        print(f"restage: {found} binaries would be repointed (--apply to do it)")
    else:
        print(f"restage: repointed {found - failed} of {found}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
