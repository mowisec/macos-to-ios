#!/usr/bin/env python3
"""symbol_check -- predict, on the Mac, which binaries iOS dyld will kill.

    ./symbol_check.py /usr/bin/curl [...] [--cryptex DIR] [--sdk PATH]
    ./symbol_check.py --cryptex DIR --all

CLAUDE.md records this as the one gap static analysis could not close:

    "What static analysis cannot see is the symbol level: all 70 symbol
     failures were invisible to it. Only launching finds those."

It can be closed. A missing *symbol* is as static as a missing library -- it
just needs the target's exported surface, which the iPhoneOS SDK's .tbd stubs
carry, plus the two-level-namespace ordinal that says which library each import
is bound to. Everything needed is in the file.

Getting `curl` working took four install-and-probe cycles, each one revealing
the next symbol behind the one just fixed. This finds them all in one pass.

WHAT IS AND IS NOT A FAILURE
----------------------------
dyld kills a process at launch for an unresolved import, but only when all of
these hold, and the whole point of this tool is getting the exceptions right:

  * the symbol is NOT a weak reference. A weak import may resolve to NULL --
    dyld binds zero and carries on. This lives in TWO places and dyld reads the
    second: nlist_64.n_desc & N_WEAK_REF, and dyld_chained_import.weak_import.
    A synthesised import table that carries the first without the second turns
    every weak import hard, which is what killed the lifted libcurl.
  * the library is NOT weak-linked-and-absent. An absent LC_LOAD_WEAK_DYLIB
    means all its symbols bind NULL, so nothing from it can fail the load.
  * the library is not one the cryptex bundles -- those are resolved against
    the staged file's own export trie, not against the SDK.

HONESTY ABOUT COVERAGE
----------------------
The SDK ships stubs for /usr/lib and public frameworks only -- no
PrivateFrameworks, no libpcap, no CoreSymbolication. A symbol from a library
with no stub is reported as `unknown`, never as a failure: `tcpdump` imports 90
libpcap symbols and works perfectly on device, and claiming those are broken
would make the tool worse than useless. `unknown` means "this tool cannot
judge", and only the device can.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
import machomorph as mm       # the package __init__ puts the repo root on the path



# --------------------------------------------------------------------------
# The analysis itself lives in machomorph -- TargetSymbols,
# MachO.bound_imports() and unresolvable_imports() -- so the conversion path
# and this report cannot drift apart. machomorph refuses, by default, to port
# a binary this would flag; --force overrides it there.
# --------------------------------------------------------------------------

def check(path, target, index, bundled_exports):
    """(will-fail, cannot-judge) for one Mach-O, each a list of (lib, sym)."""
    with open(path, "rb") as fh:
        m = mm.MachO(mm.thin(fh.read(), None)[0])
    provided = {b: e for b, e in bundled_exports.items() if e is not None}
    return mm.unresolvable_imports(m, target, index, provided)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*")
    ap.add_argument("--cryptex", help="resolve bundled libraries from here")
    ap.add_argument("--bindir", action="append", default=[])
    ap.add_argument("--libdir", action="append", default=["lib", "usr/lib"])
    ap.add_argument("--all", action="store_true",
                    help="check every binary in the cryptex")
    ap.add_argument("--dylib-index", help="target's loadable library list")
    ap.add_argument("--sdk", help="iPhoneOS SDK path")
    ap.add_argument("--target-symbols",
                    help="dsc.symindex file for the target's own cache, which "
                         "is the only thing that can speak for a "
                         "PrivateFramework -- without it those symbols are "
                         "reported `unknown` and fail nothing")
    ap.add_argument("--show-unknown", action="store_true",
                    help="also list symbols from libraries with no SDK stub")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    sdk = args.sdk
    if not sdk:
        r = subprocess.run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                           capture_output=True, text=True)
        sdk = r.stdout.strip()
    if not sdk or not os.path.isdir(sdk):
        print("error: no iPhoneOS SDK (pass --sdk)", file=sys.stderr)
        return 2
    if not args.quiet:
        print(f"target surface: {sdk}", file=sys.stderr)
    cache = None
    if args.target_symbols:
        from dsc import symindex
        cache = symindex.load(args.target_symbols)
    target = mm.TargetSymbols(sdk, cache)
    if not args.quiet:
        print(f"  {len(target.by_name)} libraries with stubs", file=sys.stderr)
        if cache:
            print(f"  + {len(target.from_cache)} more from "
                  f"{os.path.basename(args.target_symbols)} that the SDK does "
                  f"not describe", file=sys.stderr)

    index = mm.DylibIndex.load(args.dylib_index) if args.dylib_index else None

    bundled, bundled_exports = {}, {}
    if args.cryptex:
        for d in args.libdir:
            dd = os.path.join(args.cryptex, d)
            if not os.path.isdir(dd):
                continue
            for f in os.listdir(dd):
                p = os.path.join(dd, f)
                if os.path.isfile(p):
                    bundled.setdefault(f, p)
        for base, p in bundled.items():
            bundled_exports[base] = mm.dylib_exports(p)

    inputs = list(args.inputs)
    if args.all and args.cryptex:
        for d in (args.bindir or ["bin", "sbin"]):
            dd = os.path.join(args.cryptex, d)
            if not os.path.isdir(dd):
                continue
            for f in sorted(os.listdir(dd)):
                p = os.path.join(dd, f)
                if os.path.isfile(p) and not os.path.islink(p):
                    inputs.append(p)

    n_fail = 0
    for path in inputs:
        try:
            fail, unknown = check(path, target, index, bundled_exports)
        except (mm.MachOError, OSError):
            continue
        name = os.path.basename(path)
        if fail:
            n_fail += 1
            seen = set()
            print(f"{name}: WILL FAIL AT LAUNCH")
            for lib, sym in fail:
                if (lib, sym) in seen:
                    continue
                seen.add((lib, sym))
                print(f"    {sym}   (from {os.path.basename(lib)})")
        if unknown and args.show_unknown:
            libs = sorted({os.path.basename(u[0]) for u in unknown})
            print(f"{name}: cannot judge {len(unknown)} symbol(s) from "
                  f"{', '.join(libs)} -- no SDK stub")

    if not args.quiet:
        print(f"\n{n_fail} of {len(inputs)} will fail at launch",
              file=sys.stderr)
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
