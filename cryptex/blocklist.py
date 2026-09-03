#!/usr/bin/env python3
"""Turn a device probe TSV into an --exclude-from list, keeping the evidence.

    tools/blocklist_from_probe.py measurements/device_probe_*.tsv > data/blocklist_symbols.txt

The point of this script is that the list is DERIVED, never hand-maintained.
The previous blocklist was written by hand, drifted from the measurements it
claimed to encode, and ended up excluding 480 binaries on reasoning that did not
hold (see measurements/retired_blocklist_ios.txt and next-session-blocklist.md).
Regenerating from a TSV means a re-probe updates it and a stale entry cannot
survive.

Each line carries the missing symbol as an inline comment, so a fix can be
audited by grep rather than by memory:

    date        # _syslog$DARWIN_EXTSN

machomorph strips inline comments (`line.split("#", 1)[0]`), so the file is
usable as-is. When a symbol becomes resolvable -- a rename, a shim, a newer iOS
-- delete every line naming it and re-probe:

    grep -c '_syslog\\$DARWIN_EXTSN' data/blocklist_symbols.txt
    grep -v '_syslog\\$DARWIN_EXTSN' data/blocklist_symbols.txt > new && mv new ...
"""
import argparse
import os
import re
import sys
from collections import defaultdict

import machomorph as mm       # the package __init__ puts the repo root on the path

# Two spellings, because dyld reports the two namespaces differently:
#   Symbol not found: _foo                            two-level, fails at launch
#   symbol not found in flat namespace '_foo'         flat, aborts at first use
TWO_LEVEL = re.compile(r"Symbol not found:\s*(\S+)")
FLAT = re.compile(r"symbol not found in flat namespace '([^']+)'")


def symbol_of(detail: str) -> str | None:
    for rx in (TWO_LEVEL, FLAT):
        m = rx.search(detail)
        if m:
            return m.group(1)
    return None


def imports_itself(cryptex: str, name: str, sym: str) -> bool:
    """Is `sym` one of this binary's OWN undefined symbols?

    If it is, the binary asks iOS for something iOS does not have and the
    failure is genuinely its own. If it is not, the symbol came from one of its
    dependencies and the fix belongs there.
    """
    for d in ("bin", "sbin"):
        p = os.path.join(cryptex, d, name)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        try:
            with open(p, "rb") as fh:
                macho = mm.MachO(mm.thin(fh.read(), None)[0])
        except (OSError, mm.MachOError):
            return False
        for used in macho.imports_by_library().values():
            if sym in used:
                return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="blocklist_from_probe")
    ap.add_argument("tsv", nargs="+", help="device_probe TSV(s)")
    ap.add_argument("--outcome", default="symbol",
                    help="which outcome to collect (default: symbol)")
    ap.add_argument("--cryptex", metavar="DIR",
                    help="hold back any binary whose missing symbol is imported "
                         "by a library THIS CRYPTEX BUNDLES -- that failure is "
                         "ours to fix, not iOS's")
    args = ap.parse_args(argv)

    # Not every symbol failure is iOS's fault, and the difference decides
    # whether a binary belongs on this list at all.
    #
    # Measured case, and it would have cost three working tools: the lifted
    # libcrypto.46 imports _syslog$DARWIN_EXTSN, which iOS libc does not export.
    # So openssl, tcpdump and curl die at launch -- but on the LIBRARY's import,
    # not their own, and the source-built libcrypto they replaced had no such
    # dependency. Blocking them would have dropped three tools that worked the
    # day before over a bug of ours that is one string edit from fixed.
    #
    # The test has to be precise about WHOSE import it is, because the two cases
    # look identical in the probe output and need opposite verdicts. Measured:
    #
    #   date, logger      import _syslog$DARWIN_EXTSN THEMSELVES, from libSystem
    #                     -> a real iOS gap for that binary. It belongs on the
    #                        list, with the symbol recorded so a rename retires it.
    #   openssl, tcpdump  do not import it at all; they inherit it from the
    #   curl              bundled libcrypto/libcurl -> our bug, hold back.
    #
    # So a binary is held back only when the symbol is NOT one of its own
    # imports and IS imported by a bundled library. Checking only the latter
    # swept up date and logger too, and their fix is a different one.
    bundled_imports: dict[str, set[str]] = {}
    if args.cryptex:
        for d in ("lib", "usr/lib"):
            dd = os.path.join(args.cryptex, d)
            if not os.path.isdir(dd):
                continue
            for f in sorted(os.listdir(dd)):
                lp = os.path.join(dd, f)
                if os.path.islink(lp) or not os.path.isfile(lp):
                    continue
                try:
                    with open(lp, "rb") as fh:
                        macho = mm.MachO(mm.thin(fh.read(), None)[0])
                    syms = set()
                    for used in macho.imports_by_library().values():
                        syms |= set(used)
                    bundled_imports[f] = syms
                except (OSError, mm.MachOError):
                    continue

    by_symbol: dict[str, set[str]] = defaultdict(set)
    held: dict[tuple, set[str]] = defaultdict(set)
    unknown: set[str] = set()
    seen = 0
    for path in args.tsv:
        with open(path) as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2 or parts[1] != args.outcome:
                    continue
                seen += 1
                name = parts[0]
                sym = symbol_of(parts[2]) if len(parts) > 2 else None
                if sym and bundled_imports:
                    culprit = next((lib for lib, syms in bundled_imports.items()
                                    if sym in syms), None)
                    if culprit and not imports_itself(args.cryptex, name, sym):
                        held[(sym, culprit)].add(name)
                        continue
                (by_symbol[sym] if sym else unknown).add(name)

    if not seen:
        print(f"no {args.outcome} rows found", file=sys.stderr)
        return 1

    src = ", ".join(args.tsv)
    out = [
        "# Binaries that fail to launch on iOS because a symbol is missing.",
        "#",
        "#     ./machomorph.py --scan ... --exclude-from data/blocklist_symbols.txt",
        "#",
        f"# GENERATED by tools/blocklist_from_probe.py from {src}.",
        "# Do not edit by hand -- re-probe and regenerate. The list it replaced was",
        "# hand-maintained and drifted from its own measurements; see",
        "# measurements/retired_blocklist_ios.txt.",
        "#",
        "# Every line names the symbol that blocked it, as an inline comment,",
        "# because a missing symbol is a SNAPSHOT and not a verdict: it can be",
        "# fixed by a rename, a forwarding shim, or a newer iOS. To retire a",
        "# symbol, delete the lines naming it and re-probe:",
        "#",
        "#     grep -v '_the$SYMBOL' data/blocklist_symbols.txt > new",
        "#",
        "# These binaries are inert rather than dangerous -- dyld kills them at",
        "# launch, so shipping one costs disk space and a confusing error, not",
        "# correctness. Excluding them is a tidiness decision, and the evidence to",
        "# reverse it is on the line.",
        "",
        f"# {sum(len(v) for v in by_symbol.values()) + len(unknown)} binaries,"
        f" {len(by_symbol)} distinct symbols.",
        "",
    ]

    for sym, names in sorted(by_symbol.items(),
                             key=lambda kv: (-len(kv[1]), kv[0])):
        out.append(f"# {sym}  ({len(names)})")
        width = max(len(n) for n in names)
        for n in sorted(names):
            out.append(f"{n.ljust(width)}  # {sym}")
        out.append("")

    if held:
        out.append("# ---------------------------------------------------------"
                   "------------------")
        out.append("# HELD BACK -- deliberately NOT excluded. The missing symbol"
                   " is imported by a")
        out.append("# library THIS CRYPTEX BUNDLES, so the failure is ours to"
                   " fix rather than a")
        out.append("# limit of iOS. Excluding these would hide our own bug and"
                   " drop working tools.")
        out.append("# ---------------------------------------------------------"
                   "------------------")
        for (sym, lib), names in sorted(held.items(),
                                        key=lambda kv: (-len(kv[1]), kv[0])):
            out.append(f"#   {sym}")
            out.append(f"#     imported by bundled {lib}")
            out.append(f"#     blocks: {', '.join(sorted(names))}")
        out.append("")

    if unknown:
        out.append("# The probe recorded no symbol name for these -- it captured"
                   " only the first")
        out.append("# line of output, and dyld had not said which symbol yet."
                   " Re-run them by hand")
        out.append("# to name it before trusting these entries.")
        for n in sorted(unknown):
            out.append(f"{n}  # UNKNOWN symbol")
        out.append("")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
