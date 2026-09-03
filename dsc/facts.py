#!/usr/bin/env python3
"""
dsc_facts -- collect, from a dyld shared cache, the two things dsc_rebind
cannot recover from an extracted image alone.

    ./dsc_facts.py <cache> <extracted.dylib> --image /usr/lib/libfoo.dylib \\
                   -o facts.json [--slide-json FILE]

1. **data pointers.**  Which words in the image's own __DATA*/__AUTH* segments
   are pointers, and what each targets.  A cache image's data pages are covered
   by the cache's slide info rather than by a fixup load command of its own, so
   this has to come from the cache.  `ipsw dyld slide --json` emits one record
   per pointer for the whole cache; we stream it and keep the ones that land in
   this image.

2. **code GOT slots.**  The cache builder uniques GOT entries cache-wide, so a
   few of the image's data loads reach a slot that belongs to no image.  Those
   slots are populated in the cache, so the symbol is recovered by reading the
   slot's value and asking what is exported at that address.

Everything else -- which stub maps to which symbol, which GOT slot holds what
-- is still in the extracted file's indirect symbol table, and dsc_rebind reads
it from there.

The slide pass is over the whole cache and takes a minute or two.  Pass
--slide-json to reuse a dump you already have, or --keep-slide-json to save one.
"""

import argparse
import json
import re
import struct
import subprocess
import sys

from .arm64 import adrp, add_imm64, ldr_uimm64, u32
from .gotscan import Image, resolve_alias, scan_got_sites, undefined_symbols


def run(cmd: list, soft: bool = False) -> str:
    """soft=True: a failure means "no answer", not "stop"."""
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        if soft:
            return ""
        raise SystemExit(f"{' '.join(cmd[:3])}... failed:\n{p.stderr[-2000:]}")
    return p.stdout


def cache_base(cache: str) -> int:
    """The address the cache's first mapping is built for.

    `ipsw dyld slide --json` reports each pointer twice over: a `target`, and a
    `pointer.value` that is the target as an offset from this base. They agree
    for almost every record -- and where they do not, it is `value` that is
    right. A C++ typeinfo name pointer in CoreDisplay reports
    target=0x2018302e040, which is 200x past the end of the 5 GB cache, while
    value+base is 0x18302e040: the RTTI string in the image's own
    __TEXT.__const, exactly where a typeinfo points. Trusting `target` there
    turned 20 ordinary rebases across four libraries into binds with no name,
    which were then left NULL.

    So the target is computed from `value`, and this is the base it is relative
    to: the address of the first mapping in the cache header.
    """
    with open(cache, "rb") as fh:
        hdr = fh.read(32)
        if hdr[:7] != b"dyld_v1":
            raise SystemExit(f"{cache}: not a dyld shared cache")
        mapping_off, mapping_count = struct.unpack_from("<II", hdr, 16)
        if not mapping_count:
            raise SystemExit(f"{cache}: no mappings")
        fh.seek(mapping_off)
        return struct.unpack("<Q", fh.read(8))[0]


def data_ranges(img: Image):
    """The segments whose contents the cache's slide info covers."""
    out = []
    for name, vmaddr, vmsize, fo, fs in img.segments:
        if name.startswith("__DATA") or name.startswith("__AUTH"):
            out.append((vmaddr, vmaddr + vmsize))
    return out


def locate(img: Image, a: int):
    for s in img.sections:
        if s["addr"] <= a < s["addr"] + s["size"]:
            return s["seg"], s["sect"], a - s["addr"]
    return None


def stream_slide(cache: str, ranges, slide_json: str | None, keep: str | None):
    """Yield the raw JSON objects from `ipsw dyld slide` that fall in ranges."""
    def want(a):
        return any(lo <= a < hi for lo, hi in ranges)

    if slide_json:
        src = open(slide_json, "rb")
        proc = None
    else:
        proc = subprocess.Popen(["ipsw", "dyld", "slide", cache, "--json"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        src = proc.stdout

    sink = open(keep, "wb") if keep else None
    buf = b""
    scanned = 0
    try:
        while True:
            chunk = src.read(8 << 20)
            if not chunk:
                break
            if sink:
                sink.write(chunk)
            buf += chunk
            parts = buf.split(b'{"cache_file_offset":')
            buf = b'{"cache_file_offset":' + parts[-1]
            for p in parts[1:-1]:
                scanned += 1
                m = re.match(rb'(\d+),"cache_vm_address":(\d+)', p)
                if not m:
                    continue
                a = int(m.group(2))
                if want(a):
                    body = b'{"cache_file_offset":' + p.rstrip(b',')
                    yield json.loads(body.decode(errors="replace"))
    finally:
        if sink:
            sink.close()
        if proc:
            proc.stdout.close()
            proc.wait()
        elif slide_json:
            src.close()
    print(f"  scanned {scanned} slide records", file=sys.stderr)


def stub_slots(img: Image) -> dict:
    """Each stub's cache-wide GOT slot: {(section, index): address}.

    A stub is `adrp x17, page / add x17, x17, #off / ldr x16, [x17] / braa`.
    The adrp+add pair is the only record of which GOT slot the cache builder
    pointed this stub at, and therefore of which symbol it wants.
    """
    out = {}
    for s in img.sections:
        if s["sect"] not in ("__auth_stubs", "__stubs"):
            continue
        stride = s["r2"] or 16
        for i in range(s["size"] // stride):
            pc = s["addr"] + i * stride
            fo = s["off"] + i * stride
            page, rd = adrp(u32(img.data, fo), pc)
            imm, rn, _ = add_imm64(u32(img.data, fo + 4))
            if page is None or imm is None or rn != rd:
                continue
            out[(s["sect"], i)] = page + imm
    return out


def patch_table(cache: str, wanted: set, dump: str | None,
                keep: str | None) -> dict:
    """Address -> symbol, for the cache's uniqued GOT slots.

    `ipsw dyld patches` lists, per exporting image and symbol, every cache
    location that points at it -- which inverted is exactly the map we need. It
    is ~400 MB of text for a macOS cache, so it is streamed rather than stored,
    and only the addresses asked for are kept.
    """
    if dump:
        src = open(dump, "rb")
        proc = None
    else:
        proc = subprocess.Popen(["ipsw", "dyld", "patches", cache],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        src = proc.stdout
    sink = open(keep, "wb") if keep else None

    pat_sym = re.compile(rb"^0x[0-9a-f]+: (.+)$")
    pat_tgt = re.compile(rb"^\s+0x([0-9a-f]+): (?:GOT|PATCH)")
    found, sym, buf = {}, None, b""
    try:
        while True:
            chunk = src.read(8 << 20)
            if not chunk:
                break
            if sink:
                sink.write(chunk)
            buf += chunk
            lines = buf.split(b"\n")
            buf = lines.pop()
            for line in lines:
                m = pat_sym.match(line)
                if m:
                    sym = m.group(1).strip().decode(errors="replace")
                    continue
                m = pat_tgt.match(line)
                if m:
                    a = int(m.group(1), 16)
                    if a in wanted and sym:
                        found[a] = sym
    finally:
        if sink:
            sink.close()
        if proc:
            proc.stdout.close()
            proc.wait()
        else:
            src.close()
    return found


def external_code_slots(img: Image) -> dict:
    """{address: is the use an authenticated branch} for GOT slots __text
    reaches that no segment of this image covers."""
    out = {}
    for s in scan_got_sites(img):
        a = s["target"]
        if img.owns(a) or a % 8:
            continue
        out[a] = out.get(a, False) or s["auth"]
    return out


def symbol_at(cache: str, addr: int) -> str | None:
    """What symbol does the cache export at this address?"""
    s = run(["ipsw", "dyld", "a2s", cache, hex(addr)], soft=True)
    if not s.strip():
        return None
    m = re.search(r":\s*(\S+)\s*$", s.strip().splitlines()[-1])
    return m.group(1) if m else None


def resolve_slot(cache: str, addr: int) -> str | None:
    """A cache-wide GOT slot holds a real pointer; name what it points at."""
    v = run(["ipsw", "dyld", "dump", cache, hex(addr), "--count", "1",
             "--addr"], soft=True)
    val = None
    for line in v.splitlines():
        line = line.strip()
        if line.startswith("0x"):
            val = int(line, 16)
            break
    if not val:
        return None
    # A mis-decoded ADRP/LDR can land on something that is not a GOT slot at
    # all, so the "pointer" read out of it need not be an address. a2s says so;
    # that is an answer, not an error.
    return symbol_at(cache, val)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("cache")
    ap.add_argument("extracted", help="the extracted dylib, BEFORE conversion")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--slide-json", help="reuse an `ipsw dyld slide --json` dump")
    ap.add_argument("--keep-slide-json", help="save the dump for the next image")
    ap.add_argument("--patches-txt", help="reuse an `ipsw dyld patches` dump")
    ap.add_argument("--keep-patches-txt",
                    help="save the patches dump for the next image")
    args = ap.parse_args(argv)

    img = Image(open(args.extracted, "rb").read())
    base = cache_base(args.cache)
    ranges = data_ranges(img)
    print(f"data segments: " +
          ", ".join(f"0x{a:x}-0x{b:x}" for a, b in ranges), file=sys.stderr)

    recs = []
    for o in stream_slide(args.cache, ranges, args.slide_json,
                          args.keep_slide_json):
        a = o["cache_vm_address"]
        p = o["pointer"]
        # See cache_base(): `value` is authoritative, `target` is not.
        if "value" in p:
            o["target"] = p["value"] + base
        loc = locate(img, a)
        if loc is None:
            print(f"  warning: pointer at 0x{a:x} is in no section",
                  file=sys.stderr)
            continue
        seg, sect, off = loc
        rec = dict(seg=seg, sect=sect, off=off,
                   auth=bool(p.get("authenticated")),
                   key=p.get("key"), addr_div=bool(p.get("addr_div")),
                   diversity=p.get("diversity", 0))
        tloc = locate(img, o["target"])
        if tloc:
            rec["kind"] = "rebase"
            rec["tseg"], rec["tsect"], rec["toff"] = tloc
        else:
            rec["kind"] = "bind"
            rec["target"] = hex(o["target"])
            rec["symbol"] = o.get("symbol")
            if not rec["symbol"]:
                # The slide dump names most targets. When it does not, ask
                # what is exported at the target address.
                rec["symbol"] = symbol_at(args.cache, o["target"])
            if not rec["symbol"]:
                print(f"  warning: bind at 0x{a:x} -> 0x{o['target']:x} has "
                      f"no name in the cache", file=sys.stderr)
        recs.append(rec)

    # Which symbol each cache-wide GOT slot held. Two sets of addresses need
    # naming: the slot every stub was pointed at, and the slots the code reaches
    # directly with an ADRP+LDR for a data symbol.
    #
    # This cannot be read off the extraction. The indirect symbol table names
    # the slots in some libraries (libxcselect, libdtrace) but is ALL ZEROES in
    # others (libcrypto, libssl, libcurl, libpcre) -- and zeroes are not
    # detectably wrong, they just make every slot look like symbol 0. So the
    # names come from the cache, always.
    stubs = stub_slots(img)
    code_slots = external_code_slots(img)
    wanted = set(stubs.values()) | set(code_slots)
    got_symbols = patch_table(args.cache, wanted, args.patches_txt,
                              args.keep_patches_txt)
    missing = [a for a in wanted if a not in got_symbols]
    # The patch table covers what one cache image exports to another. A few
    # slots are not in it; ask what is exported at the address the slot holds.
    for a in missing:
        sym = resolve_slot(args.cache, a)
        if sym:
            got_symbols[a] = sym
    print(f"  named {len(got_symbols)} of {len(wanted)} cache GOT slots",
          file=sys.stderr)
    if wanted and not got_symbols:
        # Naming nothing is not a degraded result, it is a failed one: every
        # stub then has "no symbol in the facts" and dsc_rebind repoints zero
        # instructions, producing a library that loads and PAC-faults on its
        # first call through a stub. Which is exactly what shipped once.
        print(f"error: named none of the {len(wanted)} GOT slots. The cache "
              f"queries returned nothing -- check that `ipsw` works on "
              f"{args.cache}, or pass --slide-json/--patches-txt.",
              file=sys.stderr)
        return 1

    undef = undefined_symbols(img)
    stub_map, code_got, rejected = {}, {}, 0
    for (sect, i), a in stubs.items():
        sym = got_symbols.get(a)
        if sym is None:
            print(f"  warning: {sect}[{i}] -> 0x{a:x} has no name in the cache",
                  file=sys.stderr)
            continue
        stub_map[f"{sect}:{i}"] = resolve_alias(sym, undef)
    # Not every out-of-image ADRP+LDR is a GOT reference. A register reused
    # between an unrelated ADRP and a later LDR yields a plausible-looking
    # address that resolves to some unrelated cache symbol, so resolving is not
    # on its own enough. A stub's target is unambiguous; a code load's is not,
    # so for those keep a slot only when the symbol it names is one this
    # library actually imports.
    for a, auth in code_slots.items():
        sym = got_symbols.get(a)
        if sym is None:
            rejected += 1
            continue
        sym = resolve_alias(sym, undef)
        if undef and sym not in undef:
            rejected += 1
            continue
        # auth: the use is `blraa`/`braa`, so the slot has to be an
        # authenticated one. That is the cache builder inlining a stub straight
        # into __text instead of emitting an __auth_stubs entry for it.
        code_got[hex(a)] = dict(symbol=sym, auth=auth)
    if rejected:
        print(f"  {rejected} out-of-image code loads did not name an import "
              f"of this library; treated as decoding false positives",
              file=sys.stderr)

    # Section addresses, so dsc_rebind can translate an address it decodes out
    # of the CONVERTED image back to the one these facts are keyed by. The
    # relayout does not move everything by one delta: --reserve-header lowers
    # the segment base by whole pages while the contents move by less, so the
    # base shift and the code shift differ.
    facts = dict(image_base=hex(img.segments[0][1]),
                 sections={f"{s['seg']}.{s['sect']}": hex(s["addr"])
                           for s in img.sections},
                 data_pointers=recs, code_got=code_got, stub_got=stub_map)
    json.dump(facts, open(args.output, "w"), indent=1)
    print(f"wrote {args.output}: {len(recs)} data pointers, "
          f"{len(stub_map)} stubs, {len(code_got)} code GOT slots")
    return 0


if __name__ == "__main__":
    sys.exit(main())
