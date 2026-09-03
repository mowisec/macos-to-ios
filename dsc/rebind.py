#!/usr/bin/env python3
"""
dsc_rebind -- repair the cache-uniqued GOT damage in a dyld-shared-cache
extraction, so the library actually runs standalone.

    ./dsc_rebind.py <converted.dylib> --facts <facts.json> -o <out.dylib>

Run it on a machomorph-converted extraction (`machomorph.py ... --no-sign`),
then codesign the result.  See dsc_gotscan.py for the diagnosis this undoes,
and CLAUDE.md for how the facts file is produced from the cache.

What it does
------------
1. Repoints every stub at this image's OWN __auth_got slot.  The cache builder
   left those sections in place at the right size and the indirect symbol table
   still names every slot, so this needs nothing from the cache: stub[i] and
   __auth_got[i] are the same symbol.
2. Repoints the handful of GOT-relative data loads in __text the same way,
   using the facts file to say which symbol each cache-wide slot held.
3. Restores the S_NON_LAZY_SYMBOL_POINTERS section type the builder stripped.
4. Synthesises LC_DYLD_CHAINED_FIXUPS: an auth bind for every GOT slot, plus
   the rebases and binds for the image's own data, recovered from the cache's
   slide info.

The emitted format is DYLD_CHAINED_PTR_ARM64E_USERLAND24 with
DYLD_CHAINED_IMPORT, which is what the linker produces for a real arm64e iOS
dylib -- verified by decoding one before writing this.
"""

import argparse
import json
import struct
import sys

from .arm64 import adrp, add_imm64, ldr_uimm64, u32
from .gotscan import (Image, import_ordinals, libsystem_ordinal,
                      resolve_alias, scan_got_sites, undefined_symbols,
                      weak_ref_symbols)

S_NON_LAZY_SYMBOL_POINTERS = 0x06
LC_SEGMENT_64 = 0x19
LC_DYLD_CHAINED_FIXUPS = 0x80000034

DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12
DYLD_CHAINED_IMPORT = 1
PAGE = 0x4000

KEYS = {"IA": 0, "IB": 1, "DA": 2, "DB": 3}

class Fixup:
    """One pointer slot to be emitted into a chain."""

    def __init__(self, vmoff, fileoff, kind, **kw):
        self.vmoff = vmoff          # offset from the image base, as dyld sees it
        self.fileoff = fileoff      # where to write the value
        self.kind = kind            # 'bind' | 'rebase'
        self.auth = kw.get("auth", False)
        self.key = kw.get("key", 0)
        self.addr_div = kw.get("addr_div", False)
        self.diversity = kw.get("diversity", 0)
        self.symbol = kw.get("symbol")
        self.addend = kw.get("addend", 0)
        self.target = kw.get("target", 0)   # vm offset from base, for rebases
        self.where = kw.get("where", "")

    def encode(self, nxt: int, ordinals: dict) -> int:
        if self.kind == "bind":
            o = ordinals[self.symbol]
            if o > 0xFFFFFF:
                raise SystemExit("too many imports for a 24-bit ordinal")
            if self.auth:
                return (o | (self.diversity << 32) | (int(self.addr_div) << 48)
                        | (self.key << 49) | (nxt << 51) | (1 << 62) | (1 << 63))
            if self.addend > 0x7FFFF:
                raise SystemExit(f"addend {self.addend} too large")
            return o | (self.addend << 32) | (nxt << 51) | (1 << 62)
        if self.auth:
            if self.target > 0xFFFFFFFF:
                raise SystemExit("auth rebase target does not fit in 32 bits")
            return (self.target | (self.diversity << 32)
                    | (int(self.addr_div) << 48) | (self.key << 49)
                    | (nxt << 51) | (1 << 63))
        if self.target > (1 << 43) - 1:
            raise SystemExit("rebase target does not fit in 43 bits")
        return self.target | (nxt << 51)


def collect(img: Image, facts: dict, verbose: bool):
    """-> (fixups, instruction patches, warnings, shift, slots to zero)"""
    base = img.segments[0][1]
    fixups, patches, warn = [], [], []
    to_zero = []
    undef = undefined_symbols(img)
    ords_ = import_ordinals(img)

    def sec(seg, name):
        return img.section(seg, name)

    # The GOT sections this image already has. The cache builder left them at
    # the original size and only zeroed them, so they are the right shape to
    # rebind into -- we just have to decide what goes in each slot ourselves.
    #
    # __auth_ptr is deliberately NOT in this list. The indirect symbol table
    # accounts for exactly stubs + __got + __auth_got, with no entries left for
    # it, so it cannot be named that way. It is used further down as the pool
    # for authenticated overflow, since it too is dead space in every library
    # measured -- zeroed in the cache and named by no slide-info record.
    auth_got = sec("__AUTH_CONST", "__auth_got")
    plain_got = (sec("__DATA_CONST", "__got") or sec("__DATA", "__got")
                 or sec("__DATA_CONST", "__la_symbol_ptr"))

    used = {}          # section id -> {index: symbol}
    def claim(s, index, sym):
        used.setdefault(id(s), {})[index] = sym

    def slot_addr(s, index):
        return s["addr"] + index * 8

    def bind_fixup(s, index, sym, auth):
        # An auth GOT slot is reached by `braa x16, x17`: IA key with the slot's
        # own address as the modifier and no extra discriminator, which is
        # key=IA, addrDiv=1, diversity=0 -- the same shape the cache's patch
        # table reports for these slots, and what a real arm64e dylib emits.
        return Fixup(slot_addr(s, index) - base, s["off"] + index * 8, "bind",
                     auth=auth, key=0, addr_div=auth, diversity=0,
                     symbol=sym, where=f"{s['sect']}[{index}]")

    # -- 1. stubs -> this image's own GOT --------------------------------
    stub_got = facts.get("stub_got", {})
    n_stub = 0
    for s in img.sections:
        if s["sect"] not in ("__auth_stubs", "__stubs"):
            continue
        auth = s["sect"] == "__auth_stubs"
        target_sec = auth_got if auth else plain_got
        if target_sec is None:
            warn.append(f"{s['sect']} has no GOT section to rebind into")
            continue
        stride = s["r2"] or 16
        count = s["size"] // stride
        capacity = target_sec["size"] // 8
        if count > capacity:
            warn.append(f"{s['sect']} has {count} stubs but "
                        f"{target_sec['sect']} only {capacity} slots")
        for i in range(min(count, capacity)):
            sym = stub_got.get(f"{s['sect']}:{i}")
            if sym is None:
                warn.append(f"{s['sect']}[{i}] has no symbol in the facts")
                continue
            # The cache names the implementation; bind the spelling this image
            # imports, or the slot ends up NULL.
            sym = resolve_alias(sym, undef)
            pc, fo = s["addr"] + i * stride, s["off"] + i * stride
            newp = repoint_adrp_add(u32(img.data, fo), u32(img.data, fo + 4),
                                    pc, slot_addr(target_sec, i))
            if newp is None:
                warn.append(f"{s['sect']}[{i}] is not the adrp/add form")
                continue
            patches += [(fo, newp[0]), (fo + 4, newp[1])]
            claim(target_sec, i, sym)
            fixups.append(bind_fixup(target_sec, i, sym, auth))
            n_stub += 1

    # -- 2. GOT references the code makes directly ----------------------
    # Two forms, and one of them needs an authenticated slot: the cache builder
    # sometimes inlines a stub into __text (adrp/add/ldr/blraa) instead of
    # emitting an __auth_stubs entry for it, and a blraa through an unbound slot
    # is an EXC_ARM_PAC_FAIL a long way from its cause.
    #
    # We choose which of our own slots to use, so allocate from what the stubs
    # did not take. __auth_got and __got come out exactly full, but __auth_ptr
    # is dead space in the same way -- zeroed in the cache, named by neither the
    # indirect symbol table nor the slide info -- so it is the pool for the
    # authenticated overflow.
    #
    # __auth_ptr holds 1 to 10 slots, and the plain side has no equivalent
    # section at all, so both pools can run dry: TrustEvaluationAgent has three
    # data symbols and a __got of exactly three slots, and its fourth
    # (_voucher_mach_msg_set) had nowhere to go. So each pool also gets the
    # segment's spare tail -- see tail() below.
    reserved = {(r["seg"], r["sect"], r["off"])
                for r in facts.get("data_pointers", [])}
    # The same records by absolute address, for the tail, which no (seg, sect)
    # names. A slide-info record always names a real section, so this should
    # never match -- it is here so that "should never" is enforced rather than
    # assumed.
    reserved_addr = set()
    for r in facts.get("data_pointers", []):
        rs = sec(r["seg"], r["sect"])
        if rs is not None:
            reserved_addr.add(rs["addr"] + r["off"])

    def tail(segname):
        """The 8-aligned spare space between a segment's last section and its end.

        A relaid-out image page-aligns each segment and rounds its filesize up to
        a page, so a data segment ends in padding that no section claims. Nothing
        in the image can reach it -- a section is the only thing that gives an
        address a meaning here -- and it is mapped and writable-at-load like the
        rest of the segment, so it is somewhere to put a GOT slot when the real
        GOT sections are full. Crucially it needs nothing to move: every existing
        section keeps its address, which is the constraint the whole lift is
        built around.
        """
        for name, addr, vmsize, fileoff, filesize in img.segments:
            if name != segname:
                continue
            ends = [s["addr"] + s["size"] for s in img.sections
                    if s["seg"] == segname]
            if not ends:
                return None
            start = (max(ends) + 7) & ~7
            # Only as far as the file actually goes: a slot past filesize has no
            # bytes to patch and would not be mapped from the file.
            end = min(addr + vmsize, addr + filesize)
            if end <= start:
                return None
            return dict(seg=segname, sect="__tail", addr=start,
                        size=end - start, off=fileoff + (start - addr),
                        flags=0, r1=0, r2=0)
        return None

    def pool(sections, auth):
        out = []
        for s in sections:
            if s is None:
                continue
            taken = used.get(id(s), {})
            for i in range(s["size"] // 8):
                if i in taken:
                    continue
                if (s["seg"], s["sect"], i * 8) in reserved:
                    continue
                if s["addr"] + i * 8 in reserved_addr:
                    continue
                out.append((s, i))
        return out

    auth_pool = pool([auth_got, sec("__AUTH_CONST", "__auth_ptr"),
                      tail("__AUTH_CONST")], True)
    plain_pool = pool([plain_got, tail("__DATA_CONST") or tail("__DATA")],
                      False)

    code_got = {}
    for k, v in facts.get("code_got", {}).items():
        code_got[int(k, 16)] = (v if isinstance(v, dict)
                                else dict(symbol=v, auth=False))

    # An ADRP immediate is fixed, so a target address decoded from the converted
    # image is displaced by however far the CODE moved -- which is not the same
    # as how far the image base moved once --reserve-header has grown __TEXT
    # downward. Derive it from __text itself.
    text = sec("__TEXT", "__text")
    orig_text = facts.get("sections", {}).get("__TEXT.__text")
    shift = facts["shift"]
    code_shift = (text["addr"] - int(orig_text, 16)
                  if text is not None and orig_text else shift)

    assigned = {}          # (symbol, auth) -> (section, index)
    n_code = 0
    for site in scan_got_sites(img):
        target = site["target"]
        if img.owns(target) or target % 8:
            continue
        info = code_got.get(target) or code_got.get(target - code_shift)
        if info is None:
            continue
        sym = resolve_alias(info["symbol"], undef)
        auth = bool(info.get("auth")) or site["auth"]
        key = (sym, auth)
        if key not in assigned:
            p = auth_pool if auth else plain_pool
            if not p:
                warn.append(f"no free {'auth ' if auth else ''}GOT slot for "
                            f"{sym}; {site['first_pc']:#x} left pointing at "
                            f"the cache")
                continue
            s, i = p.pop(0)
            assigned[key] = (s, i)
            claim(s, i, sym)
            fixups.append(bind_fixup(s, i, sym, auth))
        s, i = assigned[key]
        addr = slot_addr(s, i)
        if site["kind"] == "add":
            newp = repoint_adrp_add(u32(img.data, site["first"]),
                                    u32(img.data, site["second"]),
                                    site["first_pc"], addr)
        else:
            newp = repoint_adrp_ldr(u32(img.data, site["first"]),
                                    u32(img.data, site["second"]),
                                    site["first_pc"], addr)
        if newp is None:
            warn.append(f"{site['first_pc']:#x} not repointable")
            continue
        patches += [(site["first"], newp[0]), (site["second"], newp[1])]
        n_code += 1

    # -- 3. any GOT slot no stub or code load claimed --------------------
    # Left NULL rather than carrying the cache's dead zeroes into a chain that
    # does not mention them. Nothing reaches them, so this is tidiness.
    for s in (auth_got, plain_got, sec("__AUTH_CONST", "__auth_ptr")):
        if s is None:
            continue
        taken = used.get(id(s), {})
        for i in range(s["size"] // 8):
            if i in taken:
                continue
            if (s["seg"], s["sect"], i * 8) in reserved:
                continue
            to_zero.append(s["off"] + i * 8)

    # -- 4. the image's own data pointers, from the cache slide info -----
    seen = {f.vmoff for f in fixups}
    for r in facts.get("data_pointers", []):
        s = sec(r["seg"], r["sect"])
        if s is None:
            warn.append(f"facts name {r['seg']}.{r['sect']}, absent here")
            continue
        addr = s["addr"] + r["off"]
        fo = s["off"] + r["off"]
        if addr - base in seen:
            # A GOT slot we already bound. Two fixups at one address would
            # chain to themselves and silently truncate the chain.
            continue
        seen.add(addr - base)
        auth = r["auth"]
        key = KEYS.get(r.get("key") or "IA", 0)
        if r["kind"] == "bind":
            if not r.get("symbol"):
                # Nothing in the cache names the target, so there is no bind to
                # emit. Leave the slot NULL rather than leaving the cache's raw
                # chained value in it: a null dereference is a legible crash,
                # an unrebased pointer is not.
                warn.append(f"{r['seg']}.{r['sect']}+0x{r['off']:x} binds an "
                            f"unnamed target ({r.get('target','?')}); left "
                            f"NULL -- this library is INCOMPLETE")
                to_zero.append(fo)
                continue
            sym = resolve_alias(r["symbol"], undef)
            fixups.append(Fixup(addr - base, fo, "bind", auth=auth, key=key,
                                addr_div=r["addr_div"],
                                diversity=r["diversity"], symbol=sym,
                                where=f"{r['sect']}+0x{r['off']:x}"))
        else:
            ts = sec(r["tseg"], r["tsect"])
            if ts is None:
                warn.append(f"rebase target {r['tseg']}.{r['tsect']} absent")
                continue
            fixups.append(Fixup(addr - base, fo, "rebase", auth=auth, key=key,
                                addr_div=r["addr_div"],
                                diversity=r["diversity"],
                                target=ts["addr"] + r["toff"] - base,
                                where=f"{r['sect']}+0x{r['off']:x}"))

    if verbose:
        print(f"  repointed {n_stub} stubs and {n_code} code GOT loads "
              f"(code shift 0x{code_shift:x}, base shift 0x{shift:x})")
    # The indirect symbol table is a free cross-check where it survived.
    zeroed = img.nind and all(img.indirect(i) == 0 for i in range(img.nind))
    if zeroed:
        if verbose:
            print(f"  the indirect symbol table is all zeroes "
                  f"({img.nind} entries) -- naming came from the cache alone")
    elif verbose:
        # Do not "correct" the cache from this table. In libpcre it agrees; in
        # libcurl it is in a completely different order (slot 0 reads _SSLClose
        # where the stub demonstrably points at _ASN1_STRING_get0_data's slot,
        # confirmed by two independent cache routes). An extraction's dysymtab
        # is regenerated, and its ordering does not have to match the GOT.
        bad = 0
        for s in (auth_got, plain_got):
            if s is None or not s["r1"]:
                continue
            for i, sym in used.get(id(s), {}).items():
                nm = img.indirect_name(s["r1"] + i)
                if nm and nm != sym:
                    bad += 1
        print(f"  indirect symbol table survives; it names {bad} slot(s) "
              f"differently (ignored -- the cache is authoritative)")
    return fixups, patches, warn, shift, to_zero


def repoint_adrp_add(i0, i1, pc, target):
    page, rd = adrp(i0, pc)
    imm, rn, rd2 = add_imm64(i1)
    if page is None or imm is None or rn != rd:
        return None
    new0 = set_adrp(i0, pc, target)
    if new0 is None:
        return None
    lo = target & 0xFFF
    new1 = (i1 & ~(0xFFF << 10)) | (lo << 10)
    new1 &= ~(3 << 22)          # no LSL #12
    return new0, new1


def repoint_adrp_ldr(i0, i1, pc, target):
    if target & 7:
        return None
    new0 = set_adrp(i0, pc, target)
    if new0 is None:
        return None
    new1 = (i1 & ~(0xFFF << 10)) | (((target & 0xFFF) // 8) << 10)
    return new0, new1


def set_adrp(insn, pc, target):
    delta = (target & ~0xFFF) - (pc & ~0xFFF)
    if delta % 0x1000:
        return None
    imm = delta >> 12
    if not (-(1 << 20) <= imm < (1 << 20)):
        return None
    imm &= 0x1FFFFF
    return ((insn & 0x9F00001F) | ((imm & 3) << 29) | ((imm >> 2) << 5))


BIND_FLAT_LOOKUP = 0xFE


def build_blob(img: Image, fixups: list, ordinals: dict, sym_pool: bytes,
               ordered_syms: list, lib_ord: dict,
               fallback_ord: int | None) -> bytes:
    """dyld_chained_fixups_header + starts_in_image + imports + symbols."""
    base = img.segments[0][1]
    segs = [s for s in img.segments]

    # chain the fixups, per segment, per page
    per_seg = {}
    for f in fixups:
        for i, (name, vmaddr, vmsize, fo, fs) in enumerate(segs):
            if vmaddr <= base + f.vmoff < vmaddr + vmsize:
                per_seg.setdefault(i, []).append(f)
                break
        else:
            raise SystemExit(f"fixup at 0x{f.vmoff:x} is in no segment")

    seg_blobs = {}
    for i, flist in per_seg.items():
        name, vmaddr, vmsize, fo, fs = segs[i]
        seg_off = vmaddr - base
        npages = (vmsize + PAGE - 1) // PAGE
        pages = {}
        for f in flist:
            addr = base + f.vmoff
            pi = (addr - vmaddr) // PAGE
            pages.setdefault(pi, []).append(f)
        starts = [0xFFFF] * npages
        for pi, fl in pages.items():
            fl.sort(key=lambda x: x.vmoff)
            starts[pi] = (base + fl[0].vmoff) - (vmaddr + pi * PAGE)
            for k, f in enumerate(fl):
                if k + 1 < len(fl):
                    nxt = (fl[k + 1].vmoff - f.vmoff) // 8
                    if nxt > 0x7FF:
                        raise SystemExit("gap too large for an 11-bit next")
                else:
                    nxt = 0
                f.encoded = f.encode(nxt, ordinals)
        size = 22 + 2 * npages
        size = (size + 3) & ~3
        b = struct.pack("<IHHQIH", size, PAGE,
                        DYLD_CHAINED_PTR_ARM64E_USERLAND24, seg_off, 0, npages)
        b += struct.pack("<%dH" % npages, *starts)
        b += b"\0" * (size - len(b))
        seg_blobs[i] = b

    nseg = len(segs)
    starts_hdr = struct.pack("<I", nseg)
    off = 4 + 4 * nseg
    seg_offsets = []
    body = b""
    for i in range(nseg):
        if i in seg_blobs:
            seg_offsets.append(off + len(body))
            body += seg_blobs[i]
        else:
            seg_offsets.append(0)
    starts = starts_hdr + struct.pack("<%dI" % nseg, *seg_offsets) + body
    starts += b"\0" * (-len(starts) % 4)

    imports = b""
    weak_syms = weak_ref_symbols(img)
    for sym in ordered_syms:
        noff = sym_pool.index(sym.encode() + b"\0")
        # A symbol the image's own symbol table does not list is one the
        # cache resolved for it -- typically a C++ ABI vtable slot pulled in
        # from another cache image. We have no ordinal for it, so ask for a
        # flat lookup and mark it weak: if nothing provides it the slot binds
        # to NULL, which is survivable, where a hard bind fails the load.
        if sym in lib_ord:
            # Carry N_WEAK_REF across. Dropping it makes every weak import a
            # hard one, and a weak-linked library that is absent on the target
            # then fails the load instead of binding NULL -- see
            # weak_ref_symbols().
            lib, weak = lib_ord[sym], (1 if sym in weak_syms else 0)
        elif fallback_ord is not None:
            # libSystem re-exports the libsystem_* family, and two-level
            # namespace resolution follows re-exports. Still weak, since we are
            # guessing the provider.
            lib, weak = fallback_ord, 1
        else:
            lib, weak = BIND_FLAT_LOOKUP, 1
        imports += struct.pack("<I", (lib & 0xFF) | (weak << 8) | (noff << 9))
    imports += b"\0" * (-len(imports) % 4)

    hdr_size = 28
    starts_off = hdr_size
    imports_off = starts_off + len(starts)
    symbols_off = imports_off + len(imports)
    hdr = struct.pack("<7I", 0, starts_off, imports_off, symbols_off,
                      len(ordered_syms), DYLD_CHAINED_IMPORT, 0)
    blob = hdr + starts + imports + sym_pool
    blob += b"\0" * (-len(blob) % 8)
    return blob


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("image")
    ap.add_argument("--facts", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    data = bytearray(open(args.image, "rb").read())
    img = Image(bytes(data))
    facts = json.load(open(args.facts))
    # The conversion shifts every address by a constant; the facts were taken
    # from the unconverted extraction.
    facts["shift"] = img.segments[0][1] - int(facts["image_base"], 16)

    fixups, patches, warn, shift, to_zero = collect(img, facts, args.verbose)
    print(f"{args.image}: {len(fixups)} fixups "
          f"({sum(1 for f in fixups if f.kind == 'bind')} binds, "
          f"{sum(1 for f in fixups if f.kind == 'rebase')} rebases), "
          f"{len(patches)//2} instructions repointed, shift=0x{shift:x}")
    for w in warn:
        print(f"  warning: {w}")

    # symbol pool + ordinals
    syms = sorted({f.symbol for f in fixups if f.kind == "bind"})
    pool = b"\0"
    for s in syms:
        pool += s.encode() + b"\0"
    pool += b"\0" * (-len(pool) % 4)
    ordinals = {s: i for i, s in enumerate(syms)}

    lib_ord = import_ordinals(img)
    unknown = [s for s in syms if s not in lib_ord]
    if unknown:
        via = ("libSystem" if libsystem_ordinal(img) is not None
               else "flat lookup")
        print(f"  {len(unknown)} bind(s) are not in this image's symbol "
              f"table; weak, via {via}: {', '.join(unknown[:4])}"
              + (" ..." if len(unknown) > 4 else ""))
    blob = build_blob(img, fixups, ordinals, pool, syms, lib_ord,
                      libsystem_ordinal(img))

    # Write instruction patches and chain values. The zeroes go first: a slot
    # nothing claimed can still be named by the slide info, and in that case the
    # fixup wins.
    for fo, insn in patches:
        struct.pack_into("<I", data, fo, insn & 0xFFFFFFFF)
    for fo in to_zero:
        struct.pack_into("<Q", data, fo, 0)
    for f in fixups:
        struct.pack_into("<Q", data, f.fileoff, f.encoded)

    # restore the section type the cache builder stripped
    off = 32
    for _ in range(img.ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            nsects = u32(data, off + 64)
            so = off + 72
            for _ in range(nsects):
                nm = bytes(data[so:so + 16]).rstrip(b"\0").decode()
                if nm in ("__got", "__auth_got", "__auth_ptr"):
                    fl = u32(data, so + 64)
                    struct.pack_into("<I", data, so + 64,
                                     (fl & ~0xFF) | S_NON_LAZY_SYMBOL_POINTERS)
                so += 80
        off += cmdsize

    # append the blob to __LINKEDIT and add the load command
    le_i = next(i for i, s in enumerate(img.segments) if s[0] == "__LINKEDIT")
    le = img.segments[le_i]
    blob_off = (le[3] + le[4] + 7) & ~7
    if blob_off > len(data):
        data += b"\0" * (blob_off - len(data))
    data[blob_off:blob_off + len(blob)] = blob
    del data[blob_off + len(blob):]

    new_fs = blob_off + len(blob) - le[3]
    new_vs = (new_fs + PAGE - 1) & ~(PAGE - 1)

    off = 32
    for _ in range(img.ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64 and \
                bytes(data[off + 8:off + 24]).rstrip(b"\0") == b"__LINKEDIT":
            struct.pack_into("<QQ", data, off + 32, new_vs, le[3])  # vmsize, fileoff
            struct.pack_into("<Q", data, off + 48, new_fs)          # filesize
        off += cmdsize

    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    # Only __TEXT matters: the load commands grow into the gap before its
    # first section. Other segments can carry zerofill sections whose file
    # offset is 0, which would make a global minimum meaningless.
    first = min(s["off"] for s in img.sections
                if s["seg"] == "__TEXT" and s["off"])
    if 32 + sizeofcmds + 16 > first:
        raise SystemExit("no header room for LC_DYLD_CHAINED_FIXUPS")
    lc = struct.pack("<IIII", LC_DYLD_CHAINED_FIXUPS, 16, blob_off, len(blob))
    data[32 + sizeofcmds:32 + sizeofcmds] = lc
    del data[first:first + 16]
    struct.pack_into("<II", data, 16, ncmds + 1, sizeofcmds + 16)

    open(args.output, "wb").write(bytes(data))
    print(f"  wrote {args.output} ({len(data)} bytes), "
          f"chained fixups blob {len(blob)} bytes at 0x{blob_off:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
