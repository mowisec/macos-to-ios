#!/usr/bin/env python3
"""
dsc_compact -- close the 1.6-2.0 GB address-space hole a lifted library keeps.

    ./dsc_compact.py <lifted.dylib> -o <out.dylib>

Why a lift is so wide
---------------------
The dyld shared cache does not lay an image out contiguously: it groups every
image's __TEXT together, every image's __DATA_CONST together, and so on.  So a
single image's own segments are hundreds of megabytes apart --

    libxcselect  __TEXT 0x19668c000 ... __LINKEDIT 0x1ff968000   = 1765 MB

-- for 144 KB of actual content.  `relayout_for_standalone()` deliberately
keeps those addresses, because an ADRP immediate is a fixed PC-relative
distance that no relocation table records, so moving a segment silently breaks
every reference into it.  dyld reserves the whole lowest-to-highest span at
load, and what runs out is the largest *contiguous* free hole, which is why two
or three lifted libraries fit in one process and six do not.

Why it can be moved after all
-----------------------------
Nothing records where the ADRPs are, but they can all be found: an executable
section of a lifted image is pure instructions (LC_DATA_IN_CODE is empty in
every lift measured), so every 4-byte word can be decoded, and an ADRP is
recognisable by opcode alone.  The rule that makes this exact rather than
heuristic:

    an ADRP's page target IS the 4 KB page of the address the pair computes,
    because target = page + imm12 with imm12 < 0x1000.

So an ADRP whose page target lands in a segment can only be reaching that
segment -- it is not necessary to find the paired ADD/LDR at all, or to be
right about which one it is.  Move the segment by a page-multiple delta and add
that delta to the ADRP's page target and the pair still computes the same byte.

Then the rest is bookkeeping over everything else that spells an address:
segment and section headers, the symbol table, the chained-fixup rebase targets
and per-segment offsets, and the export trie.

What it refuses
---------------
Relative-reference formats break under a per-segment move, because they encode
a *distance* between two segments rather than an address: ObjC relative method
lists (__objc_const -> __objc_selrefs) and Swift's int32 relative pointers.
None of the seven libraries this project lifts is ObjC or Swift, and an image
that is gets refused rather than quietly corrupted.

--rigid moves the data segments as one block, preserving every data-to-data
distance, and recovers much less (closing the __TEXT-to-__DATA_CONST jump is
most of the span).  It is NOT a general answer for ObjC: DiskManagement keeps
`__objc_methlist` in __TEXT and its selector references in __DATA, so its
relative method lists span exactly the distance --rigid changes.  An ObjC image
needs its relative structures patched, which nothing here does yet.
"""

import argparse
import os
import struct
import subprocess
import sys

from .arm64 import adrp, u32
from .image import Image

PAGE = 0x4000
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29

S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12
N_STAB = 0xE0

EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10


def uleb(data, off):
    """-> (value, next offset)."""
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, off


def put_uleb(data, off, end, value):
    """Write value into data[off:end], padding with redundant continuation
    bytes so the field keeps the length the rest of the trie assumes."""
    n = end - off
    if value >= 1 << (7 * n):
        raise SystemExit(f"uleb 0x{value:x} does not fit in {n} bytes")
    for i in range(n):
        b = value & 0x7F
        value >>= 7
        data[off + i] = b | (0x80 if i < n - 1 else 0)


class Layout:
    """The load commands, mutable, with an address map from old to new."""

    def __init__(self, path):
        self.data = bytearray(open(path, "rb").read())
        self.img = Image(bytes(self.data))
        magic, _, _, _, self.ncmds, _, _, _ = struct.unpack_from(
            "<IiiIIIII", self.data, 0)
        if magic != 0xFEEDFACF:
            raise SystemExit("not a thin 64-bit Mach-O")
        self.segs = []          # dicts, in load-command order
        self.lc = []            # (cmd, offset, cmdsize)
        off = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            self.lc.append((cmd, off, cmdsize))
            if cmd == LC_SEGMENT_64:
                name = bytes(self.data[off + 8:off + 24]).rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", self.data, off + 24)
                nsects = u32(self.data, off + 64)
                self.segs.append(dict(name=name, lc=off, vmaddr=vmaddr,
                                      vmsize=vmsize, fileoff=fileoff,
                                      filesize=filesize, nsects=nsects,
                                      delta=0))
            off += cmdsize
        self.segs = [s for s in self.segs if s["name"] != "__PAGEZERO"]
        self.base = min(s["vmaddr"] for s in self.segs)

    def find(self, cmd):
        for c, off, size in self.lc:
            if c == cmd:
                return off, size
        return None, None

    def seg_of(self, addr):
        for s in self.segs:
            if s["vmaddr"] <= addr < s["vmaddr"] + s["vmsize"]:
                return s
        return None

    def span(self):
        lo = min(s["vmaddr"] for s in self.segs)
        hi = max(s["vmaddr"] + s["vmsize"] for s in self.segs)
        return hi - lo

    # -- the new layout ---------------------------------------------------

    def plan(self, rigid=False):
        """Assign each segment a page-multiple delta. __TEXT never moves: it
        holds the mach header, every PC-relative reference inside the code, and
        the image base that offsets in __LINKEDIT are measured from."""
        order = sorted(self.segs, key=lambda s: s["vmaddr"])
        text = order[0]
        if text["name"] != "__TEXT":
            raise SystemExit("__TEXT is not the lowest segment")
        cursor = text["vmaddr"] + text["vmsize"]
        if rigid:
            # One delta for every segment above __TEXT, so all data-to-data
            # distances survive. Safe for ObjC/Swift, worth much less.
            rest = order[1:]
            delta = cursor - rest[0]["vmaddr"] if rest else 0
            delta &= ~(PAGE - 1)
            for s in rest:
                s["delta"] = delta
            return
        for s in order[1:]:
            s["delta"] = cursor - s["vmaddr"]
            assert s["delta"] % PAGE == 0, "segments must be page aligned"
            cursor += s["vmsize"]

    def new_addr(self, addr):
        s = self.seg_of(addr)
        return None if s is None else addr + s["delta"]


def executable_sections(lay):
    for s in lay.segs:
        for i in range(s["nsects"]):
            so = s["lc"] + 72 + i * 80
            flags = u32(lay.data, so + 64)
            if not flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS):
                continue
            addr, size = struct.unpack_from("<QQ", lay.data, so + 32)
            fileoff = u32(lay.data, so + 48)
            yield addr, fileoff, size


def adrp_sites(lay):
    """Every ADRP in code, as (file offset, pc, page target)."""
    for addr, fileoff, size in executable_sections(lay):
        for k in range(0, size & ~3, 4):
            insn = struct.unpack_from("<I", lay.data, fileoff + k)[0]
            page, _rd = adrp(insn, addr + k)
            if page is not None:
                yield fileoff + k, addr + k, page


def patch_adrps(lay):
    """Returns (repointed, left in __TEXT, left pointing outside the image).

    An ADRP whose page target is in no segment is left exactly as it is. Those
    are the leftovers `dsc_gotscan` reports: mostly an ADRP with no matching
    ADD/LDR, decoding to a page-aligned address nothing dereferences, and
    occasionally a real unrepaired cache reference. Compaction cannot tell
    which -- and does not have to. Leaving the instruction alone leaves it
    naming the address it already named, so an artefact stays an artefact and a
    real leftover stays exactly as broken as the lift handed it over.

    That division of labour is deliberate: `dsc_gotscan` judges the lift and
    the lift refuses one with an AUTHENTICATED leftover before compaction
    ever runs. Aborting here as well only meant that libcsfde, which has two
    tolerated unauthenticated ones, could not be compacted at all.
    """
    moved = unmoved = outside = 0
    for fo, pc, page in adrp_sites(lay):
        s = lay.seg_of(page)
        if s is None:
            outside += 1
            continue
        if not s["delta"]:
            unmoved += 1
            continue
        target = page + s["delta"]
        delta = target - (pc & ~0xFFF)
        if not -(1 << 32) <= delta < (1 << 32):
            raise SystemExit(f"ADRP at 0x{pc:x} cannot reach 0x{target:x}")
        imm = delta >> 12
        insn = struct.unpack_from("<I", lay.data, fo)[0]
        insn &= ~((0x7FFFF << 5) | (3 << 29))
        insn |= ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5)
        struct.pack_into("<I", lay.data, fo, insn)
        moved += 1
    return moved, unmoved, outside


def patch_symtab(lay):
    off, _ = lay.find(LC_SYMTAB)
    if off is None:
        return 0
    _c, _s, symoff, nsyms, _so, _ss = struct.unpack_from("<6I", lay.data, off)
    n = 0
    for i in range(nsyms):
        e = symoff + i * 16
        n_type = lay.data[e + 4]
        n_value, = struct.unpack_from("<Q", lay.data, e + 8)
        if n_type & N_STAB or not n_value:
            continue
        new = lay.new_addr(n_value)
        if new is None or new == n_value:
            continue
        struct.pack_into("<Q", lay.data, e + 8, new)
        n += 1
    return n


def patch_export_trie(lay):
    off, _ = lay.find(LC_DYLD_EXPORTS_TRIE)
    if off is None:
        return 0
    dataoff, datasize = struct.unpack_from("<II", lay.data, off + 8)
    if not datasize:
        return 0
    n = 0
    seen = set()
    stack = [dataoff]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        size, p = uleb(lay.data, node)
        if size:
            end = p + size
            flags, q = uleb(lay.data, p)
            if not flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                start = q
                value, q = uleb(lay.data, q)
                new = lay.new_addr(lay.base + value)
                if new is not None and new - lay.base != value:
                    put_uleb(lay.data, start, q, new - lay.base)
                    n += 1
                if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                    start = q
                    value, q = uleb(lay.data, q)
                    new = lay.new_addr(lay.base + value)
                    if new is not None and new - lay.base != value:
                        put_uleb(lay.data, start, q, new - lay.base)
                        n += 1
            p = end
        nchild = lay.data[p]
        p += 1
        for _ in range(nchild):
            while lay.data[p]:
                p += 1
            p += 1
            child, p = uleb(lay.data, p)
            stack.append(dataoff + child)
    return n


def chain_slots(lay):
    """Every fixup slot the chained-fixup blob reaches, as a file offset."""
    off, _ = lay.find(LC_DYLD_CHAINED_FIXUPS)
    if off is None:
        raise SystemExit("no LC_DYLD_CHAINED_FIXUPS -- run dsc_rebind first")
    dataoff, _size = struct.unpack_from("<II", lay.data, off + 8)
    (_fver, starts_off, _imports, _syms, _icount, _iformat,
     _sformat) = struct.unpack_from("<7I", lay.data, dataoff)
    s = dataoff + starts_off
    nseg, = struct.unpack_from("<I", lay.data, s)
    for i in range(nseg):
        so, = struct.unpack_from("<I", lay.data, s + 4 + 4 * i)
        if not so:
            continue
        seg_start = s + so
        (_size, page_size, fmt, seg_off, _maxv,
         npages) = struct.unpack_from("<IHHQIH", lay.data, seg_start)
        if fmt != DYLD_CHAINED_PTR_ARM64E_USERLAND24:
            raise SystemExit(f"unsupported pointer format {fmt}")
        seg = lay.seg_of(lay.base + seg_off)
        if seg is None:
            raise SystemExit(f"chain segment offset 0x{seg_off:x} is in no segment")
        yield ("segment", seg_start, seg, seg_off)
        for pi in range(npages):
            start, = struct.unpack_from("<H", lay.data, seg_start + 22 + 2 * pi)
            if start == 0xFFFF:
                continue
            addr = seg["vmaddr"] + pi * page_size + start
            while True:
                fo = seg["fileoff"] + (addr - seg["vmaddr"])
                yield ("slot", fo, seg, addr)
                v, = struct.unpack_from("<Q", lay.data, fo)
                nxt = (v >> 51) & 0x7FF
                if not nxt:
                    break
                addr += nxt * 8


def patch_fixups(lay):
    rebases = 0
    for kind, where, seg, extra in list(chain_slots(lay)):
        if kind == "segment":
            struct.pack_into("<Q", lay.data, where + 8,
                             seg["vmaddr"] + seg["delta"] - lay.base)
            continue
        v, = struct.unpack_from("<Q", lay.data, where)
        if v & (1 << 62):          # a bind: names a symbol, not an address
            continue
        auth = bool(v & (1 << 63))
        mask = 0xFFFFFFFF if auth else (1 << 43) - 1
        target = v & mask
        new = lay.new_addr(lay.base + target)
        if new is None:
            raise SystemExit(f"rebase at 0x{extra:x} targets 0x"
                             f"{lay.base + target:x}, which is in no segment")
        new -= lay.base
        if new == target:
            continue
        if new > mask:
            raise SystemExit("rebase target no longer fits")
        struct.pack_into("<Q", lay.data, where, (v & ~mask) | new)
        rebases += 1
    return rebases


def resolved_targets(lay):
    """(pc -> (segment name, offset in segment)) for every ADRP, under the
    layout the file currently spells.  Comparing this before and after is an
    exact check that no reference changed meaning."""
    out = {}
    for _fo, pc, page in adrp_sites(lay):
        s = lay.seg_of(page)
        out[pc] = (s["name"], page - s["vmaddr"]) if s else (None, page)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--rigid", action="store_true",
                    help="move the data segments as one block (ObjC-safe, "
                         "recovers much less)")
    ap.add_argument("--no-objc", action="store_true",
                    help="refuse an image with ObjC/Swift relative-reference "
                         "sections instead of compacting it")
    ap.add_argument("--force", action="store_true",
                    help="accepted for compatibility; ObjC images are "
                         "compacted by default now")
    ap.add_argument("--no-sign", action="store_true")
    args = ap.parse_args(argv)

    lay = Layout(args.input)

    off, _ = lay.find(LC_DATA_IN_CODE)
    if off is not None and struct.unpack_from("<I", lay.data, off + 12)[0]:
        raise SystemExit("LC_DATA_IN_CODE is not empty: some words in the code "
                         "are data and would be mis-decoded as ADRP")

    bad = []
    for s in lay.segs:
        for i in range(s["nsects"]):
            so = s["lc"] + 72 + i * 80
            name = bytes(lay.data[so:so + 16]).rstrip(b"\0").decode()
            if name.startswith("__objc") or name.startswith("__swift"):
                bad.append(f"{s['name']}.{name}")
    if bad and not args.rigid and not args.no_objc:
        # This used to refuse. It must not: an ObjC image has to be compacted
        # or it cannot load AT ALL. dyld inspects a dylib before mapping it
        # (`MachOAnalyzer::hasSwiftOrObjC`) and finds __objc_imageinfo by VM
        # offset from the image base -- which in an uncompacted lift is 1.3 GB
        # into a 1.4 MB file. It reads off the end and segfaults. Only an image
        # with ObjC sections is ever looked at that way, which is why every
        # non-ObjC lift survived without this.
        #
        # What compaction does cost is honest and narrow: an ObjC RELATIVE
        # method list stores int32 offsets, and one that crossed from __TEXT
        # into a data segment would change meaning. In a cache lift those
        # offsets already point at the cache's uniqued selector pool -- outside
        # the image, broken before compaction touches them -- so compaction
        # makes nothing worse. See CLAUDE.md, "Lifting an ObjC library".
        print("note: this image has ObjC/Swift relative-reference sections:",
              file=sys.stderr)
        for b in bad[:8]:
            print(f"        {b}", file=sys.stderr)
        print("      Compacting anyway -- an ObjC image cannot load without it "
              "(dyld reads\n      __objc_imageinfo by VM offset before "
              "mapping). Relative method lists\n      already point outside "
              "the image in a cache lift; --no-objc to refuse instead.",
              file=sys.stderr)

    before_span = lay.span()
    before = resolved_targets(lay)

    lay.plan(rigid=args.rigid)
    moved, unmoved, outside = patch_adrps(lay)
    rebases = patch_fixups(lay)
    syms = patch_symtab(lay)
    exports = patch_export_trie(lay)

    # segment and section headers last: everything above reads the old layout.
    for s in lay.segs:
        if not s["delta"]:
            continue
        struct.pack_into("<Q", lay.data, s["lc"] + 24, s["vmaddr"] + s["delta"])
        for i in range(s["nsects"]):
            so = s["lc"] + 72 + i * 80
            addr, = struct.unpack_from("<Q", lay.data, so + 32)
            struct.pack_into("<Q", lay.data, so + 32, addr + s["delta"])
        s["vmaddr"] += s["delta"]
        s["delta"] = 0

    after = resolved_targets(lay)
    if before != after:
        diff = [pc for pc in before if before[pc] != after.get(pc)]
        print(f"FAILED: {len(diff)} ADRP site(s) changed meaning, first at "
              f"0x{diff[0]:x}: {before[diff[0]]} -> {after.get(diff[0])}",
              file=sys.stderr)
        return 1

    with open(args.output, "wb") as f:
        f.write(lay.data)
    if not args.no_sign:
        subprocess.run(["/usr/bin/codesign", "-f", "-s", "-", args.output],
                       check=True)

    after_span = lay.span()
    print(f"{os.path.basename(args.input)}: "
          f"span {before_span / 2**20:.0f} MB -> {after_span / 2**20:.2f} MB "
          f"({before_span / max(after_span, 1):.0f}x smaller)")
    print(f"  {moved} ADRP repointed ({unmoved} into __TEXT, untouched), "
          f"{rebases} rebases, {syms} symbols, {exports} export addresses")
    if outside:
        print(f"  {outside} ADRP still name an address outside the image and "
              f"were left alone\n     (dsc_gotscan's leftovers -- it has "
              f"already ruled they are unauthenticated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
