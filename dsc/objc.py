#!/usr/bin/env python3
"""
dsc_objc -- repair the ObjC selector and protocol references in a lifted image.

    ./dsc_objc.py <lifted.dylib> -o <out.dylib>

The problem
-----------
`dsc_rebind` names every pointer slot from the cache, and where the cache's
answer is not a symbol this image imports it falls back to a weak flat bind so
that a name it cannot place binds NULL instead of failing the load.  CLAUDE.md
records that rule, and for a C library it is exactly right -- the only things it
catches are C++ ABI vtable slots nothing calls.

For an ObjC library it is catastrophic.  A slot in `__objc_selrefs` points into
the cache's uniqued **selector string** pool, and a slot in `__objc_protorefs`
at its canonical **protocol** object.  Asked what lives at those addresses, the
cache answers with the selector text and the protocol name -- so the rebinder
emits, in DiskManagement, 948 weak binds for symbols spelled `DADiskToUUID:`
and 2 for `SK_DM_Client2DaemonProtocol`, all against libSystem, all resolving to
NULL.  libobjc then dereferences one during `map_images` and the process dies
before `main()`.

The repair
----------
Neither reference needs the cache at all, because the image carries its own
copy of both things:

* the selector text is in this image's `__TEXT.__objc_methname`, so a selref
  becomes a **rebase** to the local string.  libobjc uniques it at load, which
  is exactly what it does for a normally linked dylib;
* the protocol object is in this image's own `__objc_protolist` whenever the
  image defines it, so a protoref becomes a rebase to that.

So each bogus bind is rewritten in place as a rebase.  Nothing moves: a chained
bind and a chained rebase are both one 64-bit word in the same chain, and the
`next` field is carried across untouched.

Run it AFTER dsc_rebind (it reads the chained fixups that step synthesises) and
BEFORE dsc_compact (which then remaps the rebase targets it creates).
"""

import argparse
import os
import struct
import subprocess
import sys

from .compact import Layout, chain_slots

LC_DYLD_CHAINED_FIXUPS = 0x80000034


def imports_table(lay):
    """-> [name] indexed by ordinal, for the chained imports table."""
    off, _ = lay.find(LC_DYLD_CHAINED_FIXUPS)
    if off is None:
        raise SystemExit("no LC_DYLD_CHAINED_FIXUPS -- run dsc_rebind first")
    dataoff, _size = struct.unpack_from("<II", lay.data, off + 8)
    (_v, _starts, imports_off, symbols_off, count, iformat,
     sformat) = struct.unpack_from("<7I", lay.data, dataoff)
    if sformat != 0:
        raise SystemExit("compressed symbol pool; refusing to guess")
    # 1 = IMPORT (4 bytes), 2 = ADDEND (8), 3 = ADDEND64 (16)
    stride, shift, mask = {1: (4, 9, (1 << 23) - 1),
                           2: (8, 9, (1 << 23) - 1),
                           3: (16, 32, (1 << 32) - 1)}[iformat]
    names = []
    for i in range(count):
        base = dataoff + imports_off + i * stride
        raw = struct.unpack_from("<Q" if iformat == 3 else "<I",
                                 lay.data, base)[0]
        noff = (raw >> shift) & mask
        s = dataoff + symbols_off + noff
        e = lay.data.index(b"\0", s)
        names.append(lay.data[s:e].decode("utf-8", "replace"))
    return names


def section(lay, seg, sect):
    for s in lay.segs:
        if s["name"] != seg:
            continue
        for i in range(s["nsects"]):
            so = s["lc"] + 72 + i * 80
            name = bytes(lay.data[so:so + 16]).rstrip(b"\0").decode()
            if name != sect:
                continue
            addr, size = struct.unpack_from("<QQ", lay.data, so + 32)
            off = struct.unpack_from("<I", lay.data, so + 48)[0]
            return dict(addr=addr, size=size, off=off, seg=seg, sect=sect)
    return None


def cstring_index(lay, seg, sect):
    """{string: address} for a NUL-separated literal section."""
    s = section(lay, seg, sect)
    out = {}
    if s is None:
        return out
    blob = bytes(lay.data[s["off"]:s["off"] + s["size"]])
    pos = 0
    while pos < len(blob):
        end = blob.find(b"\0", pos)
        if end < 0:
            break
        if end > pos:
            out.setdefault(blob[pos:end].decode("utf-8", "replace"),
                           s["addr"] + pos)
        pos = end + 1
    return out


def rebase_target(lay, word):
    """The vm address a chained rebase word names, or None if it is a bind.

    A word of zero is a NULL pointer, not a rebase to the image base. Reading it
    as one hands the caller the mach header dressed up as whatever struct it was
    walking -- which is how `entsize 64204` (the low half of 0xfeedfacf) came to
    be reported for DMManager, whose baseMethods really is NULL.
    """
    if word == 0:
        return None
    if word & (1 << 62):
        return None
    if word & (1 << 63):
        return lay.base + (word & 0xFFFFFFFF)
    return lay.base + (word & ((1 << 43) - 1))


def file_off(lay, addr):
    for s in lay.segs:
        if s["vmaddr"] <= addr < s["vmaddr"] + s["vmsize"]:
            return s["fileoff"] + (addr - s["vmaddr"])
    return None


def protocol_index(lay):
    """{protocol name: address} for the protocols this image defines."""
    s = section(lay, "__DATA_CONST", "__objc_protolist")
    out = {}
    if s is None:
        return out
    for i in range(s["size"] // 8):
        w = struct.unpack_from("<Q", lay.data, s["off"] + i * 8)[0]
        proto = rebase_target(lay, w)
        if proto is None:
            continue
        fo = file_off(lay, proto)
        if fo is None:
            continue
        # protocol_t: { isa, name, protocols, ... } -- name is the second word
        nw = struct.unpack_from("<Q", lay.data, fo + 8)[0]
        naddr = rebase_target(lay, nw)
        nfo = file_off(lay, naddr) if naddr else None
        if nfo is None:
            continue
        end = lay.data.index(b"\0", nfo)
        out[bytes(lay.data[nfo:end]).decode("utf-8", "replace")] = proto
    return out


def make_rebase(word, target_off):
    """Rewrite a chained BIND word as a rebase to target_off, keeping `next`.

    Both forms are one word in the same chain, so the 11-bit `next` field at
    bits 51..61 is carried across untouched -- that is what keeps the chain
    walkable. An authenticated bind becomes an authenticated rebase, which
    holds its key, diversity and addr-div in the same bits.
    """
    nxt = (word >> 51) & 0x7FF
    if word & (1 << 63):                      # authenticated
        keep = word & (0x7FFFF << 32)         # diversity, addrDiv, key
        if target_off > 0xFFFFFFFF:
            raise SystemExit("auth rebase target does not fit in 32 bits")
        return target_off | keep | (nxt << 51) | (1 << 63)
    if target_off > (1 << 43) - 1:
        raise SystemExit("rebase target does not fit in 43 bits")
    return target_off | (nxt << 51)



# -- repairing a class reference by FIELD ---------------------------------
#
# The cache answers "what is at this address" with whichever exported name its
# lookup finds first, and for a class object that is the bare ObjC class name
# rather than the mangled symbol. So `dsc_rebind` emitted, in DiskManagement,
# 22 binds spelled `NSObject` where the image imports `_OBJC_CLASS_$_NSObject`
# -- every class's `superclass` field, left NULL. The metaclass fields came out
# right, because `_OBJC_METACLASS_$_NSObject` is the only name at that address.
#
# A NULL superclass does not fail the load: libobjc reads it as "this is a root
# class". The class registers, its own methods work, and the damage only shows
# when something walks the class/metaclass pair -- which is `no class for
# metaclass` and an abort inside objc_msgSend.
#
# The name alone cannot be trusted to say which mangling to use (`NSObject` is
# also a protocol, and is one in __objc_const), so the repair is driven by
# STRUCTURE: walk __objc_classlist to each class_t and its metaclass, and fix
# the isa/superclass fields by their position.

# class_t: { isa, superclass, cache, vtable, data }
CLASS_ISA, CLASS_SUPER = 0x00, 0x08

# Constant objects the compiler emits: the first word of each is an `isa`, and
# every bind in these sections is one, so a bare name there is always a class.
CONST_OBJ_SECTS = ("__objc_arrayobj", "__objc_intobj", "__objc_dictobj",
                   "__objc_stringobj")


OBJC_PREFIXES = ("_OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "_OBJC_PROTOCOL_$_")


def bare_objc_name(name):
    """The class/protocol name inside a symbol, or None if it is not one.

    A field pass must be able to correct a reference that `resolve_alias`
    already spelled as a symbol -- possibly with the WRONG mangling, since the
    name alone cannot say whether an address is a class, a metaclass or a
    protocol. Position is authoritative, so strip whatever prefix is there and
    re-mangle from the field.
    """
    for pre in OBJC_PREFIXES:
        if name.startswith(pre):
            return name[len(pre):]
    return None if name.startswith("_") else name


def bind_ordinal(word):
    """The import ordinal a chained bind word names, or None if it is a rebase."""
    return (word & 0xFFFFFF) if word & (1 << 62) else None


def set_ordinal(word, ordinal):
    """Repoint a chained bind at another import. Only the low 24 bits move, so
    the key, diversity, addend and `next` field are all carried across."""
    if ordinal > 0xFFFFFF:
        raise SystemExit("ordinal does not fit in 24 bits")
    return (word & ~0xFFFFFF) | ordinal


def class_field_fixes(lay, names):
    """-> {file offset: correct symbol name} for every class reference field.

    Walks __objc_classlist to each class_t and the metaclass its `isa` names,
    and reports the isa/superclass fields that are binds on a bare class name.
    """
    out = {}
    cl = section(lay, "__DATA_CONST", "__objc_classlist")
    if cl is None:
        return out

    def word_at(fo):
        return struct.unpack_from("<Q", lay.data, fo)[0]

    def consider(fo, mangle):
        o = bind_ordinal(word_at(fo))
        if o is None or o >= len(names):
            return
        bare = bare_objc_name(names[o])
        if bare is None:             # an ordinary C symbol; not ours to touch
            return
        want = mangle + bare
        if want != names[o]:
            out[fo] = want

    for i in range(cl["size"] // 8):
        caddr = rebase_target(lay, word_at(cl["off"] + i * 8))
        if caddr is None:
            continue
        cfo = file_off(lay, caddr)
        if cfo is None:
            continue
        # The class's own superclass is a class. Its isa is its metaclass,
        # which for a class defined here is a local rebase.
        consider(cfo + CLASS_ISA, "_OBJC_METACLASS_$_")
        consider(cfo + CLASS_SUPER, "_OBJC_CLASS_$_")
        maddr = rebase_target(lay, word_at(cfo + CLASS_ISA))
        mfo = file_off(lay, maddr) if maddr is not None else None
        if mfo is None:
            continue
        # In a metaclass both fields name metaclasses.
        consider(mfo + CLASS_ISA, "_OBJC_METACLASS_$_")
        consider(mfo + CLASS_SUPER, "_OBJC_METACLASS_$_")
    return out


def const_object_fixes(lay, names):
    """-> {file offset: correct symbol name} for constant-object `isa` fields."""
    out = {}
    for seg in lay.segs:
        for sect in CONST_OBJ_SECTS:
            s = section(lay, seg["name"], sect)
            if s is None:
                continue
            for off in range(s["off"], s["off"] + s["size"], 8):
                word = struct.unpack_from("<Q", lay.data, off)[0]
                o = bind_ordinal(word)
                if o is None or o >= len(names):
                    continue
                bare = bare_objc_name(names[o])
                if bare is not None and names[o] != "_OBJC_CLASS_$_" + bare:
                    out[off] = "_OBJC_CLASS_$_" + bare
    return out



# -- repairing a protocol reference by FIELD ------------------------------
#
# Repairing these by NAME is wrong, and was tried: in __objc_const a name is
# ambiguous, because `protocol_t.name` is a char* to the string "NSObject"
# while a baseProtocols entry is a protocol_t* -- the same spelling, two
# completely different targets. Rebasing a name field to the protocol object
# earns EXC_BAD_ACCESS in libobjc's readClass.
#
# So the entries are reached structurally instead: a class_ro_t's
# `baseProtocols` and a protocol_t's own `protocols` are both protocol_list_t,
# which is { uintptr_t count; protocol_t *list[count]; }. Only the words inside
# that array are protocol references, and every one of them is.

RO_BASE_PROTOCOLS = 0x28        # class_ro_t.baseProtocols
CLASS_DATA = 0x20               # class_t.data -> class_ro_t
PROTO_PROTOCOLS = 0x10          # protocol_t.protocols


def protocol_field_fixes(lay, names):
    """-> {file offset: protocol name} for every protocol_list_t entry that is
    a bind on a bare ObjC name."""
    out = {}

    def word_at(fo):
        return struct.unpack_from("<Q", lay.data, fo)[0]

    def walk_list(list_addr):
        """Every entry of a protocol_list_t at this address."""
        if list_addr is None:
            return
        fo = file_off(lay, list_addr)
        if fo is None:
            return
        count = word_at(fo)
        if count > 4096:            # not a plausible list; refuse to guess
            return
        for i in range(count):
            efo = fo + 8 + i * 8
            o = bind_ordinal(word_at(efo))
            if o is None or o >= len(names):
                continue
            bare = bare_objc_name(names[o])
            if bare is not None:
                out[efo] = bare

    def deref(fo):
        return rebase_target(lay, word_at(fo))

    cl = section(lay, "__DATA_CONST", "__objc_classlist")
    if cl is not None:
        for i in range(cl["size"] // 8):
            caddr = rebase_target(lay, word_at(cl["off"] + i * 8))
            if caddr is None:
                continue
            for obj in (caddr, deref(file_off(lay, caddr) + CLASS_ISA)):
                ofo = file_off(lay, obj) if obj is not None else None
                if ofo is None:
                    continue
                ro = deref(ofo + CLASS_DATA)
                rfo = file_off(lay, ro & ~7) if ro is not None else None
                if rfo is not None:
                    walk_list(deref(rfo + RO_BASE_PROTOCOLS))

    pl = section(lay, "__DATA_CONST", "__objc_protolist")
    if pl is not None:
        for i in range(pl["size"] // 8):
            paddr = rebase_target(lay, word_at(pl["off"] + i * 8))
            pfo = file_off(lay, paddr) if paddr is not None else None
            if pfo is not None:
                walk_list(deref(pfo + PROTO_PROTOCOLS))
    return out



# -- repairing a relative method list ------------------------------------
#
# A relative method entry is three int32 offsets, { name, types, imp }, each
# from the address of its own field. In a cache image `types` and `imp` still
# reach this image, and only `name` was rewritten by the cache builder to reach
# the cache's uniqued selector pool. So no method on a lifted ObjC class can be
# found by selector, and `+[DMManager sharedManager]` is an unrecognized
# selector even once the class hierarchy is sound.
#
# CLAUDE.md used to say this was only the protocols' method lists and that class
# method lists were pointer-based. Both are relative. Measured on
# DiskManagement: 390 entries across 20 class and metaclass lists, every one of
# them dangling.
#
# The offset is NOT relative to the field for these. The list carries
# `relativeMethodSelectorsAreDirectFlag` (0x40000000) and objc4 then takes the
# offset from a single cache-wide selector base, which is the start of the
# uniqued pool. Solve for it once (it is the minimum address in
# `ipsw dyld objc sel`) and every entry decodes exactly: 390 of 390.
#
# The repair points each `name` at one of this image's OWN `__objc_selrefs`
# slots, because outside the shared cache objc4 reads a relative method name as
# a pointer to a selector reference rather than to the string. That needs no new
# space: all 361 distinct selectors DiskManagement's method lists name already
# have a selref, since the image sends them too. The direct-selectors flag is
# cleared, as the selectors are no longer direct.

METHOD_LIST_SMALL = 0x80000000
METHOD_LIST_DIRECT_SELS = 0x40000000
ENTSIZE_MASK = 0xFFFC

# protocol_t: { isa, name, protocols, instanceMethods, classMethods,
#               optionalInstanceMethods, optionalClassMethods, ... }
PROTO_METHOD_LISTS = (0x18, 0x20, 0x28, 0x30)
RO_BASE_METHODS = 0x20          # class_ro_t.baseMethods


def load_cache_selectors(path):
    """-> ({address: selector}, base) from an `ipsw dyld objc sel` dump."""
    sels = {}
    with open(path) as fh:
        for line in fh:
            addr, _, name = line.partition(": ")
            try:
                sels[int(addr, 16)] = name.strip()
            except ValueError:
                continue
    if not sels:
        raise SystemExit(f"{path}: no selectors parsed")
    return sels, min(sels)


def selref_index(lay):
    """-> {selector string: address of an __objc_selrefs slot naming it}."""
    out = {}
    for seg in lay.segs:
        s = section(lay, seg["name"], "__objc_selrefs")
        if s is None:
            continue
        for i in range(s["size"] // 8):
            word = struct.unpack_from("<Q", lay.data, s["off"] + i * 8)[0]
            tgt = rebase_target(lay, word)
            if tgt is None:
                continue
            fo = file_off(lay, tgt)
            if fo is None:
                continue
            end = lay.data.index(b"\0", fo)
            out.setdefault(bytes(lay.data[fo:end]).decode("utf-8", "replace"),
                           s["addr"] + i * 8)
    return out


def method_lists(lay):
    """Every relative method list address reachable from classes and protocols."""
    out = set()

    def word_at(fo):
        return struct.unpack_from("<Q", lay.data, fo)[0]

    def deref(fo):
        return rebase_target(lay, word_at(fo))

    cl = section(lay, "__DATA_CONST", "__objc_classlist")
    if cl is not None:
        for i in range(cl["size"] // 8):
            caddr = rebase_target(lay, word_at(cl["off"] + i * 8))
            if caddr is None:
                continue
            for obj in (caddr, deref(file_off(lay, caddr) + CLASS_ISA)):
                ofo = file_off(lay, obj) if obj is not None else None
                if ofo is None:
                    continue
                ro = deref(ofo + CLASS_DATA)
                rfo = file_off(lay, ro & ~7) if ro is not None else None
                if rfo is None:
                    continue
                bm = deref(rfo + RO_BASE_METHODS)
                if bm is not None:
                    out.add(bm)

    pl = section(lay, "__DATA_CONST", "__objc_protolist")
    if pl is not None:
        for i in range(pl["size"] // 8):
            paddr = rebase_target(lay, word_at(pl["off"] + i * 8))
            pfo = file_off(lay, paddr) if paddr is not None else None
            if pfo is None:
                continue
            for off in PROTO_METHOD_LISTS:
                ml = deref(pfo + off)
                if ml is not None:
                    out.add(ml)
    return out


def repair_method_lists(lay, sels, base, selrefs):
    """Repoint every relative method name at a local selref.

    -> (repaired, [(selector or None, why)]) leaving anything unresolved alone.
    """
    fixed, problems = 0, []
    for ml in sorted(method_lists(lay)):
        mfo = file_off(lay, ml)
        if mfo is None:
            continue
        flags, count = struct.unpack_from("<II", lay.data, mfo)
        if not flags & METHOD_LIST_SMALL:
            continue                       # pointer-based; nothing to do
        if not flags & METHOD_LIST_DIRECT_SELS:
            # Already repaired: the names are selrefs now, not offsets from the
            # cache's selector base, so decoding them again would report every
            # entry as naming no selector. Makes the pass idempotent.
            continue
        entsize = flags & ENTSIZE_MASK
        if entsize != 12:
            problems.append((None, f"entsize {entsize} in a small list"))
            continue
        # Work out every entry before writing any of them. A half-repaired
        # list is worse than an untouched one: clearing the direct-selectors
        # flag tells objc4 to read every `name` as a selref, so an entry still
        # holding a pool offset becomes a wild pointer rather than a stale one.
        writes, failed = [], False
        for k in range(count):
            fa = ml + 8 + k * entsize      # address of this entry's name field
            ffo = mfo + 8 + k * entsize
            off = struct.unpack_from("<i", lay.data, ffo)[0]
            sel = sels.get(base + off)
            if sel is None:
                problems.append((None, f"0x{base + off:x} names no selector"))
                failed = True
                continue
            slot = selrefs.get(sel)
            if slot is None:
                # No selref to point at, and there is no room to add one
                # without moving a section, which the lift exists to avoid.
                problems.append((sel, "no __objc_selrefs slot"))
                failed = True
                continue
            delta = slot - fa
            if not -(1 << 31) <= delta < (1 << 31):
                problems.append((sel, "selref out of int32 range"))
                failed = True
                continue
            writes.append((ffo, delta))
        if failed:
            continue
        for ffo, delta in writes:
            struct.pack_into("<i", lay.data, ffo, delta)
        fixed += len(writes)
        # The selectors are selrefs now, not direct pointers into the cache.
        struct.pack_into("<I", lay.data, mfo, flags & ~METHOD_LIST_DIRECT_SELS)
    return fixed, problems


REPAIRS = {
    "__objc_selrefs": "selector",
    "__objc_protorefs": "protocol",
}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--cache-selectors", metavar="FILE",
                    help="an `ipsw dyld objc sel <cache>` dump, used to repair "
                         "relative method lists")
    ap.add_argument("--no-sign", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    lay = Layout(args.input)
    if not any(section(lay, s["name"], n)
               for s in lay.segs for n in REPAIRS):
        if not args.quiet:
            print(f"{os.path.basename(args.input)}: no ObjC selector or "
                  f"protocol references, nothing to repair")
        if args.output != args.input:
            open(args.output, "wb").write(lay.data)
        return 0

    names = imports_table(lay)
    sels = cstring_index(lay, "__TEXT", "__objc_methname")
    protos = protocol_index(lay)

    # which file offsets belong to a section we repair
    ranges = []
    for seg in lay.segs:
        for sect in REPAIRS:
            s = section(lay, seg["name"], sect)
            if s:
                ranges.append((s["off"], s["off"] + s["size"], REPAIRS[sect]))

    def kind_of(fo):
        for lo, hi, kind in ranges:
            if lo <= fo < hi:
                return kind
        return None

    # -- class references, repaired by field rather than by name ---------
    # These are genuine imports of another image's class, so the repair is to
    # name the symbol correctly and let dyld bind it -- not to rebase locally.
    ordinal_of = {n: i for i, n in enumerate(names)}
    want = class_field_fixes(lay, names)
    want.update(const_object_fixes(lay, names))
    renamed, unnameable = 0, []
    # Protocol references are the mirror image: the protocol object is in this
    # image's own __objc_protolist, so these become local rebases.
    proto_fixed, proto_missing = 0, []
    for fo, nm in sorted(protocol_field_fixes(lay, names).items()):
        tgt = protos.get(nm)
        if tgt is None:
            proto_missing.append(nm)
            continue
        word = struct.unpack_from("<Q", lay.data, fo)[0]
        struct.pack_into("<Q", lay.data, fo, make_rebase(word, tgt - lay.base))
        proto_fixed += 1

    for fo, sym in sorted(want.items()):
        o = ordinal_of.get(sym)
        if o is None:
            # The correct spelling is not in the imports table, and growing
            # that table would move __LINKEDIT. Reported, left NULL.
            unnameable.append(sym)
            continue
        word = struct.unpack_from("<Q", lay.data, fo)[0]
        struct.pack_into("<Q", lay.data, fo, set_ordinal(word, o))
        renamed += 1

    fixed = {"selector": 0, "protocol": 0}
    unresolved = []
    skipped = []
    for k, where, _seg, _extra in list(chain_slots(lay)):
        if k != "slot":
            continue
        word, = struct.unpack_from("<Q", lay.data, where)
        if not word & (1 << 62):          # already a rebase: nothing to do
            continue
        ordinal = word & 0xFFFFFF
        if ordinal >= len(names):
            continue
        name = names[ordinal]
        kind = kind_of(where)
        if kind is None:
            # Deliberately NOT repaired: the same bug also affects protocol
            # references in __objc_const (a class's `baseProtocols`, a
            # protocol's own `protocols` list). Repairing those by NAME was
            # tried and is wrong, because a name is ambiguous there:
            # `protocol_t.name` is a char* to the string "NSObject" while a
            # baseProtocols entry is a protocol_t* -- the same spelling, two
            # different targets. Rebasing a name field to the protocol object
            # gets `readClass` a garbage pointer and the process dies with
            # EXC_BAD_ACCESS in libobjc, which is how this comment was earned.
            #
            # Telling them apart needs real structure parsing: walk
            # __objc_classlist to each class_ro_t and __objc_protolist to each
            # protocol_t, and repair by FIELD rather than by name. Until then
            # these stay weak binds and resolve NULL, which is survivable --
            # a NULL baseProtocols means "conforms to nothing".
            if not name.startswith("_"):
                skipped.append(name)
            continue
        target = sels.get(name) if kind == "selector" else protos.get(name)
        if target is None:
            unresolved.append((kind, name))
            continue
        struct.pack_into("<Q", lay.data, where,
                         make_rebase(word, target - lay.base))
        fixed[kind] += 1

    # -- relative method lists -------------------------------------------
    meth_fixed, meth_problems = 0, []
    if args.cache_selectors:
        sels, sel_base = load_cache_selectors(args.cache_selectors)
        meth_fixed, meth_problems = repair_method_lists(
            lay, sels, sel_base, selref_index(lay))

    open(args.output, "wb").write(lay.data)
    if not args.no_sign:
        subprocess.run(["/usr/bin/codesign", "-f", "-s", "-", args.output],
                       check=True)

    if not args.quiet:
        print(f"{os.path.basename(args.input)}: "
              f"{fixed['selector']} selector and {fixed['protocol']} protocol "
              f"reference(s) rebased to this image's own copy")
        if meth_fixed:
            print(f"  {meth_fixed} relative method name(s) repointed at this "
                  f"image's own __objc_selrefs")
        if meth_problems:
            print(f"  {len(meth_problems)} method name(s) NOT repaired:")
            for sel, why in meth_problems[:6]:
                print(f"      {sel or '(unknown)'}: {why}")
        if proto_fixed:
            print(f"  {proto_fixed} protocol conformance reference(s) "
                  f"(baseProtocols / protocol_t.protocols) rebased by field")
        if proto_missing:
            u = sorted(set(proto_missing))
            print(f"  {len(proto_missing)} protocol conformance reference(s) "
                  f"NOT repaired -- not defined in this image: {', '.join(u[:6])}")
        if renamed:
            print(f"  {renamed} class reference(s) (isa/superclass) repointed "
                  f"at the mangled symbol the image imports")
        if unnameable:
            u = sorted(set(unnameable))
            print(f"  {len(unnameable)} class reference(s) NOT repaired -- no "
                  f"such import to bind ({len(u)} distinct), left NULL:")
            print(f"      {', '.join(u[:6])}"
                  + (f", +{len(u) - 6} more" if len(u) > 6 else ""))
        if skipped:
            u = sorted(set(skipped))
            print(f"  {len(skipped)} ObjC name bind(s) outside "
                  f"__objc_selrefs/__objc_protorefs left as weak binds "
                  f"(NULL at runtime):")
            print(f"      {', '.join(u[:8])}"
                  + (f", +{len(u) - 8} more" if len(u) > 8 else ""))
        if unresolved:
            print(f"  {len(unresolved)} NOT repaired -- they stay weak binds "
                  f"and will be NULL at runtime:")
            for kind, n in unresolved[:10]:
                print(f"      {kind:9s} {n}")
    return 1 if unresolved else 0


if __name__ == "__main__":
    sys.exit(main())
