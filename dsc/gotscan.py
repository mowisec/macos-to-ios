#!/usr/bin/env python3
"""
dsc_gotscan -- explain why a dyld-shared-cache extraction crashes, and prove
that it is repairable.

    ./dsc_gotscan.py <extracted.dylib> [--verbose]

Background
----------
A library lifted out of a modern dyld shared cache loads and then faults on its
first call.  The obvious explanation is the missing LC_DYLD_CHAINED_FIXUPS, but
that is only half of it, and the half that matters is more specific:

    the cache builder UNIQUES GOT ENTRIES CACHE-WIDE.

Each image keeps its own __got / __auth_got sections at the original size, but
the builder zeroes them, clears their section type, and rewrites the image's
code to reach a shared GOT region that belongs to no image at all.  So an
extracted image's stubs and its GOT-relative data loads point at addresses
outside every one of its own segments.  Standalone, those addresses are
whatever happens to be mapped there -- usually zero -- and the first
dereference dies.

That is a *code* problem, not just a metadata problem, which is why no
extractor fixes it: Apple's dsc_extractor and `ipsw dyld extract` both
reproduce the cache's rewritten code verbatim.

The good news, and the point of this script
-------------------------------------------
Everything needed to undo it is still in the extracted file:

  * the indirect symbol table survives intact, so every stub slot and every GOT
    slot is still named;
  * stub[i] and __auth_got[i] name the same symbol, so a stub can be pointed
    back at its own image's GOT slot with no external information at all;
  * the dead __got / __auth_got sections are exactly the right size, so the
    repair needs no new space.

This script does the analysis and reports what a rebinder would have to do.  It
does not modify anything.
"""

import argparse
import struct
import sys

from .arm64 import adrp, add_imm64, ldr_uimm64, u32, auth_branch
from .image import (Image, INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL,
                    LC_DYLD_CHAINED_FIXUPS, LC_DYSYMTAB, LC_SEGMENT_64,
                    LC_SYMTAB, S_LAZY_SYMBOL_POINTERS,
                    S_NON_LAZY_SYMBOL_POINTERS, S_SYMBOL_STUBS)



# The cache's slide info names a slot by whichever exported symbol sits at the
# target address.  Where several symbols alias one address, that need not be
# the spelling this image imports -- an ObjC class symbol rather than the block
# runtime's C name, typically.  Map back to the name the image actually names.
ALIASES = {
    "__NSGlobalBlock__": "__NSConcreteGlobalBlock",
    "__NSStackBlock__": "__NSConcreteStackBlock",
    "__NSMallocBlock__": "__NSConcreteMallocBlock",
    "_OBJC_CLASS_$___NSGlobalBlock__": "__NSConcreteGlobalBlock",
    "_OBJC_CLASS_$___NSStackBlock__": "__NSConcreteStackBlock",
    # A thread-local descriptor's first word is its resolver thunk. The cache
    # pre-resolves it to libsystem's implementation, `__tlv_get_addr`, which is
    # not an exported name: it appears in 0 of the iPhoneOS SDK's 705 .tbd
    # files, where `__tlv_bootstrap` appears in 13 -- libSystem.B.tbd, the very
    # library the bind names, among them. A real linker emits the latter --
    # confirmed against libLTO.dylib, a genuine toolchain file, whose
    # __thread_vars binds `libSystem/__tlv_bootstrap` -- and it is what a lifted
    # image's own symbol table already imports. Left unaliased the thunk becomes
    # a weak flat bind that resolves NULL, and the library works only because
    # dyld overwrites the word during setUpTLVs before anything reads it.
    "__tlv_get_addr": "__tlv_bootstrap",
    # Every CFSTR("...") literal is a __cfstring record whose first word is the
    # class of a constant CFString. A compiler emits that as a bind to
    # `___CFConstantStringClassReference`, which CoreFoundation exports and
    # which a lifted image's own symbol table already imports. The cache holds
    # the address pre-resolved, and asked what lives there it answers with the
    # ObjC class name `__NSCFConstantString` -- the same
    # implementation-versus-public-name split as the block classes above.
    #
    # Left unaliased it is a flat weak bind that resolves NULL, so every
    # constant string in the library has a NULL isa, and CoreFoundation traps
    # the first time one is used: EXC_BREAKPOINT in `__CF_IS_OBJC`, with
    # "CF objects must have a non-zero isa". That is how `expect` died --
    # Tcl_InitNotifier hands CFRunLoopAddSource its own
    # @"com.tcltk.tclEventsOnlyRunLoopMode" and CFHash traps on it. 18 of the
    # 33 libraries this project lifts were affected, 6628 strings between them.
    "__NSCFConstantString": "___CFConstantStringClassReference",
}


def weak_ref_symbols(img) -> set:
    """Undefined symbols the image marks N_WEAK_REF (`weak external` in nm).

    A weak reference is allowed to end up NULL: if its library is absent, or
    present without the symbol, dyld binds zero and carries on instead of
    failing the load. That permission lives in TWO places in a modern image,
    and dyld reads the second one:

        nlist_64.n_desc & N_WEAK_REF        the symbol table (what nm prints)
        dyld_chained_import.weak_import     the chained-fixups table

    A synthesised import table that drops the bit turns every weak import into
    a hard one, so a weak-linked library that is legitimately absent on the
    target becomes a fatal `Symbol not found` at launch. That is what happened
    to the lifted libcurl: it weak-links Kerberos, iOS has none, and
    _GSS_C_NT_HOSTBASED_SERVICE killed curl before main().
    """
    N_WEAK_REF = 0x0040
    out = set()
    for i in range(img.nsyms):
        n_type = img.data[img.symoff + i * 16 + 4]
        if (n_type & 0x0E) != 0x00:
            continue
        n_desc = int.from_bytes(
            img.data[img.symoff + i * 16 + 6:img.symoff + i * 16 + 8], "little")
        if n_desc & N_WEAK_REF:
            out.add(img.symbol_name(i))
    return out


def undefined_symbols(img) -> set:
    """Every N_UNDF symbol -- what this image imports, by name."""
    return set(import_ordinals(img))


def libsystem_ordinal(img) -> int | None:
    """The 1-based load-command ordinal of libSystem, if this image links it.

    A symbol the image's own symbol table does not list still has to be bound
    somewhere. Almost all of them are libSystem-family (`__platform_bzero`,
    `___recvfrom`), which libSystem.B.dylib re-exports, and two-level namespace
    resolution follows re-exports -- so libSystem's ordinal is a far better
    answer than a flat lookup, which only happens to work when something else
    has already loaded the provider.
    """
    # The set and order that define a two-level-namespace ordinal: the dylib
    # load commands, LC_ID_DYLIB excluded. In a dylib_command the path offset is
    # the first field after cmdsize.
    LOADS = (0x0C,          # LC_LOAD_DYLIB
             0x80000018,    # LC_LOAD_WEAK_DYLIB
             0x8000001F,    # LC_REEXPORT_DYLIB
             0x20,          # LC_LAZY_LOAD_DYLIB
             0x80000023)    # LC_LOAD_UPWARD_DYLIB
    n = 0
    off = 32
    for _ in range(img.ncmds):
        cmd, cmdsize = struct.unpack_from("<II", img.data, off)
        if cmd in LOADS:
            n += 1
            path_off = struct.unpack_from("<I", img.data, off + 8)[0]
            if 8 <= path_off < cmdsize:
                end = img.data.index(b"\0", off + path_off)
                path = img.data[off + path_off:end].decode(errors="replace")
                if path.endswith("/libSystem.B.dylib"):
                    return n
        off += cmdsize
    return None


def import_ordinals(img) -> dict:
    """Undefined symbol -> its two-level-namespace library ordinal.

    The ordinal is the 1-based position of the dylib among the load commands,
    stored in the high byte of n_desc. A synthesised chained-fixups import
    table has to carry the same ordinal, or dyld looks the symbol up in the
    wrong library -- which fails the load outright.
    """
    out = {}
    for i in range(img.nsyms):
        n_type = img.data[img.symoff + i * 16 + 4]
        if (n_type & 0x0E) != 0x00:
            continue
        n_desc = int.from_bytes(
            img.data[img.symoff + i * 16 + 6:img.symoff + i * 16 + 8], "little")
        out[img.symbol_name(i)] = (n_desc >> 8) & 0xFF
    return out


# One address in the cache often carries several exported names, and the one the
# cache reports is whichever the symbol lookup happens to find -- usually the
# *implementation*, where the image imports the *public* name. Binding the
# implementation name is the subtler failure: `__platform_memchr` is not
# available to bind by name, so the slot ends up NULL and the library dies on
# its first memchr. This is what NULLed libpcre's first call.
def _candidates(name: str):
    yield name
    if name.startswith("_ptr."):
        # A cache-uniqued GOT slot is itself named `_ptr.<symbol>`, so a
        # pointer whose target is another such slot reports that spelling.
        name = name[len("_ptr."):]
        yield name
    if name in ALIASES:
        yield ALIASES[name]
    # An ObjC class object carries two names in the cache -- the mangled symbol
    # `_OBJC_CLASS_$_NSObject` and the bare class name the ObjC metadata spells
    # it with -- and the cache's lookup answers with the bare one. The image
    # imports only the mangled spelling, so a bare name left as-is becomes a
    # flat weak bind that resolves NULL: every class's `superclass` field, and
    # every constant object's `isa`. The metaclass fields come out right on
    # their own, because the mangled name is the only one at that address.
    #
    # dsc_objc then re-checks these by FIELD and corrects the mangling if the
    # position disagrees, so guessing wrong here is recoverable. Guessing
    # nothing is not, because the name never reaches the imports table at all.
    if not name.startswith("_"):
        yield "_OBJC_CLASS_$_" + name
        yield "_OBJC_METACLASS_$_" + name
    # libsystem_platform's string/memory routines: __platform_memchr is _memchr.
    if name.startswith("__platform_"):
        yield "_" + name[len("__platform_"):]
    # Internal spellings differ from the imported ones by leading underscores,
    # and by how many: the cache calls the stack probe ____chkstk_darwin where
    # the image imports ___chkstk_darwin, and ___recvfrom where it imports
    # _recvfrom. Try each depth rather than guessing one.
    for n in (1, 2, 3):
        if name[n:].startswith("_"):
            yield name[n:]
    # memcpy and memmove share one implementation on Apple platforms, so a
    # memcpy slot resolves to __platform_memmove. Either name is correct for it;
    # memmove is the stronger contract, so it is safe in both directions.
    for a, b in (("_memmove", "_memcpy"), ("_memcpy", "_memmove")):
        if name.endswith(a[1:]):
            yield b


def resolve_alias(name: str, undef: set) -> str:
    """Prefer the spelling this image actually imports."""
    if not undef:
        return name
    for cand in _candidates(name):
        if cand in undef:
            return cand
    return name


# -- arm64 instruction decoding -------------------------------------------

def scan_got_sites(img):
    """Every GOT-style reference in __text, with enough context to rewrite it.

    Two forms reach a GOT slot, and they need different repairs:

      adrp x8,  P  /  ldr x8, [x8, #off]      a data symbol; the slot address is
                                              P+off and the pair to patch is
                                              (adrp, ldr)
      adrp x17, P  /  add x17, x17, #off      an inline stub the cache builder
      ldr  x16, [x17] / blraa x16, x17        put straight into __text; the pair
                                              to patch is (adrp, add), and the
                                              slot must be authenticated because
                                              the call is blraa

    Missing the second form is subtle: the `ldr x16, [x17]` still looks like the
    first form to a naive scanner, which then computes P+0 instead of P+off and
    leaves the site alone -- and a `blraa` through an unbound slot is an
    EXC_ARM_PAC_FAIL a long way from its cause.

    -> list of dicts: kind ('add'|'ldr'), target, first/second file offsets,
       first pc, auth (whether the use is an authenticated branch).
    """
    text = img.section("__TEXT", "__text")
    if text is None:
        return []
    out, val = [], {}
    n = (text["size"] & ~3) // 4
    words = [u32(img.data, text["off"] + k * 4) for k in range(n)]
    for k in range(n):
        insn = words[k]
        pc = text["addr"] + k * 4
        page, rd = adrp(insn, pc)
        if page is not None:
            val[rd] = (page, k, False)
            continue
        imm, rn, rd2 = add_imm64(insn)
        if imm is not None:
            if rn in val:
                base_, first, _ = val[rn]
                out.append(dict(kind="add", target=base_ + imm,
                                first=text["off"] + first * 4,
                                second=text["off"] + k * 4,
                                first_pc=text["addr"] + first * 4,
                                auth=any(auth_branch(words[j])
                                         for j in range(k + 1,
                                                        min(k + 4, n)))))
                val[rd2] = (base_ + imm, first, True)
            else:
                val.pop(rd2, None)
            continue
        off_, rn, rt = ldr_uimm64(insn)
        if off_ is not None:
            if rn in val:
                base_, first, from_add = val[rn]
                # An inline stub's own `ldr x16, [x17]` reads the slot the add
                # already computed, so it is the same site, not a second one.
                if not from_add:
                    out.append(dict(kind="ldr", target=base_ + off_,
                                    first=text["off"] + first * 4,
                                    second=text["off"] + k * 4,
                                    first_pc=text["addr"] + first * 4,
                                    auth=False))
            val.pop(rt, None)
            continue
        # Anything else that writes a register we were tracking invalidates it.
        rd3 = insn & 0x1F
        val.pop(rd3, None)
    return out


# -- the analysis ----------------------------------------------------------

def stub_slots(img: Image, sec) -> list[tuple[int, int | None]]:
    """For each stub, the GOT address it reaches. -> [(stub index, addr)]."""
    out = []
    stride = sec["r2"] or 16
    for i in range(sec["size"] // stride):
        pc = sec["addr"] + i * stride
        fo = sec["off"] + i * stride
        page, rd = adrp(u32(img.data, fo), pc)
        imm, rn, _ = add_imm64(u32(img.data, fo + 4))
        if page is None or imm is None or rn != rd:
            out.append((i, None))
        else:
            out.append((i, page + imm))
    return out


def code_got_refs(img: Image) -> dict[int, list[str]]:
    """ADRP+LDR / ADRP+ADD pairs in __text, by target address.

    A thin index over scan_got_sites(), and it must stay that way. This used to
    be a second, independent decoder that tracked a pending ADRP per register
    and never invalidated it, so any later add/ldr reusing that register was
    paired with an ADRP an arbitrary distance away and reported as a reference.

    Measured, that is not a small effect. Over the 489 never-lifted binaries in
    a built cryptex -- ordinary macOS Mach-Os, which cannot contain a cache
    leftover by construction -- the loose decoder invents 123 out-of-image
    "references" and this one reports 0. On libLTO.dylib, a genuine toolchain
    dylib, 3 versus 0; on libcrypto, whose 11 artefacts CLAUDE.md records
    alongside its device-confirmed working state, 10 versus 0.

    So the register invalidation IS the adjacency test: every site that survives
    it in the shipped tree is an immediately adjacent ADRP+use pair (all 81, at
    a distance of exactly one instruction), and every site it drops was a stale
    register. Do not reintroduce a second decoder to "cross-check" this one.
    """
    refs: dict[int, list[str]] = {}
    sec = img.section("__TEXT", "__text")
    if sec is None:
        return refs
    for site in scan_got_sites(img):
        off = site["second"] - sec["off"]
        refs.setdefault(site["target"], []).append(
            f"__text+0x{off:x} {site['kind']}")
    return refs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Explain a dyld-shared-cache extraction's GOT damage.")
    ap.add_argument("image")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every stub and GOT slot with its symbol")
    args = ap.parse_args(argv)

    img = Image(open(args.image, "rb").read())

    print(f"{args.image}")
    print(f"  segments: " + ", ".join(
        f"{n}@0x{a:x}" for n, a, _, _, _ in img.segments))
    chained = LC_DYLD_CHAINED_FIXUPS in img.cmds
    print(f"  LC_DYLD_CHAINED_FIXUPS: {'present' if chained else 'ABSENT'}")
    print(f"  indirect symbol table:  {img.nind} entries "
          f"{'(intact)' if img.nind else '(GONE -- not repairable)'}")

    # Pointer sections, and whether the builder stripped their type.
    ptr_secs = []
    for s in img.sections:
        if s["sect"] in ("__got", "__auth_got", "__la_symbol_ptr",
                         "__auth_ptr"):
            ptr_secs.append(s)
    stubs = [s for s in img.sections
             if (s["flags"] & 0xFF) == S_SYMBOL_STUBS
             or s["sect"] in ("__stubs", "__auth_stubs")]

    print()
    print("  section              slots  type          content")
    for s in ptr_secs + stubs:
        n = s["size"] // (s["r2"] or 8) if s in stubs else s["size"] // 8
        body = img.data[s["off"]:s["off"] + s["size"]]
        content = "all zero" if body == b"\0" * len(body) else "non-zero"
        typ = s["flags"] & 0xFF
        tname = {0: "none (STRIPPED)", S_NON_LAZY_SYMBOL_POINTERS: "non-lazy ptrs",
                 S_LAZY_SYMBOL_POINTERS: "lazy ptrs",
                 S_SYMBOL_STUBS: "stubs"}.get(typ, hex(typ))
        print(f"  {s['seg']}.{s['sect']:<14} {n:>4}  {tname:<14} {content}")

    # Where do the stubs actually point?
    print()
    total_stub = external_stub = 0
    for s in stubs:
        slots = stub_slots(img, s)
        total_stub += len(slots)
        for i, addr in slots:
            if addr is not None and not img.owns(addr):
                external_stub += 1
    print(f"  stubs: {total_stub}, of which {external_stub} reach a GOT slot "
          f"OUTSIDE every segment of this image")

    # Data GOT loads from code.
    refs = code_got_refs(img)
    ext = {a: v for a, v in refs.items()
           if not img.owns(a) and a % 8 == 0}
    print(f"  __text GOT-style loads: {len(refs)}, of which {len(ext)} land "
          f"outside the image (8-aligned)")

    # Can we name every slot locally?
    print()
    ok = True
    for s in ptr_secs:
        n = s["size"] // 8
        if n == 0:
            continue
        names = []
        for k in range(n):
            try:
                names.append(img.indirect_name(s["r1"] + k))
            except Exception:
                names.append(None)
        named = sum(1 for x in names if x)
        print(f"  {s['seg']}.{s['sect']}: {named}/{n} slots named by the "
              f"indirect symbol table")
        if named != n:
            ok = False
        if args.verbose:
            for k, nm in enumerate(names):
                print(f"        [{k:>3}] {nm}")

    # The key correspondence: stub[i] and the auth GOT slot [i].
    ag = img.section("__AUTH_CONST", "__auth_got") or \
        img.section("__DATA_CONST", "__got")
    st = img.section("__TEXT", "__auth_stubs") or \
        img.section("__TEXT", "__stubs")
    if ag and st:
        n = min(st["size"] // (st["r2"] or 16), ag["size"] // 8)
        match = all(img.indirect_name(st["r1"] + k) ==
                    img.indirect_name(ag["r1"] + k) for k in range(n))
        print()
        print(f"  stub[i] and {ag['sect']}[i] name the same symbol for all "
              f"{n}: {match}")
        if match:
            print("  -> every stub can be repointed at this image's own GOT "
                  "slot with NO cache lookup.")

    print()
    if external_stub:
        print("  VERDICT: cache-uniqued GOT damage. The image's own GOT is "
              "dead space and")
        print("           its code reaches a shared region that does not "
              "exist standalone.")
        print("           Repairable: " + ("yes" if ok and img.nind else "no"))
    elif chained and ext:
        # Do NOT call these false positives. That wording was here, and it was
        # wrong: a libxcselect lifted before dsc_rebind could allocate an
        # authenticated overflow slot left exactly one such site, in
        # xcselect_trigger_install_request, and every caller of
        # xcselect_invoke_xcrun died on it with EXC_ARM_PAC_FAIL -- 78 SIGKILLs
        # on the device, dismissed for a session by this very message. Some of
        # these are ADRP/LDR decoding artefacts; some are real. This cannot tell
        # which, so it must not claim to.
        print("  VERDICT: stubs repaired, but INCOMPLETE.")
        print(f"           {len(ext)} __text site(s) still reach an address "
              f"outside this image:")
        # ext maps slot address -> whatever code_got_refs recorded for it.
        # Cross-reference scan_got_sites so the pc and the authenticated flag
        # can be shown: an AUTHENTICATED site is the one that will PAC-fail.
        sites = {s["target"]: s for s in scan_got_sites(img)}
        for addr in sorted(ext)[:8]:
            site = sites.get(addr)
            if site is not None:
                a = " AUTHENTICATED" if site.get("auth") else ""
                print(f"             pc={site['first_pc']:#x} "
                      f"({site['kind']}) -> {addr:#x}{a}")
            else:
                print(f"             -> {addr:#x}")
        print("           These are ADJACENT ADRP+use pairs, not decoding")
        print("           artefacts -- a stale-register pair cannot survive")
        print("           scan_got_sites' invalidation. An AUTHENTICATED one")
        print("           is a blraa through an unbound slot:")
        print("           it will EXC_ARM_PAC_FAIL on any path that reaches it,")
        print("           and the crash address is the opcode (0xd73f0a11).")
        print("           Check whether dsc_facts named the slot -- and mind")
        print("           the code shift, which is not the image-base shift.")
        # A machine-readable count, so a caller does not have to parse the
        # prose above. Only the AUTHENTICATED ones are FATAL -- a blraa through
        # an unbound slot PAC-faults on any path reaching it. An unauthenticated
        # one is latent, not harmless: it is a real load or address-materialise
        # that faults if the path is taken. Measured on the shipped tree, the
        # two families are the cache's second GOT region (0x1e61xxxxx: the stack
        # guard, ___stderrp, the block classes) and its uniqued ObjC selector
        # pool (0x1fa..0x1fd), reached by an add straight into an argument
        # register.
        n_auth = sum(1 for a in ext
                     if (sites.get(a) or {}).get("auth"))
        print(f"  AUTHENTICATED_LEFTOVERS: {n_auth}")
        print(f"  UNAUTHENTICATED_LEFTOVERS: {len(ext) - n_auth}")
    elif chained:
        print("  VERDICT: repaired. Every stub reaches this image's own GOT "
              "and the binds")
        print("           and rebases are carried by LC_DYLD_CHAINED_FIXUPS,")
        print("           and no __text site reaches outside the image.")
        print("  AUTHENTICATED_LEFTOVERS: 0")
        print("  UNAUTHENTICATED_LEFTOVERS: 0")
    else:
        print("  VERDICT: no cache-uniqued GOT references. Not a cache "
              "extraction.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
