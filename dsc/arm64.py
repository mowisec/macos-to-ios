"""arm64 instruction decoding, for the handful of forms this project reads.

Only four shapes matter, and between them they are how a lifted image's
references to its own data are found and moved:

    ADRP xN, page            the page half of every PC-relative data reference
    ADD  xN, xN, #imm        the offset half, when the target is a data symbol
    LDR  xN, [xN, #imm]      the offset half, when the pair loads through a slot
    BLRAA/BRAA xN, xM        an authenticated indirect branch, i.e. a stub call

An ADRP's immediate is a fixed distance recorded in no relocation table, which
is why this decoding exists at all: an executable section of a lifted image is
pure instructions (LC_DATA_IN_CODE is empty, and refused if it is not), so
every 4-byte word can be decoded and an ADRP recognised by opcode alone.
"""

import struct


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def adrp(insn, pc):
    """-> (page address, Rd) or (None, None)."""
    if (insn & 0x9F000000) != 0x90000000:
        return None, None
    imm = (((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12), insn & 0x1F


def add_imm64(insn):
    """-> (imm, Rn, Rd) or (None, None, None)."""
    if (insn & 0xFF800000) != 0x91000000:
        return None, None, None
    imm = (insn >> 10) & 0xFFF
    if ((insn >> 22) & 3) == 1:
        imm <<= 12
    return imm, (insn >> 5) & 0x1F, insn & 0x1F


def ldr_uimm64(insn):
    """64-bit LDR (immediate, unsigned offset) -> (byte offset, Rn, Rt)."""
    if (insn & 0xFFC00000) != 0xF9400000:
        return None, None, None
    return ((insn >> 10) & 0xFFF) * 8, (insn >> 5) & 0x1F, insn & 0x1F



def auth_branch(insn):
    """Is this `blraa Xn, Xm` / `braa Xn, Xm` (authenticated indirect branch)?"""
    # BRAA  0xD71F0800 | (Rn << 5) | Rm      BRAB  same with bit 10 set
    # BLRAA 0xD73F0800 | (Rn << 5) | Rm      BLRAB same with bit 10 set
    # Masking bits 10..0 away covers both keys and both register fields.
    return (insn & 0xFFFFF800) in (0xD71F0800, 0xD73F0800)
