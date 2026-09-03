#!/usr/bin/env python3
"""machomorph -- retarget a Mach-O binary at another Apple platform.

Does in one run what ``lipo`` + ``cbv`` + ``install_name_tool`` + ``ldid`` +
``codesign`` used to do, with no dependencies beyond the Python standard
library and ``/usr/bin/codesign``.

    ./machomorph.py /usr/sbin/ioreg -o ioreg_ios --platform ios --version 27.0

See CLAUDE.md for the design notes and for what exactly ``cbv`` mutates.
"""

from __future__ import annotations

import argparse
import copy
import fnmatch
import glob
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys

# The dyld-shared-cache stages: importing them rather than shelling out is what
# lets this file own the lift pipeline without owning 2800 more lines of it.
# They stay separate modules and keep their CLIs (`python3 -m dsc.gotscan`),
# because when a lift comes out wrong the way to find out why is to run one
# stage by hand on the intermediate.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dsc          # noqa: E402
import dsc.compact       # noqa: F401  (reached through run_stage by name)
import dsc.extract
import dsc.facts         # noqa: F401
import dsc.gotscan       # noqa: F401
import dsc.objc          # noqa: F401
import dsc.rebind        # noqa: F401
import dsc.symindex

# ---------------------------------------------------------------------------
# Mach-O constants
# ---------------------------------------------------------------------------

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE

CPU_ARCH_ABI64 = 0x01000000
CPU_ARCH_ABI64_32 = 0x02000000
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64
CPU_TYPE_ARM64_32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32

CPU_SUBTYPE_MASK = 0xFF000000
CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64_V8 = 1
CPU_SUBTYPE_ARM64E = 2

# arm64e pointer-authentication ABI encoding, kept in the "capability" byte.
CPU_SUBTYPE_PTRAUTH_ABI = 0x80000000  # subtype carries a versioned ptrauth ABI
CPU_SUBTYPE_ARM64E_VERSION_MASK = 0x0F000000
CPU_SUBTYPE_ARM64E_MACOS = CPU_SUBTYPE_PTRAUTH_ABI | 0x01000000  # -> 0x81000002

ARCH_NAMES = {
    (CPU_TYPE_X86_64, 3): "x86_64",
    (CPU_TYPE_X86_64, 8): "x86_64h",
    (CPU_TYPE_X86, 3): "i386",
    (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL): "arm64",
    (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8): "arm64v8",
    (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E): "arm64e",
    (CPU_TYPE_ARM64_32, 1): "arm64_32",
    (CPU_TYPE_ARM, 9): "armv7",
    (CPU_TYPE_ARM, 11): "armv7s",
    (CPU_TYPE_ARM, 12): "armv7k",
}

LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19

# segment_command_64.flags: dyld requires __DATA_CONST to be marked
# read-only, and refuses to load a dylib whose __DATA_CONST is not.
SG_READ_ONLY = 0x10

# objc_image_info.flags bits the dyld shared cache adds and a standalone dylib
# must not keep. (1<<3) is OBJC_IMAGE_OPTIMIZED_BY_DYLD; (1<<0) travels with it
# on every cache image measured. See MachO.fix_objc_imageinfo.
OBJC_IMAGE_DYLD_OPTIMISED = (1 << 3) | (1 << 0)

# Load commands whose payload is a file offset into __LINKEDIT, and which
# therefore move with it.
LC_SYMTAB_CMD = 0x02
LC_DYSYMTAB = 0x0B
LINKEDIT_OFFSET_FIELDS = {
    LC_SYMTAB_CMD: (8, 16),          # symoff, stroff
    0x1D: (8,),                      # LC_CODE_SIGNATURE
    0x1E: (8,),                      # LC_SEGMENT_SPLIT_INFO
    0x22: (8,),                      # LC_DYLD_INFO
    0x26: (8,),                      # LC_FUNCTION_STARTS
    0x29: (8,),                      # LC_DATA_IN_CODE
    0x2B: (8,),                      # LC_LINKER_OPTIMIZATION_HINT
    0x80000022: (8,),                # LC_DYLD_INFO_ONLY
    0x80000033: (8,),                # LC_DYLD_EXPORTS_TRIE
    0x80000034: (8,),                # LC_DYLD_CHAINED_FIXUPS
}
DYSYMTAB_OFFSET_FIELDS = (32, 40, 48, 56, 64, 72)

PAGE_SIZE = 0x4000

# nlist_64.n_type bits
N_SECT_TYPE = 0x0E
N_EXT_BIT = 0x01
LC_ID_DYLIB = 0x0D
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x1D
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_BUILD_VERSION = 0x32
LC_SYMTAB = 0x02
LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_FUNCTION_STARTS = 0x26

# section.flags & SECTION_TYPE. An initialiser recorded here is a 32-bit
# OFFSET FROM THE MACH HEADER rather than a pointer, which is why it is not
# carried by the chained fixups and why --reserve-header has to adjust it.
SECTION_TYPE = 0xFF
S_INIT_FUNC_OFFSETS = 0x16

# The macOS-only variant symbols iOS libc does not export, and the plain name
# that carries the same call with the older semantics. Only `syslog` is
# actually missing on iOS -- `realpath`, `fopen`, `popen`, `fdopen` and
# `select` all ship their $DARWIN_EXTSN forms.
# Stands in for "this import names no library". A flat-namespace binary
# (`-flat_namespace`) resolves every symbol across all loaded images, so there
# is no per-library attribution to check against.
FLAT_NAMESPACE = "<flat namespace>"

DARWIN_EXTSN_REDIRECTS = [("_syslog$DARWIN_EXTSN", "_syslog")]

# nlist_64.n_type bits, and the two-level-namespace library ordinal that lives
# in the top byte of n_desc.
N_STAB = 0xE0
N_TYPE = 0x0E
N_UNDF = 0x00
N_WEAK_REF = 0x0040     # the import may resolve to NULL rather than fail
SELF_LIBRARY_ORDINAL = 0
MAX_LIBRARY_ORDINAL = 0xFD

DYLIB_COMMANDS = {
    LC_ID_DYLIB,
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
}

VERSION_MIN_COMMANDS = {
    LC_VERSION_MIN_MACOSX: 1,
    LC_VERSION_MIN_IPHONEOS: 2,
    LC_VERSION_MIN_TVOS: 3,
    LC_VERSION_MIN_WATCHOS: 4,
}

PLATFORMS = {
    "macos": 1,
    "ios": 2,
    "tvos": 3,
    "watchos": 4,
    "bridgeos": 5,
    "maccatalyst": 6,
    "iossimulator": 7,
    "tvossimulator": 8,
    "watchossimulator": 9,
    "driverkit": 10,
    "visionos": 11,
    "visionossimulator": 12,
}
PLATFORM_NAMES = {v: k for k, v in PLATFORMS.items()}
PLATFORM_PRETTY = {
    1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS",
    6: "Mac Catalyst", 7: "iOS Simulator", 8: "tvOS Simulator",
    9: "watchOS Simulator", 10: "DriverKit", 11: "visionOS",
    12: "visionOS Simulator",
}

# Code signing blob magics (cs_blobs.h)
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172

LICENSE_TO_OPERATE = "research.com.apple.license-to-operate"


# dyld_chained_import formats. The entry size and the field widths BOTH change
# with the format, and getting either wrong silently yields nonsense ordinals:
#
#   1 DYLIB_CHAINED_IMPORT          4 bytes   u32: ord:8  weak:1  name:23
#   2 DYLIB_CHAINED_IMPORT_ADDEND   8 bytes   the same u32, then i32 addend
#   3 DYLIB_CHAINED_IMPORT_ADDEND64 16 bytes  u64: ord:16 weak:1 pad:15 name:32
#                                             then u64 addend
#
# Format 3 is 16 bytes, not 8 -- reading it as 8 walks off into the addends and
# produces library ordinals in the thousands (`dscl` decodes as ordinal 3589 of
# 6 dylibs). Only format 1 is common, which is exactly why the other two go
# unnoticed.
CHAINED_IMPORT_SIZES = {1: 4, 2: 8, 3: 16}


def chained_import_fields(data, off: int, ifmt: int) -> tuple[int, int, int]:
    """(library ordinal, weak_import, name offset) of one import entry."""
    if ifmt in (1, 2):
        v, = struct.unpack_from("<I", data, off)
        return v & 0xFF, (v >> 8) & 1, v >> 9
    if ifmt == 3:
        v, = struct.unpack_from("<Q", data, off)
        return v & 0xFFFF, (v >> 16) & 1, v >> 32
    raise MachOError(f"unknown chained imports format {ifmt}")


def set_chained_import_weak(data, off: int, ifmt: int) -> None:
    """Set weak_import on one import entry, in place."""
    if ifmt in (1, 2):
        v, = struct.unpack_from("<I", data, off)
        struct.pack_into("<I", data, off, v | (1 << 8))
    elif ifmt == 3:
        v, = struct.unpack_from("<Q", data, off)
        struct.pack_into("<Q", data, off, v | (1 << 16))
    else:
        raise MachOError(f"unknown chained imports format {ifmt}")


class MachOError(Exception):
    pass


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


def parse_version(text: str) -> tuple[int, int, int]:
    """'27', '27.1', '27.1.2' -> (27, 1, 2)."""
    parts = text.strip().split(".")
    if not 1 <= len(parts) <= 3:
        raise ValueError(f"version should be major[.minor[.micro]], got {text!r}")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        raise ValueError(f"version should be numeric, got {text!r}") from None
    while len(nums) < 3:
        nums.append(0)
    if not (0 <= nums[0] <= 0xFFFF and 0 <= nums[1] <= 0xFF and 0 <= nums[2] <= 0xFF):
        raise ValueError(f"version component out of range: {text!r}")
    return nums[0], nums[1], nums[2]


def encode_version(v: tuple[int, int, int]) -> int:
    return (v[0] << 16) | (v[1] << 8) | v[2]


def decode_version(raw: int) -> tuple[int, int, int]:
    return ((raw >> 16) & 0xFFFF, (raw >> 8) & 0xFF, raw & 0xFF)


def format_version(raw: int) -> str:
    maj, minor, micro = decode_version(raw)
    return f"{maj}.{minor}.{micro}"


# ---------------------------------------------------------------------------
# Fat / universal binaries  (replaces `lipo -thin`)
# ---------------------------------------------------------------------------


class Slice:
    def __init__(self, cputype: int, cpusubtype: int, offset: int, size: int):
        self.cputype = cputype
        self.cpusubtype = cpusubtype
        self.offset = offset
        self.size = size

    @property
    def arch(self) -> str:
        return arch_name(self.cputype, self.cpusubtype)


def arch_name(cputype: int, cpusubtype: int) -> str:
    key = (cputype, cpusubtype & ~CPU_SUBTYPE_MASK)
    return ARCH_NAMES.get(key, f"cpu{cputype}:{cpusubtype & ~CPU_SUBTYPE_MASK}")


def read_fat_slices(data: bytes) -> list[Slice] | None:
    """Return the slices of a fat binary, or None if `data` is not fat."""
    if len(data) < 8:
        return None
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return None
    is64 = magic == FAT_MAGIC_64
    nfat = struct.unpack_from(">I", data, 4)[0]
    entry_size = 32 if is64 else 20
    if 8 + nfat * entry_size > len(data):
        raise MachOError("truncated fat header")
    slices = []
    for i in range(nfat):
        off = 8 + i * entry_size
        if is64:
            cputype, cpusubtype, foff, fsize = struct.unpack_from(">iIQQ", data, off)
        else:
            cputype, cpusubtype, foff, fsize = struct.unpack_from(">iIII", data, off)
        if foff + fsize > len(data):
            raise MachOError(f"fat slice {i} extends past end of file")
        slices.append(Slice(cputype, cpusubtype & 0xFFFFFFFF, foff, fsize))
    return slices


def pick_slice(slices: list[Slice], wanted: str | None) -> Slice:
    if wanted:
        for s in slices:
            if s.arch == wanted:
                return s
        have = ", ".join(s.arch for s in slices)
        raise MachOError(f"no slice for architecture {wanted!r} (have: {have})")
    # Prefer the arm64e / arm64 slice: that is what an iPhone wants.
    for pref in ("arm64e", "arm64", "arm64_32"):
        for s in slices:
            if s.arch == pref:
                return s
    if len(slices) == 1:
        return slices[0]
    have = ", ".join(s.arch for s in slices)
    raise MachOError(f"ambiguous architecture, pass --arch (have: {have})")


def thin(data: bytes, wanted: str | None) -> tuple[bytes, str]:
    """Extract a single-architecture Mach-O from `data`."""
    slices = read_fat_slices(data)
    if slices is None:
        return data, "<thin>"
    s = pick_slice(slices, wanted)
    return data[s.offset:s.offset + s.size], s.arch


# ---------------------------------------------------------------------------
# Thin Mach-O
# ---------------------------------------------------------------------------


class LoadCommand:
    __slots__ = ("cmd", "data")

    def __init__(self, cmd: int, data: bytes):
        self.cmd = cmd
        self.data = bytearray(data)

    @property
    def cmdsize(self) -> int:
        return len(self.data)


class MachO:
    """A single-architecture Mach-O image held entirely in memory."""

    HEADER_FMT = "<IiIIIII"          # up to `flags`; 64-bit adds `reserved`

    def __init__(self, data: bytes):
        self.data = bytearray(data)
        if len(self.data) < 32:
            raise MachOError("file too small to be a Mach-O")
        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic in (MH_CIGAM_64, MH_CIGAM):
            raise MachOError(f"big-endian Mach-O is not supported (magic {magic:#x})")
        if magic == MH_MAGIC:
            raise MachOError("32-bit Mach-O is not supported")
        if magic != MH_MAGIC_64:
            raise MachOError(f"not a Mach-O (magic {magic:#010x})")
        (self.magic, self.cputype, self.cpusubtype, self.filetype,
         self.ncmds, self.sizeofcmds, self.flags) = struct.unpack_from(
            self.HEADER_FMT, self.data, 0)
        self.reserved = struct.unpack_from("<I", self.data, 28)[0]
        self.header_size = 32
        self.commands: list[LoadCommand] = []
        self._parse_commands()

    # -- parsing ----------------------------------------------------------

    def _parse_commands(self) -> None:
        off = self.header_size
        end = self.header_size + self.sizeofcmds
        if end > len(self.data):
            raise MachOError("load commands extend past end of file")
        for i in range(self.ncmds):
            if off + 8 > end:
                raise MachOError(f"load command {i} falls outside the header")
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmdsize < 8 or off + cmdsize > end:
                raise MachOError(f"load command {i} has a bogus size ({cmdsize})")
            self.commands.append(LoadCommand(cmd, self.data[off:off + cmdsize]))
            off += cmdsize

    # -- generic accessors -------------------------------------------------

    @property
    def arch(self) -> str:
        return arch_name(self.cputype, self.cpusubtype)

    def find(self, cmd: int) -> LoadCommand | None:
        for lc in self.commands:
            if lc.cmd == cmd:
                return lc
        return None

    def segments(self):
        """Yield (name, vmaddr, vmsize, fileoff, filesize, nsects, lc)."""
        for lc in self.commands:
            if lc.cmd != LC_SEGMENT_64:
                continue
            name = lc.data[8:24].split(b"\0")[0].decode("utf-8", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", lc.data, 24)
            nsects = struct.unpack_from("<I", lc.data, 64)[0]
            yield name, vmaddr, vmsize, fileoff, filesize, nsects, lc

    def header_capacity(self) -> int:
        """Bytes available for mach_header + load commands before real content."""
        lowest = None
        for name, _vmaddr, _vmsize, fileoff, filesize, nsects, lc in self.segments():
            # Section file offsets are the hard limit; a segment with fileoff 0
            # (__TEXT / __PAGEZERO) covers the header itself and does not count.
            for i in range(nsects):
                soff = 72 + i * 80
                sec_offset = struct.unpack_from("<I", lc.data, soff + 48)[0]
                sec_size = struct.unpack_from("<Q", lc.data, soff + 40)[0]
                if sec_size and sec_offset:
                    lowest = sec_offset if lowest is None else min(lowest, sec_offset)
            if fileoff and filesize:
                lowest = fileoff if lowest is None else min(lowest, fileoff)
        return lowest if lowest is not None else len(self.data)

    # -- platform / version (this is what cbv does) ------------------------

    def build_version(self) -> tuple[int, int, int] | None:
        """Return (platform, minos_raw, sdk_raw) from whichever LC carries it."""
        lc = self.find(LC_BUILD_VERSION)
        if lc is not None:
            platform, minos, sdk = struct.unpack_from("<III", lc.data, 8)
            return platform, minos, sdk
        for cmd, platform in VERSION_MIN_COMMANDS.items():
            lc = self.find(cmd)
            if lc is not None:
                version, sdk = struct.unpack_from("<II", lc.data, 8)
                return platform, version, sdk
        return None

    def set_platform(self, platform: int, version: tuple[int, int, int],
                     sdk: tuple[int, int, int] | None = None) -> None:
        """Retarget the image. Mirrors cbv, including its SDK-is-major-only rule."""
        minos_raw = encode_version(version)
        sdk_raw = encode_version(sdk) if sdk is not None else (version[0] << 16)

        builds = [c for c in self.commands if c.cmd == LC_BUILD_VERSION]
        if builds:
            struct.pack_into("<III", builds[0].data, 8,
                             platform, minos_raw, sdk_raw)
            # A library can declare more than one platform -- anything
            # macCatalyst-capable carries a second LC_BUILD_VERSION (platform 6)
            # beside the macOS one. Retargeting only the first leaves the other
            # in place, and dyld then rejects the image outright:
            #   "incompatible platforms: iOS - macCatalyst"
            # There is no ordinal tied to LC_BUILD_VERSION, so dropping the
            # extras is safe; the load-command area is rebuilt anyway.
            for extra in builds[1:]:
                self.commands.remove(extra)
            for cmd in VERSION_MIN_COMMANDS:
                stale = self.find(cmd)
                if stale is not None:
                    self.commands.remove(stale)
            return

        # No LC_BUILD_VERSION: retarget an old-style LC_VERSION_MIN_* in place if
        # the destination platform has one, otherwise convert it.
        for cmd in VERSION_MIN_COMMANDS:
            old = self.find(cmd)
            if old is None:
                continue
            new_cmd = next((c for c, p in VERSION_MIN_COMMANDS.items()
                            if p == platform), None)
            if new_cmd is not None:
                # version_min_command is 16 bytes; same layout for every platform.
                struct.pack_into("<IIII", old.data, 0, new_cmd, 16, minos_raw, sdk_raw)
            else:
                # Grow it into a 24-byte LC_BUILD_VERSION with ntools = 0.
                old.data = bytearray(struct.pack(
                    "<IIIIII", LC_BUILD_VERSION, 24, platform, minos_raw, sdk_raw, 0))
            return

        # Nothing at all: append a fresh LC_BUILD_VERSION.
        self.commands.append(LoadCommand(LC_BUILD_VERSION, struct.pack(
            "<IIIIII", LC_BUILD_VERSION, 24, platform, minos_raw, sdk_raw, 0)))

    def fix_data_const_flags(self) -> list[str]:
        """Put SG_READ_ONLY back on __DATA_CONST. Returns the segments fixed.

        dyld will not load a dylib whose __DATA_CONST segment lacks
        SG_READ_ONLY -- it fails with "__DATA_CONST segment missing
        SG_READ_ONLY flag". Images that live in a dyld shared cache do not
        carry the flag (the cache guarantees the protection itself), so a
        library pulled out of a cache with `ipsw dyld extract` comes out
        without it and cannot be loaded as a standalone file until it is
        restored.

        __AUTH_CONST is covered too. It only exists in cache images (an on-disk
        arm64e dylib has no such segment), so anything carrying one came out of
        a cache and is missing the flag for the same reason.
        """
        fixed = []
        for lc in self.commands:
            if lc.cmd != LC_SEGMENT_64:
                continue
            name = bytes(lc.data[8:24]).split(b"\0")[0].decode(
                "utf-8", "surrogateescape")
            if name not in ("__DATA_CONST", "__AUTH_CONST"):
                continue
            # segment_command_64: cmd, cmdsize, segname[16], vmaddr, vmsize,
            # fileoff, filesize (4 x uint64), maxprot, initprot, nsects, flags.
            flags_off = 8 + 16 + 8 * 4 + 4 * 3
            flags = struct.unpack_from("<I", lc.data, flags_off)[0]
            if flags & SG_READ_ONLY:
                continue
            struct.pack_into("<I", lc.data, flags_off, flags | SG_READ_ONLY)
            fixed.append(name)
        return fixed

    def fix_objc_imageinfo(self) -> tuple[int, int] | None:
        """Clear the dyld-optimisation markers in __objc_imageinfo.

        An ObjC image inside the shared cache advertises that the cache has
        pre-optimised it, and libobjc believes it: `getPreoptimizedHeaderRW()`
        looks the image up in the cache's preoptimized header tables by pointer
        arithmetic against the cache's own header array. A LIFTED image is not
        in that array, so the index is nonsense, the lookup returns a wild
        pointer, and `map_images` dereferences it -- SIGSEGV inside libobjc
        before main(), from a fault address like 0xfffffffe........

        The markers are two flag bits that a normally linked dylib does not
        have. Measured, on this Mac: a locally built ObjC dylib carries 0x50
        and the cache's DiskManagement carries 0x59, so the cache adds
        OPTIMIZED_BY_DYLD (1<<3) and (1<<0). Clearing exactly those two makes
        libobjc treat the image as the ordinary dylib it now is.

        Returns (old flags, new flags), or None if there is nothing to do.
        """
        for lc in self.commands:
            if lc.cmd != LC_SEGMENT_64:
                continue
            nsects = struct.unpack_from("<I", lc.data, 64)[0]
            for i in range(nsects):
                so = 72 + i * 80
                sect = bytes(lc.data[so:so + 16]).split(b"\0")[0]
                if sect != b"__objc_imageinfo":
                    continue
                off = struct.unpack_from("<I", lc.data, so + 48)[0]
                size = struct.unpack_from("<Q", lc.data, so + 40)[0]
                if size < 8 or off + 8 > len(self.data):
                    continue
                flags = struct.unpack_from("<I", self.data, off + 4)[0]
                new = flags & ~OBJC_IMAGE_DYLD_OPTIMISED
                if new == flags:
                    return None
                struct.pack_into("<I", self.data, off + 4, new)
                return flags, new
        return None

    def _segments(self) -> list[dict]:
        out = []
        for lc in self.commands:
            if lc.cmd != LC_SEGMENT_64:
                continue
            name = bytes(lc.data[8:24]).split(b"\0")[0].decode(
                "utf-8", "surrogateescape")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<4Q", lc.data, 24)
            out.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize,
                            fileoff=fileoff, filesize=filesize,
                            nsects=struct.unpack_from("<I", lc.data, 64)[0],
                            lc=lc))
        return out

    def exported_symbols(self, base: int) -> dict[str, int]:
        """Defined external symbols, as offsets from the image base."""
        symtab = self.find(LC_SYMTAB_CMD)
        if symtab is None:
            return {}
        _c, _s, symoff, nsyms, stroff, _ss = struct.unpack_from(
            "<6I", symtab.data, 0)
        out: dict[str, int] = {}
        for i in range(nsyms):
            off = symoff + i * 16
            if off + 16 > len(self.data):
                break
            n_strx, n_type = struct.unpack_from("<IB", self.data, off)
            n_value, = struct.unpack_from("<Q", self.data, off + 8)
            if n_type & N_STAB or not n_type & N_EXT_BIT:
                continue
            if (n_type & N_SECT_TYPE) != 0x0E or n_value == 0:
                continue
            end = self.data.find(b"\0", stroff + n_strx)
            if end < 0:
                continue
            name = bytes(self.data[stroff + n_strx:end]).decode(
                "utf-8", "surrogateescape")
            if name:
                out[name] = n_value - base
        return out

    def _all_symbols(self) -> dict[str, int]:
        """Every symbol with an address, name -> n_value. Local ones included,
        because `$tlv$init` markers are local."""
        symtab = self.find(LC_SYMTAB_CMD)
        if symtab is None:
            return {}
        _c, _s, symoff, nsyms, stroff, _ss = struct.unpack_from(
            "<6I", symtab.data, 0)
        out: dict[str, int] = {}
        for i in range(nsyms):
            off = symoff + i * 16
            if off + 16 > len(self.data):
                break
            n_strx, n_type = struct.unpack_from("<IB", self.data, off)
            n_value, = struct.unpack_from("<Q", self.data, off + 8)
            if n_type & N_STAB or n_value == 0:
                continue
            end = self.data.find(b"\0", stroff + n_strx)
            if end < 0:
                continue
            name = bytes(self.data[stroff + n_strx:end]).decode(
                "utf-8", "surrogateescape")
            if name:
                out.setdefault(name, n_value)
        return out

    def _section(self, want: bytes):
        """-> (addr, size, fileoff) of the first section with this name."""
        for lc in self.commands:
            if lc.cmd != LC_SEGMENT_64:
                continue
            nsects = struct.unpack_from("<I", lc.data, 64)[0]
            for i in range(nsects):
                so = 72 + i * 80
                if bytes(lc.data[so:so + 16]).split(b"\0")[0] != want:
                    continue
                addr, size = struct.unpack_from("<QQ", lc.data, so + 32)
                off = struct.unpack_from("<I", lc.data, so + 48)[0]
                return addr, size, off
        return None

    def malformed_tlv_descriptors(self) -> list[str]:
        """Descriptors a standalone dyld would reject. Read-only.

        The gate for fix_tlv_descriptors: dyld validates each `offset` against
        the TLV template span and aborts the process at load if one is out of
        range, so this must never reach a device.
        """
        tv = self._section(b"__thread_vars")
        if tv is None:
            return []
        tv_addr, tv_size, tv_off = tv
        data = self._section(b"__thread_data")
        bss = self._section(b"__thread_bss")
        present = [x for x in (data, bss) if x is not None]
        if not present:
            return ["__thread_vars with no template"]
        base = min(x[0] for x in present)
        total = max(x[0] + x[1] for x in present) - base
        out = []
        for i in range(tv_size // 24):
            off = tv_off + i * 24
            if off + 24 > len(self.data):
                break
            cur, = struct.unpack_from("<Q", self.data, off + 16)
            if not 0 <= cur < max(total, 1):
                out.append(f"descriptor at {tv_addr + i * 24:#x} has offset "
                           f"{cur:#x}, template is {total:#x} bytes")
        return out

    def fix_tlv_descriptors(self) -> tuple[int, list[str]]:
        """Rewrite __thread_vars so a standalone dyld will accept it.

        A thread-local descriptor is { thunk, key, offset }, three 64-bit words,
        and `offset` is the variable's position in the TLV template (which is
        __thread_data followed by __thread_bss). dyld validates it at load:

            failed to set up thread local variables for '...':
            malformed thread-local, offset=0xC800000000 is larger than
            total size=0xC8

        A cache image does not carry that layout. dyld fills both words in for
        a cache image from the cache's own TLV tables and never reads what is
        in the file, so the builder leaves its own bookkeeping there. Lift the
        image out and dyld reads them, and refuses.

        Measured over every image in the macOS shared cache that has
        `__thread_vars` -- 80 of 3649, holding 446 descriptors between them, of
        which **all 446** are malformed in exactly this way:

            key    = (the real offset << 32) | <the cache's TLV key index>
            offset = (the template size << 32) | <unused>

        So the cache records the answer, and both words are recoverable
        exactly rather than guessed at:

            offset = key >> 32

        Cross-checked against the linker's own local `<symbol>$tlv$init`
        marker, which sits at each variable's storage, so that

            offset = addr(<symbol>$tlv$init) - start of the TLV template

        The two agree on **233 of 233** descriptors across 45 images where the
        symbol survives. The symbol is preferred where it exists, because it is
        the linker's ground truth; `key >> 32` is what makes a **stripped**
        image repairable, and 213 of the 446 descriptors -- 35 of the 80 images
        -- have no such symbol and were previously left broken. A disagreement
        between the two has never been observed and is reported loudly, since
        it would mean one of these two assumptions had stopped holding.

        `offset >> 32` gives the cache's own record of the template size, which
        is an independent arbiter for the span computation below: it agrees with
        the span in 80 of 80 images, and with the sum of the section sizes in
        only 75.

        Returns (descriptors fixed, [complaints]). A descriptor whose offset can
        be recovered from neither source is left alone and reported.
        """
        tv = self._section(b"__thread_vars")
        if tv is None:
            return 0, []
        tv_addr, tv_size, tv_off = tv
        data = self._section(b"__thread_data")
        bss = self._section(b"__thread_bss")
        # The template is __thread_data then __thread_bss; either may be absent.
        starts = [x[0] for x in (data, bss) if x is not None]
        if not starts:
            return 0, ["__thread_vars with neither __thread_data nor __thread_bss"]
        base = min(starts)
        # The template is the SPAN from the first section to the end of the
        # last, not the sum of their sizes: __thread_bss is aligned after
        # __thread_data, and the gap counts. Summing sizes makes the template
        # look too small and condemns valid descriptors -- libLTO has five
        # whose offsets fall in exactly that gap.
        total = max(x[0] + x[1] for x in (data, bss) if x is not None) - base

        syms = self._all_symbols()
        by_addr: dict[int, list[str]] = {}
        for n, v in syms.items():
            by_addr.setdefault(v, []).append(n)

        fixed, notes = 0, []
        limit = max(total, 1)
        for i in range(tv_size // 24):
            desc_addr = tv_addr + i * 24
            off = tv_off + i * 24
            if off + 24 > len(self.data):
                break
            cur_key, cur_off = struct.unpack_from("<QQ", self.data, off + 8)
            if 0 <= cur_off < limit:
                continue        # already what a standalone dyld expects

            # The cache's own record of the template size, as an independent
            # check on the span computed above: the two agree in all 80 images
            # measured, and the sum of the section sizes agrees in only 75. A
            # disagreement means the cache's bookkeeping is not laid out the way
            # this code believes, so `key >> 32` cannot be trusted either -- but
            # the linker's own symbol still can, so only the fallback is barred.
            recorded = cur_off >> 32
            trust_cache = recorded == total

            names = by_addr.get(desc_addr, [])
            init = None
            for n in names:
                cand = syms.get(n + "$tlv$init")
                if cand is not None:
                    init = cand
                    break

            # Two independent sources, measured to agree on every descriptor
            # where both exist. The symbol is the linker's own ground truth, so
            # it wins; the cache's copy is what rescues a stripped image.
            from_sym = None if init is None else init - base
            from_cache = (cur_key >> 32) if trust_cache else None
            if (from_sym is not None and from_cache is not None
                    and 0 <= from_cache < limit and from_sym != from_cache):
                notes.append(
                    f"{names[0]}: $tlv$init says offset {from_sym:#x} but the "
                    f"cache says {from_cache:#x} -- using the symbol, but one "
                    f"of these two assumptions no longer holds")

            if from_sym is None and from_cache is None:
                notes.append(
                    f"the descriptor at {desc_addr:#x} has no $tlv$init, and "
                    f"the cache records a {recorded:#x}-byte template where the "
                    f"sections span {total:#x}, so its offset cannot be "
                    f"recovered; left as it is")
                continue

            value = from_sym if from_sym is not None else from_cache
            source = "$tlv$init" if from_sym is not None else "the cache's key"
            if not 0 <= value < limit:
                notes.append(f"{names[0] if names else f'descriptor at {desc_addr:#x}'}: "
                             f"offset {value:#x} from {source} is outside the "
                             f"{total:#x}-byte template; left as it is")
                continue
            # key is assigned by dyld at load; offset is what it validates.
            struct.pack_into("<QQ", self.data, off + 8, 0, value)
            fixed += 1
        return fixed, notes

    def _linkedit_regions(self) -> list[tuple[LoadCommand, int, int, int]]:
        """Every blob that lives in __LINKEDIT, as (command, offset field, size).

        Returned as (lc, offset_field_index, current_offset, byte_length).
        """
        out = []
        for lc in self.commands:
            if lc.cmd == LC_SYMTAB_CMD:
                _c, _s, symoff, nsyms, stroff, strsize = struct.unpack_from(
                    "<6I", lc.data, 0)
                if symoff:
                    out.append((lc, 8, symoff, nsyms * 16))
                if stroff:
                    out.append((lc, 16, stroff, strsize))
            elif lc.cmd == LC_DYSYMTAB:
                # (offset field, count field, element size)
                for off_f, cnt_f, esize in ((32, 36, 8), (40, 44, 56),
                                            (48, 52, 4), (56, 60, 4),
                                            (64, 68, 8), (72, 76, 8)):
                    off, = struct.unpack_from("<I", lc.data, off_f)
                    cnt, = struct.unpack_from("<I", lc.data, cnt_f)
                    if off and cnt:
                        out.append((lc, off_f, off, cnt * esize))
            elif lc.cmd in LINKEDIT_OFFSET_FIELDS and lc.cmd != LC_SYMTAB_CMD:
                if lc.cmd == LC_CODE_SIGNATURE:
                    continue                 # codesign rewrites this itself
                off, size = struct.unpack_from("<II", lc.data, 8)
                if off and size:
                    out.append((lc, 8, off, size))
        return out

    def rebuild_linkedit(self, extra: bytes = b"",
                         override: dict[int, bytes] | None = None
                         ) -> tuple[bytes, int, list]:
        """Repack __LINKEDIT with every table 8-byte aligned.

        dyld rejects a table that is not ("mis-aligned LINKEDIT content
        'function starts'"), and a cache extraction can arrive with tables that
        were never aligned to begin with -- so preserving their relative
        positions is not enough, they have to be moved. Each is addressed by an
        explicit (offset, size) pair in a load command, so relocating them is
        bookkeeping.

        LC_CODE_SIGNATURE is deliberately not carried over: the stale Apple
        signature is dead weight once anything has moved, and `codesign` writes
        a fresh ad-hoc one afterwards.

        *override* replaces one table's bytes, keyed by load-command id, and
        may change its length -- the size field beside the offset is rewritten
        to match. `LC_FUNCTION_STARTS` needs it: its first entry is an offset
        from the mach header, so --reserve-header changes it, and the new value
        does not always fit in the ULEB128 the old one used.

        Returns (blob, offset of *extra* within it, [(command, field) ...])
        where the offsets written into the commands are relative to the blob;
        the caller adds the file offset __LINKEDIT ends up at.
        """
        blob = bytearray()
        relocated = []
        for lc, field, off, size in sorted(self._linkedit_regions(),
                                           key=lambda r: r[2]):
            while len(blob) % 8:
                blob += b"\0"
            struct.pack_into("<I", lc.data, field, len(blob))
            relocated.append((lc, field))
            fresh = (override or {}).get(lc.cmd)
            if fresh is not None and lc.cmd != LC_SYMTAB_CMD:
                blob += fresh
                struct.pack_into("<I", lc.data, field + 4, len(fresh))
            else:
                blob += bytes(self.data[off:off + size])
        extra_off = -1
        if extra:
            while len(blob) % 8:
                blob += b"\0"
            extra_off = len(blob)
            blob += extra
        while len(blob) % 16:
            blob += b"\0"
        return bytes(blob), extra_off, relocated

    def header_relative_offsets(self, gap: int) -> dict[int, bytes]:
        """Add *gap* to everything stored as an offset from the mach header.

        `--reserve-header` lowers `__TEXT`'s vmaddr by whole pages and pushes
        the segment's contents the same distance further into the file, so every
        section keeps the address it had. That is the point of it -- an ADRP
        immediate cannot be rewritten. But it means the image base moves and the
        code does not, so anything recorded as a distance from the header is now
        that much too small.

        Two such things, and both were missed when the export trie (the third)
        was fixed:

        * `__init_offsets` (`S_INIT_FUNC_OFFSETS`), the modern spelling of
          `__mod_init_func`. A pointer-based `__mod_init_func` is covered by the
          chained fixups and comes out right; a 32-bit offset is not covered by
          anything. dyld calls `base + offset`, which lands a page short of the
          real initialiser -- **inside another function**, with garbage in every
          register. That is a SIGSEGV before `main()` in whatever loads the
          library: the lifted `LDAP` took `curl` and `sendmail` down that way,
          and nothing static reported it because the file is perfectly
          well-formed. The offsets are edited in place; they cannot change size.

        * `LC_FUNCTION_STARTS`, whose first ULEB128 is an offset from the header
          and whose later ones are deltas. Not fatal -- it is symbolication and
          unwind bookkeeping -- but a wrong one makes every crash report and
          every `dyld_info` reading of a lifted library subtly wrong, which is
          expensive in a different way. Returned as a replacement blob because
          the larger value may need one more byte than the old one used.
        """
        if not gap:
            return {}
        for seg in self._segments():
            for i in range(seg["nsects"]):
                sec = 72 + i * 80
                flags, = struct.unpack_from("<I", seg["lc"].data, sec + 64)
                if flags & SECTION_TYPE != S_INIT_FUNC_OFFSETS:
                    continue
                addr, size = struct.unpack_from("<QQ", seg["lc"].data, sec + 32)
                off, = struct.unpack_from("<I", seg["lc"].data, sec + 48)
                for k in range(size // 4):
                    at = off + k * 4
                    value, = struct.unpack_from("<I", self.data, at)
                    struct.pack_into("<I", self.data, at, value + gap)

        starts = self.find(LC_FUNCTION_STARTS)
        if starts is None:
            return {}
        off, size = struct.unpack_from("<II", starts.data, 8)
        if not off or not size:
            return {}
        blob = bytes(self.data[off:off + size])
        try:
            first, after = _uleb(blob, 0)
        except MachOError:
            return {}
        if not first:
            return {}
        return {LC_FUNCTION_STARTS: _uleb128(first + gap) + blob[after:]}

    def stray_header_offsets(self) -> list[str]:
        """Base-relative offsets that do not land in an executable section.

        The gate for `header_relative_offsets()`, and the reason it exists is
        that nothing else notices. An image whose `__init_offsets` entry is a
        page short is perfectly well-formed: it parses, it signs, `codesign
        --verify` passes, `dyld_info` reads it happily -- and dyld calls into the
        middle of an unrelated function before `main()`. The lifted `LDAP`
        shipped that way and took `curl` and `sendmail` down with a SIGSEGV
        inside `memchr`, five frames under `findAndRunAllInitializers`.

        Worth knowing why it hid so well: `LC_FUNCTION_STARTS` is base-relative
        too and was wrong by the same amount, so the bad initialiser address
        landed on what `dyld_info` reported as a function start. The two errors
        agreed with each other.

        The `LC_FUNCTION_STARTS` check is the sharper one, and it is free: the
        first entry of a real linker's output is the first function in `__text`,
        so if it does not even land inside `__text` the encoding has been moved
        out from under it.
        """
        out = []
        exec_ranges = []
        for seg in self._segments():
            for i in range(seg["nsects"]):
                sec = 72 + i * 80
                name = bytes(seg["lc"].data[sec:sec + 16]).rstrip(b"\0")
                addr, size = struct.unpack_from("<QQ", seg["lc"].data, sec + 32)
                flags, = struct.unpack_from("<I", seg["lc"].data, sec + 64)
                if name == b"__text" or flags & 0x80000400 == 0x80000400:
                    exec_ranges.append((addr, addr + size))
        if not exec_ranges:
            return out
        # The mach header's own address, which is __TEXT's -- not segments[0],
        # which in a main executable is __PAGEZERO at 0 and made this report
        # every binary on the system.
        text = next((s for s in self._segments() if s["name"] == "__TEXT"), None)
        if text is None:
            return out
        base = text["vmaddr"]
        for seg in self._segments():
            for i in range(seg["nsects"]):
                sec = 72 + i * 80
                flags, = struct.unpack_from("<I", seg["lc"].data, sec + 64)
                if flags & SECTION_TYPE != S_INIT_FUNC_OFFSETS:
                    continue
                _addr, size = struct.unpack_from("<QQ", seg["lc"].data, sec + 32)
                off, = struct.unpack_from("<I", seg["lc"].data, sec + 48)
                for k in range(size // 4):
                    value, = struct.unpack_from("<I", self.data, off + k * 4)
                    at = base + value
                    if not any(lo <= at < hi for lo, hi in exec_ranges):
                        out.append(f"__init_offsets[{k}] = {value:#x} -> "
                                   f"{at:#x}, which is in no executable section")

        starts = self.find(LC_FUNCTION_STARTS)
        if starts is not None:
            off, size = struct.unpack_from("<II", starts.data, 8)
            if off and size:
                try:
                    first, _ = _uleb(bytes(self.data[off:off + size]), 0)
                except MachOError:
                    first = 0
                if first and not any(lo <= base + first < hi
                                     for lo, hi in exec_ranges):
                    out.append(f"LC_FUNCTION_STARTS starts at {base + first:#x}, "
                               f"which is in no executable section")
        return out

    def needs_relayout(self) -> bool:
        """True if this image is a shared-cache extraction dyld cannot map.

        Three ways to fail, and the third was found by a device rejecting a
        library the other two said was fine:

        1. segments out of VM order -- cache images share pages, so `__AUTH`
           can sit below `__DATA_CONST`;
        2. a segment start that is not page aligned -- likewise;
        3. **a mapped segment whose FILESIZE is not page aligned**, so the
           segments do not tile the file and the signature ends up covering
           file pages no segment claims. Only the kernel checks that, and it
           says `code signature invalid ... (errno=1)`, which reads as a trust
           problem; `codesign --verify` passes happily.

        The third case is what a small umbrella framework looks like:
        `libHeimdalProxy`, `ApplicationServices` and `Cocoa` have only `__TEXT`
        and `__LINKEDIT`, both already page-aligned and in order, so 1 and 2
        said nothing and the relayout never ran -- leaving `__TEXT` at a
        filesize of 0x3f8. dyld then refused `libHeimdalProxy`, taking curl,
        ssh-add, ssh-keygen and ssh-keyscan down with it.
        """
        segs = self._segments()
        if not segs:
            return False
        addrs = [s["vmaddr"] for s in segs]
        if addrs != sorted(addrs) or any(a % PAGE_SIZE for a in addrs):
            return True
        # __LINKEDIT is last and keeps its exact size, as in a normal dylib.
        return any(s["filesize"] % PAGE_SIZE for s in segs[:-1]
                   if s["filesize"])

    def relayout_for_standalone(self, reserve: int = 0) -> tuple[int, int]:
        """Turn a cache extraction into something dyld will load.

        Returns (segments moved, exports rebuilt). No code or data changes
        address: segments are only grown backwards to a page boundary, so every
        PC-relative reference and every chained fixup stays valid. __LINKEDIT is
        repacked so each of its tables is 8-byte aligned, which dyld requires
        and a cache extraction does not always satisfy, and the stale Apple
        signature blob is dropped on the way -- `codesign` writes a fresh
        ad-hoc one afterwards.
        """
        segs = self._segments()
        text = next((s for s in segs if s["name"] == "__TEXT"), None)
        linkedit = next((s for s in segs if s["name"] == "__LINKEDIT"), None)
        if text is None or linkedit is None:
            return 0, 0

        base = text["vmaddr"]

        # Room for load commands we have not added yet -- LC_DYLD_CHAINED_FIXUPS,
        # synthesised by dsc_rebind after this runs. A cache extraction usually
        # has only a few dozen spare bytes between its load commands and its
        # first section, and a section cannot simply move: its address is baked
        # into every ADRP that reaches it.
        #
        # So __TEXT grows DOWNWARD instead. Lower the segment's vmaddr by whole
        # pages, keep the mach header at file offset 0 (dyld requires the header
        # at the segment base), and put the new slack after the load commands.
        # Section contents then sit that many bytes further into the segment,
        # which is exactly the amount the segment base moved -- so every section
        # keeps the address it had.
        text_gap = 0
        if reserve:
            _nc, socmds = struct.unpack_from("<II", self.data, 16)
            need = 32 + socmds + reserve
            nsects = struct.unpack_from("<I", text["lc"].data, 64)[0]
            offs = [struct.unpack_from("<I", text["lc"].data, 72 + i * 80 + 48)[0]
                    for i in range(nsects)]
            offs = [o for o in offs if o]
            first = min(offs) if offs else need
            while first + text_gap < need:
                text_gap += PAGE_SIZE
            if text_gap:
                text["vmaddr"] -= text_gap
                text["vmsize"] += text_gap

        # The export trie stores offsets from the image base, and text_gap moves
        # that base down -- so it has to be known before the trie is built.
        # Getting this order wrong puts every exported symbol one page early,
        # which dlsym reports without complaint and which then calls into the
        # middle of some other function.
        # Everything stored as a distance from the mach header has to grow by
        # text_gap, because the base moved and the code did not. The export trie
        # below is one; __init_offsets and LC_FUNCTION_STARTS are the others.
        override = self.header_relative_offsets(text_gap)

        exports = self.exported_symbols(base - text_gap)
        trie_lc = self.find(LC_DYLD_EXPORTS_TRIE)
        rebuild_trie = (trie_lc is not None and exports
                        and struct.unpack_from("<I", trie_lc.data, 12)[0] == 0)
        trie = build_export_trie(exports) if rebuild_trie else b""

        shift = base % PAGE_SIZE
        for seg in segs:
            seg["vmaddr"] -= shift

        # The symbol table records absolute addresses, so it follows the shift.
        # This has to happen before __LINKEDIT is repacked, which copies it.
        symtab = self.find(LC_SYMTAB_CMD)
        if symtab is not None and shift:
            _c, _s, symoff, nsyms, _so, _ss = struct.unpack_from(
                "<6I", symtab.data, 0)
            for i in range(nsyms):
                off = symoff + i * 16
                n_type, = struct.unpack_from("<B", self.data, off + 4)
                n_value, = struct.unpack_from("<Q", self.data, off + 8)
                if not n_type & N_STAB and n_value:
                    struct.pack_into("<Q", self.data, off + 8, n_value - shift)

        new_linkedit, trie_off, relocated = self.rebuild_linkedit(trie, override)

        order = sorted(segs, key=lambda s: s["vmaddr"])
        old = bytes(self.data)

        out = bytearray()
        linkedit_base = 0
        for seg in order:
            pad = seg["vmaddr"] % PAGE_SIZE
            seg["vmaddr"] -= pad
            seg["vmsize"] += pad
            while len(out) % PAGE_SIZE:
                out += b"\0"          # every segment starts on a page
            new_fileoff = len(out)
            # A segment's contents must sit at the same offset from its file
            # start as from its vm start, because that is the only thing that
            # makes a section's recorded vmaddr agree with its recorded file
            # offset once dyld maps file[fileoff, +filesize) at vmaddr.
            #
            # An earlier version padded here to keep the file-offset delta a
            # multiple of 16, on the theory that this preserved the alignment
            # of the segment's contents. It did the opposite: vm addresses do
            # not move at all in this relayout (only the uniform page `shift`,
            # itself a multiple of 16), so their alignment was never at risk,
            # while the extra padding displaced every non-__TEXT segment's
            # bytes by 8 relative to its own section table. Nothing complained
            # -- dlopen and codesign are both happy -- but every data address
            # the code computed was then off by 8. It is what made the
            # synthesised chained fixups read the wrong slots, and it is why a
            # cache-extracted library could work on one path and not another.
            #
            # __LINKEDIT is exempt because it is repacked from scratch and its
            # contents carry their own alignment; it must start exactly at the
            # page boundary.
            seg["delta"] = new_fileoff + pad - seg["fileoff"]
            out += b"\0" * pad
            if seg["name"] == "__LINKEDIT":
                linkedit_base = len(out)
                out += new_linkedit
                # the segment starts at new_fileoff, the content after the pad
                seg["filesize"] = pad + len(new_linkedit)
                seg["vmsize"] = pad + len(new_linkedit)
            elif seg is text and text_gap:
                _nc, socmds = struct.unpack_from("<II", old, 16)
                hdr_end = 32 + socmds
                out += old[seg["fileoff"]:seg["fileoff"] + hdr_end]
                out += b"\0" * text_gap
                out += old[seg["fileoff"] + hdr_end:
                           seg["fileoff"] + seg["filesize"]]
                seg["delta"] += text_gap
                seg["filesize"] += pad + text_gap
                seg["filesize"] = ((seg["filesize"] + PAGE_SIZE - 1)
                                   & ~(PAGE_SIZE - 1))
            else:
                out += old[seg["fileoff"]:seg["fileoff"] + seg["filesize"]]
                seg["filesize"] += pad
                # A mapped segment's file range must be a whole number of
                # pages, so the segments tile the file with no gaps. A normal
                # dylib is laid out that way; leaving the tail short means file
                # pages that the code signature covers but no segment claims,
                # and the kernel refuses the signature ("code signature
                # invalid", errno=1) even though codesign(1) is happy with it.
                seg["filesize"] = ((seg["filesize"] + PAGE_SIZE - 1)
                                   & ~(PAGE_SIZE - 1))
            seg["fileoff"] = new_fileoff
            seg["vmsize"] = (seg["vmsize"] + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)

        # The repack wrote blob-relative offsets; make them file offsets.
        for lc, field in relocated:
            value, = struct.unpack_from("<I", lc.data, field)
            struct.pack_into("<I", lc.data, field, value + linkedit_base)
        if trie:
            struct.pack_into("<II", trie_lc.data, 8,
                             linkedit_base + trie_off, len(trie))

        for seg in order:
            struct.pack_into("<4Q", seg["lc"].data, 24, seg["vmaddr"],
                             seg["vmsize"], seg["fileoff"], seg["filesize"])
            if seg["name"] == "__LINKEDIT":
                continue
            for i in range(seg["nsects"]):
                sec = 72 + i * 80
                addr, = struct.unpack_from("<Q", seg["lc"].data, sec + 32)
                struct.pack_into("<Q", seg["lc"].data, sec + 32, addr - shift)
                off, = struct.unpack_from("<I", seg["lc"].data, sec + 48)
                if off:
                    struct.pack_into("<I", seg["lc"].data, sec + 48,
                                     off + seg["delta"])

        positions = [self.commands.index(s["lc"]) for s in segs]
        for pos, seg in zip(positions, order):
            self.commands[pos] = seg["lc"]
        self.data = out
        return len(order), len(exports) if trie else 0

    def fix_cpusubtype(self, platform: int) -> int | None:
        """arm64e ptrauth ABI fixup. Returns the new subtype if changed."""
        if self.cputype != CPU_TYPE_ARM64:
            return None
        if (self.cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E:
            return None
        if platform in (1, 6):  # macOS / Mac Catalyst
            # PTRAUTH version 0 gets the process killed by XNU on macOS.
            new = (self.cpusubtype & ~CPU_SUBTYPE_ARM64E_VERSION_MASK)
            new |= CPU_SUBTYPE_ARM64E_MACOS
        else:
            # Devices expect the unversioned (0) ptrauth ABI.
            new = (self.cpusubtype & ~CPU_SUBTYPE_ARM64E_VERSION_MASK)
            new |= CPU_SUBTYPE_PTRAUTH_ABI
        new &= 0xFFFFFFFF
        if new == self.cpusubtype:
            return None
        self.cpusubtype = new
        return new

    # -- dylib / rpath paths (this is what install_name_tool does) ---------

    def _path_field_offset(self, lc: LoadCommand) -> int | None:
        if lc.cmd in DYLIB_COMMANDS:
            return 8
        if lc.cmd == LC_RPATH:
            return 8
        return None

    def paths(self) -> list[tuple[LoadCommand, str]]:
        out = []
        for lc in self.commands:
            off = self._path_field_offset(lc)
            if off is None:
                continue
            str_off = struct.unpack_from("<I", lc.data, off)[0]
            if not 0 < str_off < len(lc.data):
                continue
            raw = bytes(lc.data[str_off:]).split(b"\0")[0]
            out.append((lc, raw.decode("utf-8", "surrogateescape")))
        return out

    def set_path(self, lc: LoadCommand, new_path: str) -> None:
        """Rewrite the trailing string of a dylib/rpath load command."""
        off = self._path_field_offset(lc)
        assert off is not None
        str_off = struct.unpack_from("<I", lc.data, off)[0]
        head = bytes(lc.data[:str_off])
        blob = new_path.encode("utf-8", "surrogateescape") + b"\0"
        size = str_off + len(blob)
        size = (size + 7) & ~7
        new = bytearray(size)
        new[:len(head)] = head
        new[str_off:str_off + len(blob)] = blob
        struct.pack_into("<I", new, 4, size)
        lc.data = new

    def weaken(self, lc: LoadCommand) -> bool:
        """Turn LC_LOAD_DYLIB into LC_LOAD_WEAK_DYLIB.

        dyld tolerates a weak dylib being absent: the image still launches and
        every symbol imported from it binds to NULL. That turns a hard launch
        failure into a crash only if the code actually calls one of them --
        which for a conditionally-used library is often never.

        Note this *rewrites* the command rather than deleting it, and that is
        deliberate: chained-fixup binds address their library by ORDINAL (its
        1-based position among the dylib load commands), so removing one
        silently re-points every later import at the wrong library. Weakening
        keeps every ordinal exactly where it was.
        """
        if lc.cmd != LC_LOAD_DYLIB:
            return False
        lc.cmd = LC_LOAD_WEAK_DYLIB
        struct.pack_into("<I", lc.data, 0, LC_LOAD_WEAK_DYLIB)
        return True

    def dylib_commands(self) -> list[LoadCommand]:
        """The dylib load commands, in the order that defines their ordinals."""
        return [lc for lc in self.commands if lc.cmd in DYLIB_COMMANDS
                and lc.cmd != LC_ID_DYLIB]

    def undefined_symbols(self):
        """Every undefined `nlist_64`, as (entry offset, name, n_desc).

        Four callers walked this table with their own copy of the same loop --
        `imports_by_library`, `weak_ref_symbols`, `sync_weak_imports` and
        `weaken_symbol` -- each re-deriving N_WEAK_REF and the N_STAB/N_TYPE
        filtering. One place to get it wrong is enough.

        The entry offset is yielded so a caller can write `n_desc` back.
        """
        st = self.find(LC_SYMTAB_CMD)
        if st is None:
            return
        _c, _s, symoff, nsyms, stroff, strsize = struct.unpack_from(
            "<6I", st.data, 0)
        if not symoff or symoff + nsyms * 16 > len(self.data):
            return
        if stroff + strsize > len(self.data):
            return
        for i in range(nsyms):
            off = symoff + i * 16
            n_strx, n_type, _sect, n_desc = struct.unpack_from(
                "<IBBH", self.data, off)
            if n_type & N_STAB or (n_type & N_TYPE) != N_UNDF:
                continue
            end = self.data.find(b"\0", stroff + n_strx)
            if end < 0:
                continue
            yield off, bytes(self.data[stroff + n_strx:end]).decode(
                "utf-8", "surrogateescape"), n_desc

    def imports_by_library(self) -> dict[str, list[str]]:
        """Which symbols this image imports from which library.

        Read from the classic symbol table: every undefined `nlist_64` carries
        a 1-based library ordinal in the top byte of `n_desc`, indexing the
        dylib load commands. That is still present in chained-fixup binaries,
        and it is far less work than walking the fixup chains.
        """
        dylibs = self.dylib_commands()
        names: list[str | None] = []
        for lc in dylibs:
            found = None
            for lc2, path in self.paths():
                if lc2 is lc:
                    found = path
                    break
            names.append(found)

        out: dict[str, list[str]] = {}
        for _off, sym, n_desc in self.undefined_symbols():
            ordinal = (n_desc >> 8) & 0xFF
            if not SELF_LIBRARY_ORDINAL < ordinal <= MAX_LIBRARY_ORDINAL:
                continue                      # self, dynamic lookup, executable
            if ordinal > len(names) or names[ordinal - 1] is None:
                continue
            out.setdefault(names[ordinal - 1], []).append(sym)
        return {k: sorted(set(v)) for k, v in out.items()}

    # -- redirecting an import to a differently-named symbol -----------------

    def _symbol_string_regions(self) -> list[tuple[str, int, int]]:
        """Where imported symbol names are spelled, as (what, offset, size).

        Two places, both inside __LINKEDIT, and both have to agree:

        * the LC_SYMTAB string table -- what `nm` reads, and what the library
          ordinal in each undefined nlist_64's n_desc is paired with;
        * the symbols pool of LC_DYLD_CHAINED_FIXUPS -- what dyld actually
          binds through, and therefore what decides whether the process
          launches at all.
        """
        out = []
        symtab = self.find(LC_SYMTAB_CMD)
        if symtab is not None:
            _c, _s, _symoff, _nsyms, stroff, strsize = struct.unpack_from(
                "<6I", symtab.data, 0)
            if stroff and strsize:
                out.append(("symbol table", stroff, strsize))

        lc = self.find(LC_DYLD_CHAINED_FIXUPS)
        if lc is not None:
            dataoff, datasize = struct.unpack_from("<II", lc.data, 8)
            if dataoff and datasize >= 28:
                (_ver, _starts, _imports, symbols_off, _icount, _ifmt,
                 symbols_format) = struct.unpack_from(
                    "<7I", self.data, dataoff)
                if symbols_format != 0:
                    raise MachOError(
                        "the chained-fixups symbol pool is compressed "
                        f"(symbols_format={symbols_format}); a name cannot be "
                        "edited in place")
                if symbols_off < datasize:
                    out.append(("chained fixups", dataoff + symbols_off,
                                datasize - symbols_off))
        return out

    def _referenced_string_offsets(self) -> dict[str, set[int]]:
        """Every file offset some table points at as the start of a name.

        Used to refuse an edit that would truncate a neighbour: string tables
        are free to overlap names by sharing a suffix, and quietly clobbering
        one would be a miserable bug to find later.
        """
        out: dict[str, set[int]] = {"symbol table": set(),
                                    "chained fixups": set()}

        symtab = self.find(LC_SYMTAB_CMD)
        if symtab is not None:
            _c, _s, symoff, nsyms, stroff, strsize = struct.unpack_from(
                "<6I", symtab.data, 0)
            if symoff and stroff and symoff + nsyms * 16 <= len(self.data):
                for i in range(nsyms):
                    n_strx, = struct.unpack_from("<I", self.data,
                                                 symoff + i * 16)
                    out["symbol table"].add(stroff + n_strx)

        lc = self.find(LC_DYLD_CHAINED_FIXUPS)
        if lc is not None:
            dataoff, datasize = struct.unpack_from("<II", lc.data, 8)
            if dataoff and datasize >= 28:
                (_ver, _starts, imports_off, symbols_off, icount, ifmt,
                 _sfmt) = struct.unpack_from("<7I", self.data, dataoff)
                esize = CHAINED_IMPORT_SIZES.get(ifmt)
                for k in range(icount if esize else 0):
                    e = dataoff + imports_off + k * esize
                    if e + esize > dataoff + datasize:
                        break
                    _ord, _w, name_off = chained_import_fields(
                        self.data, e, ifmt)
                    out["chained fixups"].add(dataoff + symbols_off + name_off)
        return out

    def redirect_symbol(self, old: str, new: str) -> list[str]:
        """Rename an imported symbol in place, in every table that spells it.

        The point is to reach a symbol the target platform actually exports
        without moving a single byte: `_syslog$DARWIN_EXTSN` is absent from
        iOS libc while plain `_syslog` is present, and the shorter name fits
        inside the longer one's storage. Because both live in the same
        library, the two-level-namespace ordinal is unchanged -- which is the
        entire reason this is a string edit and not a relink.

        Returns a note per region patched; an empty list means the binary does
        not import `old` at all.
        """
        old_b = old.encode()
        new_b = new.encode()
        if len(new_b) > len(old_b):
            raise MachOError(
                f"{new!r} is longer than {old!r} ({len(new_b)} > "
                f"{len(old_b)} bytes), so it cannot be written in place")

        # An old-style bind opcode stream spells names inline, and the stream
        # is parsed sequentially: NUL-padding a shortened name there would be
        # read as BIND_OPCODE_DONE and silently truncate the binds. Refuse
        # rather than corrupt. (No binary measured here uses one -- every
        # importer of _syslog$DARWIN_EXTSN has chained fixups.)
        for cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            lc = self.find(cmd)
            if lc is None:
                continue
            for field in (32, 40, 48):        # bind, weak bind, lazy bind
                off, size = struct.unpack_from("<II", lc.data, field)
                if off and size and old_b in bytes(
                        self.data[off:off + size]):
                    raise MachOError(
                        f"{old} is spelled inside an LC_DYLD_INFO bind opcode "
                        "stream, which cannot be shortened in place")

        referenced = self._referenced_string_offsets()
        notes = []
        for what, start, size in self._symbol_string_regions():
            region = bytes(self.data[start:start + size])
            hits = []
            pos = region.find(old_b)
            while pos >= 0:
                # Only a whole, NUL-terminated string counts, so that a name
                # merely ending in `old` can never be hit.
                if ((pos == 0 or region[pos - 1] == 0)
                        and region[pos + len(old_b):pos + len(old_b) + 1]
                        == b"\0"):
                    hits.append(pos)
                pos = region.find(old_b, pos + 1)

            for pos in hits:
                lo = start + pos
                hi = lo + len(old_b)          # the NUL itself may be reused
                clash = sorted(o for o in referenced[what] if lo < o <= hi)
                if clash:
                    raise MachOError(
                        f"refusing to rename {old}: another symbol in the "
                        f"{what} starts at "
                        f"{', '.join(hex(c) for c in clash)}, inside the "
                        f"bytes {new} would overwrite (names share suffixes)")
                self.data[lo:lo + len(new_b)] = new_b
                self.data[lo + len(new_b):hi + 1] = b"\0" * (
                    len(old_b) - len(new_b) + 1)
                notes.append(f"{what} at {lo:#x}")
        return notes

    def sync_weak_imports(self) -> tuple[int, list[str]]:
        """Make the chained-imports weak flags agree with the symbol table.

        A weak reference is permission for a symbol to end up NULL: if its
        library is absent, or present without it, dyld binds zero and carries
        on rather than failing the load. That permission is recorded twice --

            nlist_64.n_desc & N_WEAK_REF       what `nm -mu` prints
            dyld_chained_import.weak_import    what dyld actually reads

        -- and a synthesised import table can carry the first without the
        second. `dsc_rebind` did exactly that, so every weak import in a lifted
        library became a hard one. The symptom is a launch-time
        `Symbol not found: X, Expected in: <no uuid> unknown` naming a symbol
        from a weak-linked library the target legitimately does not have: the
        lifted libcurl weak-links Kerberos, iOS ships none, and
        `_GSS_C_NT_HOSTBASED_SERVICE` killed curl before main().

        Matched on (name, library ordinal), never on the name alone. The same
        name legitimately appears more than once in an imports table -- Apple's
        own `codesign` carries three entries for one Swift dispatch thunk, and
        `appleh13camerad` fourteen for `_CreateISPEmulator` -- and those
        entries may differ in exactly this flag. Keying on the name alone would
        flip a deliberately-hard import in an untouched Apple binary.

        Only ever *adds* the weak bit, and only where the symbol table already
        says weak for that same library -- it never makes a hard import weak on
        its own guess. Returns (how many entries changed, their names).
        """
        lc = self.find(LC_DYLD_CHAINED_FIXUPS)
        if lc is None:
            return 0, []
        dataoff, datasize = struct.unpack_from("<II", lc.data, 8)
        if not dataoff or datasize < 28:
            return 0, []
        (_ver, _starts, imports_off, symbols_off, icount, ifmt,
         _sfmt) = struct.unpack_from("<7I", self.data, dataoff)
        esize = CHAINED_IMPORT_SIZES.get(ifmt)
        if esize is None:
            raise MachOError(f"unknown chained imports format {ifmt}")

        # Which (symbol, library ordinal) pairs the symbol table marks weak.
        weak = {(name, (n_desc >> 8) & 0xFF)
                for _off, name, n_desc in self.undefined_symbols()
                if n_desc & N_WEAK_REF}

        changed = []
        for k in range(icount):
            e = dataoff + imports_off + k * esize
            if e + esize > dataoff + datasize:
                break
            ordinal, is_weak, name_off = chained_import_fields(
                self.data, e, ifmt)
            end = self.data.find(b"\0", dataoff + symbols_off + name_off)
            if end < 0:
                continue
            name = bytes(self.data[dataoff + symbols_off + name_off:end]).decode(
                "utf-8", "surrogateescape")
            if is_weak or (name, ordinal) not in weak:
                continue
            set_chained_import_weak(self.data, e, ifmt)
            changed.append(name)
        return len(changed), changed

    def weaken_symbol(self, name: str) -> tuple[int, int]:
        """Mark one imported symbol weak, in both tables that record it.

        A weak import is allowed to resolve to NULL: dyld binds zero and lets
        the process start, instead of killing it at launch with `Symbol not
        found`. That is the only lever available when the target genuinely does
        not export a symbol and there is nowhere else to get it -- iOS has no
        `SecItemImport`, and no library can be bundled to supply it, because
        the import is bound in the two-level namespace to Security.framework
        specifically.

        **This trades a certain failure for a conditional one.** The binary
        loads and every path that does not touch the symbol works; a path that
        calls it dereferences NULL and crashes. Only do this for a symbol on a
        path the tool does not need -- and say which path in the commit
        message, because the crash will look nothing like a linking problem.

        Returns (symbol-table entries changed, chained-import entries changed).
        A symbol that is already weak, or is not imported at all, changes
        nothing and is not an error.
        """
        want = name.encode()

        # 1. the symbol table, and the ordinals of the entries we touch, so the
        #    chained-imports pass matches the same (name, library) pairs.
        ordinals: set[int] = set()
        n_sym = 0
        for off, sym, n_desc in self.undefined_symbols():
            if sym != name:
                continue
            ordinals.add((n_desc >> 8) & 0xFF)
            if not (n_desc & N_WEAK_REF):
                struct.pack_into("<H", self.data, off + 6,
                                 n_desc | N_WEAK_REF)
                n_sym += 1

        # 2. the chained-imports table, which is what dyld reads.
        n_imp = 0
        lc = self.find(LC_DYLD_CHAINED_FIXUPS)
        if lc is not None:
            dataoff, datasize = struct.unpack_from("<II", lc.data, 8)
            if dataoff and datasize >= 28:
                (_v, _st, imports_off, symbols_off, icount, ifmt,
                 _sf) = struct.unpack_from("<7I", self.data, dataoff)
                esize = CHAINED_IMPORT_SIZES.get(ifmt)
                for k in range(icount if esize else 0):
                    e = dataoff + imports_off + k * esize
                    if e + esize > dataoff + datasize:
                        break
                    ordinal, is_weak, noff = chained_import_fields(
                        self.data, e, ifmt)
                    end = self.data.find(b"\0", dataoff + symbols_off + noff)
                    if end < 0:
                        continue
                    if bytes(self.data[dataoff + symbols_off + noff:end]) != want:
                        continue
                    # Same (name, library) pair the symbol table named.
                    if ordinals and ordinal not in ordinals:
                        continue
                    if is_weak:
                        continue
                    set_chained_import_weak(self.data, e, ifmt)
                    n_imp += 1
        return n_sym, n_imp

    def bound_imports(self) -> dict[str, list[tuple[str, bool]]]:
        """Every bind dyld will actually perform: library -> [(symbol, weak)].

        Where the image has chained fixups, that table is the authority in both
        directions, and both matter:

        * it lists every bind dyld performs. An undefined `nlist_64` with no
          entry here is never resolved and cannot fail the load -- Apple's own
          `swift-inspect` carries an undefined, absent
          `__swift_FORCE_LOAD_$_swiftIOKit` (a Swift autolink marker) and runs
          fine on iOS, as does `appleh13camerad` with three absent
          `AppleISPEmulator` constants.
        * its `weak_import` bit, NOT the symbol table's `N_WEAK_REF`, is what
          lets a bind resolve to NULL. The two disagree in real binaries:
          `swift-inspect` marks 8 weak in the symbol table and 1 here.

        Falls back to the symbol table for an image with no chained fixups.
        """
        lc = self.find(LC_DYLD_CHAINED_FIXUPS)
        if lc is None:
            weak = self.weak_ref_symbols()
            return {lib: [(s, s in weak) for s in syms]
                    for lib, syms in self.imports_by_library().items()}

        dataoff, datasize = struct.unpack_from("<II", lc.data, 8)
        if not dataoff or datasize < 28:
            return {}
        (_v, _st, imports_off, symbols_off, icount, ifmt,
         _sf) = struct.unpack_from("<7I", self.data, dataoff)
        esize = CHAINED_IMPORT_SIZES.get(ifmt)
        if esize is None:
            return {}

        dylibs = [p for c, p in self.paths()
                  if c.cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
                               LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB)]
        out: dict[str, list[tuple[str, bool]]] = {}
        for k in range(icount):
            e = dataoff + imports_off + k * esize
            if e + esize > dataoff + datasize:
                break
            ordinal, weak, noff = chained_import_fields(self.data, e, ifmt)
            end = self.data.find(b"\0", dataoff + symbols_off + noff)
            if end < 0:
                continue
            sym = bytes(self.data[dataoff + symbols_off + noff:end]).decode(
                "utf-8", "surrogateescape")
            if 0 < ordinal <= len(dylibs):
                lib = dylibs[ordinal - 1]
            else:
                # self, main-executable, or a FLAT-namespace lookup. Not an
                # error and not nothing: a flat-namespace binary attributes
                # none of its imports to a library, so dropping these silently
                # made the whole binary look import-free. The postfix tools are
                # built that way -- all 155 of postalias's undefined symbols
                # carry ordinal 0 -- and were invisible to the launch
                # prediction as a result.
                lib = FLAT_NAMESPACE
            out.setdefault(lib, []).append((sym, bool(weak)))
        return out

    def weak_ref_symbols(self) -> set[str]:
        """Undefined symbols the symbol table marks N_WEAK_REF."""
        return {name for _off, name, n_desc in self.undefined_symbols()
                if n_desc & N_WEAK_REF}

    # -- code signature ----------------------------------------------------

    def code_signature(self) -> tuple[int, int] | None:
        lc = self.find(LC_CODE_SIGNATURE)
        if lc is None:
            return None
        dataoff, datasize = struct.unpack_from("<II", lc.data, 8)
        return dataoff, datasize

    # -- serialisation -----------------------------------------------------

    def build(self) -> bytes:
        """Re-emit the image. Only the header area changes; nothing moves."""
        body = b"".join(bytes(lc.data) for lc in self.commands)
        needed = self.header_size + len(body)
        capacity = self.header_capacity()
        if needed > capacity:
            raise MachOError(
                f"load commands need {needed} bytes but only {capacity} are "
                f"available before the first section; the binary was linked "
                f"without enough header padding "
                f"(short {needed - capacity} bytes)")

        out = bytearray(self.data)
        struct.pack_into(self.HEADER_FMT, out, 0, self.magic, self.cputype,
                         self.cpusubtype, self.filetype, len(self.commands),
                         len(body), self.flags)
        struct.pack_into("<I", out, 28, self.reserved)
        out[self.header_size:self.header_size + len(body)] = body
        # Zero the slack so no stale load command bytes linger.
        out[self.header_size + len(body):capacity] = b"\0" * (
            capacity - self.header_size - len(body))
        return bytes(out)


# ---------------------------------------------------------------------------
# Entitlements  (replaces `ldid -e`)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Making a shared-cache image loadable
# ---------------------------------------------------------------------------
#
# A library that lives only inside a dyld shared cache is not a file, and what
# `ipsw dyld extract` or Apple's dsc_extractor.bundle hand back is not a
# loadable dylib either. Two things are wrong with it, and both are repairable:
#
#  1. Its segments keep the virtual addresses they had in the cache. Those are
#     spread across separate cache regions, so they are neither in ascending
#     order nor page aligned -- images share pages, so each segment begins
#     wherever it happens to. dyld refuses such an image ("segment '__AUTH' vm
#     address out of order", then "file offset out of order", then a bare
#     mmap EINVAL once the ordering is fixed).
#
#  2. Its export trie is empty. A cache holds that information centrally, so
#     the per-image LC_DYLD_EXPORTS_TRIE is present but zero-sized -- the
#     library loads and exports nothing, and every import against it fails.
#
# The repair for (1) does not move a single byte of code or data: each segment
# is grown *backwards* to the page boundary below it, zero-filling the gap, so
# every address stays exactly where it was. That matters, because addresses are
# baked into the image in places nothing could rewrite -- every ADRP/ADD pair
# in the code computes a PC-relative distance to data. A uniform shift first
# makes __TEXT page aligned, which keeps the mach header at file offset 0.
#
# The repair for (2) rebuilds the trie from the symbol table, which extraction
# leaves intact.


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


class _TrieNode:
    __slots__ = ("children", "terminal", "offset")

    def __init__(self) -> None:
        self.children: list[tuple[str, _TrieNode]] = []
        self.terminal: int | None = None
        self.offset = 0


def _trie_insert(root: _TrieNode, name: str, addr: int) -> None:
    """Insert into a radix tree. Edges under one node start with distinct bytes.

    The splitting matters: a flat "one child per symbol" trie is legal but wrong
    whenever one name is a prefix of another (``_foo`` and ``_foobar``), because
    dyld descends into the first matching edge and never comes back.
    """
    node = root
    while True:
        for i, (label, child) in enumerate(node.children):
            if label[0] != name[0]:
                continue
            common = 0
            limit = min(len(label), len(name))
            while common < limit and label[common] == name[common]:
                common += 1
            if common == len(label):
                name = name[common:]
                node = child
                if not name:
                    node.terminal = addr
                    return
                break
            split = _TrieNode()
            split.children.append((label[common:], child))
            node.children[i] = (label[:common], split)
            name = name[common:]
            node = split
            if not name:
                node.terminal = addr
                return
            break
        else:
            leaf = _TrieNode()
            leaf.terminal = addr
            node.children.append((name, leaf))
            return


def build_export_trie(exports: dict[str, int]) -> bytes:
    """Serialise {symbol: offset from the image base} as a dyld export trie."""
    root = _TrieNode()
    for name, addr in sorted(exports.items()):
        _trie_insert(root, name, addr)

    nodes: list[_TrieNode] = []
    stack = [root]
    while stack:                      # parents before children, root first
        node = stack.pop()
        nodes.append(node)
        stack.extend(child for _label, child in node.children)

    def encode(node: _TrieNode) -> bytes:
        out = bytearray()
        if node.terminal is None:
            out += _uleb128(0)
        else:
            info = _uleb128(0) + _uleb128(node.terminal)   # flags = REGULAR
            out += _uleb128(len(info)) + info
        out.append(len(node.children))
        for label, child in node.children:
            out += label.encode("utf-8", "surrogateescape") + b"\0"
            out += _uleb128(child.offset)
        return bytes(out)

    # Child offsets are ULEB128, so their own width depends on the layout.
    # Iterate until it stops changing.
    for _ in range(16):
        previous = [n.offset for n in nodes]
        position = 0
        for node in nodes:
            node.offset = position
            position += len(encode(node))
        if previous == [n.offset for n in nodes]:
            break

    blob = bytearray()
    for node in nodes:
        blob += encode(node)
    while len(blob) % 8:
        blob += b"\0"
    return bytes(blob)


def extract_entitlements(macho: MachO) -> bytes | None:
    """Return the XML entitlements blob payload, or None."""
    sig = macho.code_signature()
    if sig is None:
        return None
    off, size = sig
    if size < 8 or off + size > len(macho.data):
        return None
    blob = bytes(macho.data[off:off + size])
    return _find_entitlements(blob)


def _find_entitlements(blob: bytes) -> bytes | None:
    if len(blob) < 8:
        return None
    magic, length = struct.unpack_from(">II", blob, 0)
    if magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
        return blob[8:length]
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return None
    count = struct.unpack_from(">I", blob, 8)[0]
    for i in range(count):
        idx = 12 + i * 8
        if idx + 8 > len(blob):
            break
        _typ, offset = struct.unpack_from(">II", blob, idx)
        if offset + 8 > len(blob):
            continue
        sub_magic, sub_len = struct.unpack_from(">II", blob, offset)
        if sub_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            if 8 < sub_len <= len(blob) - offset:
                return blob[offset + 8:offset + sub_len]
    return None


def entitlements_dict(xml: bytes | None) -> dict:
    if not xml:
        return {}
    try:
        value = plistlib.loads(xml)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------
# Path rewriting policy
# ---------------------------------------------------------------------------

VERSIONS_RE = re.compile(r"/Versions/[^/]+/")
PUBLIC_FW = "/System/Library/Frameworks/"
PRIVATE_FW = "/System/Library/PrivateFrameworks/"

# An index measured off a real device, shipped with the tool and used when
# --dylib-index is not given. Without one, path rewriting falls back to
# auto_fix_path(), which knows only that iOS frameworks are flat -- and for a
# framework iOS demoted to PrivateFrameworks that produces a path which looks
# plausible, is reported as a successful rewrite, and does not exist. It also
# silently disables two checks: the missing-library warning, and the half of
# the launch prediction that needs to know a library is absent (a PrivateFramework
# has no SDK stub, so its symbols fall through to `unknown` instead of failing).
# Hardcoding the moves instead would be a guess about one iOS version; a
# measured list is not.
BUNDLED_INDEX = {2: "data/ios27_24A5424a_index.txt"}      # platform id -> path


def bundled_index(platform: int | None) -> str | None:
    """The shipped index for this platform, if we have one and it is readable."""
    name = BUNDLED_INDEX.get(platform or 0)
    if name is None:
        return None
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    return path if os.path.exists(path) else None


# What a SCAN should not pick up, shipped with the tool and applied by default.
#
# Only to what a scan FINDS, never to a path the user named: an exclusion is a
# statement about sweeping a directory, and silently dropping a binary someone
# asked for by name would be indefensible. --no-exclude-defaults turns them off,
# --exclude-from adds more.
#
# The two are believed for different reasons, which is why they are separate
# files rather than one list. exclude_xcrun_shims.txt is 95 PATHS, identified by
# symbol (_xcselect_invoke_xcrun) rather than by hand: /usr/bin hard-links one
# inode under 78 names whose whole body is the xcrun call, they are SIGKILLed on
# iOS, and their names collide with the real Xcode toolchain tools -- so without
# this, bin/otool, bin/nm, bin/objdump, bin/dwarfdump, bin/size and bin/c++filt
# become symlinks to DeRez. blocklist_symbols.txt is generated from a device
# probe by cryptex.blocklist and names binaries measured to die at launch on a
# symbol iOS does not export, which is complementary to the launch prediction
# rather than redundant: the SDK stubs cover no PrivateFramework, so a symbol
# from one falls through to `unknown` and fails nothing.
BUNDLED_EXCLUDES = ("data/exclude_xcrun_shims.txt",
                    "data/blocklist_symbols.txt")


def bundled_excludes() -> list[str]:
    """The shipped exclusion lists that are actually present."""
    here = os.path.dirname(os.path.abspath(__file__))
    return [p for p in (os.path.join(here, n) for n in BUNDLED_EXCLUDES)
            if os.path.exists(p)]


def read_exclude_file(path: str) -> list[str]:
    """One glob per line, '#' for comments."""
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line)
    return out


def auto_fix_path(path: str) -> str | None:
    """macOS framework paths carry a /Versions/A/ that iOS does not have."""
    fixed = VERSIONS_RE.sub("/", path)
    return fixed if fixed != path else None


class DylibIndex:
    """Every library path the target's dyld cache can load.

    Built by dsc_index.py from a real shared cache. With one of these we can do
    better than guessing: rewrite a path to wherever the library actually lives
    on the target, and say plainly when it is not there at all.
    """

    def __init__(self, paths):
        self.paths = set(p.strip() for p in paths if p.strip())
        self.by_base: dict[str, list[str]] = {}
        for p in self.paths:
            self.by_base.setdefault(p.rsplit("/", 1)[-1], []).append(p)

    @classmethod
    def load(cls, filename: str) -> "DylibIndex":
        with open(filename) as fh:
            return cls(fh.read().splitlines())

    def __contains__(self, path: str) -> bool:
        return path in self.paths

    def resolve(self, path: str) -> tuple[str | None, str]:
        """Map a path onto the target. Returns (path_or_None, why).

        None means the library does not exist on the target under any name, so
        the binary will fail at load no matter what we write into it.
        """
        if path in self.paths:
            return path, "present"

        # 1. macOS frameworks are versioned bundles, iOS ones are flat.
        flat = VERSIONS_RE.sub("/", path)
        if flat != path and flat in self.paths:
            return flat, "flattened Versions/"

        # 2. iOS demotes several public macOS frameworks to PrivateFrameworks
        #    (DiskArbitration, SecurityFoundation, ServiceManagement, FSKit...).
        for src, dst in ((PUBLIC_FW, PRIVATE_FW), (PRIVATE_FW, PUBLIC_FW)):
            if flat.startswith(src):
                moved = dst + flat[len(src):]
                if moved in self.paths:
                    kind = "public->private" if src == PUBLIC_FW else "private->public"
                    return moved, kind

        # 3. A dylib bundled inside a framework on macOS may ship loose on iOS
        #    (e.g. WirelessDiagnostics' libprotobuf -> /usr/lib/libprotobuf).
        candidates = self.by_base.get(path.rsplit("/", 1)[-1], [])
        if len(candidates) == 1:
            return candidates[0], "relocated"
        if len(candidates) > 1:
            return None, "ambiguous: " + ", ".join(sorted(candidates))

        return None, "not in the target's dyld cache"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Will this binary even launch?  (replaces a device probe)
# ---------------------------------------------------------------------------
#
# A missing *library* has always been visible statically. A missing *symbol*
# was not, and this file recorded that as the gap: "all 70 symbol failures were
# invisible to it. Only launching finds those." It is closable -- the two-level
# namespace records which library each import is bound to, and the iPhoneOS SDK
# ships a stub listing what that library exports on the target.
#
# Getting `curl` running cost four install-and-probe cycles, each revealing the
# symbol behind the one just fixed, and all four were in the file the whole
# time. Validated against 423 real device launches: 39 of the 39 that died on a
# symbol are flagged, and 0 of the 384 that ran.


class TargetSymbols:
    """What the target platform exports, per library.

    Two sources, and the second one exists because the first has a hole this
    project has now paid for twice.

    The SDK's `.tbd` stubs are the cheap source, and their coverage is the
    honest limit: /usr/lib and the public frameworks only -- no
    PrivateFrameworks, no libpcap, no CoreSymbolication. A library with no stub
    yields `unknown`, never a failure. `tcpdump` imports 90 libpcap symbols and
    works perfectly on device; claiming those are broken would make this worse
    than useless. A false positive is the expensive mistake -- it refuses to
    port a binary that would have run.

    *cache* closes the hole: an index built by `dsc.symindex` from the target's
    own shared cache, which knows what every image really exports,
    PrivateFrameworks included. `csrutil` died on device with
    `_DAUnregisterApprovalCallback` from `DiskArbitration` -- a PrivateFramework
    on iOS -- and the gate said `0 of 539` because all 45 of `DiskManagement`'s
    imports from it were `unknown`. With the index it is a real answer, and
    `--weaken-unresolvable` derives what a hand-written list of 33 symbol names
    used to carry.

    Where both sources describe a library the two are UNIONED rather than the
    cache preferred. `_symbols()` is deliberately coarse -- a regex over a whole
    .tbd -- so it can name things that are not really exports, and the union
    keeps the existing behaviour for every SDK-covered library exactly as it was
    measured (39 of 39 real failures, 0 of 384 wrongly condemned). The index can
    then only ever add knowledge where there was none.
    """

    def __init__(self, sdk: str, cache: dict[str, set[str]] | None = None):
        self.sdk = sdk
        self.by_name: dict[str, set[str]] = {}
        reexp: dict[str, list[str]] = {}
        for path in self._stub_paths(sdk):
            try:
                text = open(path, errors="replace").read()
            except OSError:
                continue
            m = re.search(r"^install-name:\s*'?\"?([^'\"\n]+)'?\"?\s*$", text,
                          re.MULTILINE)
            if not m:
                continue
            name = m.group(1).strip()
            self.by_name[name] = self._symbols(text)
            reexp[name] = self._reexports(text)

        # A basename is only a safe key when it is unique across the SDK.
        seen: dict[str, list[str]] = {}
        for name in self.by_name:
            seen.setdefault(os.path.basename(name), []).append(name)
        self._by_base = {b: v[0] for b, v in seen.items() if len(v) == 1}

        # Two-level-namespace lookup follows re-exports: libSystem.B re-exports
        # the whole libsystem_* family, so a symbol defined in libsystem_c
        # really is resolvable as libSystem.
        for name in list(self.by_name):
            done, stack = set(), list(reexp.get(name, []))
            while stack:
                dep = stack.pop()
                if dep in done:
                    continue
                done.add(dep)
                self.by_name[name] |= self.by_name.get(dep, set())
                stack += reexp.get(dep, [])

        # The cache index, unioned in. dsc.symindex has already followed
        # LC_REEXPORT_DYLIB, so an umbrella framework arrives complete.
        self.from_cache: set[str] = set()
        for name, syms in (cache or {}).items():
            if name in self.by_name:
                self.by_name[name] |= syms
            else:
                self.by_name[name] = set(syms)
                self.from_cache.add(name)
        if cache:
            # The basename fallback is rebuilt with the SDK's answers kept.
            # Recomputing it over the union instead loses 31 of them --
            # `IOKit`, `UIKit`, `AVFoundation`, `WebKit` among them -- because a
            # basename that is unique across 625 stubs need not be unique across
            # 4691 cache images, and a name that stops resolving stops being
            # judged. None of the 31 is reached through the fallback in practice
            # (a macOS binary spells IOKit versioned, which the iOS cache
            # carries verbatim), but losing a resolution quietly is the failure
            # mode this file keeps recording.
            seen: dict[str, list[str]] = {}
            for name in self.from_cache:
                seen.setdefault(os.path.basename(name), []).append(name)
            for b, v in seen.items():
                if len(v) == 1 and b not in self._by_base:
                    self._by_base[b] = v[0]

    @staticmethod
    def _stub_paths(sdk: str) -> list[str]:
        out = []
        for pat in ("/usr/lib/**/*.tbd",
                    "/System/Library/Frameworks/**/*.tbd",
                    "/System/Library/PrivateFrameworks/**/*.tbd"):
            out += glob.glob(sdk + pat, recursive=True)
        return out

    @staticmethod
    def _symbols(text: str) -> set[str]:
        """Every exported name in a .tbd.

        Deliberately coarse -- a .tbd is YAML with several symbol-bearing keys,
        and the only question is "does this name appear as an export". Over-
        collecting can lose a detection; under-collecting invents a failure,
        which is the costlier direction.
        """
        syms = set(re.findall(r"[A-Za-z_$][A-Za-z0-9_$.]*", text))
        # `objc-classes:` lists a class bare ("NSObject"), but a binary imports
        # it as _OBJC_CLASS_$_NSObject, _OBJC_METACLASS_$_NSObject, or
        # _OBJC_EHTYPE_$_NSObject (the @catch type). Without this every
        # Objective-C binary looks broken.
        for cls in list(syms):
            for pre in ("_OBJC_CLASS_$_", "_OBJC_METACLASS_$_",
                        "_OBJC_EHTYPE_$_", "OBJC_CLASS_$_",
                        "OBJC_METACLASS_$_", "OBJC_EHTYPE_$_"):
                syms.add(pre + cls)
        return syms

    @staticmethod
    def _reexports(text: str) -> list[str]:
        block = re.search(r"reexported-libraries:(.*?)(?=\n[a-z-]+:|\Z)", text,
                          re.DOTALL)
        if not block:
            return []
        found = re.findall(r"'([^']+)'|\"([^\"]+)\"|(/[^\s,\]]+)",
                           block.group(1))
        return [p for p in (a or b or c for a, b, c in found)
                if p.startswith("/")]

    def resolve(self, install_name: str) -> str | None:
        """The stub describing this library on the target, if any.

        A converted binary still spells libraries the macOS way while the stubs
        use the iOS one: `Security.framework/Versions/A/Security` and
        `Security.framework/Security` are the same library. Missing that made
        ocspd's `_SecKeychainOpen` look resolvable -- a false negative.
        """
        if install_name in self.by_name:
            return install_name
        flat = auto_fix_path(install_name)
        if flat and flat in self.by_name:
            return flat
        return self._by_base.get(os.path.basename(install_name))

    def knows(self, install_name: str) -> bool:
        return self.resolve(install_name) is not None

    def exports(self, install_name: str, symbol: str) -> bool:
        name = self.resolve(install_name)
        return name is not None and symbol in self.by_name[name]


_TARGET_CACHE: dict[str, "TargetSymbols | None"] = {}


def target_symbols(sdk: str | None, platform_name: str,
                   symbol_index: str | None = None) -> "TargetSymbols | None":
    """Load (once) the target's exported surface. None if unavailable.

    *symbol_index* is a `dsc.symindex` file for the target's own shared cache,
    which is the only thing that can speak for a PrivateFramework -- see
    TargetSymbols.
    """
    key = (sdk or platform_name) + "|" + (symbol_index or "")
    if key in _TARGET_CACHE:
        return _TARGET_CACHE[key]
    path = sdk
    if not path:
        sdk_name = {"ios": "iphoneos", "tvos": "appletvos",
                    "watchos": "watchos", "macos": "macosx"}.get(platform_name)
        if sdk_name:
            try:
                r = subprocess.run(["xcrun", "--sdk", sdk_name,
                                    "--show-sdk-path"],
                                   capture_output=True, text=True)
                path = r.stdout.strip()
            except OSError:
                path = None
    cache = None
    if symbol_index:
        try:
            cache = dsc.symindex.load(symbol_index)
        except OSError as exc:
            print(f"warning: {symbol_index}: {exc}; PrivateFramework symbols "
                  f"cannot be judged", file=sys.stderr)
    out = TargetSymbols(path, cache) if path and os.path.isdir(path) else None
    if out is None:
        # Say so once. A silently-skipped check is the failure mode this
        # project keeps re-learning: the caller gets a binary that looks
        # converted and dies in dyld on the device instead.
        print(f"note: no SDK for {platform_name!r} "
              f"(xcrun --sdk ... --show-sdk-path), so the launch prediction is "
              f"skipped and a binary that cannot start will still be ported",
              file=sys.stderr)
    _TARGET_CACHE[key] = out
    return out


def unresolvable_imports(macho: MachO, target: "TargetSymbols",
                         index: "DylibIndex | None" = None,
                         provided_exports: dict | None = None
                         ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Imports that will kill this binary at launch, and ones we cannot judge.

    Returns (will_fail, unknown), each a list of (library, symbol).

    Four rules, each of which cost a real misdiagnosis to get right:

    1. Only what `bound_imports()` returns can fail -- see there.
    2. A weak *symbol* survives. It binds NULL and the process starts.
    3. A weak-linked ABSENT *library* does NOT make its imports optional.
       `LC_LOAD_WEAK_DYLIB` tolerates the library being missing; a hard import
       from it still kills the process. That is exactly how the lifted libcurl
       died on `_GSS_C_NT_HOSTBASED_SERVICE`: Kerberos is absent from iOS and
       the import was hard.
    4. A library with no SDK stub is `unknown`, never a failure.
    """
    provided_exports = provided_exports or {}
    weak_lib = {p for lc, p in macho.paths()
                if lc.cmd == LC_LOAD_WEAK_DYLIB}
    fail, unknown = [], []
    for lib, syms in macho.bound_imports().items():
        if lib == FLAT_NAMESPACE:
            # Judging these would mean asking whether the symbol exists
            # ANYWHERE on the target, and the SDK stubs cover only /usr/lib and
            # the public frameworks -- so an absence would as often mean "no
            # stub" as "not there". Reported, never failed: that is what
            # data/blocklist_symbols.txt is for, and it is why that measured
            # list is complementary to this prediction rather than redundant.
            unknown += [(lib, sym) for sym, w in syms if not w]
            continue
        base = os.path.basename(lib)
        exports = provided_exports.get(base)
        if exports is None and lib.startswith("@"):
            # @rpath / @loader_path / @executable_path. A cache index can say
            # nothing about these -- resolve_rpath() checks whether the dylib is
            # staged where the binary will look, and that is the right place for
            # it. Judging them here condemned six Xcode tools that reference
            # @rpath/libcodedirectory.dylib, which is staged a step later.
            unknown += [(lib, sym) for sym, _w in syms]
            continue
        absent = (exports is None and index is not None
                  and index.resolve(lib)[0] is None)
        for sym, weak in syms:
            if weak:
                continue                      # binds NULL, survivable
            if exports is not None:           # a library we bundle ourselves
                if sym not in exports:
                    fail.append((lib, sym))
                continue
            if absent:
                # Not on the target at all. The conversion weakens the library
                # (--weaken-missing) so the binary still loads, but that only
                # tolerates its absence -- a hard import from it is still
                # fatal. This is why chpass dies on _ODNodeCopyRecord rather
                # than on "OpenDirectory missing".
                fail.append((lib, sym))
                continue
            if not target.knows(lib):
                unknown.append((lib, sym))
            elif not target.exports(lib, sym):
                fail.append((lib, sym))
    return fail, unknown


def describe(macho: MachO, path: str) -> None:
    print(f"{path}:")
    print(f"  arch        {macho.arch} "
          f"(cputype {macho.cputype:#010x}, cpusubtype {macho.cpusubtype:#010x})")
    bv = macho.build_version()
    if bv is None:
        print("  platform    <none>")
    else:
        platform, minos, sdk = bv
        pretty = PLATFORM_PRETTY.get(platform, f"platform {platform}")
        print(f"  platform    {pretty} {format_version(minos)} "
              f"(sdk {format_version(sdk)})")
    paths = macho.paths()
    if paths:
        print("  linked:")
        for lc, p in paths:
            kind = "rpath" if lc.cmd == LC_RPATH else (
                "id" if lc.cmd == LC_ID_DYLIB else "dylib")
            flag = " <- macOS-only path" if auto_fix_path(p) else ""
            print(f"    [{kind:5}] {p}{flag}")
    ents = extract_entitlements(macho)
    if ents:
        print("  entitlements:")
        for line in ents.decode("utf-8", "replace").splitlines():
            print(f"    {line}")
    else:
        print("  entitlements: <none>")


# ---------------------------------------------------------------------------
# Signing  (the one thing we shell out for)
# ---------------------------------------------------------------------------


def codesign(path: str, identity: str, ents_file: str | None,
             identifier: str | None, verbose: bool) -> None:
    codesign_bin = shutil.which("codesign") or "/usr/bin/codesign"
    subprocess.run([codesign_bin, "--remove-signature", path],
                   capture_output=True, check=False)
    cmd = [codesign_bin, "--force", "--sign", identity]
    if identifier:
        cmd += ["--identifier", identifier]
    if ents_file:
        cmd += ["--entitlements", ents_file]
    cmd.append(path)
    if verbose:
        print("  $ " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise MachOError("codesign failed:\n" + (proc.stderr or proc.stdout).strip())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Scanning a tree for Mach-O binaries
# ---------------------------------------------------------------------------

SCAN_DEFAULT_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")

# The Xcode toolchain's bin directory. Most of what macOS puts in /usr/bin for
# these names is a stub that re-execs the real tool from here (94 of them --
# /usr/bin/otool, nm, lipo and strip are literally the same file), so this is
# where the actual binaries live.
XCODE_TOOLCHAIN_BIN = ("/Applications/Xcode.app/Contents/Developer/Toolchains/"
                       "XcodeDefault.xctoolchain/usr/bin")

# What NOT to take from the toolchain when the target is a phone you are
# reverse-engineering on. Two reasons to drop something: it exists to *build*
# code (there is no source on the device, and clang alone is 141 MB and
# swift-frontend 171 MB), or it serves an editor/build system rather than a
# person at a shell.
#
# Matched with fnmatch against the file name. Careful: the tools worth keeping
# are themselves llvm binaries -- otool IS llvm-otool, nm IS llvm-nm, objdump
# IS llvm-objdump -- so a blanket "llvm-*" would remove exactly what you want.
# Blocklist by purpose, never by prefix.
XCODE_SKIP = (
    # compilers, drivers and the language servers that front them
    "clang", "clang++", "clang-*", "clangd", "cc", "c++", "cpp",
    "gcc", "g++", "llvm-gcc", "llvm-g++", "sourcekit-lsp",
    "swift*",                       # swift-demangle is exempted below
    # linking and archiving: building, not inspecting. Dropping ld also drops
    # its libtapi and libswiftDemangle dependencies.
    "ld", "ld-classic", "libtool", "ranlib",
    # build-system plumbing, caching, packaging, asset compilers
    "cache-build-session", "llvm-cas", "modules-verifier", "docc",
    "snippet-extract", "tapi", "tapi-analyze", "metal*", "iig", "exutil",
    "appintents*", "appshortcut*", "coremlc", "coremlcompiler", "createml",
    "fmadapter*", "referenceobject*", "stapler", "actool", "ibtool",
    "clang-format",
    # coverage and profiling: needs an instrumented build to be worth anything
    "gcov", "llvm-cov", "llvm-profdata",
    # classic unix build tools, not reverse-engineering tools
    "ar", "asa", "bison", "byacc", "bm4", "c89", "c99", "flex", "flex++",
    "gm4", "m4", "yacc", "gperf", "indent", "ctags", "rpcgen", "unifdef",
)

# Exempt from the patterns above, because they really are RE tools.
XCODE_KEEP = {
    "swift-demangle",   # the only way to read a mangled Swift symbol
    "c++filt",          # ditto for C++
}


MACHO_MAGICS = (FAT_MAGIC, FAT_MAGIC_64, MH_MAGIC_64, MH_CIGAM_64,
                MH_MAGIC, MH_CIGAM)


def is_macho(path: str) -> bool:
    """True if *path* starts with a Mach-O or fat magic."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    if len(head) < 4:
        return False
    return struct.unpack(">I", head)[0] in MACHO_MAGICS


def scan_binaries(dirs: list[str], recursive: bool = False) -> list[str]:
    """Every executable Mach-O directly in *dirs* (or below, if recursive).

    Symlinks are skipped -- on macOS ``/usr/bin`` is full of them, and the
    target is normally in the same directory anyway. Anything that is not a
    regular, executable Mach-O file is skipped silently.

    Hard links are *not* deduplicated here. On macOS the xcrun shim is a single
    inode with 78 names (``/usr/bin/otool``, ``clang``, ``git``, ``make``,
    ``python3`` ... are all the same file), and the names are the whole point --
    the shim reads ``argv[0]`` to decide which tool to look for. main() groups
    them and converts each inode once, linking the rest.
    """
    found: list[str] = []
    seen: set[str] = set()
    for root in dirs:
        walker = os.walk(root) if recursive else [(root, [], _listdir(root))]
        for base, _subdirs, names in walker:
            for name in names:
                path = os.path.join(base, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue        # symlink, directory, socket, ...
                if not st.st_mode & 0o111:
                    continue        # not executable
                if path in seen:
                    continue
                if not is_macho(path):
                    continue
                seen.add(path)
                found.append(path)
    return sorted(found)


def resolve_rpath(macho: MachO, path: str, output: str) -> str | None:
    """Find an `@rpath/...` dependency among the binary's own LC_RPATHs.

    `@rpath` is resolved by dyld at load time against each LC_RPATH in turn, so
    a static index of the target's dyld cache can say nothing about it. What we
    *can* check is the common case where the rpath is `@executable_path`- or
    `@loader_path`-relative and the dylib has been staged next to the binary --
    which is exactly how the Xcode toolchain ships libLTO and libcodedirectory.
    Returns the path it found, or None.
    """
    if not path.startswith("@rpath/"):
        return None
    leaf = path[len("@rpath/"):]
    base = os.path.dirname(os.path.abspath(output))
    for lc, rpath in macho.paths():
        if lc.cmd != LC_RPATH:
            continue
        for prefix in ("@executable_path/", "@loader_path/"):
            if rpath.startswith(prefix):
                cand = os.path.join(base, rpath[len(prefix):], leaf)
                if os.path.exists(cand):
                    return os.path.normpath(cand)
        if rpath.startswith("/"):
            cand = os.path.join(rpath, leaf)
            if os.path.exists(cand):
                return cand
    return None


def is_blocked(name: str, patterns) -> bool:
    """True if *name* matches any fnmatch pattern and is not exempted."""
    if name in XCODE_KEEP:
        return False
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def xcode_toolchain_bin() -> str | None:
    """The active toolchain's bin directory, or None if it is not there."""
    dev = os.environ.get("DEVELOPER_DIR")
    if dev:
        cand = os.path.join(dev, "Toolchains", "XcodeDefault.xctoolchain",
                            "usr", "bin")
        if os.path.isdir(cand):
            return cand
    return XCODE_TOOLCHAIN_BIN if os.path.isdir(XCODE_TOOLCHAIN_BIN) else None


def _listdir(path: str) -> list[str]:
    try:
        return os.listdir(path)
    except OSError as exc:
        print(f"warning: cannot scan {path}: {exc.strerror}", file=sys.stderr)
        return []


def _uleb(data: bytes, off: int) -> tuple[int, int]:
    """Read one ULEB128. Returns (value, offset after it)."""
    result = shift = 0
    while True:
        if off >= len(data):
            raise MachOError("truncated ULEB128")
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
        if shift > 63:
            raise MachOError("ULEB128 too long")


def export_trie_symbols(macho: MachO) -> set[str] | None:
    """Every symbol name exported by *macho*, from its export trie.

    Returns None if the image has no `LC_DYLD_EXPORTS_TRIE` (an older binary
    using `LC_DYLD_INFO`, say) -- the caller should then not draw conclusions
    from an empty set.
    """
    lc = macho.find(LC_DYLD_EXPORTS_TRIE)
    if lc is None:
        return None
    _cmd, _size, dataoff, datasize = struct.unpack_from("<4I", lc.data, 0)
    if datasize == 0 or dataoff + datasize > len(macho.data):
        return None
    trie = bytes(macho.data[dataoff:dataoff + datasize])

    names: set[str] = set()
    # (node offset, name accumulated on the way here)
    stack = [(0, "")]
    seen = set()
    while stack:
        node, prefix = stack.pop()
        if node in seen or node >= len(trie):
            continue
        seen.add(node)
        terminal_size, off = _uleb(trie, node)
        if terminal_size:
            names.add(prefix)          # a terminal node names an export
        off = node + (off - node) + terminal_size
        if off >= len(trie):
            continue
        nchildren = trie[off]
        off += 1
        for _ in range(nchildren):
            end = trie.find(b"\0", off)
            if end < 0:
                break
            label = trie[off:end].decode("utf-8", "surrogateescape")
            off = end + 1
            child, off = _uleb(trie, off)
            stack.append((child, prefix + label))
    return names


def dylib_exports(path: str) -> set[str] | None:
    """The exported symbol names of the dylib at *path*, or None if unknown."""
    try:
        with open(path, "rb") as fh:
            macho = MachO(thin(fh.read(), None)[0])
    except (OSError, MachOError):
        return None
    try:
        return export_trie_symbols(macho)
    except MachOError:
        return None


def dylib_id(path: str) -> str | None:
    """The LC_ID_DYLIB install name of *path*, or None if it has none."""
    try:
        with open(path, "rb") as fh:
            macho = MachO(thin(fh.read(), None)[0])
    except (OSError, MachOError):
        return None
    for lc, name in macho.paths():
        if lc.cmd == LC_ID_DYLIB:
            return name
    return None


# ---------------------------------------------------------------------------
# Cryptex layout
# ---------------------------------------------------------------------------

class Cryptex:
    """Where converted binaries and their bundled libraries are staged.

    A cryptex is just a directory tree that ``srdtool cryptex install`` bundles
    into a signed disk image. Binaries go in ``<root>/bin``, replacement
    libraries in ``<root>/usr/lib``. The mount point on the device carries a
    per-install random suffix, so a bundled library must never be referenced by
    an absolute path -- we rewrite references to ``@executable_path``-relative
    ones, which are stable.
    """

    MANIFEST = ".machomorph-manifest"

    def __init__(self, root: str, bindir: str = "bin",
                 libdir: str = "usr/lib", anchor: str = "@executable_path") -> None:
        self.root = os.path.abspath(root)
        self.bindir = os.path.join(self.root, bindir)
        self.libdir = os.path.join(self.root, libdir)
        self.anchor = anchor

    # -- ownership ---------------------------------------------------------
    #
    # A cryptex is not ours alone. It usually already holds binaries someone
    # else built *for iOS* -- a real iOS bash, vim, ldid -- and a macOS port of
    # the same name would replace a native build with a retargeted one, which
    # is strictly worse. We cannot tell those apart by name (the names are
    # ordinary), and hardcoding them would bake one person's setup into the
    # tool. So we record what we ourselves wrote, and treat everything else as
    # someone else's.

    def manifest_path(self) -> str:
        return os.path.join(self.root, self.MANIFEST)

    def owned(self) -> set[str]:
        """Paths, relative to the root, written by an earlier run."""
        try:
            with open(self.manifest_path()) as fh:
                return {line.split("#", 1)[0].strip() for line in fh
                        if line.split("#", 1)[0].strip()}
        except OSError:
            return set()

    def record(self, paths: list[str]) -> None:
        """Add *paths* to what we own. Ownership is cumulative.

        A cryptex is normally built in several passes -- the main batch, then
        the bundled libraries, then the tools that need them -- and each pass is
        a separate run of this tool. Replacing the manifest each time would let
        the last pass disown everything the earlier ones wrote, which is exactly
        the bug this note exists to prevent. Entries whose file has since gone
        are dropped, so the list cannot grow forever.
        """
        rel = {os.path.relpath(os.path.abspath(p), self.root) for p in paths}
        rel |= self.owned()
        rel = sorted(r for r in rel
                     if os.path.lexists(os.path.join(self.root, r)))
        try:
            with open(self.manifest_path(), "w") as fh:
                fh.write("# Written by machomorph. Lists what this tool "
                         "produced in this cryptex,\n"
                         "# so a later run can refresh its own files and leave "
                         "everything else alone.\n")
                fh.write("\n".join(rel) + "\n")
        except OSError as exc:
            print(f"warning: cannot write {self.manifest_path()}: "
                  f"{exc.strerror}", file=sys.stderr)

    def output_for(self, input_path: str) -> str:
        os.makedirs(self.bindir, exist_ok=True)
        return os.path.join(self.bindir, os.path.basename(input_path))

    def library_dest(self, orig: str) -> str:
        """Where a bundled library goes. A cryptex libdir is always flat."""
        os.makedirs(self.libdir, exist_ok=True)
        return os.path.join(self.libdir, os.path.basename(orig))

    def install_name_for(self, orig: str, referrer: str | None = None) -> str:
        """The name binaries will ask for. Relative to bindir, not to the
        referrer: every binary in a cryptex sits in the one bin/, and the
        libraries reference each other from the one lib/ at the same depth, so
        a single spelling is correct for both. verify_cryptex check 4 and
        restage.py both assume that, and the shorter name matters -- tcpdump
        has 16 bytes of load-command slack for its two references."""
        rel = os.path.relpath(os.path.join(self.libdir,
                                           os.path.basename(orig)),
                              self.bindir)
        return self.anchor + "/" + rel

    def reference_name(self, orig: str) -> str:
        """The spelling a converted BINARY uses. Same thing in a cryptex."""
        return self.install_name_for(orig)

    def add_library(self, src: str) -> str:
        """Copy *src* into the cryptex's library directory. Returns its path."""
        os.makedirs(self.libdir, exist_ok=True)
        dst = os.path.join(self.libdir, os.path.basename(src))
        if os.path.realpath(src) != os.path.realpath(dst):
            shutil.copy2(src, dst)
        return dst


# ---------------------------------------------------------------------------
# Where a converted binary and the libraries it needs are written
# ---------------------------------------------------------------------------
#
# A conversion has two outputs, not one: the binary, and every library the
# target does not have. Those have to land somewhere the binary can reach with
# a *relative* install name -- an absolute one cannot work, because a cryptex
# mounts at a different random path every install and a plain output directory
# is wherever the user put it.
#
# Two layouts, and the difference is only where a library file goes:
#
#   mirror (default)  <root>/System/Library/PrivateFrameworks/Foo.framework/Foo
#   flat              <root>/Foo                     -- or <root>/<subdir>/Foo
#
# mirror keeps the target's own spelling, so the output directory reads as a
# small root filesystem and two libraries with the same basename cannot collide
# (`Versions/A/A` and `libA.dylib` are one basename apart more often than is
# comfortable). flat is what a cryptex does, and it is four to sixty bytes
# shorter per reference -- which is not cosmetic: the load-command area is
# fixed, and tcpdump has exactly 16 bytes of slack for its two references.


class DirStaging:
    """Binary and libraries under one output directory."""

    def __init__(self, root: str, layout: str = "mirror",
                 subdir: str | None = None,
                 anchor: str = "@loader_path") -> None:
        self.root = os.path.abspath(root)
        self.layout = layout
        self.subdir = subdir
        self.anchor = anchor

    def output_for(self, input_path: str) -> str:
        os.makedirs(self.root, exist_ok=True)
        return os.path.join(self.root, os.path.basename(input_path))

    def library_dest(self, orig: str) -> str:
        if self.layout == "mirror":
            # The TARGET's spelling of the path, not the macOS one: iOS
            # frameworks are flat, so mirroring `Versions/A/` would carry a
            # macOS-ism into the tree and cost 11 bytes in every reference to
            # it. The library is absent on the target by definition here, so
            # the index cannot answer and the rule is all there is.
            return os.path.join(self.root,
                                (auto_fix_path(orig) or orig).lstrip("/"))
        parts = [self.root]
        if self.subdir:
            parts.append(self.subdir)
        parts.append(os.path.basename(orig))
        return os.path.join(*parts)

    def install_name_for(self, orig: str, referrer: str) -> str:
        # Relative to the directory of whoever names the library. For a main
        # executable @loader_path and @executable_path mean the same thing, so
        # @loader_path is the one that is also right in a library -- and a
        # bundled library referencing another bundled library is the common
        # case here (CoreDisplay pulls in GPUWrangler and IOPresentment).
        base = os.path.dirname(os.path.abspath(referrer))
        rel = os.path.relpath(self.library_dest(orig), base)
        return self.anchor + "/" + rel

    def reference_name(self, orig: str) -> str:
        """The spelling a converted BINARY uses -- binaries sit at the root.

        A bundled library referencing a sibling gets a different spelling (a
        different number of ../), and that is fine: dyld resolves an
        @loader_path request to a real path and dedupes by that, so both reach
        the one file. The library's own LC_ID_DYLIB is set to this one.
        """
        return self.install_name_for(orig, os.path.join(self.root, "x"))

    def record(self, paths: list[str]) -> None:
        pass                              # nothing to own: the dir is ours

    def owned(self) -> set[str]:
        return set()


# ---------------------------------------------------------------------------
# Obtaining a library the target does not have
# ---------------------------------------------------------------------------
#
# A library iOS lacks comes from exactly one of three places, cheapest first:
#
#   1. a --prebuilt directory, for something built or lifted earlier;
#   2. the macOS filesystem, for the libraries that really are files
#      (libperl.dylib, the Xcode toolchain's dylibs);
#   3. the macOS dyld shared cache -- and then it has to be LIFTED, not merely
#      extracted.
#
# The third is the interesting one and the reason this code exists. An image
# inside a shared cache is not a dylib: the cache builder zeroes its GOT,
# rewrites its code to reach a cache-wide uniqued GOT belonging to no image,
# and relocates everything centrally through the cache's slide info instead of
# a fixup load command. Extract it and it loads, then dies the moment a code
# path dereferences a global -- which is why `tcpdump -c 1` captured happily
# while `tcpdump --version` segfaulted. Lifting repairs all of that; see
# CLAUDE.md, "The real wall: the cache-uniqued GOT".

MAC_DSC = dsc.extract.MAC_DSC
LIFT_WORK = "/tmp/dsc_lift"       # shared with the per-stage CLIs, so facts are reused

# A lift is a BUILD PRODUCT of these stages, so a cached one is stale when any
# of them is newer -- not merely when it is absent. Skipping on mere existence
# shipped a libxcselect produced before the rebinder could allocate an
# authenticated overflow slot: one site in xcselect_trigger_install_request was
# left reaching the cache and every xcrun shim died there with
# EXC_ARM_PAC_FAIL, on a path the nine tools that matter never take. It looked
# fine for a whole session.
LIFT_STAGES = ("facts", "rebind", "objc", "compact", "gotscan", "extract")

# The two cache-wide dumps dsc.facts reads, and the flags for each half.
#     kind -> (read flag, write flag, environment override, what it is)
CACHE_DUMPS = {
    "slide": ("--slide-json", "--keep-slide-json", "DSC_SLIDE_JSON",
              "`ipsw dyld slide --json`"),
    "patches": ("--patches-txt", "--keep-patches-txt", "DSC_PATCHES_TXT",
                "`ipsw dyld patches`"),
}


def cache_dump_path(cache: str, kind: str, work: str) -> str:
    """Where the cached *kind* dump for *cache* lives.

    Keyed by the cache's size and mtime as well as its name, so a dump can
    never outlive the cache it was read from -- a dump naming addresses from a
    previous macOS update would resolve every GOT slot to the wrong symbol,
    which is worse than not having one.
    """
    try:
        st = os.stat(cache)
        tag = f"{os.path.basename(cache)}-{st.st_size}-{int(st.st_mtime)}"
    except OSError:
        tag = os.path.basename(cache)
    ext = ".slide.jsonl" if kind == "slide" else ".patches.txt"
    return os.path.join(work, tag + ext)


def usable_dump(path: str, kind: str, say=print, why: str = "") -> bool:
    """Is *path* a dump worth reading? A zero-byte one is not, and says so.

    An empty or truncated dump is read without complaint by dsc.facts -- it
    simply yields no records -- so the lift comes out with nothing repointed,
    loads, and PAC-faults on the first stub. That is the same shape of failure
    a truncated facts.json produced, and this project has shipped a damaged
    library from a mere existence test five times. Zero bytes is the case that
    can be recognised for certain; a half-written dump cannot be, which is why
    the ones written here are renamed into place only once the stage that wrote
    them has succeeded.
    """
    where = f"{why} " if why else ""
    if not os.path.exists(path):
        if why:
            say(f"  warning: {where}names {path}, which does not exist -- "
                f"ignoring it")
        return False
    if os.path.getsize(path) == 0:
        say(f"  warning: {where}{path} is 0 bytes, not a saved "
            f"{CACHE_DUMPS[kind][3]} dump -- ignoring it. A dump still being "
            f"written is the usual reason; nothing is repointed from an empty "
            f"one.")
        return False
    return True


def facts_dump_args(cache: str, work: str, say=print):
    """(extra argv for dsc.facts, {kind: (temp path, final path)}).

    dsc.facts otherwise streams the WHOLE cache once per image -- `ipsw dyld
    slide` over 5 GB, minutes each -- and a from-scratch build lifts on the
    order of forty libraries, so the same pass is paid for forty times. Both
    dumps are cache-wide rather than per-image, so the first lift saves them
    and every later one reads them.

    They are written to a per-process `.part` name and renamed by the caller
    once the stage has succeeded, so an interrupted lift leaves nothing that a
    later run could mistake for a complete dump, and two concurrent builds
    cannot write the same file.
    """
    extra, pending = [], {}
    for kind, (read_flag, keep_flag, env, what) in CACHE_DUMPS.items():
        given = os.environ.get(env)
        if given and usable_dump(given, kind, say, why=f"${env}"):
            extra += [read_flag, given]
            continue
        cached = cache_dump_path(cache, kind, work)
        if usable_dump(cached, kind, say):
            extra += [read_flag, cached]
            continue
        # Per-process, because two lifts running at once against the same
        # cache would otherwise write the same file and one of them would
        # rename the interleaving into place as a complete dump.
        part = f"{cached}.{os.getpid()}.part"
        extra += [keep_flag, part]
        pending[kind] = (part, cached)
        say(f"  saving the {what} dump for the next lift "
            f"({os.path.basename(cached)})")
    return extra, pending


def keep_dumps(pending: dict, ok: bool, say=print) -> None:
    """Rename the dumps this lift saved into place, or discard them."""
    for kind, (part, final) in pending.items():
        if ok and os.path.exists(part) and os.path.getsize(part):
            os.replace(part, final)
            mb = os.path.getsize(final) / (1 << 20)
            say(f"  saved {os.path.basename(final)} ({mb:.0f} MB); later lifts "
                f"read it instead of the cache")
        elif os.path.exists(part):
            os.unlink(part)


def stage_files() -> list[str]:
    """The files a lift is built from, for the staleness check."""
    return [os.path.join(os.path.dirname(os.path.abspath(dsc.__file__)),
                         f"{s}.py") for s in LIFT_STAGES]


def run_stage(name: str, argv: list[str], capture: bool = False):
    """Call a stage's main(). Returns (rc, output) -- rc is None on a hard error.

    Every stage raises SystemExit for a malformed image ("no header room for
    LC_DYLD_CHAINED_FIXUPS", "LC_DATA_IN_CODE is not empty"), which as a
    subprocess was an exit status and in-process would take the whole run down.
    """
    import contextlib
    import io
    mod = getattr(dsc, name, None)
    if mod is None:
        return None, f"no such stage: dsc.{name}"
    buf = io.StringIO()
    try:
        if capture:
            with contextlib.redirect_stdout(buf):
                rc = mod.main(argv)
        else:
            rc = mod.main(argv)
    except SystemExit as exc:
        return None, str(exc.code) if exc.code else ""
    except Exception as exc:                       # a stage bug, not an image
        return None, f"{type(exc).__name__}: {exc}"
    return (rc or 0), buf.getvalue()


def has_fixups(path: str) -> bool | None:
    """Does this library carry its own chained-fixup information?

    A cache image does not: a cache relocates centrally, so nothing in the
    image says which words are pointers. Loaded standalone none get rebased and
    no import gets bound, so the first dereference of one reads a raw
    chained-pointer bit pattern. The failure is path-dependent rather than
    total, which is what makes it worth checking for statically.
    """
    try:
        with open(path, "rb") as fh:
            macho = MachO(thin(fh.read(), None)[0])
    except (OSError, MachOError):
        return None
    return macho.find(LC_DYLD_CHAINED_FIXUPS) is not None


VM_SPAN_WARN = 512 << 20


def vm_span(path: str) -> int | None:
    """Lowest-to-highest VM address a library makes dyld reserve at load."""
    try:
        with open(path, "rb") as fh:
            macho = MachO(thin(fh.read(), None)[0])
    except (OSError, MachOError):
        return None
    lo = hi = None
    for seg in macho.segments():
        name, addr, vmsize = seg[0], seg[1], seg[2]
        if name == "__PAGEZERO":
            continue
        lo = addr if lo is None else min(lo, addr)
        hi = addr + vmsize if hi is None else max(hi, addr + vmsize)
    return None if lo is None else hi - lo


def dylib_deps(path: str) -> list[str] | None:
    """Absolute (non-@) dylib dependencies of a Mach-O.

    LC_REEXPORT_DYLIB counts, and leaving it out was a bug the device found. An
    umbrella framework is nothing BUT re-exports -- ApplicationServices has zero
    exports of its own and re-exports ATSUI, CoreGraphics, CoreText and six more
    -- so a closure that only followed LC_LOAD_DYLIB bundled the umbrella, saw
    no dependencies, and shipped it. `assetutil` and `layerutil` then died on
    `Library not loaded: .../ATSUI.framework/Versions/A/ATSUI`, which nothing
    static had reported, because as far as the closure was concerned there was
    nothing to report.

    LC_LOAD_UPWARD_DYLIB is a real dependency too, and rarer; included for the
    same reason.
    """
    try:
        with open(path, "rb") as fh:
            macho = MachO(thin(fh.read(), None)[0])
    except (OSError, MachOError):
        return None
    kinds = (LC_LOAD_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB)
    return [p for lc, p in macho.paths()
            if lc.cmd in kinds and not p.startswith("@")]


def _no_compact_list() -> set[str]:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "data", "no_compact.txt")
    names = set()
    try:
        with open(path) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    names.add(line)
    except OSError:
        pass
    return names


def lift_is_stale(out: str) -> bool:
    """Is a cached lift older than the code that makes one, or not a lift?"""
    if not os.path.isfile(out):
        return True
    if has_fixups(out) is not True:
        # A raw extraction left in the cache directory by an earlier --dry-run
        # or an interrupted run. "The file is there" is not a check: this
        # project has shipped four separate stale artefacts on that reasoning.
        return True
    age = os.path.getmtime(out)
    deps = stage_files() + [os.path.abspath(__file__)]
    return any(os.path.exists(d) and os.path.getmtime(d) > age for d in deps)


def lift_library(image: str, out: str, platform_name: str, osversion: str,
                 *, changes: list[tuple[str, str]] = (),
                 redirects: list[tuple[str, str]] = (),
                 weaken_symbols: list[str] = (),
                 compact: bool = True, cache: str = MAC_DSC,
                 work: str = LIFT_WORK, arch: str | None = None,
                 cpusubtype_fix: bool = True, say=print) -> str | None:
    """Lift *image* out of the shared cache into a dylib that actually runs.

    Seven steps, because a cache image is damaged in several independent ways
    and each needs its own repair. The ORDER is load-bearing throughout and
    every ordering here was learned from a failure:

      1. extract              Apple's dsc_extractor.
      2. dsc_facts            the two things the extraction cannot tell us:
                              which words in its data are pointers (the cache's
                              slide info) and which symbol each cache-wide GOT
                              slot its code reaches was holding.
      3. machomorph           retarget, and relay the segments out for a
                              standalone image.
      4. dsc_rebind           repoint the stubs at this image's own GOT and
                              synthesise LC_DYLD_CHAINED_FIXUPS.
      4a. dsc_objc            rebase the ObjC selector and protocol references
                              the rebinder mistook for C symbols. BEFORE
                              compaction, which remaps the rebases it creates.
      4b. redirect_symbol     rename an import the target does not export, now
                              that both tables exist. AFTER the rebind: the
                              rebinder matches the cache's name against this
                              image's undefined symbols, and renaming first
                              leaves the slot silently NULL.
      5. gotscan              refuse to hand back a library that is not
                              actually repaired.
      6. dsc_compact          pack the segments, so the image reserves its own
                              size instead of the cache's 1.6-2.0 GB span.
                              AFTER the verdict: gotscan recognises a leftover
                              cache reference by its address landing outside
                              every segment, and compaction fills that in.
      7. dsc_objc --methods   repair the relative method lists. AFTER
                              compaction: the repair makes `name` a
                              __TEXT -> __DATA_CONST distance, which is exactly
                              what compaction moves.
    """
    os.makedirs(work, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    base = os.path.basename(image)

    src = dsc.extract.image(image, cache, say=say)
    if src is None:
        say(f"  cannot extract {base} from {cache}")
        return None

    # 2. facts from the cache. The two cache-WIDE dumps this needs (the slide
    # info and the patch table) are saved on the first lift and read by every
    # later one -- see facts_dump_args(). Without that a from-scratch build
    # streams the whole 5 GB cache once per library, forty times over.
    #
    # Reuse a cached file only when it holds something:
    # a truncated one from an interrupted run is reused happily by a mere
    # existence test, and then nothing is repointed, the library loads and
    # PAC-faults. That is how a damaged libxcselect got built while the cache
    # queries themselves worked fine.
    facts = os.path.join(work, base + ".facts.json")
    if os.path.isfile(facts):
        try:
            with open(facts) as fh:
                if '"stub_got"' not in fh.read():
                    say(f"  discarding {facts}: no stub_got in it")
                    os.unlink(facts)
        except OSError:
            pass
    if not os.path.isfile(facts):
        argv = [cache, src, "-o", facts]
        extra, pending = facts_dump_args(cache, work, say)
        rc, err = run_stage("facts", argv + extra)
        keep_dumps(pending, rc == 0, say)
        if rc is None or rc != 0:
            say(f"  dsc_facts failed for {base}: {err}")
            return None

    # 3. retarget and relay out. Unsigned: the rebind still has to add a load
    # command and grow __LINKEDIT.
    #
    # --reserve-header, generously: a cache extraction has about 100 spare
    # header bytes, the rebind adds a load command, and the install name is
    # rewritten to an @loader_path spelling later -- which grows the load
    # commands again, with no second chance to make room. The reserve only
    # applies while the segments are being relaid out.
    #
    # --no-symbol-check because this is an intermediate, not a loadable
    # library: it has no LC_DYLD_CHAINED_FIXUPS yet, so nothing here says what
    # actually gets bound, and any rename held back to 4b has not run.
    raw = os.path.join(work, base + ".raw")
    mm_args = ["-p", platform_name, "-v", osversion]
    if not cpusubtype_fix:
        # A macOS arm64e target otherwise gets ptrauth ABI version 1, which an
        # ordinary process cannot load -- which is exactly how the local
        # dlopen loop is run, so the lift has to honour it too.
        mm_args.append("--no-cpusubtype-fix")
    if arch:
        mm_args += ["-a", arch]
    for old, new in changes:
        mm_args += ["--change", old, new]
    for sym in weaken_symbols:
        mm_args += ["--weaken-symbol", sym]
    reserve = os.environ.get("DSC_RESERVE", "512")
    # --no-libraries: the closure is the STAGING pass's job, not the lift's. A
    # lift is one image; if its own dependencies are absent from the target
    # they get bundled beside it, and only the caller knows where that is. This
    # was worth a byte-diff: without it the lifted libssl came out pointing at
    # @loader_path copies of libcrypto and TrustEvaluationAgent that were
    # bundled into the work directory.
    if main([src, "-o", raw, "--no-sign", "--no-symbol-check",
             "--no-libraries", "--reserve-header", reserve, "-q"] + mm_args):
        say(f"  retargeting {base} failed")
        return None

    # 4. rebind
    rc, err = run_stage("rebind", [raw, "--facts", facts, "-o", out])
    if rc is None or rc != 0:
        say(f"  dsc_rebind failed for {base}: {err}")
        return None

    # 4a. the ObjC selector and protocol references.
    #
    # dsc_rebind names every slot from the cache and falls back to a weak flat
    # bind for a name it cannot place. For __objc_selrefs and __objc_protorefs
    # the cache's answer IS the selector text and the protocol name, so that
    # fallback emits hundreds of weak binds for "symbols" like `DADiskToUUID:`
    # -- all NULL at runtime, and libobjc dereferences one during map_images.
    rc, _err = run_stage("objc", [out, "-o", out + ".objc", "--no-sign",
                                      "--quiet"])
    if os.path.exists(out + ".objc"):
        os.replace(out + ".objc", out)

    # 4b. renames, now that both tables exist.
    if redirects:
        argv = [out, "-o", out + ".redirected", "--no-sign",
                "--no-symbol-check", "--no-libraries", "-q"] + mm_args
        for old, new in redirects:
            argv += ["--redirect-symbol", old, new]
        if main(argv) == 0 and os.path.exists(out + ".redirected"):
            os.replace(out + ".redirected", out)

    try:
        codesign(out, "-", None, None, verbose=False)
    except MachOError as exc:
        say(f"  codesign failed for {base}: {exc}")
        return None

    # 5. refuse to hand back a library that is not repaired.
    #
    # This step exists because the alternative happened: a lift whose facts came
    # out empty printed "0 instructions repointed", exited 0, and was staged,
    # installed and shipped. A lift either repairs the image or it is worthless.
    rc, scan = run_stage("gotscan", [out], capture=True)
    auth_left = 0
    verdict_ok = False
    for line in scan.splitlines():
        if line.strip().startswith("AUTHENTICATED_LEFTOVERS:"):
            try:
                auth_left = int(line.split(":", 1)[1])
            except ValueError:
                auth_left = 1
        if "VERDICT: repaired" in line or "VERDICT: stubs repaired" in line:
            verdict_ok = True
    # "INCOMPLETE" is accepted as long as every leftover __text site is
    # UNAUTHENTICATED -- the same rule verify_cryptex applies, and they must
    # agree. An AUTHENTICATED one is fatal: it PAC-faults on any path that
    # reaches it.
    #
    # This comment used to say an unauthenticated leftover was "almost always an
    # ADRP with no matching add/ldr", citing libcrypto's 11. That was measured
    # and is wrong: those 11 came from a second, looser decoder in
    # code_got_refs() that never invalidated a pending ADRP, and libcrypto now
    # reports 0. What survives scan_got_sites' invalidation is an adjacent
    # ADRP+use pair -- a real reference, latent rather than benign, which faults
    # on the path that reaches it. Accepting it is a judgement that the path is
    # not one the tool needs, not a claim that the site is imaginary.
    if auth_left or not verdict_ok:
        say(f"  {base} is NOT repaired -- refusing to hand it back."
            f"{f' {auth_left} authenticated site(s) still reach the cache.' if auth_left else ''}"
            f"\n  Most likely the facts are empty: dsc_facts needs the cache, "
            f"and an empty slide or patch dump yields no records at all rather "
            f"than failing. Check the dumps under {work} and $DSC_SLIDE_JSON / "
            f"$DSC_PATCHES_TXT if set."
            f"\n  Facts used: {facts}")
        if os.path.exists(out):
            os.unlink(out)
        return None

    # 6. compact the address space.
    #
    # A refused compaction is NOT a lift failure: the lift above is already
    # good, it just keeps the cache's span, which is what every lift did before
    # this step existed. Treating a refusal as fatal took a whole cryptex build
    # down with it once.
    if compact and os.path.basename(out) not in _no_compact_list():
        rc, _err = run_stage("compact", [out, "-o", out + ".compact"])
        if rc == 0 and os.path.exists(out + ".compact"):
            os.replace(out + ".compact", out)
        else:
            if os.path.exists(out + ".compact"):
                os.unlink(out + ".compact")
            say(f"  {base} not compacted -- keeping the lift as it is "
                f"(it works, it just reserves the cache's address span)")

    # 7. the relative method lists, after compaction.
    #
    # The cache rewrote each entry's `name` to reach its uniqued selector pool,
    # so no method on a lifted ObjC class can be found by selector. Needs the
    # pool's base, which only the cache's ObjC optimisation tables know.
    if _has_section(out, "__objc_methlist"):
        sel = os.environ.get("DSC_SELECTORS_TXT",
                             os.path.join(work, "cache_selectors.txt"))
        if not os.path.exists(sel) or os.path.getsize(sel) == 0:
            if shutil.which("ipsw"):
                say(f"  building the cache selector index (once) -> {sel}")
                with open(sel + ".tmp", "w") as fh:
                    p = subprocess.run(["ipsw", "dyld", "objc", "sel", cache],
                                       stdout=fh, stderr=subprocess.DEVNULL)
                if p.returncode == 0 and os.path.getsize(sel + ".tmp"):
                    os.replace(sel + ".tmp", sel)
                else:
                    os.unlink(sel + ".tmp")
        if os.path.exists(sel) and os.path.getsize(sel):
            rc, _err = run_stage("objc", [out, "-o", out + ".methods",
                                              "--no-sign",
                                              "--cache-selectors", sel])
            if os.path.exists(out + ".methods"):
                os.replace(out + ".methods", out)
        else:
            say(f"  {base}: no selector index; relative method lists left as "
                f"they are -- classes load but no method is findable by "
                f"selector")
    return out


def _has_section(path: str, want: str) -> bool:
    try:
        with open(path, "rb") as fh:
            macho = MachO(thin(fh.read(), None)[0])
    except (OSError, MachOError):
        return False
    return macho._section(want.encode()) is not None


def obtain_library(image: str, dest: str, platform_name: str, osversion: str,
                   *, prebuilt: list[str] = (), compact: bool = True,
                   cache: str = MAC_DSC, redirects=(), say=print,
                   cpusubtype_fix: bool = True, arch: str | None = None,
                   lift: bool = True) -> str | None:
    """A local copy of *image* at *dest*, lifted out of the cache if need be.

    A library that is a real file on disk is copied: it already carries its own
    fixups, so there is nothing for a lift to repair.
    """
    base = os.path.basename(image)
    for d in prebuilt or ():
        cand = os.path.join(d, base)
        if os.path.isfile(cand):
            if os.path.realpath(cand) != os.path.realpath(dest):
                os.makedirs(os.path.dirname(os.path.abspath(dest)),
                            exist_ok=True)
                shutil.copyfile(cand, dest)
                os.chmod(dest, 0o755)
            return dest
    if os.path.isfile(image):
        # copyfile, not copy2: system files carry SIP flags that cannot be
        # reproduced, and only the bytes are wanted.
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        shutil.copyfile(image, dest)
        os.chmod(dest, 0o755)
        return dest
    if not lift:
        return None
    if not lift_is_stale(dest):
        say(f"  reusing {os.path.relpath(dest)}")
        return dest
    say(f"  lifting {base} out of the shared cache")
    return lift_library(image, dest, platform_name, osversion,
                        compact=compact, cache=cache, redirects=redirects,
                        cpusubtype_fix=cpusubtype_fix, arch=arch, say=say)


def library_closure(binary: str, index, resolve_local,
                    also: list[str] = ()) -> tuple[dict[str, str], list[str]]:
    """Every library *binary* needs that the target does not have, transitively.

    *resolve_local* obtains one and returns a local path, or None. It is called
    at most once per image, and a library's own dependencies are followed
    through the local copy -- so a lifted framework drags in what it references
    (CoreDisplay pulls in GPUWrangler and IOPresentment) without that being
    written down anywhere.

    Returns ({original path: local copy}, [what could not be obtained]).
    """
    need = list(dylib_deps(binary) or []) + list(also)
    bundled: dict[str, str] = {}
    unreachable: list[str] = []
    seen: set[str] = set()
    while need:
        image = need.pop(0)
        if image in seen:
            continue
        seen.add(image)
        if index is not None and image not in also:
            if index.resolve(image)[0] is not None:
                continue                          # the target has it
        local = resolve_local(image)
        if local is None:
            unreachable.append(image)
            continue
        bundled[image] = local
        sub = dylib_deps(local)
        if sub is None:
            unreachable.append(image)
            continue
        need.extend(sub)
    return bundled, unreachable


def probe_library(image: str, cache: str, prebuilt=(), say=print) -> str | None:
    """A local copy good enough to READ from -- no repair, nothing signed.

    Enumerating a closure has to happen before anything is lifted, because the
    size of the closure is what decides whether the binary is worth porting at
    all, and a lift costs minutes. An extraction is worthless as a library and
    perfectly good as a source of load commands.
    """
    base = os.path.basename(image)
    for d in prebuilt or ():
        cand = os.path.join(d, base)
        if os.path.isfile(cand):
            return cand
    if os.path.isfile(image):
        return image
    return dsc.extract.image(image, cache, say=say)


def default_prebuilt(args) -> tuple[list[str], str]:
    """(--prebuilt directories, the lift cache). Both default to ./lifted."""
    repo = os.path.dirname(os.path.abspath(__file__))
    default = os.path.join(repo, "lifted")
    cache = args.lift_cache or default
    dirs = args.prebuilt
    if dirs is None:
        # NOT the lift cache. Making it a --prebuilt directory by default was a
        # bug, and the fifth instance of the pattern this project keeps
        # relearning: "the file is there" is not a check. obtain_library() looks
        # in the prebuilt directories FIRST and unconditionally, so a cached
        # lift was handed back whatever its age -- which made lift_is_stale()
        # dead code in the default case, and quietly reused libraries produced
        # by an older rebinder. Reuse of the cache goes through lift_is_stale()
        # instead, which is what it is for.
        #
        # An explicit --prebuilt still wins over everything: that is the point
        # of the flag, and trusting what the user points at is reasonable in a
        # way that trusting our own leftovers is not.
        dirs = []
    return dirs, cache


def obtain_libraries(args, sources: list[str], index, staging, platform,
                     version, sdk, say) -> tuple[dict[str, dict[str, str]],
                                                 dict[str, str], int]:
    """Get, repair and stage every library the target does not have.

    Returns (per_source, staged, rc):
      per_source  source -> {original library path: staged file}
      staged      original library path -> staged file
      rc          non-zero only for an error that should stop the run

    Three phases, and the split is what makes the cost gate meaningful:
    enumerate every closure from cheap extractions, decide what is worth
    paying for, and only then lift.
    """
    prebuilt, lift_cache = default_prebuilt(args)
    redirects = [tuple(r) for r in args.redirect_symbol]
    if args.darwin_extsn:
        redirects += [r for r in DARWIN_EXTSN_REDIRECTS if r not in redirects]

    # --- 1. enumerate ------------------------------------------------------
    probed: dict[str, str] = {}

    def probe(image: str) -> str | None:
        if image not in probed:
            local = probe_library(image, args.dsc, prebuilt, say)
            if local is None:
                return None
            probed[image] = local
        return probed[image]

    per_source: dict[str, dict[str, str]] = {}
    too_big: list[tuple[str, int]] = []
    unreachable: dict[str, list[str]] = {}
    for source in sources:
        libs, bad = library_closure(source, index, probe, args.also)
        if bad:
            unreachable[source] = bad
        if not libs:
            continue
        if args.max_libs and len(libs) > args.max_libs:
            # A closure this large means the binary is dragging in a whole
            # macOS subsystem that cannot work on the target -- system_profiler
            # wants AppKit, SkyLight, HIToolbox and OpenGL, which is the macOS
            # window server, and it would load and have nothing to talk to. The
            # binary is still converted; it will simply report its libraries as
            # missing, which is the truth.
            too_big.append((source, len(libs)))
            continue
        per_source[source] = libs

    wanted = sorted({orig for libs in per_source.values() for orig in libs})
    if not wanted:
        if too_big:
            say(f"\n{len(too_big)} binaries need more than {args.max_libs} "
                f"libraries the target lacks, so none was bundled for them:")
            for source, n in sorted(too_big, key=lambda kv: -kv[1])[:10]:
                say(f"  {n:3d}  {os.path.basename(source)}")
        return {}, {}, 0

    # --- report the cost, which is the point of --dry-run -------------------
    say("")
    total = sum(os.path.getsize(probed[o]) for o in wanted
                if os.path.exists(probed.get(o, "")))
    say(f"===== {len(wanted)} librar{'y' if len(wanted) == 1 else 'ies'} the "
        f"target does not have, {total / 1e6:.1f} MB")
    for orig in sorted(wanted, key=lambda o: -os.path.getsize(probed[o])):
        users = sum(1 for libs in per_source.values() if orig in libs)
        say(f"  {os.path.getsize(probed[orig]) / 1e6:8.2f} MB  {orig}"
            + (f"   [{users} binaries]" if len(sources) > 1 else ""))
    for source, bad in unreachable.items():
        for u in bad:
            print(f"warning: {os.path.basename(source)}: cannot obtain {u}",
                  file=sys.stderr)
    if too_big:
        say(f"  {len(too_big)} binaries need more than {args.max_libs} of them "
            f"and were left unbundled (--max-libs):")
        for source, n in sorted(too_big, key=lambda kv: -kv[1])[:10]:
            say(f"      {n:3d}  {os.path.basename(source)}")
    if args.dry_run:
        # The two ceilings a lift runs into, neither of which is size. Reported
        # from the extraction, which keeps the cache's segment addresses just as
        # the lift will.
        spans = [(vm_span(probed[o]), o) for o in wanted]
        big = sorted(((s, o) for s, o in spans if s and s > VM_SPAN_WARN),
                     reverse=True)
        if big:
            say(f"  {len(big)} would reserve over {VM_SPAN_WARN / 1e6:.0f} MB "
                f"of contiguous address space each, uncompacted:")
            for span, orig in big:
                say(f"      {span / 1e6:8.0f} MB  {os.path.basename(orig)}")
        return per_source, {}, 0

    # --- 2. obtain: lift what only exists inside the cache ------------------
    local: dict[str, str] = {}
    for orig in wanted:
        dest = os.path.join(lift_cache, os.path.basename(orig))
        got = obtain_library(orig, dest, args.platform, args.osversion,
                             prebuilt=prebuilt, compact=not args.no_compact,
                             cache=args.dsc, redirects=redirects,
                             cpusubtype_fix=not args.no_cpusubtype_fix,
                             arch=args.arch, say=say)
        if got is None:
            print(f"warning: cannot obtain {orig} -- every binary that needs "
                  f"it will fail at load", file=sys.stderr)
            continue
        local[orig] = got

    # --- 3. stage: convert each one into the layout -------------------------
    #
    # Each bundled library needs its own LC_ID_DYLIB rewritten to the name
    # binaries will ask for, and every reference BETWEEN bundled libraries
    # rewritten too. Keying the rewrite only on the referenced path is not
    # enough: a lift has had Versions/A flattened out of its own install name,
    # so the path a tool asks for and the path the library calls itself are
    # different strings, and four libraries once shipped with their original
    # absolute macOS names while every binary asked for the relative one.
    # Read each one's exports from the local copy, before any of them is
    # staged: a sibling's export trie is what keeps the launch prediction from
    # condemning libssl for the 330 symbols it imports from the libcrypto we
    # bundle right beside it.
    exports = {orig: dylib_exports(src) for orig, src in local.items()}
    staged: dict[str, str] = {}
    for orig, src in local.items():
        dest = staging.library_dest(orig)
        changes = {}
        for other, other_src in local.items():
            changes[other] = staging.install_name_for(other, dest)
            actual = dylib_id(other_src)
            if actual and actual not in changes:
                changes[actual] = staging.install_name_for(other, dest)
        # Its own identity is the name a BINARY asks for, not the name a
        # sibling library asks for: the two differ under a mirror layout, and
        # dyld resolves either to the same file.
        own = staging.reference_name(orig)
        changes[orig] = own
        actual = dylib_id(src)
        if actual:
            changes[actual] = own
        libargs = copy.copy(args)
        # --weaken-unresolvable applies HERE and only here. For a bundled
        # library it is the difference between the whole closure loading and
        # none of it: iOS has no equivalent of Authorization Services or the
        # SecTransform pipeline at all, so there is nothing to fix and the
        # choice is between not shipping the library and binding those symbols
        # NULL. For a BINARY it is a different trade entirely -- it converts a
        # clean skip into a crash later, and this project's own rule is that a
        # port which dies is dead weight that shadows a native tool of the same
        # name. The first wide build weakened 155 symbols in `screencapture`,
        # 65 in `profiles` and 49 in `networksetup` before this was scoped.
        libargs._weaken_unresolvable_here = args.weaken_unresolvable
        libargs.change = []
        libargs.provide_lib = []
        libargs.cryptex = None
        libargs.output = dest
        libargs.quiet = True
        libargs.libraries = False
        sibling = {o: (staging.install_name_for(o, dest), exports[o])
                   for o in local if o != orig}
        res = convert_one(libargs, src, dest, platform, version, sdk, index,
                          changes, set(), sibling, lambda *a: None)
        if not res.ok:
            why = res.error
            if res.skipped:
                why = ("it imports symbols the target does not export "
                       "(--weaken-unresolvable to bind them NULL and ship it "
                       "anyway)")
            print(f"warning: cannot stage {os.path.basename(orig)}: {why}",
                  file=sys.stderr)
            continue
        staged[orig] = dest
        note = ""
        if has_fixups(dest) is False:
            note = ("   NO FIXUPS: a raw cache extraction. It loads, and "
                    "crashes on the first path that dereferences a global")
        span = vm_span(dest)
        if span and span > VM_SPAN_WARN:
            note += (f"   reserves {span / 1e6:.0f} MB of contiguous address "
                     f"space")
        shown = dest
        root = getattr(staging, "root", None)
        if root and dest.startswith(root):
            shown = os.path.relpath(dest, root)
        say(f"Bundled library           {shown}\n"
            f"  {orig}\n     -> {own}{note}")

    # Hand back the STAGED path, not the extraction the closure was walked
    # with. A binary is pointed at what was actually written into the layout,
    # and anything that could not be staged is dropped rather than referenced.
    for libs in list(per_source.values()):
        for orig in list(libs):
            if orig in staged:
                libs[orig] = staged[orig]
            else:
                libs.pop(orig)
    return per_source, staged, 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="machomorph",
        description="Retarget a Mach-O binary at another Apple platform "
                    "(lipo + cbv + install_name_tool + ldid + codesign in one).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  machomorph.py --info /usr/sbin/ioreg
  machomorph.py /usr/sbin/ioreg -o ioreg_ios --platform ios --version 27.0
  machomorph.py /usr/bin/lsmp -o lsmp_ios -p ios -v 27.0 --license-to-operate
  machomorph.py app -o app_mac -p macos -v 15.0 \\
      --change /usr/lib/libfoo.dylib /usr/lib/libbar.dylib

  # convert every Mach-O in the macOS system directories into a cryptex tree,
  # bundling a replacement for a library iOS does not have:
  machomorph.py --scan -p ios -v 26.0 --cryptex ~/srd/combined \\
      --dylib-index ios27_index.txt --weaken-missing \\
      --provide-lib /usr/lib/libxcselect.dylib \\
                    lifted/libxcselect.dylib
""")
    p.add_argument("input", nargs="*", help="Mach-O binaries (fat or thin)")
    p.add_argument("-o", "--output",
                   help="output path; a directory when converting more than "
                        "one input (default: ./<basename>)")
    p.add_argument("-p", "--platform", choices=sorted(PLATFORMS),
                   help="target platform")
    p.add_argument("-v", "--version", dest="osversion",
                   help="target OS version, e.g. 27 / 27.0 / 27.0.1")
    p.add_argument("--sdk", help="SDK version (default: target major version)")
    p.add_argument("-a", "--arch",
                   help="architecture to extract from a fat binary "
                        "(default: arm64e, else arm64, else the only one)")

    g = p.add_argument_group("batch conversion")
    g.add_argument("--scan", nargs="*", metavar="DIR", default=None,
                   help="convert every executable Mach-O found in these "
                        "directories, in addition to any given as arguments "
                        f"(default: {' '.join(SCAN_DEFAULT_DIRS)})")
    g.add_argument("--scan-recursive", action="store_true",
                   help="with --scan, descend into subdirectories")
    g.add_argument("--scan-xcode", dest="scan_xcode", action="store_true",
                   default=None,
                   help="also convert the Xcode toolchain's own binaries -- "
                        "the real otool, nm, objdump, strings and friends, "
                        "which on macOS are only stubs in /usr/bin. ON BY "
                        "DEFAULT whenever anything is scanned, since a scan "
                        "that takes /usr/bin's stubs and leaves the real tools "
                        "behind is the wrong half. Tools that exist to compile "
                        "rather than inspect are skipped; see --list-skipped")
    g.add_argument("--no-scan-xcode", dest="scan_xcode", action="store_false",
                   help="do not scan the Xcode toolchain, even when scanning "
                        "the system directories")
    g.add_argument("--no-xcode-blocklist", action="store_true",
                   help="with --scan-xcode, take the whole toolchain including "
                        "clang, swift and the language servers (~+600 MB)")
    g.add_argument("--exclude", action="append", metavar="GLOB", default=[],
                   help="skip inputs whose file name matches this glob; a "
                        "pattern containing '/' is matched against the whole "
                        "path instead, so /usr/bin/otool can be excluded "
                        "without also excluding the toolchain's otool. "
                        "Repeatable, applies to every source")
    g.add_argument("--exclude-from", action="append", metavar="FILE", default=[],
                   help="skip the names/globs listed in FILE, one per line, "
                        "'#' for comments. Repeatable, and ADDS to the lists "
                        "shipped in data/, which a scan applies by default")
    g.add_argument("--no-exclude-defaults", action="store_true",
                   help="do not apply the exclusion lists shipped in data/ "
                        "(the 95 xcrun shims by path, and the binaries a device "
                        "probe measured dying on a missing symbol). They apply "
                        "only to what a scan finds, never to a path given as an "
                        "argument")
    g.add_argument("--no-clobber", action="store_true",
                   help="never overwrite a file this tool did not write. A "
                        "cryptex usually already holds binaries someone built "
                        "natively for iOS, and a macOS port of the same name "
                        "would be a downgrade; with --cryptex, ownership is "
                        "read from the .machomorph-manifest an earlier run "
                        "left behind")
    g.add_argument("--list-skipped", action="store_true",
                   help="print what the scan would convert and what it would "
                        "skip, then exit")
    g.add_argument("--keep-going", action="store_true",
                   help="do not stop the batch at the first failure")

    g = p.add_argument_group("cryptex staging")
    g.add_argument("--cryptex", metavar="DIR",
                   help="stage the results into this cryptex root: binaries "
                        "go to DIR/<bindir>, bundled libraries to DIR/<libdir>. "
                        "Implies the output path, so -o is not needed")
    g.add_argument("--cryptex-bindir", metavar="REL", default="bin",
                   help="binary directory inside the cryptex (default: bin)")
    g.add_argument("--cryptex-libdir", metavar="REL", default="usr/lib",
                   help="library directory inside the cryptex "
                        "(default: usr/lib)")
    g.add_argument("--loader-path", action="store_true",
                   help="anchor bundled-library references at @loader_path "
                        "instead of @executable_path. Identical meaning for a "
                        "main executable, but four bytes shorter -- which can "
                        "be the difference between fitting in the load-command "
                        "area and not (tcpdump is 8 bytes short otherwise)")
    g.add_argument("--provide-lib", nargs=2, action="append", default=[],
                   metavar=("OLDPATH", "FILE"),
                   help="bundle FILE (an already-built dylib for the target) "
                        "into the cryptex library directory and point every "
                        "reference to OLDPATH at it, via an "
                        "@executable_path-relative install name. The reference "
                        "is also made weak, so a binary still launches if the "
                        "library fails to load. Repeatable, needs --cryptex")

    g = p.add_argument_group("libraries the target does not have")
    g.add_argument("--no-libraries", dest="libraries", action="store_false",
                   default=True,
                   help="do not obtain the libraries the target lacks. The "
                        "binary is converted alone, and will fail at load on "
                        "every one of them")
    g.add_argument("--lib-layout", choices=("mirror", "flat"), default="mirror",
                   help="where a bundled library goes under the output "
                        "directory: 'mirror' keeps the target's own path, so "
                        "the output reads as a small root and two libraries "
                        "with one basename cannot collide; 'flat' puts them all "
                        "beside the binary, which is shorter per reference "
                        "(default: mirror). --cryptex is always flat")
    g.add_argument("--lib-subdir", metavar="REL",
                   help="with --lib-layout flat, put the libraries in this "
                        "subdirectory of the output rather than beside the "
                        "binary")
    g.add_argument("--libs-into", metavar="DIR",
                   help="root for the bundled libraries (default: the "
                        "directory the binary is written to)")
    g.add_argument("--prebuilt", action="append", metavar="DIR", default=None,
                   help="look here first for a library, by basename, before "
                        "going to the shared cache. For one built from source "
                        "or lifted earlier. Repeatable (default: ./lifted if "
                        "it exists)")
    g.add_argument("--lift-cache", metavar="DIR",
                   help="where lifted libraries are kept between runs "
                        "(default: ./lifted). A lift is a build product of the "
                        "lifting tools, so a cached one is re-made when any of "
                        "them is newer")
    g.add_argument("--max-libs", type=int, default=7, metavar="N",
                   help="do not port a binary needing more than N libraries "
                        "the target lacks. A big closure means it is dragging "
                        "in a whole macOS subsystem that will not work there "
                        "anyway -- system_profiler wants AppKit, SkyLight and "
                        "HIToolbox, which is the macOS window server. 0 for no "
                        "limit (default: 7)")
    g.add_argument("--also", action="append", metavar="PATH", default=[],
                   help="bundle this library too, even though the target has "
                        "one of the same name. For when the target ships it "
                        "with a smaller export surface, so the binary loads "
                        "and then dies on a missing symbol. Repeatable")
    g.add_argument("--no-compact", action="store_true",
                   help="do not pack a lifted library's segments together. A "
                        "lift keeps the shared cache's segment addresses, so "
                        "it reserves 1.3-2.0 GB of contiguous address space "
                        "and only two or three fit in one process; compaction "
                        "brings that down to the library's own size, and an "
                        "ObjC image does not load without it")
    g.add_argument("--dsc", default=MAC_DSC, metavar="PATH",
                   help="the macOS shared cache to lift out of")
    g.add_argument("--weaken-unresolvable", action="store_true",
                   help="in a BUNDLED LIBRARY, weaken every import the target "
                        "does not export instead of refusing to stage it. The "
                        "library then loads and any path that reaches one of "
                        "those symbols crashes -- a judgement, and only "
                        "defensible when the tool does not need that path. "
                        "What was weakened is always reported. It deliberately "
                        "does NOT apply to the binaries being converted: for "
                        "one of those the same trade turns a clean skip into a "
                        "crash later, and --force is the way to ask for that")
    g.add_argument("--dry-run", action="store_true",
                   help="work out each binary's library closure, print it with "
                        "its size and address-space cost, and stop")

    p.add_argument("--change", nargs=2, action="append", metavar=("OLD", "NEW"),
                   default=[], help="rewrite a dylib/rpath path (repeatable)")
    p.add_argument("--no-auto-paths", action="store_true",
                   help="do not strip macOS-only /Versions/A/ from paths")
    p.add_argument("--weak", action="append", metavar="PATH", default=[],
                   help="mark this dylib weak (LC_LOAD_WEAK_DYLIB) so the "
                        "binary still launches when it is absent. Repeatable")
    p.add_argument("--weaken-missing", action="store_true",
                   help="with --dylib-index, mark every library that is absent "
                        "on the target weak, so the binary loads anyway. It "
                        "will crash if it actually calls into one")
    p.add_argument("--dylib-index", metavar="FILE",
                   help="list of library paths the target can load, from "
                        "dsc_index.py. Enables rewriting a library to wherever "
                        "it actually lives on the target, and warns about "
                        "libraries that are missing there entirely")
    p.add_argument("--no-dylib-index", action="store_true",
                   help="do not fall back to the index shipped with this tool "
                        "when --dylib-index is not given. Paths are then "
                        "rewritten by rule alone, and nothing can be said "
                        "about which libraries the target actually has")
    p.add_argument("--force", action="store_true",
                   help="convert even a binary predicted to fail at launch on "
                        "a symbol the target does not export. The prediction "
                        "is checked against the SDK stubs and was measured at "
                        "0 false positives over 384 working binaries, so this "
                        "is normally only wanted when you know better than the "
                        "SDK -- a private framework, or a newer OS")
    p.add_argument("--no-symbol-check", action="store_true",
                   help="skip the launch prediction entirely")
    p.add_argument("--target-symbols", metavar="FILE",
                   help="what the target's own dyld cache exports, per library, "
                        "from `python3 -m dsc.symindex`. The SDK stubs cover no "
                        "PrivateFramework, so without this a symbol from one is "
                        "`unknown` and fails nothing -- which is how csrutil "
                        "shipped and died on _DAUnregisterApprovalCallback")
    p.add_argument("--sdk-path", metavar="PATH",
                   help="SDK whose .tbd stubs define what the target exports, "
                        "for the launch prediction (default: xcrun --sdk "
                        "<platform> --show-sdk-path). Not --sdk, which is the "
                        "SDK version written into LC_BUILD_VERSION")
    p.add_argument("--weaken-symbol", action="append", metavar="SYM", default=[],
                   help="mark an imported symbol weak so it binds NULL instead "
                        "of failing the load when the target does not export "
                        "it. Use only for a symbol on a path the tool does not "
                        "need: the binary launches, but calling it crashes. "
                        "Repeatable")
    p.add_argument("--fix-weak-imports", action="store_true",
                   help="make the chained-imports weak flags agree with the "
                        "symbol table. A synthesised import table can lose "
                        "N_WEAK_REF, which turns every weak import into a hard "
                        "one -- so a weak-linked library the target does not "
                        "have fails the load instead of binding NULL. Only "
                        "adds the bit, never removes it")
    p.add_argument("--redirect-symbol", nargs=2, action="append", default=[],
                   metavar=("OLD", "NEW"),
                   help="rename an imported symbol in place, in both the "
                        "symbol table and the chained-fixups pool. NEW must be "
                        "no longer than OLD (nothing moves) and must live in "
                        "the same library, so the two-level-namespace ordinal "
                        "is unchanged. Repeatable")
    p.add_argument("--darwin-extsn", action="store_true",
                   help="shorthand for --redirect-symbol "
                        "'_syslog$DARWIN_EXTSN' _syslog. It is the one "
                        "$DARWIN_EXTSN variant iOS libc does not export, and "
                        "plain _syslog is the same call with the older "
                        "semantics")
    p.add_argument("--reserve-header", type=int, default=0, metavar="BYTES",
                   help="when relaying out a shared-cache extraction, leave "
                        "this many spare bytes after the load commands, by "
                        "growing __TEXT downward. Needed before dsc_rebind "
                        "can add LC_DYLD_CHAINED_FIXUPS")
    p.add_argument("--no-cpusubtype-fix", action="store_true",
                   help="leave the arm64e ptrauth ABI subtype alone")
    p.add_argument("--entitlements", metavar="FILE",
                   help="sign with these entitlements instead of the "
                        "binary's existing ones")
    p.add_argument("--license-to-operate", dest="license", action="store_true",
                   default=None,
                   help=f"always add <{LICENSE_TO_OPERATE}> to the "
                        f"entitlements, even if the binary had none")
    p.add_argument("--no-license-to-operate", dest="license",
                   action="store_false",
                   help=f"never add <{LICENSE_TO_OPERATE}>. By default it is "
                        f"added whenever the binary already carries "
                        f"entitlements, since an entitled binary needs it to "
                        f"run on a research device")
    p.add_argument("--dump-entitlements", metavar="FILE",
                   help="also write the entitlements used to FILE")
    p.add_argument("--sign-identity", default="-",
                   help="codesign identity (default: '-', ad-hoc)")
    p.add_argument("--identifier", help="codesign --identifier to use")
    p.add_argument("--no-sign", action="store_true",
                   help="skip re-signing (leaves an invalid signature!)")
    p.add_argument("--info", action="store_true",
                   help="just print what is in the binary and exit")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


class Result:
    """What became of one input binary."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.output: str | None = None
        self.error: str | None = None
        self.missing: list[tuple[str, str]] = []   # unresolved, still hard-linked
        self.needs: dict[str, list[str]] = {}      # provided lib -> symbols used
        self.unsatisfied: dict[str, list[str]] = {}  # ... that it does not export
        self.redirected: list[tuple[str, str]] = []  # imported symbols renamed
        self.weakened_syms: list[str] = []          # imports forced weak
        self.unresolved_syms: list[tuple[str, str]] = []  # will fail at launch
        self.skipped: bool = False                 # not ported, and why

    @property
    def ok(self) -> bool:
        return self.error is None and not self.skipped


def convert_one(args, source: str, output: str, platform: int,
                version: tuple[int, int, int], sdk, index,
                extra_changes: dict[str, str], extra_weak: set[str],
                provided: dict[str, tuple[str, set[str] | None]],
                say) -> Result:
    """Convert a single binary. Never raises; failures land in Result.error."""
    res = Result(source)

    try:
        with open(source, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        res.error = f"cannot read: {exc.strerror}"
        return res

    try:
        thin_data, picked = thin(raw, args.arch)
        macho = MachO(thin_data)
    except MachOError as exc:
        res.error = str(exc)
        return res

    if os.path.realpath(output) == os.path.realpath(source):
        res.error = "output would overwrite the input"
        return res

    if picked != "<thin>":
        say(f"Thinned to {picked} ({len(thin_data)} bytes)")

    # Which symbols come from which library, keyed by the *original* paths --
    # it has to be read before any of them is rewritten.
    imports = macho.imports_by_library() if provided else {}

    # --- entitlements are read before we touch anything ---------------------
    if args.entitlements:
        try:
            with open(args.entitlements, "rb") as fh:
                ent_xml = fh.read()
        except OSError as exc:
            res.error = f"cannot read {args.entitlements}: {exc.strerror}"
            return res
    else:
        ent_xml = extract_entitlements(macho)

    # An entitled binary is useless on a research device without the
    # license-to-operate entitlement, so add it by default whenever there are
    # entitlements to begin with. --no-license-to-operate opts out;
    # --license-to-operate forces it on even for unentitled binaries.
    add_license = args.license
    if add_license is None:
        add_license = bool(entitlements_dict(ent_xml))
    if add_license:
        ents = entitlements_dict(ent_xml)
        if ents.get(LICENSE_TO_OPERATE) is True:
            say(f"Entitlements: {LICENSE_TO_OPERATE} already present")
        else:
            ents[LICENSE_TO_OPERATE] = True
            ent_xml = plistlib.dumps(ents, fmt=plistlib.FMT_XML)
            say(f"Entitlements: added {LICENSE_TO_OPERATE}")

    # --- platform ----------------------------------------------------------
    before = macho.build_version()
    if before:
        say(f"Original build version:   "
            f"{PLATFORM_PRETTY.get(before[0], before[0])} "
            f"{format_version(before[1])} (sdk {format_version(before[2])})")
    else:
        say("Original build version:   <none>")
    macho.set_platform(platform, version, sdk)
    after = macho.build_version()
    say(f"Converted to:             {PLATFORM_PRETTY[platform]} "
        f"{format_version(after[1])} (sdk {format_version(after[2])})")

    if not args.no_cpusubtype_fix:
        new_sub = macho.fix_cpusubtype(platform)
        if new_sub is not None:
            say(f"Adjusted cpusubtype to    {new_sub:#010x}")

    fixed_segs = macho.fix_data_const_flags()
    if fixed_segs:
        say(f"Restored SG_READ_ONLY on   {', '.join(fixed_segs)}")

    # Before the relayout, because it copies section contents around: an image
    # that needs relaying out is a cache extraction, which is exactly the case
    # where these flags are a lie.
    if macho.needs_relayout():
        objc = macho.fix_objc_imageinfo()
        if objc is not None:
            say(f"Cleared dyld-optimised ObjC flags  "
                f"{objc[0]:#06x} -> {objc[1]:#06x}")


    # Same class of problem as the ObjC flags, but it is self-detecting rather
    # than lift-only: a descriptor whose offset already lies inside the TLV
    # template is left alone, so an ordinary macOS binary is never touched.
    n_tlv, tlv_notes = macho.fix_tlv_descriptors()
    if n_tlv:
        say(f"Repaired {n_tlv} thread-local descriptor(s)")
    for note in tlv_notes:
        print(f"warning: thread-local: {note}", file=sys.stderr)

    if macho.needs_relayout():
        moved, exports = macho.relayout_for_standalone(
            getattr(args, 'reserve_header', 0))
        say(f"Relaid out {moved} segments for a standalone image"
            + (f", rebuilt {exports} exports" if exports else ""))

    # --- weak-import flags --------------------------------------------------
    if getattr(args, "fix_weak_imports", False):
        try:
            n, names = macho.sync_weak_imports()
        except MachOError as exc:
            res.error = str(exc)
            return res
        if n:
            shown = ", ".join(names[:4]) + (", ..." if n > 4 else "")
            say(f"Restored weak_import on {n} chained import(s): {shown}")

    # --- individually weakened imports --------------------------------------
    for sym in getattr(args, "weaken_symbol", []):
        n_sym, n_imp = macho.weaken_symbol(sym)
        if n_sym or n_imp:
            res.weakened_syms.append(sym)
            say(f"Weakened import {sym}   [symtab {n_sym}, chained {n_imp}]")
        else:
            print(f"note: {source}: --weaken-symbol {sym}: not an import here "
                  f"(or already weak)", file=sys.stderr)

    # --- imported symbol renames --------------------------------------------
    # A symbol the target does not export kills the process at launch, before
    # main(). Where the target exports the same call under a shorter name --
    # iOS has plain _syslog but not _syslog$DARWIN_EXTSN -- the name can be
    # rewritten inside its own storage, so nothing moves and the library
    # ordinal is untouched.
    redirects = list(tuple(pair) for pair in args.redirect_symbol)
    if getattr(args, "darwin_extsn", False):
        redirects += [r for r in DARWIN_EXTSN_REDIRECTS if r not in redirects]
    for old_sym, new_sym in redirects:
        try:
            notes = macho.redirect_symbol(old_sym, new_sym)
        except MachOError as exc:
            res.error = str(exc)
            return res
        if notes:
            res.redirected.append((old_sym, new_sym))
            say(f"Redirected import {old_sym}\n"
                f"               -> {new_sym}   [{'; '.join(notes)}]")

    # --- dylib / rpath paths ------------------------------------------------
    explicit = dict(extra_changes)
    explicit.update(tuple(pair) for pair in args.change)
    original_paths = {p for _lc, p in macho.paths()}
    changed = 0
    unresolved: list[tuple[str, str]] = []
    for lc, path in macho.paths():
        new = explicit.get(path)
        why = "--change"
        # LC_ID_DYLIB is what this library calls ITSELF, not something it
        # loads, so resolving it against the target index is meaningless and
        # reporting it missing is a lie: every lifted library would be told
        # "1 library is missing on the target; this binary will fail at load"
        # about its own name. It still falls through to auto_fix_path below,
        # which flattens Versions/ out of it -- behaviour bundle.py depends on.
        if (new is None and index is not None
                and lc.cmd not in (LC_RPATH, LC_ID_DYLIB)):
            if path.startswith("@rpath/"):
                # Not something the cache index can answer; check whether the
                # dylib has been staged where this binary's rpath will look.
                staged = resolve_rpath(macho, path, output)
                if staged is None:
                    unresolved.append((path, "no LC_RPATH resolves it, and it "
                                             "is not staged alongside"))
                else:
                    say(f"  rpath: {path}\n     -> {staged}   [staged]")
                continue
            resolved, why = index.resolve(path)
            if resolved is None:
                unresolved.append((path, why))
            elif resolved != path:
                new = resolved
        elif new is None and not args.no_auto_paths:
            new = auto_fix_path(path)
            why = "flattened Versions/"
        if new is None or new == path:
            continue
        macho.set_path(lc, new)
        say(f"  path: {path}\n     -> {new}   [{why}]")
        changed += 1
    # Only warn about paths the user named by hand. The implicit
    # --provide-lib rewrites apply to a whole batch, and most binaries in it
    # will not reference the library at all.
    for old_path, _new in args.change:
        if old_path not in original_paths:
            print(f"warning: {source}: --change source path not found in "
                  f"binary: {old_path}", file=sys.stderr)
    if changed:
        say(f"Rewrote {changed} path(s)")

    # A bundled replacement library is also weakened: if it somehow fails to
    # load, the binary should still launch rather than die at dyld time.
    weak_wanted = set(args.weak) | set(extra_weak)
    if args.weaken_missing:
        weak_wanted |= {p for p, _why in unresolved}
    weakened = set()
    if weak_wanted:
        for lc, path in macho.paths():
            if path in weak_wanted and macho.weaken(lc):
                weakened.add(path)
                say(f"  weak: {path}")
        for miss in sorted(weak_wanted - weakened):
            if miss not in original_paths or miss in set(args.weak):
                # Only complain about what the user asked for by hand: the
                # implicit --provide-lib weakening is best-effort by design.
                if miss in set(args.weak):
                    if miss in original_paths:
                        print(f"warning: {source}: --weak {miss}: already "
                              f"weak, or not a plain LC_LOAD_DYLIB",
                              file=sys.stderr)
                    else:
                        print(f"warning: {source}: --weak {miss}: not linked "
                              f"by this binary", file=sys.stderr)
    if weakened:
        say(f"Weakened {len(weakened)} librar"
            f"{'y' if len(weakened) == 1 else 'ies'}")

    # An absent library the binary already weak-links is not a problem: dyld
    # will launch it regardless. Only a hard LC_LOAD_DYLIB that resolves to
    # nothing on the target actually blocks the binary.
    tolerated = {path for lc, path in macho.paths()
                 if lc.cmd == LC_LOAD_WEAK_DYLIB}
    for path, why in unresolved:
        if path in weakened:
            print(f"note: {source}: {path}: {why} -- weak-linked, so it will "
                  f"load; calling into it would crash", file=sys.stderr)
        elif path in tolerated:
            say(f"  absent on target, but already weak: {path}")
        else:
            print(f"warning: {source}: {path}: {why}", file=sys.stderr)
    unresolved = [u for u in unresolved if u[0] not in tolerated]
    res.missing = unresolved
    if unresolved:
        print(f"warning: {source}: {len(unresolved)} librar"
              f"{'y is' if len(unresolved) == 1 else 'ies are'} missing on the "
              f"target; this binary will fail at load", file=sys.stderr)

    # --- does each bundled replacement actually export what is used? --------
    for old_path, (install_name, exports) in provided.items():
        used = imports.get(old_path, [])
        if not used:
            continue
        res.needs[old_path] = used
        say(f"  uses {len(used)} symbol(s) from {os.path.basename(old_path)}: "
            f"{', '.join(used)}")
        if exports is None:
            continue                 # could not read the trie; say nothing
        gap = [sym for sym in used if sym not in exports]
        if gap:
            res.unsatisfied[old_path] = gap
            print(f"warning: {source}: {install_name} does not export "
                  f"{', '.join(gap)}; the binary will load but crash if it "
                  f"calls them", file=sys.stderr)

    # --- will it even launch? -----------------------------------------------
    # A missing symbol kills the process before main(), and unlike a missing
    # library it used to be invisible until the binary was on the device. It is
    # not: the two-level-namespace ordinal says which library each bind is
    # aimed at, and the SDK stub for that library says what the target exports.
    # Measured against 423 real device launches: 39 of 39 failures caught, 0 of
    # 384 working binaries wrongly flagged.
    #
    # Refusing to port is the useful default -- a binary that cannot launch is
    # dead weight that shadows a working native tool of the same name. --force
    # ports it anyway.
    if not getattr(args, "no_symbol_check", False) and platform is not None:
        target = target_symbols(getattr(args, "sdk_path", None),
                                args.platform or "",
                                getattr(args, "target_symbols", None))
        if target is not None:
            provided_exports = {os.path.basename(old): ex
                                for old, (_name, ex) in provided.items()
                                if ex is not None}
            will_fail, _unknown = unresolvable_imports(
                macho, target, index, provided_exports)
            if will_fail:
                res.unresolved_syms = will_fail
                seen, shown = set(), []
                for lib, sym in will_fail:
                    if sym not in seen:
                        seen.add(sym)
                        shown.append(f"{sym} (from {os.path.basename(lib)})")
                detail = "; ".join(shown[:3]) + (
                    f"; +{len(shown) - 3} more" if len(shown) > 3 else "")
                if getattr(args, "_weaken_unresolvable_here", False):
                    # Bind them NULL instead of refusing to convert. The image
                    # loads and any path that reaches one of them crashes, so
                    # this is a judgement about what the tool needs, not a fix
                    # -- which is why every symbol is named rather than
                    # counted. DiskManagement and libcsfde need 30 between
                    # them, all macOS-only Security APIs (Authorization
                    # Services, SecKeychain, the SecTransform pipeline, the
                    # FileVault recovery-key calls) that iOS has no equivalent
                    # of at all.
                    done = []
                    for _lib, sym in will_fail:
                        if sym in done:
                            continue
                        n_sym, n_imp = macho.weaken_symbol(sym)
                        if n_sym or n_imp:
                            done.append(sym)
                    if done:
                        res.weakened_syms += done
                        print(f"warning: {source}: weakened {len(done)} import"
                              f"(s) the target does not export, so it loads "
                              f"and crashes only if it calls them: "
                              f"{', '.join(done)}", file=sys.stderr)
                    still = [s for _l, s in will_fail if s not in done]
                    if still:
                        res.unresolved_syms = will_fail
                        res.skipped = True
                        print(f"skipped: {source}: cannot weaken "
                              f"{', '.join(sorted(set(still)))}",
                              file=sys.stderr)
                        return res
                elif args.force:
                    print(f"warning: {source}: will fail at launch: {detail} "
                          f"-- converting anyway (--force)", file=sys.stderr)
                else:
                    res.skipped = True
                    print(f"skipped: {source}: will fail at launch on "
                          f"{len(seen)} symbol(s) the target does not export: "
                          f"{detail}   (--force to convert anyway)",
                          file=sys.stderr)
                    return res

    # --- write out ----------------------------------------------------------
    try:
        out_bytes = macho.build()
    except MachOError as exc:
        res.error = str(exc)
        return res

    try:
        os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
        # If a previous run left a symlink here, opening it for writing would
        # write *through* it into whatever it points at.
        if os.path.islink(output):
            os.unlink(output)
        with open(output, "wb") as fh:
            fh.write(out_bytes)
        os.chmod(output, 0o755)
    except OSError as exc:
        res.error = f"cannot write {output}: {exc.strerror}"
        return res

    # --- entitlements file + signing ---------------------------------------
    ent_file = None
    tmp_ent = None
    if ent_xml:
        if args.dump_entitlements:
            with open(args.dump_entitlements, "wb") as fh:
                fh.write(ent_xml)
            ent_file = args.dump_entitlements
            say(f"Entitlements written to   {args.dump_entitlements}")
        else:
            tmp_ent = output + ".entitlements.plist"
            with open(tmp_ent, "wb") as fh:
                fh.write(ent_xml)
            ent_file = tmp_ent

    if args.no_sign:
        say("Skipping code signing (--no-sign): the signature is now invalid.")
    else:
        try:
            codesign(output, args.sign_identity, ent_file, args.identifier,
                     verbose=not args.quiet)
            say(f"Signed with identity      {args.sign_identity!r}"
                + (f" and {len(entitlements_dict(ent_xml))} entitlement(s)"
                   if ent_xml else " (no entitlements)"))
        except MachOError as exc:
            res.error = str(exc)
            return res
        finally:
            if tmp_ent and os.path.exists(tmp_ent):
                os.unlink(tmp_ent)

    say(f"Output to                 {output}")
    res.output = output
    return res


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    say = (lambda *a: None) if args.quiet else print

    # --- work out the input list -------------------------------------------
    sources = list(args.input)
    # Which paths a SCAN found, as opposed to being named on the command line.
    # The shipped exclusion lists apply only to the former: they are statements
    # about sweeping a directory, and dropping a binary someone asked for by
    # name would be indefensible.
    scanned: set[str] = set()
    if args.scan is not None:
        found = scan_binaries(list(args.scan) or list(SCAN_DEFAULT_DIRS),
                              recursive=args.scan_recursive)
        sources += found
        scanned |= set(found)

    # The Xcode toolchain comes along with any scan unless refused. A scan that
    # takes /usr/bin's otool, nm, objdump, lipo and strip -- which are one
    # hard-linked xcrun stub, not tools -- and leaves the real llvm binaries in
    # the toolchain behind has swept up the wrong half.
    want_xcode = args.scan_xcode
    if want_xcode is None:
        want_xcode = args.scan is not None
    skipped: list[tuple[str, str]] = []
    if want_xcode:
        tc = xcode_toolchain_bin()
        if tc is None:
            if args.scan_xcode:               # asked for explicitly
                print(f"error: --scan-xcode: no toolchain at "
                      f"{XCODE_TOOLCHAIN_BIN} (set DEVELOPER_DIR)",
                      file=sys.stderr)
                return 1
            print(f"note: no Xcode toolchain at {XCODE_TOOLCHAIN_BIN}, so the "
                  f"real otool/nm/objdump are not in this scan (set "
                  f"DEVELOPER_DIR, or --no-scan-xcode to stop saying so)",
                  file=sys.stderr)
            tc = None
    if want_xcode and tc is not None:
        say(f"Xcode toolchain           {tc}"
            + ("" if args.scan_xcode else "   (--no-scan-xcode to skip)"))
        block = () if args.no_xcode_blocklist else XCODE_SKIP
        for path in scan_binaries([tc], recursive=args.scan_recursive):
            name = os.path.basename(path)
            if is_blocked(name, block):
                skipped.append((name, "builds rather than inspects"))
            else:
                sources.append(path)
                scanned.add(path)
        # scan_binaries skips symlinks; the toolchain's aliases (otool ->
        # llvm-otool) are wanted, so add back the ones pointing at a kept tool.
        keep = {os.path.realpath(p) for p in sources}
        for name in sorted(_listdir(tc)):
            link = os.path.join(tc, name)
            if not os.path.islink(link):
                continue
            if os.path.realpath(link) not in keep:
                continue
            if is_blocked(name, block):
                skipped.append((name, "alias of a skipped tool"))
                continue
            sources.append(link)
            scanned.add(link)

    for listfile in args.exclude_from:
        try:
            args.exclude += read_exclude_file(listfile)
        except OSError as exc:
            print(f"error: cannot read {listfile}: {exc.strerror}",
                  file=sys.stderr)
            return 1

    # The shipped lists, for scanned paths only.
    scan_only_exclude: list[str] = []
    if scanned and not args.no_exclude_defaults:
        names = []
        for listfile in bundled_excludes():
            try:
                pats = read_exclude_file(listfile)
            except OSError as exc:
                print(f"warning: cannot read {listfile}: {exc.strerror}",
                      file=sys.stderr)
                continue
            scan_only_exclude += pats
            names.append(f"{os.path.basename(listfile)} ({len(pats)})")
        if names:
            print(f"Exclusion lists           {', '.join(names)} (bundled, "
                  f"applied to the scan; --no-exclude-defaults to skip)")

    if args.exclude or scan_only_exclude:
        # A pattern containing '/' is matched against the whole path, not the
        # basename. That distinction is load-bearing: /usr/bin/otool is an xcrun
        # shim worth excluding, while the Xcode toolchain's otool is the real
        # llvm-otool and must survive the same run. A basename-only rule cannot
        # express that, and excluding the name dropped both.
        kept_after_exclude = []
        for path in sources:
            name = os.path.basename(path)
            pats = args.exclude + (scan_only_exclude if path in scanned else [])
            hit = None
            for pat in pats:
                subject = path if "/" in pat else name
                if fnmatch.fnmatch(subject, pat):
                    hit = pat
                    break
            if hit is not None:
                skipped.append((name, f"excluded by {hit}"))
            else:
                kept_after_exclude.append(path)
        sources = kept_after_exclude

    if args.list_skipped:
        uniq = list(dict.fromkeys(sources))
        print(f"would convert {len(uniq)}:")
        for path in uniq:
            print(f"  {os.path.basename(path):28s} {path}")
        print(f"\nwould skip {len(skipped)}:")
        for name, why in sorted(set(skipped)):
            print(f"  {name:28s} {why}")
        return 0
    # De-duplicate while keeping the order the user gave.
    sources = list(dict.fromkeys(sources))
    if not sources:
        print("error: no input binaries (give paths, or --scan)",
              file=sys.stderr)
        return 2

    # A symlink whose target is also being converted is reproduced as a
    # symlink, not as a second copy: `otool` -> `llvm-otool` and `clang++` ->
    # `clang` would otherwise duplicate a binary that is sometimes hundreds of
    # megabytes, and argv[0] is what tells clang++ to behave as a C++ driver,
    # so the link name has to survive anyway.
    real_targets = {os.path.realpath(s) for s in sources
                    if not os.path.islink(s)}
    aliases: list[tuple[str, str]] = []       # (link name, target basename)
    kept: list[str] = []
    # Hard links are the same story: one inode under many names. Convert the
    # inode once and link the other names at it, rather than writing the same
    # bytes out 78 times.
    by_inode: dict[tuple[int, int], str] = {}
    for source in sources:
        target = os.path.realpath(source)
        if os.path.islink(source) and target in real_targets:
            aliases.append((os.path.basename(source),
                            os.path.basename(target)))
            continue
        try:
            st = os.stat(source)
            key = (st.st_dev, st.st_ino)
        except OSError:
            key = None
        if key is not None and st.st_nlink > 1:
            first = by_inode.get(key)
            if first is not None:
                aliases.append((os.path.basename(source),
                                os.path.basename(first)))
                continue
            by_inode[key] = source
        kept.append(source)
    sources = kept

    # --info is a read-only report and works for any number of inputs.
    if args.info:
        bad = 0
        for i, source in enumerate(sources):
            try:
                with open(source, "rb") as fh:
                    raw = fh.read()
                thin_data, _picked = thin(raw, args.arch)
                macho = MachO(thin_data)
            except OSError as exc:
                print(f"error: cannot read {source}: {exc.strerror}",
                      file=sys.stderr)
                bad += 1
                continue
            except MachOError as exc:
                print(f"error: {source}: {exc}", file=sys.stderr)
                bad += 1
                continue
            if i:
                print()
            describe(macho, source)
        return 1 if bad else 0

    if not args.platform or not args.osversion:
        print("error: --platform and --version are required (or use --info)",
              file=sys.stderr)
        return 2

    platform = PLATFORMS[args.platform]
    try:
        version = parse_version(args.osversion)
        sdk = parse_version(args.sdk) if args.sdk else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # --- where the results go ----------------------------------------------
    cryptex = None
    if args.cryptex:
        cryptex = Cryptex(args.cryptex, args.cryptex_bindir,
                          args.cryptex_libdir,
                          "@loader_path" if args.loader_path
                          else "@executable_path")
        if args.output:
            print("error: --output and --cryptex are mutually exclusive",
                  file=sys.stderr)
            return 2
    elif len(sources) > 1:
        if not args.output:
            print("error: converting more than one binary needs --output DIR "
                  "or --cryptex DIR", file=sys.stderr)
            return 2
        if os.path.exists(args.output) and not os.path.isdir(args.output):
            print(f"error: --output {args.output} is not a directory",
                  file=sys.stderr)
            return 2

    # Where a bundled library goes, and what binaries will call it. A cryptex
    # is one of these; without one the output directory plays the same role.
    if cryptex is not None:
        staging = cryptex
    else:
        batch_out = args.output if len(sources) > 1 else None
        if batch_out is not None:
            root = batch_out
        elif args.output:
            root = os.path.dirname(os.path.abspath(args.output)) or "."
        else:
            root = os.getcwd()
        # @loader_path, always: for a main executable it means the same as
        # @executable_path, and it is the one that is also right inside a
        # bundled library referencing another one -- which is the common case
        # (CoreDisplay pulls in GPUWrangler and IOPresentment).
        staging = DirStaging(args.libs_into or root,
                             args.lib_layout, args.lib_subdir, "@loader_path")

    if args.provide_lib and cryptex is None:
        print("error: --provide-lib needs --cryptex", file=sys.stderr)
        return 2
    if args.dump_entitlements and len(sources) > 1:
        print("error: --dump-entitlements writes one file, so it cannot be "
              "used on a batch", file=sys.stderr)
        return 2

    # --- bundled replacement libraries -------------------------------------
    extra_changes: dict[str, str] = {}
    extra_weak: set[str] = set()
    provided: dict[str, tuple[str, set[str] | None]] = {}
    for old_path, lib_file in args.provide_lib:
        if not os.path.isfile(lib_file):
            print(f"error: --provide-lib: no such file: {lib_file}",
                  file=sys.stderr)
            return 1
        try:
            staged = cryptex.add_library(lib_file)
        except OSError as exc:
            print(f"error: --provide-lib {lib_file}: {exc.strerror}",
                  file=sys.stderr)
            return 1
        install_name = cryptex.install_name_for(os.path.basename(lib_file))
        extra_changes[old_path] = install_name
        extra_weak.add(install_name)
        exports = dylib_exports(lib_file)
        provided[old_path] = (install_name, exports)
        if exports is None:
            print(f"warning: cannot read the exports of {lib_file}; symbol "
                  f"coverage will not be checked", file=sys.stderr)
        else:
            say(f"  exports {len(exports)} symbol(s)")
        say(f"Bundled library           {staged}\n"
            f"  {old_path}\n     -> {install_name}")
        # The staged copy must carry that same install name, or dyld will
        # register it under the old one and the reference will not match.
        actual = dylib_id(staged)
        if actual is not None and actual != install_name:
            print(f"warning: {staged} has install name {actual!r}, but "
                  f"binaries will ask for {install_name!r}; rebuild it with "
                  f"-install_name {install_name}", file=sys.stderr)

    index = None
    index_path = args.dylib_index
    if index_path is None and not args.no_dylib_index:
        index_path = bundled_index(platform)
        if index_path is not None:
            print(f"Dylib index               {os.path.relpath(index_path)} "
                  f"(bundled; --dylib-index to override, --no-dylib-index to "
                  f"skip)")
    if index_path:
        try:
            index = DylibIndex.load(index_path)
        except OSError as exc:
            print(f"error: cannot read {index_path}: {exc.strerror}",
                  file=sys.stderr)
            return 1
    elif platform != PLATFORMS["macos"] and not args.no_dylib_index:
        # Not for a macOS target: the source is macOS, so its paths are already
        # right and there is nothing an index would resolve.
        print(f"warning: no dylib index for {args.platform}: library paths are "
              f"rewritten by rule rather than resolved, and neither missing "
              f"libraries nor symbols from them can be reported",
              file=sys.stderr)

    # --- an input that exists only inside the shared cache -------------------
    #
    # `machomorph.py /usr/lib/libxcselect.dylib -o lifted/libxcselect.dylib`
    # asks for a library that is not a file anywhere: the cache is the only copy
    # of it. That is not an error to report, it is a lift to run -- and the same
    # pipeline the closure pass uses, so there is one implementation of it.
    lifted_out: list[Result] = []
    real_sources = []
    for source in sources:
        if os.path.exists(source):
            real_sources.append(source)
            continue
        if probe_library(source, args.dsc, (), lambda *a: None) is None:
            real_sources.append(source)          # genuinely missing; let it fail
            continue
        res = Result(source)
        out = args.output or os.path.join(os.getcwd(),
                                          os.path.basename(source))
        if len(sources) > 1:
            out = os.path.join(args.output or ".", os.path.basename(source))
        say(f"{source} is not a file -- lifting it out of {args.dsc}")
        got = lift_library(source, out, args.platform, args.osversion,
                           changes=[tuple(c) for c in args.change],
                           redirects=([tuple(r) for r in args.redirect_symbol]
                                      + (list(DARWIN_EXTSN_REDIRECTS)
                                         if args.darwin_extsn else [])),
                           weaken_symbols=args.weaken_symbol,
                           compact=not args.no_compact, cache=args.dsc,
                           cpusubtype_fix=not args.no_cpusubtype_fix,
                           arch=args.arch, say=say)
        if got is None:
            res.error = "could not be lifted out of the shared cache"
            print(f"error: {source}: {res.error}", file=sys.stderr)
            if not args.keep_going:
                return 1
        else:
            res.output = got
            say(f"Lifted to                 {got}")
        lifted_out.append(res)
    sources = real_sources
    if not sources:
        return 1 if any(not r.ok for r in lifted_out) else 0

    # --- the libraries the target does not have ------------------------------
    #
    # The other half of a conversion, and until now a separate tool driven by a
    # hand-written list of binaries. That list is why the same bug kept coming
    # back: a batch converted `ssh` too, left its libcrypto reference at the
    # absolute macOS path (weak-linked, so it loaded and crashed on the first
    # call), and a second tool existed to retrofit the fix. A closure computed
    # from the binary in front of us cannot have that gap.
    per_source: dict[str, dict[str, str]] = {}
    staged_libs: dict[str, str] = {}
    if args.libraries and index is not None:
        per_source, staged_libs, rc_libs = obtain_libraries(
            args, sources, index, staging, platform, version, sdk, say)
        if rc_libs:
            return rc_libs
    elif args.libraries and index is None and platform != PLATFORMS["macos"]:
        print("note: without a dylib index nothing can be said about which "
              "libraries the target lacks, so none is bundled",
              file=sys.stderr)
    if args.dry_run:
        return 0

    # --- convert ------------------------------------------------------------
    results: list[Result] = []
    owned = cryptex.owned() if cryptex is not None else set()
    foreign: list[str] = []
    batch = len(sources) > 1
    for source in sources:
        if cryptex is not None:
            output = cryptex.output_for(source)
        elif batch:
            output = os.path.join(args.output, os.path.basename(source))
        else:
            output = args.output or os.path.join(os.getcwd(),
                                                 os.path.basename(source))
        # What this binary gets pointed at: EVERY library that ended up staged,
        # not only the ones from this binary's own closure.
        #
        # That distinction is a bug this cost a whole build to learn. A binary
        # whose closure --max-libs refused gets nothing bundled FOR it -- but
        # another binary may have brought the same library in anyway, and then
        # leaving this one naming `/usr/lib/libCoreStorage.dylib` absolutely is
        # the "a batch undoes --provide-lib" trap in a new costume: it loads,
        # because the reference is weakened, and crashes on the first call into
        # a library that is sitting right there in lib/. verify_cryptex check 3
        # caught 30 such references across 7 binaries (asr, automount, bless,
        # kextcache, kextload, kextutil, networksetup).
        #
        # Rewriting a reference to a library that IS staged is free and always
        # right; the --max-libs gate is about what to PAY to lift, not about
        # what a binary is allowed to see.
        changes = dict(extra_changes)
        weak = set(extra_weak)
        prov = dict(provided)
        mine = per_source.get(source, {})
        for orig, dest in staged_libs.items():
            name = staging.reference_name(orig)
            changes[orig] = name
            weak.add(name)
            actual = dylib_id(dest)
            if actual and actual != orig and actual != name:
                changes[actual] = name
            # Report the symbol demand only for the closure this binary was
            # actually costed for, so the batch summary stays about that.
            if orig in mine:
                prov[orig] = (name, dylib_exports(dest))
        if args.no_clobber and os.path.lexists(output):
            rel = (os.path.relpath(os.path.abspath(output), cryptex.root)
                   if cryptex is not None else None)
            if cryptex is None or rel not in owned:
                foreign.append(os.path.basename(output))
                continue
        if batch:
            say(f"\n===== {source}")
        res = convert_one(args, source, output, platform, version, sdk, index,
                          changes, weak, prov, say)
        results.append(res)
        if res.skipped:
            # Not an error: the binary was deliberately not ported because it
            # cannot launch on the target. It has already said so on stderr,
            # and a batch carries on regardless -- skipping the dead weight is
            # the point.
            continue
        if not res.ok:
            print(f"error: {source}: {res.error}", file=sys.stderr)
            if not (batch and args.keep_going):
                return 1

    alias_names: list[str] = []
    if aliases:
        # Reproducing a symlink needs a directory to put it in.
        outdir = cryptex.bindir if cryptex is not None else args.output
        if outdir is None or not os.path.isdir(outdir):
            print(f"error: {len(aliases)} of the inputs are symlinks to other "
                  f"inputs; reproducing them needs --cryptex DIR or "
                  f"--output DIR", file=sys.stderr)
            return 2
        # An alias must never clobber a real conversion of the same name. The
        # macOS xcrun shim is one inode called `strings`, `lipo`, `strip`,
        # `dyld_info` and 74 other things, while the Xcode toolchain ships the
        # real tools under those same names -- so without this the shim's
        # aliases would overwrite every genuine tool converted before them.
        converted = {os.path.basename(r.output) for r in results
                     if r.ok and r.output}
        made = skipped_alias = 0
        for link_name, target_name in aliases:
            if link_name in converted:
                skipped_alias += 1
                continue
            link = os.path.join(outdir, link_name)
            if args.no_clobber and os.path.lexists(link):
                rel = (os.path.relpath(os.path.abspath(link), cryptex.root)
                       if cryptex is not None else None)
                if cryptex is None or rel not in owned:
                    foreign.append(link_name)
                    continue
            if os.path.lexists(link):
                os.unlink(link)
            try:
                os.symlink(target_name, link)     # relative, stays valid
                alias_names.append(link_name)
                made += 1
            except OSError as exc:
                print(f"error: cannot link {link} -> {target_name}: "
                      f"{exc.strerror}", file=sys.stderr)
        say(f"Linked {made} alias(es)"
            + (f", skipped {skipped_alias} that a real binary already claims"
               if skipped_alias else ""))

    if foreign:
        say(f"\nLeft {len(foreign)} existing file(s) alone (--no-clobber): "
            + ", ".join(sorted(set(foreign))[:12])
            + (" ..." if len(set(foreign)) > 12 else ""))

    if cryptex is not None:
        cryptex.record([r.output for r in results if r.ok and r.output]
                       + [os.path.join(cryptex.bindir, n)
                          for n in alias_names])

    if batch:
        report(results, say)
    # A skip is an intended outcome, not an error: the binary cannot launch on
    # the target and was deliberately left out. Counting it as failure made a
    # `set -e` build script abort halfway through, which is how the first
    # from-scratch rebuild stopped after the main batch with an empty lib/.
    failed = [r for r in results if not r.ok and not r.skipped]
    return 1 if failed else 0


def report(results: list[Result], say) -> None:
    """Summarise a batch: what converted, and what will not load anyway."""
    skipped = [r for r in results if r.skipped]
    failed = [r for r in results if not r.ok and not r.skipped]
    missing = [r for r in results if r.ok and r.missing]
    clean = [r for r in results if r.ok and not r.missing]

    say(f"\n===== {len(results)} binaries: {len(clean)} ready, "
        f"{len(missing)} with libraries missing on the target, "
        f"{len(failed)} failed")

    if missing:
        # Which absent libraries block the most binaries? That is the list
        # worth working down -- one replacement can unblock a hundred tools.
        counts: dict[str, list[str]] = {}
        for r in missing:
            for path, _why in r.missing:
                counts.setdefault(path, []).append(os.path.basename(r.source))
        say("\nmissing libraries, most-blocking first:")
        for path, users in sorted(counts.items(),
                                  key=lambda kv: -len(kv[1])):
            sample = ", ".join(sorted(users)[:6])
            more = f", +{len(users) - 6} more" if len(users) > 6 else ""
            say(f"  {len(users):4d}  {path}\n          {sample}{more}")

    # Which symbols does the batch actually want from a bundled replacement?
    # This is what separates binaries the stub genuinely serves from ones that
    # merely link the library -- and it is measured, not guessed.
    demand: dict[str, dict[str, list[str]]] = {}
    for r in results:
        for lib, syms in r.needs.items():
            key = ", ".join(syms)
            demand.setdefault(lib, {}).setdefault(key, []).append(
                os.path.basename(r.source))
    for lib, groups in demand.items():
        say(f"\nsymbols used from {lib}:")
        for syms, users in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            sample = ", ".join(sorted(users)[:6])
            more = f", +{len(users) - 6} more" if len(users) > 6 else ""
            say(f"  {len(users):4d}  {syms}\n          {sample}{more}")

    unsat = [r for r in results if r.unsatisfied]
    if unsat:
        say(f"\n{len(unsat)} binaries use symbols the bundled library does not "
            f"export:")
        for r in unsat:
            for lib, syms in r.unsatisfied.items():
                say(f"  {os.path.basename(r.source)}: {', '.join(syms)}")

    if skipped:
        say(f"\n{len(skipped)} not ported -- predicted to fail at launch on a "
            f"symbol the target does not export (--force to port anyway):")
        for r in sorted(skipped, key=lambda x: x.source)[:20]:
            syms = []
            for _lib, sym in r.unresolved_syms:
                if sym not in syms:
                    syms.append(sym)
            lib = os.path.basename(r.unresolved_syms[0][0])
            extra = f" (+{len(syms) - 1} more)" if len(syms) > 1 else ""
            say(f"  {os.path.basename(r.source):<24} {syms[0]} "
                f"from {lib}{extra}")
        if len(skipped) > 20:
            say(f"  ... and {len(skipped) - 20} more")

        # Which symbol blocks the most binaries -- only worth printing when
        # something actually repeats, which is what makes it a lever.
        by_sym: dict[str, set[str]] = {}
        for r in skipped:
            for _lib, sym in r.unresolved_syms:
                by_sym.setdefault(sym, set()).add(r.source)
        ranked = sorted(by_sym.items(), key=lambda kv: -len(kv[1]))
        ranked = [(k, v) for k, v in ranked if len(v) > 1]
        if ranked:
            say("\nsymbols blocking the most binaries:")
            for sym, srcs in ranked[:10]:
                shown = ", ".join(sorted(os.path.basename(x)
                                         for x in srcs)[:6])
                more = f", +{len(srcs) - 6} more" if len(srcs) > 6 else ""
                say(f"  {len(srcs):4d}  {sym}")
                say(f"        {shown}{more}")

    if failed:
        say("\nfailed:")
        for r in failed:
            say(f"  {r.source}: {r.error}")


if __name__ == "__main__":
    sys.exit(main())
