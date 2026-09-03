"""Just enough Mach-O to reason about stubs, GOTs and the symbol table.

Deliberately not machomorph's MachO class. That one rebuilds a file -- load
commands, __LINKEDIT, signatures -- and every stage here wants the opposite: a
read-only view over the bytes, edited in place at known offsets. Two small
readers with different jobs beat one that has to serve both.

This used to live in gotscan.py, and four modules imported it from there
through a sys.path hack -- the diagnostic tool acting as the library for the
repair tools that it judges. Inverted here.
"""

import struct

from .arm64 import u32

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_DYLD_CHAINED_FIXUPS = 0x80000034

# Section types (section.flags & 0xff) that hold symbol pointers.
S_NON_LAZY_SYMBOL_POINTERS = 0x06
S_LAZY_SYMBOL_POINTERS = 0x07
S_SYMBOL_STUBS = 0x08

INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000

class Image:
    """Just enough Mach-O to reason about stubs, GOTs and the symbol table."""

    def __init__(self, data: bytes):
        self.data = data
        magic = u32(data, 0)
        if magic not in (0xFEEDFACF,):
            raise SystemExit("not a thin 64-bit Mach-O (lipo -thin it first)")
        self.ncmds = u32(data, 16)
        self.segments = []      # (name, vmaddr, vmsize, fileoff, filesize)
        self.sections = []      # dicts
        self.cmds = set()
        self.symoff = self.nsyms = self.stroff = 0
        self.indoff = self.nind = 0
        self._parse()

    def _parse(self):
        d = self.data
        off = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            self.cmds.add(cmd)
            if cmd == LC_SEGMENT_64:
                name = d[off + 8:off + 24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", d, off + 24)
                nsects = u32(d, off + 64)
                self.segments.append((name, vmaddr, vmsize, fileoff, filesize))
                so = off + 72
                for _ in range(nsects):
                    self.sections.append(dict(
                        sect=d[so:so + 16].rstrip(b"\0").decode(),
                        seg=d[so + 16:so + 32].rstrip(b"\0").decode(),
                        addr=struct.unpack_from("<Q", d, so + 32)[0],
                        size=struct.unpack_from("<Q", d, so + 40)[0],
                        off=u32(d, so + 48),
                        flags=u32(d, so + 64),
                        r1=u32(d, so + 68),
                        r2=u32(d, so + 72),
                    ))
                    so += 80
            elif cmd == LC_SYMTAB:
                self.symoff, self.nsyms, self.stroff, _ = \
                    struct.unpack_from("<IIII", d, off + 8)
            elif cmd == LC_DYSYMTAB:
                self.indoff, self.nind = struct.unpack_from("<II", d, off + 56)
            off += cmdsize

    # -- symbols ----------------------------------------------------------

    def symbol_name(self, index: int) -> str:
        n_strx = u32(self.data, self.symoff + index * 16)
        start = self.stroff + n_strx
        end = self.data.index(b"\0", start)
        return self.data[start:end].decode(errors="replace")

    def indirect(self, i: int) -> int:
        return u32(self.data, self.indoff + i * 4)

    def indirect_name(self, i: int) -> str | None:
        v = self.indirect(i)
        if v & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS):
            return None
        return self.symbol_name(v)

    # -- addresses --------------------------------------------------------

    def owns(self, addr: int) -> bool:
        return any(a <= addr < a + sz
                   for name, a, sz, _, _ in self.segments
                   if name != "__PAGEZERO")

    def section(self, seg: str, sect: str):
        for s in self.sections:
            if s["seg"] == seg and s["sect"] == sect:
                return s
        return None
