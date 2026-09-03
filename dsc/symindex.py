#!/usr/bin/env python3
"""dsc_symindex -- what every library in a dyld shared cache exports.

The companion to ``dsc.index``, which answers "can the target load this path".
This one answers the question after it: "does that library export this symbol".

Why it exists. machomorph's launch prediction reads the target's surface out of
the SDK's ``.tbd`` stubs, and the SDK ships stubs for ``/usr/lib`` and the
public frameworks only -- **no PrivateFrameworks**. A symbol from a library with
no stub is reported ``unknown``, and ``unknown`` never fails a binary and never
gets weakened. That is deliberate and it was the right default while the SDK was
the only source: inventing a failure is the expensive mistake, because it
refuses to port a binary that would have run.

But the hole is real, and it has now cost the same thing twice:

  * ``csrutil`` died on device with ``_DAUnregisterApprovalCallback``, from
    ``DiskArbitration`` -- a PrivateFramework on iOS. All 45 symbols
    ``DiskManagement`` imports from it were ``unknown``, so the gate passed a
    library that cannot load.
  * the fix, the first time round, was a hand-written list of symbol names in
    ``rebuild_cryptex.sh``. CLAUDE.md records four separate occasions on which a
    hand-written list is what went wrong.

The cache is the ground truth and it is on disk, so ask it. With this index the
answer for a PrivateFramework is as good as the answer for ``libSystem``, and
``--weaken-unresolvable`` derives what used to be transcribed.

The exports really are in the cache, in the image's own export trie -- which is
worth stating because an *extraction* of a cache image has an empty one (that is
why ``machomorph`` rebuilds the trie from the symbol table when it lifts). The
trie itself lives in the ``.dyldlinkedit`` subcache, reached through the image's
``__LINKEDIT`` segment, so a device's bare cache head is not enough: use an
IPSW, exactly as ``dsc.index`` does.

    python3 -m dsc.symindex iPhone18,3_27.0_24A5424a_Restore.ipsw \
        -o data/ios27_24A5424a_symbols.txt.gz

Format: one line per library, then its symbols one per tab-indented line.
Written gzipped when the name ends in ``.gz`` (it is a 40 MB text file and
compresses about six-fold).
"""

from __future__ import annotations

import argparse
import glob
import gzip
import os
import struct
import sys

from .index import (CacheError, OFF_IMAGES_COUNT, OFF_IMAGES_OFFSET,
                    OFF_IMAGES_COUNT_OLD, OFF_IMAGES_OFFSET_OLD,
                    OFF_MAPPING_OFFSET, MAGIC_PREFIX, read_mappings,
                    resolve_cache, trie_paths)

LC_SEGMENT_64 = 0x19
LC_ID_DYLIB = 0x0D
LC_REEXPORT_DYLIB = 0x8000001F
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033


class Cache:
    """Random access to the images of a (multi-file) shared cache.

    Everything is addressed by VM address and translated through the mappings
    of the main file and every subcache, because an image's header, its
    ``__LINKEDIT`` and its export trie routinely live in three different files.
    """

    def __init__(self, path: str):
        with open(path, "rb") as fh:
            head = fh.read(0x4000)
        if not head.startswith(MAGIC_PREFIX):
            raise CacheError(f"{path}: not a dyld shared cache")
        self.path = path
        self.regions: list[tuple[int, int, int, str]] = []
        for sib in sorted(glob.glob(path + "*")):
            if sib.endswith((".symbols", ".atlas")):
                continue
            try:
                self.regions += read_mappings(sib)
            except OSError:
                pass
        self._files: dict[str, object] = {}

        with open(path, "rb") as fh:
            data = fh.read()
        mapping_offset = struct.unpack_from("<I", data, OFF_MAPPING_OFFSET)[0]
        if mapping_offset >= OFF_IMAGES_COUNT + 4:
            io, ic = struct.unpack_from("<II", data, OFF_IMAGES_OFFSET)
        else:
            io, ic = struct.unpack_from("<II", data, OFF_IMAGES_OFFSET_OLD)
        self.images: list[tuple[int, str]] = []
        for i in range(ic):
            off = io + i * 32
            if off + 32 > len(data):
                break
            addr = struct.unpack_from("<Q", data, off)[0]
            pfo = struct.unpack_from("<I", data, off + 24)[0]
            if not addr or not pfo or pfo >= len(data):
                continue
            end = data.find(b"\0", pfo)
            if end < 0:
                continue
            self.images.append(
                (addr, data[pfo:end].decode("utf-8", "replace")))

    # --- vm -> bytes -------------------------------------------------------
    def read(self, addr: int, size: int) -> bytes | None:
        for a, s, fo, fn in self.regions:
            if a <= addr < a + s:
                fh = self._files.get(fn)
                if fh is None:
                    fh = self._files[fn] = open(fn, "rb")
                fh.seek(fo + (addr - a))
                return fh.read(size)
        return None

    # --- one image ---------------------------------------------------------
    def image_exports(self, addr: int) -> tuple[set[str], list[str], str | None]:
        """(exported names, re-exported library paths, install name).

        A re-exporting library -- an umbrella framework above all -- exports
        almost nothing of its own, so following ``LC_REEXPORT_DYLIB`` is not an
        optional refinement. ``ApplicationServices`` and ``Cocoa`` export zero
        symbols themselves, and treating that as the answer would condemn every
        binary that uses them.
        """
        hdr = self.read(addr, 0x20)
        if hdr is None or len(hdr) < 0x20 or struct.unpack_from("<I", hdr, 0)[0] != 0xFEEDFACF:
            return set(), [], None
        ncmds, sizeofcmds = struct.unpack_from("<II", hdr, 16)
        lcs = self.read(addr + 0x20, sizeofcmds)
        if lcs is None or len(lcs) < sizeofcmds:
            return set(), [], None

        le_vm = le_fo = None
        trie = None
        reexports: list[str] = []
        install = None
        pos = 0
        for _ in range(ncmds):
            if pos + 8 > len(lcs):
                break
            cmd, size = struct.unpack_from("<II", lcs, pos)
            if size < 8 or pos + size > len(lcs):
                break
            if cmd == LC_SEGMENT_64:
                name = lcs[pos + 8:pos + 24].rstrip(b"\0").decode(
                    "utf-8", "replace")
                if name == "__LINKEDIT":
                    le_vm, _vs, le_fo, _fs = struct.unpack_from(
                        "<QQQQ", lcs, pos + 24)
            elif cmd == LC_DYLD_EXPORTS_TRIE:
                trie = struct.unpack_from("<II", lcs, pos + 8)
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY) and trie is None:
                vals = struct.unpack_from("<10I", lcs, pos + 8)
                trie = (vals[8], vals[9])
            elif cmd in (LC_REEXPORT_DYLIB, LC_ID_DYLIB):
                off = struct.unpack_from("<I", lcs, pos + 8)[0]
                if 0 < off < size:
                    raw = lcs[pos + off:pos + size].split(b"\0")[0]
                    text = raw.decode("utf-8", "replace")
                    if cmd == LC_ID_DYLIB:
                        install = text
                    else:
                        reexports.append(text)
            pos += size

        names: set[str] = set()
        if trie and trie[1] and le_vm is not None:
            # A __LINKEDIT table is recorded as a file offset, and in a cache
            # that offset belongs to whichever subcache holds the shared
            # __LINKEDIT. Going through the segment's own (vmaddr, fileoff)
            # pair turns it into an address, which the mappings can place.
            off, size = trie
            blob = self.read(le_vm + (off - le_fo), size)
            if blob and len(blob) == size:
                names = {n for n in trie_paths(blob) if n}
        return names, reexports, install


def build(cache_path: str, quiet: bool = False) -> dict[str, set[str]]:
    """{install name: every symbol resolvable through it}, re-exports followed."""
    cache = Cache(cache_path)
    direct: dict[str, set[str]] = {}
    reexp: dict[str, list[str]] = {}
    aliases: dict[str, str] = {}     # install name -> cache path, when they differ
    empty = 0
    for addr, path in cache.images:
        names, re_list, install = cache.image_exports(addr)
        direct[path] = names
        reexp[path] = re_list
        if install and install != path:
            aliases[install] = path
        if not names and not re_list:
            empty += 1
    if not quiet:
        total = sum(len(v) for v in direct.values())
        print(f"  images: {len(direct)}, exported symbols: {total} "
              f"({empty} images export nothing directly)", file=sys.stderr)

    # Two-level-namespace lookup follows re-exports, so a symbol defined in
    # libsystem_c really is resolvable as libSystem, and every symbol an
    # umbrella framework offers comes from a library underneath it.
    out: dict[str, set[str]] = {}
    for path in direct:
        acc = set(direct[path])
        done, stack = {path}, list(reexp.get(path, []))
        while stack:
            dep = stack.pop()
            key = dep if dep in direct else aliases.get(dep)
            if key is None or key in done:
                continue
            done.add(key)
            acc |= direct.get(key, set())
            stack += reexp.get(key, [])
        out[path] = acc
    for install, path in aliases.items():
        out.setdefault(install, out.get(path, set()))
    if not quiet:
        grew = sum(1 for p in direct if len(out[p]) > len(direct[p]))
        print(f"  {grew} libraries gained symbols by re-export", file=sys.stderr)
    return out


# --- reading one back ------------------------------------------------------

def load(path: str) -> dict[str, set[str]]:
    """Read an index written by this module."""
    opener = gzip.open if path.endswith(".gz") else open
    out: dict[str, set[str]] = {}
    cur: set[str] | None = None
    with opener(path, "rt", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            if line[0] == "\t":
                if cur is not None:
                    cur.add(line[1:])
            else:
                cur = out.setdefault(line, set())
    return out


def write(index: dict[str, set[str]], path: str | None, cache: str) -> int:
    lines = [f"# dsc.symindex: exported symbols per library\n",
             f"# cache: {os.path.basename(cache)}\n"]
    for name in sorted(index):
        lines.append(name + "\n")
        for sym in sorted(index[name]):
            lines.append("\t" + sym + "\n")
    text = "".join(lines)
    if not path:
        sys.stdout.write(text)
        return len(text)
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "wt") as fh:
        fh.write(text)
    return len(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dsc_symindex",
        description="What every library in a dyld shared cache exports, for "
                    "machomorph's launch prediction.")
    ap.add_argument("cache",
                    help="an IPSW, a directory `ipsw extract --dyld` wrote, "
                         "or the main dyld_shared_cache_* file itself")
    ap.add_argument("-o", "--output",
                    help="write here instead of stdout; gzipped if it ends .gz")
    ap.add_argument("--arch", default="arm64e")
    ap.add_argument("--extract-dir")
    ap.add_argument("--re-extract", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    try:
        cache = resolve_cache(args.cache, args.arch, args.extract_dir,
                              args.re_extract, args.quiet)
        if not args.quiet and cache != args.cache:
            print(f"  cache: {cache}", file=sys.stderr)
        index = build(cache, args.quiet)
    except (CacheError, OSError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    n = write(index, args.output, cache)
    if args.output and not args.quiet:
        size = os.path.getsize(args.output)
        print(f"  {len(index)} libraries, "
              f"{sum(len(v) for v in index.values())} symbols -> "
              f"{args.output} ({size / 1e6:.1f} MB, {n / 1e6:.1f} MB of text)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
