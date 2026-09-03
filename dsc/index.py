#!/usr/bin/env python3
"""dsc_index -- list every library path a dyld shared cache can load.

The output is a plain list of paths, one per line, for machomorph's
``--dylib-index``. With it, machomorph can rewrite a macOS library path to
wherever that library actually lives on the target, and warn about the ones
that are simply not there.

Three sources, all fine:

  # straight from an IPSW -- the extraction is run for you and cached, so a
  # second call on the same IPSW is instant (complete: canonical + aliases)
  ./dsc_index.py iPhone18,3_27.0_24A5424a_Restore.ipsw -o ios27.txt

  # from a cache already extracted out of one -- a file, or the directory
  # `ipsw extract --dyld` wrote, which is searched for the main cache file
  ipsw extract --dyld --dyld-arch arm64e -o out/ iPhone18,3_27.0_..._Restore.ipsw
  ./dsc_index.py out/24A5424a__iPhone18,3/dyld_shared_cache_arm64e -o ios27.txt
  ./dsc_index.py out/ -o ios27.txt

  # straight off a device (the main cache file is small; subcaches not needed,
  # but without them the alias trie is unreachable and you get canonical paths
  # only -- still enough for most work)
  ssh iphone cat /System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/\\
      dyld_shared_cache_arm64e > cache_head
  ./dsc_index.py cache_head -o ios27.txt

Aliases matter: on iOS, IOKit is registered as BOTH
``/System/Library/Frameworks/IOKit.framework/IOKit`` and
``.../IOKit.framework/Versions/A/IOKit``, and only the second is a canonical
image. Treating the first as missing would be wrong.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import struct
import subprocess
import sys
import zipfile

MAGIC_PREFIX = b"dyld_v1"

# dyld_cache_header offsets we care about
OFF_MAPPING_OFFSET = 0x10
OFF_MAPPING_COUNT = 0x14
OFF_IMAGES_OFFSET_OLD = 0x18
OFF_IMAGES_COUNT_OLD = 0x1C
OFF_IMAGES_OFFSET = 0x1C0
OFF_IMAGES_COUNT = 0x1C4
OFF_DYLIBS_TRIE_ADDR = 0x108
OFF_DYLIBS_TRIE_SIZE = 0x110


class CacheError(Exception):
    pass


# --- getting to a cache file, from whatever the caller had to hand ----------
#
# The index is a property of the TARGET, so the thing a caller actually has is
# usually an IPSW rather than a cache: the device's own copy is missing the
# .dyldlinkedit subcache the alias trie lives in, and canonical-paths-only is
# how IOKit gets reported absent when it is merely registered under its flat
# spelling. So accept the IPSW and do the extraction here.


def find_cache(root: str, arch: str) -> str:
    """The main cache file for *arch* somewhere under *root*.

    Subcaches (``.01``, ``.symbols``, ``.dyldlinkedit``) sit beside the main
    file and are found through it, so only the unsuffixed name is a hit.
    """
    want = "dyld_shared_cache_" + arch
    hits = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name == want:
                hits.append(os.path.join(dirpath, name))
    if not hits:
        raise CacheError(f"no {want} under {root} "
                         f"(wrong --arch, or the extraction did not run?)")
    if len(hits) > 1:
        joined = "\n  ".join(sorted(hits))
        raise CacheError(f"several {want} under {root}; name one:\n  {joined}")
    return hits[0]


def extract_ipsw(ipsw: str, arch: str, out_dir: str, re_extract: bool,
                 quiet: bool) -> str:
    """Run `ipsw extract --dyld` on *ipsw*, into *out_dir*, and find the cache.

    The result is cached: an IPSW is immutable, so a cache already sitting in
    *out_dir* is the same one this would produce. That is a freshness
    assumption of the kind this project has been bitten by, which is why the
    reuse says so out loud and --re-extract overrides it.
    """
    if not re_extract and os.path.isdir(out_dir):
        try:
            found = find_cache(out_dir, arch)
        except CacheError:
            found = None
        if found:
            if not quiet:
                print(f"  reusing the cache already extracted to {out_dir}\n"
                      f"  ({os.path.basename(found)}; --re-extract to redo it)",
                      file=sys.stderr)
            return found

    if shutil.which("ipsw") is None:
        raise CacheError("extracting a cache from an IPSW needs the `ipsw` "
                         "tool: brew install blacktop/tap/ipsw")
    os.makedirs(out_dir, exist_ok=True)
    cmd = ["ipsw", "extract", "--dyld", "--dyld-arch", arch, "-o", out_dir, ipsw]
    if not quiet:
        print("  " + " ".join(cmd), file=sys.stderr)
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise CacheError(f"ipsw extract failed (exit {exc.returncode})") from exc
    return find_cache(out_dir, arch)


def resolve_cache(arg: str, arch: str, extract_dir: str | None,
                  re_extract: bool, quiet: bool) -> str:
    """*arg* may be a cache file, a directory holding one, or an IPSW."""
    if os.path.isdir(arg):
        return find_cache(arg, arch)
    if not os.path.exists(arg):
        raise CacheError(f"{arg}: no such file or directory")
    with open(arg, "rb") as fh:
        if fh.read(len(MAGIC_PREFIX)) == MAGIC_PREFIX:
            return arg
    if zipfile.is_zipfile(arg):
        out = extract_dir or os.path.join(
            "/tmp/machomorph-ipsw",
            os.path.basename(arg).rsplit(".", 1)[0] + "_" + arch)
        if not quiet:
            print(f"  {os.path.basename(arg)} is an IPSW; extracting its "
                  f"{arch} cache", file=sys.stderr)
        return extract_ipsw(arg, arch, out, re_extract, quiet)
    raise CacheError(f"{arg}: not a dyld shared cache, a directory holding "
                     f"one, or an IPSW")


def read_mappings(path: str) -> list[tuple[int, int, int, str]]:
    """(vmaddr, size, fileoff, path) for every mapping in one cache file."""
    with open(path, "rb") as fh:
        head = fh.read(0x1000)
    if not head.startswith(MAGIC_PREFIX):
        return []
    mo, mc = struct.unpack_from("<II", head, OFF_MAPPING_OFFSET)
    out = []
    for i in range(mc):
        a, s, fo = struct.unpack_from("<QQQ", head, mo + i * 32)
        out.append((a, s, fo, path))
    return out


def canonical_paths(data: bytes) -> list[str]:
    """The cache's image list -- canonical install names, no aliases."""
    mapping_offset = struct.unpack_from("<I", data, OFF_MAPPING_OFFSET)[0]
    if mapping_offset >= OFF_IMAGES_COUNT + 4:
        images_offset, images_count = struct.unpack_from("<II", data, OFF_IMAGES_OFFSET)
    else:
        images_offset, images_count = struct.unpack_from(
            "<II", data, OFF_IMAGES_OFFSET_OLD)
    paths = []
    for i in range(images_count):
        off = images_offset + i * 32
        if off + 32 > len(data):
            break
        path_file_offset = struct.unpack_from("<I", data, off + 24)[0]
        if not path_file_offset or path_file_offset >= len(data):
            continue
        end = data.find(b"\0", path_file_offset)
        if end < 0:
            continue
        paths.append(data[path_file_offset:end].decode("utf-8", "replace"))
    return paths


def _uleb(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, pos


def trie_paths(trie: bytes) -> list[str]:
    """Walk the dylibs trie: canonical paths *and* their aliases."""
    out: list[str] = []
    # Iterative walk; some caches nest deeply enough to blow the recursion limit.
    stack = [(0, "")]
    seen = set()
    while stack:
        node, prefix = stack.pop()
        if (node, prefix) in seen:
            continue
        seen.add((node, prefix))
        if node >= len(trie):
            continue
        term_size, pos = _uleb(trie, node)
        if term_size:
            out.append(prefix)
            pos += term_size
        if pos >= len(trie):
            continue
        child_count = trie[pos]
        pos += 1
        for _ in range(child_count):
            end = trie.find(b"\0", pos)
            if end < 0:
                break
            edge = trie[pos:end].decode("utf-8", "replace")
            pos = end + 1
            child, pos = _uleb(trie, pos)
            stack.append((child, prefix + edge))
    return out


def index_for(cache_path: str, quiet: bool = False) -> list[str]:
    with open(cache_path, "rb") as fh:
        data = fh.read()
    if not data.startswith(MAGIC_PREFIX):
        raise CacheError(f"{cache_path}: not a dyld shared cache")

    paths = set(canonical_paths(data))
    if not quiet:
        print(f"  canonical images: {len(paths)}", file=sys.stderr)

    # The alias trie usually lives in a subcache; find it across every sibling.
    trie_addr = struct.unpack_from("<Q", data, OFF_DYLIBS_TRIE_ADDR)[0]
    trie_size = struct.unpack_from("<Q", data, OFF_DYLIBS_TRIE_SIZE)[0]
    if trie_addr and trie_size:
        regions: list[tuple[int, int, int, str]] = []
        for sib in sorted(glob.glob(cache_path + "*")):
            if sib.endswith((".symbols", ".atlas")):
                continue
            try:
                regions += read_mappings(sib)
            except OSError:
                pass
        hit = [r for r in regions if r[0] <= trie_addr < r[0] + r[1]]
        if hit:
            addr, _size, file_off, fname = hit[0]
            with open(fname, "rb") as fh:
                fh.seek(file_off + (trie_addr - addr))
                trie = fh.read(trie_size)
            found = trie_paths(trie)
            extra = set(found) - paths
            paths |= set(found)
            if not quiet:
                print(f"  aliases from trie: {len(extra)} "
                      f"(in {os.path.basename(fname)})", file=sys.stderr)
        elif not quiet:
            print("  alias trie is in a subcache that is not present; "
                  "canonical paths only", file=sys.stderr)
    return sorted(p for p in paths if p)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dsc_index",
        description="List every library path a dyld shared cache can load, "
                    "for machomorph --dylib-index.")
    ap.add_argument("cache",
                    help="an IPSW, a directory `ipsw extract --dyld` wrote, "
                         "or the main dyld_shared_cache_* file itself "
                         "(subcaches are read from alongside it)")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument("--arch", default="arm64e",
                    help="cache architecture to index (default arm64e)")
    ap.add_argument("--extract-dir",
                    help="where to extract an IPSW's cache; the default is "
                         "under /tmp/machomorph-ipsw, keyed by IPSW and arch, "
                         "and is reused on a second run")
    ap.add_argument("--re-extract", action="store_true",
                    help="extract from the IPSW again even if a cache is "
                         "already sitting in the extraction directory")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    try:
        cache = resolve_cache(args.cache, args.arch, args.extract_dir,
                              args.re_extract, args.quiet)
        if not args.quiet and cache != args.cache:
            print(f"  cache: {cache}", file=sys.stderr)
        paths = index_for(cache, args.quiet)
    except (CacheError, OSError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    text = "\n".join(paths) + "\n"
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
        if not args.quiet:
            print(f"  {len(paths)} loadable paths -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
