#!/usr/bin/env python3
"""Pull an image out of a dyld shared cache, as the cache holds it.

    python3 -m dsc.extract /usr/lib/libxcselect.dylib

This is step 1 of a lift and nothing more: the file it hands back is a cache
image written to disk, still carrying every one of the cache's rewrites. It
loads and then dies on the first path that dereferences a global. What makes it
useful on its own is that reading load commands from it is cheap, which is how
a dependency closure gets enumerated before anything is paid for.

Apple's dsc_extractor.bundle has no per-image entry point, so the whole cache
comes out in one go -- 3649 images, several GB. Keep the tree: every later lift
reuses it, and `DSC_OUT` says where it is.

`ipsw dyld extract` is the fallback. Both keep the image's cache addresses and
neither rebases anything, but only Apple's reliably produces a complete symbol
table -- and the export trie is rebuilt from that, so an incomplete one costs
exported symbols.
"""

import argparse
import os
import shutil
import subprocess
import sys

MAC_DSC = ("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/"
           "dyld_shared_cache_arm64e")
TREE = "/tmp/dsc_out"

HERE = os.path.dirname(os.path.abspath(__file__))
NATIVE = os.path.join(os.path.dirname(HERE), "native")


def extractor(say=print) -> str | None:
    """Path to the built dsc_extract, building it once if it is not there.

    It must be built -arch arm64e: Apple's bundle ships only x86_64 and arm64e
    slices, and dlopen needs a matching one.
    """
    path = os.path.join(NATIVE, "dsc_extract")
    if os.path.exists(path):
        return path
    if not shutil.which("make") or not os.path.exists(
            os.path.join(NATIVE, "Makefile")):
        return None
    say(f"  building {os.path.relpath(path)}")
    subprocess.run(["make", "-s", "-C", NATIVE, "dsc_extract"],
                   capture_output=True)
    return path if os.path.exists(path) else None


def tree() -> str:
    return os.environ.get("DSC_OUT", TREE)


def image(path: str, cache: str = MAC_DSC, out_tree: str | None = None,
          say=print) -> str | None:
    """The image at cache path *path*, extracted to a file. None if it cannot be."""
    out_tree = out_tree or tree()
    src = out_tree + path
    if os.path.isfile(src):
        return src
    exe = extractor(say)
    if exe and os.path.exists(cache):
        say(f"  extracting the whole cache into {out_tree} (slow, once)")
        subprocess.run([exe, cache, out_tree])
        if os.path.isfile(src):
            return src
    if shutil.which("ipsw") and os.path.exists(cache):
        os.makedirs(out_tree, exist_ok=True)
        subprocess.run(["ipsw", "dyld", "extract", cache, path,
                        "--output", out_tree], capture_output=True, text=True)
        if os.path.isfile(src):
            return src
        # ipsw does not always place the file where the cache path says.
        for root, _dirs, files in os.walk(out_tree):
            for f in files:
                if f == os.path.basename(path):
                    return os.path.join(root, f)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("image", help="path of the image INSIDE the cache")
    ap.add_argument("--cache", default=MAC_DSC)
    ap.add_argument("--tree", default=None,
                    help=f"where the extraction goes (default: $DSC_OUT or {TREE})")
    args = ap.parse_args(argv)
    got = image(args.image, args.cache, args.tree)
    if got is None:
        print(f"cannot extract {args.image} from {args.cache}", file=sys.stderr)
        return 1
    print(got)
    return 0


if __name__ == "__main__":
    sys.exit(main())
