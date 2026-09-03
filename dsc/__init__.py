"""dsc -- read and repair an image from a dyld shared cache.

An image inside a modern shared cache is not a dylib. The cache builder zeroes
its GOT, clears the section type that says what it was, rewrites its code to
reach a cache-wide uniqued GOT belonging to no image at all, relocates
everything centrally through the cache's slide info instead of a fixup load
command, rewrites every ObjC selector reference to reach a cache-wide uniqued
pool, and leaves its thread-local descriptors holding the cache's own
bookkeeping. Extract it and it loads, then dies the moment a code path
dereferences a global.

Undoing all of that is what this package does. The stages, and the order, which
is load-bearing at every step:

    extract.py   pull the image out of the cache -- Apple's dsc_extractor,
                 falling back to `ipsw dyld extract`
    facts.py     the two things the extraction cannot tell us: which words in
                 its data are pointers (the cache's slide info) and which
                 symbol each cache-wide GOT slot its code reaches was holding
                 (the cache's patch table)
    ---          machomorph retargets the platform and relays the segments out
    rebind.py    repoint the stubs at the image's own GOT and synthesise
                 LC_DYLD_CHAINED_FIXUPS
    objc.py      rebase the selector, protocol and class references the
                 rebinder mistook for C symbols -- BEFORE compaction, which
                 remaps the rebases it creates
    gotscan.py   judge the result, and refuse anything still reaching the cache
                 -- BEFORE compaction, which fills in the outside-every-segment
                 hole that is how a leftover is recognised
    compact.py   pack the segments, so the image reserves its own size rather
                 than the cache's 1.3-2.0 GB span. Required for an ObjC image:
                 dyld reads __objc_imageinfo by VM offset before mapping
    objc.py      again, for the relative method lists -- AFTER compaction,
                 because the repair makes `name` an inter-segment distance,
                 which is exactly what compaction moves

`machomorph.lift_library()` runs them in that order. Each module also has a CLI
(`python3 -m dsc.gotscan FILE`), and that is not decoration: when a lift comes
out wrong, running one stage by hand on the intermediate is how it gets
diagnosed. Every ObjC bug in CLAUDE.md was found that way.

index.py and symindex.py are the odd ones out. They read a cache (or an IPSW)
for what the TARGET can load rather than for an image to repair: index.py for
the list of loadable paths, which is what tells a conversion whether the target
has a library at all, and symindex.py for what each of those libraries exports,
which is the only source that can speak for a PrivateFramework -- the SDK ships
no .tbd for one, so without it those symbols are `unknown` and fail nothing.
"""
