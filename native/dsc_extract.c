/*
 * dsc_extract -- drive Apple's dsc_extractor.bundle.
 *
 *     ./dsc_extract <shared-cache> <output-dir>
 *
 * `ipsw dyld extract` produces a Mach-O that keeps the image's *cache* virtual
 * addresses. In a shared cache the segments of one library are spread across
 * separate cache regions, so those addresses are not in ascending order, and
 * dyld refuses to load the result as a standalone file:
 *
 *     segment '__AUTH' vm address out of order
 *
 * Apple's own extractor rebases each image to a contiguous layout and rewrites
 * the fixups that depend on it, which is what makes the output loadable. There
 * is no public header for it, only a bundle exporting one symbol that takes a
 * block, so this is the smallest possible wrapper around it.
 *
 * Build (must be arm64e: the bundle ships x86_64 and arm64e only, and dlopen
 * needs a slice matching the calling process):
 *
 *     clang -arch arm64e -O2 -o dsc_extract dsc_extract.c
 *
 * It extracts the entire cache -- there is no per-image entry point -- so
 * expect several GB and a few minutes. Do it once and keep the output.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*extract_fn)(const char *cache, const char *root,
                          void (^progress)(unsigned current, unsigned total));

static const char *BUNDLES[] = {
    "/usr/lib/dsc_extractor.bundle",
    "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/"
        "usr/lib/dsc_extractor.bundle",
    NULL,
};

int
main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <shared-cache> <output-dir>\n", argv[0]);
        return 2;
    }

    void *handle = NULL;
    const char *which = NULL;
    for (int i = 0; BUNDLES[i] != NULL; i++) {
        handle = dlopen(BUNDLES[i], RTLD_LAZY);
        if (handle != NULL) {
            which = BUNDLES[i];
            break;
        }
    }
    if (handle == NULL) {
        fprintf(stderr, "cannot load dsc_extractor.bundle: %s\n", dlerror());
        return 1;
    }

    extract_fn extract = (extract_fn)dlsym(
        handle, "dyld_shared_cache_extract_dylibs_progress");
    if (extract == NULL) {
        fprintf(stderr, "no dyld_shared_cache_extract_dylibs_progress in %s\n",
                which);
        return 1;
    }

    fprintf(stderr, "using %s\n", which);
    __block unsigned last = 0;
    int rc = extract(argv[1], argv[2], ^(unsigned current, unsigned total) {
        if (current == total || current >= last + 200) {
            last = current;
            fprintf(stderr, "\r  %u/%u", current, total);
            fflush(stderr);
        }
    });
    fprintf(stderr, "\ndone, result %d\n", rc);
    return rc == 0 ? 0 : 1;
}
