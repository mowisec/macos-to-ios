/*
 * dlopen a dylib, look up a symbol and actually CALL it.
 *
 *     ./dlcall_test <dylib> <symbol>
 *
 * dlopen_test proves an image is mappable and dlsym_test proves its export
 * trie works, but neither executes a single instruction of it.  A library
 * lifted out of the dyld shared cache passes both and then faults on its first
 * call, because a cache image carries no LC_DYLD_CHAINED_FIXUPS and Apple's
 * dsc_extractor zeroes the GOT -- so every import is a jump to 0.  This is the
 * third step that catches that.
 *
 * The signature is unknown, so the symbol is called with five scratch
 * arguments: a 1 KB buffer, its size, and three pointers to scratch bools.
 * On arm64 a function that takes fewer simply ignores the extra registers, so
 * this reaches the first import call of almost any C function -- which is all
 * we are testing for.  It is a fault detector, not a correctness test: a
 * meaningful return value only exists if the signature happens to match.
 *
 * Convert the library with `-p macos --no-cpusubtype-fix` first, so it loads
 * into an ordinary process here rather than needing a cryptex install.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

typedef long (*fn5_t)(void *, long, void *, void *, void *);

int
main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <dylib> <symbol>\n", argv[0]);
		return 2;
	}

	void *h = dlopen(argv[1], RTLD_NOW);
	if (h == NULL) {
		printf("LOAD FAILS: %s\n", dlerror());
		return 1;
	}
	printf("loads\n");

	fn5_t f = (fn5_t)dlsym(h, argv[2]);
	if (f == NULL) {
		printf("LOADS but no %s: %s\n", argv[2], dlerror());
		return 1;
	}
	printf("resolves %s = %p\n", argv[2], (void *)f);

	char buf[1024];
	bool a = false, b = false, c = false;

	memset(buf, 0, sizeof buf);
	/* Flush before the call: if it faults, this is the last thing printed. */
	fflush(stdout);

	long r = f(buf, (long)sizeof buf, &a, &b, &c);

	printf("CALLS OK, returned %ld, buf=\"%.200s\" out=%d,%d,%d\n",
	    r, buf, a, b, c);
	return 0;
}
