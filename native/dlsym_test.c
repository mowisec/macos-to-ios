/* dlopen a dylib and look up a symbol -- proves the image is usable, not just mappable. */
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <dylib> <symbol>\n", argv[0]); return 2; }
    void *h = dlopen(argv[1], RTLD_LAZY);
    if (!h) { printf("LOAD FAILS: %s\n", dlerror()); return 1; }
    void *s = dlsym(h, argv[2]);
    if (!s) { printf("LOADS but no %s: %s\n", argv[2], dlerror()); return 1; }
    printf("LOADS, %s = %p\n", argv[2], s);
    return 0;
}
