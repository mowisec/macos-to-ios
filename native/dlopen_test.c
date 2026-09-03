/* dlopen a dylib and print the error. Built arm64e to match cache images. */
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <dylib>\n", argv[0]); return 2; }
    void *h = dlopen(argv[1], RTLD_LAZY);
    if (h) { printf("LOADS\n"); return 0; }
    printf("FAILS: %s\n", dlerror());
    return 1;
}
