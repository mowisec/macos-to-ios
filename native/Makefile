# The C part of this project: one program that is a build dependency of a lift,
# and three that are the local test loop.
#
#   dsc_extract   wraps Apple's /usr/lib/dsc_extractor.bundle, which has no
#                 per-image entry point -- so it extracts a whole cache at
#                 once. MUST be arm64e: the bundle ships only x86_64 and
#                 arm64e slices and dlopen needs a matching one.
#
#   dlopen_test   does it map?
#   dlsym_test    does its export trie work?
#   dlcall_test   does it RUN? The only one of the three that catches the
#                 failure this project is mostly about -- a damaged cache
#                 extraction loads and resolves symbols perfectly, and faults
#                 the moment you call into it. Prefer this one.
#
# Convert a library with `-p macos --no-cpusubtype-fix` to use them: without
# that flag the macOS arm64e ptrauth ABI version becomes arm64e.v1, which an
# ordinary process cannot load.

ARCH ?= arm64e
CFLAGS ?= -arch $(ARCH) -O2 -Wall

PROGS = dsc_extract dlopen_test dlsym_test dlcall_test

all: $(PROGS)

$(PROGS): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGS)

.PHONY: all clean
