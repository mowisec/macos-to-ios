#!/bin/sh
# Rebuild the ported half of an SRD cryptex from scratch.
#
#     ./rebuild_cryptex.sh [options] <cryptex-root>
#
# THIS SCRIPT DOES THREE THINGS, and deliberately no more:
#
#   * scrape the macOS system directories and the Xcode toolchain for Mach-Os
#     and hand them all to machomorph in one batch (step 3);
#   * copy along the data trees a converted binary needs and no load command
#     mentions -- perl's module trees, zsh's modules and functions, a TLS trust
#     store -- retargeting the Mach-Os among them (steps 5 and 7);
#   * check the finished tree before an install cycle (step 8).
#
# Everything else is machomorph's. It works out each binary's closure of
# libraries the target does not have, lifts each one out of the shared cache,
# compacts it, stages it and repoints the binary -- so there is no list of
# libraries here, and no second tool. The primary way to use any of this is a
# single binary at a time:
#
#     ../machomorph.py /usr/bin/csrutil -o out/csrutil -p ios -v 27.0
#
# which produces out/csrutil and, beside it, every library iOS lacks. This
# script is the batch case of that, not a different mechanism.
#
# Options:
#   --ipsw FILE          build the target dylib index from this IPSW, instead
#                        of the one shipped in data/. Also accepts a directory
#                        `ipsw extract --dyld` wrote, or a cache file itself --
#                        anything dsc.index takes. The extraction and the
#                        index are cached under /tmp, so a second build on the
#                        same IPSW costs nothing.
#   --dylib-index FILE   use this already-built index (dsc.index output).
#   --arch ARCH          which cache to index out of the IPSW (default arm64e).
#   --os-version VER     the minos written into LC_BUILD_VERSION (default 26.0).
#   --target-symbols F   what the target's cache exports, per library, from
#                        dsc.symindex. Built automatically alongside the index
#                        when --ipsw is given, and cached the same way. Not
#                        shipped in data/ because it is a 37 MB file.
#   --no-target-symbols  build without it, accepting that no PrivateFramework
#                        symbol can be judged.
#
# WITHOUT a symbol index the launch prediction is blind to every
# PrivateFramework, because the SDK ships no stub for one -- so those symbols
# come back `unknown`, which never fails a binary and never gets weakened. That
# is how DiskManagement shipped with a hard import of
# _DAUnregisterApprovalCallback, which iOS does not export, and took csrutil
# with it. Four bundled libraries in the last build had such an import.
#
# The index is the ONLY thing that knows what the target can load, and every
# check downstream of it -- the path rewriting, the missing-library warning and
# half the launch prediction -- is silently weaker without a matching one. So
# point it at the IPSW of the iOS build actually on the device when that is not
# the one in data/.
#
# Everything the cryptex already contained that is NOT a port of ours is left
# alone: machomorph records what it wrote in a .machomorph-manifest, so a
# rebuild removes exactly its own output and --no-clobber refuses to touch
# anything else. Afterwards:
#
#     srdtool cryptex install <cryptex-root>
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)      # machomorph.py, dsc/, cryptex/ and data/
# The python packages are reached as modules from the repo root, which is what
# `python3 -m` wants -- so every call below runs with $ROOT as the working
# directory rather than spelling a file path.
PY="python3"
MM=$ROOT/machomorph.py
PLATFORM=ios
OSVER=26.0

usage() {
    sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-2}"
}

C=
IPSW=
INDEX=
SYMS=
NOSYMS=
ARCH=arm64e
while [ $# -gt 0 ]; do
    case $1 in
        --ipsw)         IPSW=${2:?--ipsw needs a path}; shift 2 ;;
        --dylib-index)  INDEX=${2:?--dylib-index needs a path}; shift 2 ;;
        --arch)         ARCH=${2:?--arch needs a value}; shift 2 ;;
        --target-symbols) SYMS=${2:?--target-symbols needs a path}; shift 2 ;;
        --no-target-symbols) NOSYMS=1; shift ;;
        --os-version|-v) OSVER=${2:?--os-version needs a value}; shift 2 ;;
        -h|--help)      usage 0 ;;
        --)             shift; break ;;
        -*)             echo "unknown option: $1" >&2; usage ;;
        *)              [ -n "$C" ] && { echo "unexpected argument: $1" >&2; usage; }
                        C=$1; shift ;;
    esac
done
[ $# -gt 0 ] && [ -z "$C" ] && { C=$1; shift; }
[ -n "$C" ] || usage

# --- 0. the target dylib index ----------------------------------------------
# What the target's dyld cache can load. Without it machomorph rewrites paths
# by rule, which for a framework iOS demoted to PrivateFrameworks turns a
# CORRECT macOS path into a plausible iOS path that does not exist -- and
# reports it as a successful rewrite. See CLAUDE.md, "The index is the rule".
#
# data/ holds one for iOS 27.0 24A5424a. --ipsw builds a matching one for any
# other build: dsc.index runs `ipsw extract --dyld` itself and caches both
# the extraction and the index, so only the first build on a given IPSW pays
# for it.
if [ -n "$IPSW" ] && [ -n "$INDEX" ]; then
    echo "--ipsw and --dylib-index are alternatives; pass one" >&2
    exit 2
fi
if [ -n "$IPSW" ]; then
    IPSW_WORK=${DSC_IPSW_DIR:-/tmp/machomorph-ipsw}
    IPSW_TAG=$(basename "$IPSW" | sed 's/\.[Ii][Pp][Ss][Ww]$//')
    INDEX=$IPSW_WORK/${IPSW_TAG}_${ARCH}_index.txt
    # Rebuilt when absent or older than its inputs -- a lift is a build product
    # of its tools and so is this, and "the file is there" has shipped a stale
    # artefact in this project four times.
    if [ ! -s "$INDEX" ] || [ "$IPSW" -nt "$INDEX" ] || \
       [ "$ROOT/dsc/index.py" -nt "$INDEX" ]; then
        mkdir -p "$IPSW_WORK"
        echo "building the target dylib index from $(basename "$IPSW")"
        (cd "$ROOT" && $PY -m dsc.index "$IPSW" --arch "$ARCH" \
            --extract-dir "$IPSW_WORK/${IPSW_TAG}_${ARCH}" -o "$INDEX") || {
            echo "could not build an index from $IPSW -- refusing to build a" >&2
            echo "  cryptex against the wrong target." >&2
            exit 1; }
    else
        echo "target dylib index: $INDEX (up to date)"
    fi
    echo "  to make this the default for a bare machomorph run, copy it into"
    echo "  data/ and add it to BUNDLED_INDEX in machomorph.py."
fi
INDEX=${INDEX:-$ROOT/data/ios27_24A5424a_index.txt}
[ -s "$INDEX" ] || { echo "no dylib index at $INDEX" >&2; exit 1; }
echo "target dylib index: $INDEX ($(grep -c . "$INDEX") loadable paths)"

# --- 0b. the target symbol index -------------------------------------------
# The dylib index says whether the target HAS a library; this says what that
# library exports. It is the only source that can speak for a PrivateFramework,
# and it is what turns `--weaken-unresolvable` from a judgement about the
# libraries the SDK happens to describe into one about all of them.
#
# It is not shipped in data/ (37 MB gzipped, 4.7 million symbols), so it is
# built from the IPSW and cached beside the extraction. Without --ipsw there is
# nothing to build it from and the build says so rather than going quiet.
if [ -z "$NOSYMS" ] && [ -z "$SYMS" ] && [ -n "${IPSW:-}" ]; then
    SYMS=$IPSW_WORK/${IPSW_TAG}_${ARCH}_symbols.txt.gz
    if [ ! -s "$SYMS" ] || [ "$IPSW" -nt "$SYMS" ] || \
       [ "$ROOT/dsc/symindex.py" -nt "$SYMS" ]; then
        echo "building the target symbol index from $(basename "$IPSW")"
        (cd "$ROOT" && $PY -m dsc.symindex "$IPSW" --arch "$ARCH" \
            --extract-dir "$IPSW_WORK/${IPSW_TAG}_${ARCH}" -o "$SYMS") || {
            echo "could not build a symbol index from $IPSW" >&2; exit 1; }
    else
        echo "target symbol index: $SYMS (up to date)"
    fi
fi
SYMARGS=
if [ -n "$SYMS" ]; then
    [ -s "$SYMS" ] || { echo "no symbol index at $SYMS" >&2; exit 1; }
    SYMARGS="--target-symbols $SYMS"
    echo "target symbol index: $SYMS"
elif [ -z "$NOSYMS" ]; then
    echo "NOTE: no target symbol index (pass --ipsw or --target-symbols)."
    echo "  Every PrivateFramework symbol will be reported 'unknown', which"
    echo "  fails no binary and weakens nothing -- how csrutil shipped broken."
fi

# Compaction is on by default. A lift keeps the shared cache's segment
# addresses, so it reserves 1.6-2.0 GB of contiguous address space and only one
# or two fit in a process; dsc_compact packs the segments and brings that down
# to the library's own size. It is refused automatically for anything it cannot
# prove safe and verifies every ADRP still names the same byte before writing,
# so having it on costs nothing when it cannot help. DSC_COMPACT=0 opts out.
export DSC_COMPACT=${DSC_COMPACT:-1}

# --- 1. clear out only what we put there -----------------------------------
# machomorph leaves a .machomorph-manifest listing what it wrote, so a rebuild
# can remove exactly its own output. Anything else in the cryptex belongs to
# someone else -- typically binaries built natively for iOS, which a macOS port
# of the same name would only downgrade -- and is never touched. --no-clobber
# below is the belt to this braces.
mkdir -p "$C/bin" "$C/lib"
M=$C/.machomorph-manifest
if [ -f "$M" ]; then
    while IFS= read -r rel; do
        case $rel in ''|\#*) continue ;; esac
        rm -f "$C/$rel"
    done < "$M"
fi

# --- 2. what the lifts used to be ------------------------------------------
# Nothing here any more, and that is the point of this rewrite. This script
# used to lift twelve libraries out of the shared cache by hand -- libxcselect,
# libcrypto, libssl, libcurl, libpcre, libdtrace, TrustEvaluationAgent and
# csrutil's five -- because machomorph could only convert a file that already
# existed and bundle.py could only *extract*, which produces a library that
# loads and then crashes on the first path that dereferences a global.
#
# machomorph does the whole thing now: it computes each binary's closure of
# libraries the target does not have, lifts each one out of the cache, compacts
# it, stages it and repoints the binary at it. So the hand-written list is gone,
# and with it the bug it kept causing -- a library bundled for the tools on the
# list while every other binary in the batch that linked the same library was
# left pointing at the absolute macOS path.
#
# The lifts are cached in ./lifted (see --lift-cache), keyed by basename and
# re-made whenever any of the lifting code is newer, so only the first build
# pays for them.
#
# So are the two cache-WIDE dumps a lift reads -- the slide info and the patch
# table -- but machomorph now saves and reuses those itself, keyed by the
# cache's own size and mtime, so nothing has to be prepared here. A full cache
# pass is minutes and used to be paid once per library, forty times over.
#
# These two paths are still honoured, because a dump built by hand is usually
# left at one of them. The test is on SIZE, not existence: an empty dump is read
# by dsc.facts without complaint, yields no records, and produces a library with
# nothing repointed that loads and then PAC-faults -- which is what happens when
# one is still being written. "The file is there" is not a check.
for _d in /tmp/slide.jsonl:DSC_SLIDE_JSON /tmp/patches.txt:DSC_PATCHES_TXT; do
    _f=${_d%%:*}; _v=${_d#*:}
    [ -e "$_f" ] || continue
    if [ -s "$_f" ]; then
        eval "export $_v=\${$_v:-$_f}"
    else
        echo "warning: $_f is 0 bytes -- not a saved dump, ignoring it." >&2
        echo "  (a dump still being written looks exactly like this, and an" >&2
        echo "   empty one repoints nothing and lifts a library that faults)" >&2
    fi
done
unset _d _f _v
LIBDIR=lib

# --- 3. the main batch ------------------------------------------------------
# macOS system directories plus the Xcode toolchain.
#
# The old data/blocklist_ios.txt is RETIRED as of 2026-08-31 (archived under
# measurements/). It excluded ~480 binaries on three kinds of inference that
# did not hold up: "iOS ships its own" was read off `ls` rather than from a
# launch, and the native ioreg turns out to be SIGKILLed; "library absent" was
# measured before this cryptex bundled libcrypto, libssl, libperl, libpcre and
# libdtrace, so 36 of its entries name a library we now ship; and a symbol
# failure is a snapshot, not a verdict. So the batch now ports everything and
# the measurement decides afterwards -- see next-session-blocklist.md.
#
# Nothing about the scan is spelled out here any more. `--scan` takes the Xcode
# toolchain as well and applies both lists in data/ by default -- the 95 xcrun
# shims by path, and the binaries a probe measured dying on a symbol -- because
# those are properties of scanning a macOS system, not of this script. See
# CLAUDE.md, "A scan's defaults are the tool's, not the script's".
# --no-scan-xcode and --no-exclude-defaults are the overrides.
#
# EXPECT THIS BUILD TO BE BIGGER AND TO CONTAIN FAILURES. That is deliberate:
# a binary that fails to load is inert, while a binary wrongly excluded is
# invisible. Two things to watch, both in the doc: a port in bin/ SHADOWS a
# native tool of the same name if the cryptex is earlier in PATH, and the probe
# is what tells you which way round is better.
# The second list is data/blocklist_symbols.txt: binaries measured to die at
# launch on a symbol iOS does not export. It is GENERATED from a probe TSV by
# `python3 -m cryptex.blocklist`, never hand-written -- that is the whole
# difference from the list this replaced. Each line carries the symbol as an
# inline comment, so when a symbol becomes resolvable you retire its entries by
# grep and re-probe. Regenerate after every probe:
#
#   python3 -m cryptex.blocklist measurements/<latest>.tsv --cryptex <cx> \
#       > data/blocklist_symbols.txt
#
# It deliberately HOLDS BACK a binary whose missing symbol comes from a library
# we bundle rather than from iOS -- openssl, tcpdump and curl are failing on the
# lifted libcrypto's _syslog$DARWIN_EXTSN, which is ours to fix. See the file.
#
# --darwin-extsn renames the one $DARWIN_EXTSN variant iOS libc does not
# export, _syslog$DARWIN_EXTSN, to plain _syslog. It was the single largest
# remaining symbol blocker -- 96 binaries here import it and dyld kills each of
# them at launch. The name is shorter, so it is written inside its own storage:
# nothing moves, and both names live in libSystem so the two-level-namespace
# ordinal is untouched. Plain syslog is the same call with the older semantics.
#
# Every library iOS does not have comes along automatically. machomorph walks
# each binary's dependency closure, lifts what only exists inside the shared
# cache, compacts it, stages it into $LIBDIR and repoints the binary -- so
# libxcselect, libcrypto, libssl, libcurl, libpcre, libdtrace, libperl and
# TrustEvaluationAgent are here because the binaries that need them say so, not
# because this script names them.
#
# That also closes CLAUDE.md's "a batch undoes --provide-lib" trap by
# construction. It used to be that only the tools on a hand-written list got
# their libraries, and every other binary in this batch that linked the same
# library kept the absolute macOS path, weak-linked -- so it loaded and crashed
# on the first call. A closure computed per binary cannot have that gap, and
# restage.py, which existed to retrofit the fix, is no longer run.
#
# --max-libs (7 by default) is the cost gate. A closure larger than that means
# the binary is dragging in a whole macOS subsystem that cannot work on iOS --
# system_profiler wants AppKit, SkyLight, HIToolbox and OpenGL, which is the
# macOS window server, and it would load and have nothing to talk to. Such a
# binary is still converted; it simply reports its libraries as missing.
#
# --weaken-unresolvable IS A JUDGEMENT, and it is this script's rather than
# machomorph's, which is why it is a flag here and off by default there. A
# bundled library that imports a symbol iOS does not export cannot load, so the
# choice is between not shipping it and binding those symbols NULL -- the
# library then loads and any path that reaches one crashes. DiskManagement (7)
# and libcsfde (23) need it, all macOS-only Security APIs (Authorization
# Services, SecKeychain, the SecTransform pipeline, the FileVault recovery-key
# calls), and libcurl needs three Secure Transport ones. Those 33 symbol names
# used to be written out by hand in this file; they are now derived, and every
# one is named in the output.
"$MM" --scan -p "$PLATFORM" -v "$OSVER" --cryptex "$C" --no-clobber \
    --dylib-index "$INDEX" $SYMARGS --weaken-missing --keep-going --darwin-extsn \
    --loader-path --cryptex-libdir "$LIBDIR" --weaken-unresolvable

# --- 4. the Xcode toolchain's own @rpath dylibs -----------------------------
# libcodedirectory is needed by 7 of the Mach-O editing tools; libLTO carries
# LLVM's disassembler, which dyld_info calls into. Their rpath is already
# @executable_path/../lib/, so they need no rewriting -- just staging.
TC=$(xcrun --find otool 2>/dev/null | sed 's|/usr/bin/otool$|/usr/lib|')
if [ -d "$TC" ]; then
    "$MM" "$TC/libcodedirectory.dylib" "$TC/libLTO.dylib" \
        -p "$PLATFORM" -v "$OSVER" --cryptex "$C" --cryptex-bindir lib \
        --dylib-index "$INDEX" $SYMARGS --keep-going --darwin-extsn
fi

# --- 5. the data trees a converted binary needs beside it -------------------
# The ONLY thing left in this script that machomorph cannot work out for
# itself, and the reason is worth stating: these are not Mach-O dependencies.
# perl finds its modules through a compiled-in path, zsh dlopens its through
# another, and neither is a load command -- so nothing static can see them.
# They have to be copied, and the XS modules and zsh .so files among them
# retargeted like any other Mach-O.
#
# perl and zsh themselves came out of the main batch in step 3, with libperl
# and libpcre bundled by the closure. Nothing here converts a tool.

# A loadable module -- a perl XS .bundle, a zsh .so, a ruby .bundle -- is
# converted like any other Mach-O, with two differences that both cost real
# space before they were noticed.
#
# --no-libraries, because the closure must NOT be staged beside the module.
# Since the one-tool refactor made the closure the default, `-o module.new`
# also wrote every library the module needs next to it: 9 copies of libruby,
# 5 of libcrypto, 5 of libssl, 37 MB across 25 files, at paths like
#   share/ruby/universal-darwin25/racc/System/Library/Frameworks/
#       Ruby.framework/usr/lib/libruby.2.6.dylib
# They loaded, which is exactly why it went unnoticed -- perl and ruby were
# both device-confirmed working while reaching into those scratch copies.
#
# And every reference to a library the cryptex ALREADY staged in lib/ is
# repointed there, DERIVED from the module's own load commands rather than from
# a list. That subsumes the three hand-written --change flags these steps used
# to carry (one each for libperl, libruby, libpcre -- since each basename is in
# lib/) and picks up the six they never mentioned: libssl, libcrypto, libapr,
# libaprutil, libsasl2 and libHeimdalProxy. A hand-written list of libraries is
# the thing this project has got wrong four times; see "The hand-written tool
# list leaves binaries pointing at nothing".
#
# @executable_path, not @loader_path: the interpreter is <cryptex>/bin/ruby, so
# ../lib is right whatever depth the module sits at -- and they sit at four
# different depths, which is what makes @loader_path (and --libs-into, which
# emits it) the wrong answer here.
#
# $_ch is deliberately unquoted, for word splitting. These are Apple system
# paths and contain no spaces.
module_changes() {
    otool -L "$1" | tail -n +2 | awk '{print $1}' | while IFS= read -r ref; do
        case $ref in @*|'') continue ;; esac
        b=${ref##*/}
        [ -e "$C/lib/$b" ] || continue
        printf '%s %s %s ' --change "$ref" "@executable_path/../lib/$b"
    done
}

# --no-symbol-check for two reasons. It is the right semantics: the launch
# prediction exists to keep a binary that cannot start out of bin/, where it
# would shadow a native tool of the same name. A module is dlopened by its
# interpreter, and one with an unresolved symbol fails at `use Foo` /
# `require "foo"` with the interpreter's own error, which is a diagnosable
# runtime problem rather than a silent kill. And it is 20x faster: the check
# parses 625 SDK stubs per invocation (1.40s vs 0.07s), which over 300 modules
# is most of the build.
#
# --darwin-extsn matters here too: perl's Sys/Syslog/Syslog.bundle is the
# binding for syslog(3) and imports the macOS-only variant, so without the
# rename it is simply not portable and gets skipped.
retarget_module() {
    _m=$1
    _ch=$(module_changes "$_m")
    if "$MM" "$_m" -o "$_m.new" -p "$PLATFORM" -v "$OSVER" -q \
            --dylib-index "$INDEX" --darwin-extsn --no-symbol-check \
            --no-libraries $_ch >/dev/null 2>&1 && [ -f "$_m.new" ]; then
        mv "$_m.new" "$_m"
        return 0
    fi
    rm -f "$_m.new"
    return 1
}

# perl is useless without its module tree, and macOS keeps it in TWO places:
# the core modules in /System/Library/Perl/5.34 and a much larger Extras
# tree beside it (112 more XS bundles -- Archive, CGI, Crypt, DBI, JSON,
# LWP...). Staging only the core tree, as this did at first, gives a perl
# that runs and then cannot `use` most of what a real script wants.
#
# Every .bundle in either tree is an XS module: a Mach-O that has to be
# retargeted like any other, and repointed at the staged libperl.
PERLPATH=
for tree in /System/Library/Perl/5.34 /System/Library/Perl/Extras/5.34; do
    [ -d "$tree" ] || continue
    case $tree in
        */Extras/*) rel=share/perl5-extras ;;
        *)          rel=share/perl5 ;;
    esac
    rm -rf "$C/$rel"
    mkdir -p "$C/share"
    cp -R "$tree" "$C/$rel"
    # cp -R off a SIP volume brings read-only modes with it, which makes the
    # next rebuild's rm -rf fail.
    chmod -R u+w "$C/$rel"
    n=0
    skipped=0
    # An `if` rather than a && || chain, because a chain that ends in
    # `|| rm -f` is easy to get subtly wrong under `set -e` and a
    # half-converted module tree is not worth the brevity.
    for b in $(find "$C/$rel" -name '*.bundle'); do
        if retarget_module "$b"; then
            n=$((n + 1))
        else
            skipped=$((skipped + 1))
        fi
    done
    echo "perl: $rel, $n XS modules retargeted, $skipped left as-is"
    PERLPATH="${PERLPATH:+$PERLPATH:}\$CRYPTEX_MOUNT_PATH/$rel"
done
if [ -n "$PERLPATH" ] && [ -f "$C/lib/libperl.dylib" ]; then
    # perl finds libperl through the load command, but a module that dlopens
    # it wants a real file at the CORE path too.
    cp "$C/lib/libperl.dylib" \
       "$C/share/perl5/darwin-thread-multi-2level/CORE/libperl.dylib"
fi
[ -n "$PERLPATH" ] && \
    echo "perl: needs  export PERL5LIB=$PERLPATH"

# zsh keeps its modules in /usr/lib/zsh/5.9 on macOS. Without them zsh runs
# but cannot load zsh/zle, so there is no interactive line editing.
ZSHSRC=/usr/lib/zsh/5.9
if [ -d "$ZSHSRC" ]; then
    rm -rf "$C/share/zsh/5.9"
    mkdir -p "$C/share/zsh"
    cp -R "$ZSHSRC" "$C/share/zsh/5.9"
    # `find`, not a glob. `zsh/*.so` misses zsh/net/ and zsh/param/, so
    # zsh/net/tcp, zsh/net/socket and zsh/param/private shipped as untouched
    # FAT macOS binaries for as long as this step has existed -- and the way
    # that surfaced is instructive: `zmodload zsh/zftp` failed on a missing
    # `_tcp_close`, which reads as a broken zftp and is really its dependency
    # never having been converted. dyld's own message says so if you read to
    # the end of it: "incompatible platform (have 'macOS', need 'iOS')".
    zn=0
    zskipped=0
    for m in $(find "$C/share/zsh/5.9" -name '*.so'); do
        if retarget_module "$m"; then
            zn=$((zn + 1))
        else
            zskipped=$((zskipped + 1))
        fi
    done
    echo "zsh:  $zn modules retargeted, $zskipped left as-is"
    # zsh's data tree, which is SEPARATE from its module tree and was
    # missed at first. `strings /bin/zsh` names three compiled-in defaults:
    #
    #   /usr/lib/zsh/5.9              module_path   -> staged above
    #   /usr/share/zsh/5.9/functions  fpath         -> staged here
    #   /usr/share/zsh/site-functions fpath
    #
    # Without the functions tree (1203 files) zsh starts, but compinit and
    # every autoloaded function fail. It is plain script data, so nothing
    # needs converting -- just copying.
    for d in functions help scripts; do
        [ -d "/usr/share/zsh/5.9/$d" ] || continue
        rm -rf "$C/share/zsh/5.9/$d"
        cp -R "/usr/share/zsh/5.9/$d" "$C/share/zsh/5.9/$d"
        chmod -R u+w "$C/share/zsh/5.9/$d"
    done

    # And now the part that cannot be fixed by staging: zsh dlopens a module
    # through its compiled-in module_path, and that is a C string in __TEXT,
    # not a load command, so machomorph never sees it. The failure is
    #
    #   zsh: failed to load module `zsh/zle':
    #        dlopen(/usr/lib/zsh/5.9/zsh/zle.so) ... no such file
    #
    # Patching the string is not an option either: the cryptex mount point
    # carries a per-install random suffix, so there is no fixed path to
    # patch it to.
    #
    # NOT `export MODULE_PATH=...`. That was the advice here and it does
    # nothing: module_path is not one of the zsh arrays tied to an
    # environment variable (path/PATH is, module_path/MODULE_PATH is not),
    # so zsh keeps its compiled-in default and zmodload fails. Device-
    # checked: setting the array works, the env var does not.
    #
    # So set the array, from a startup file we ship. ZDOTDIR *is* honoured
    # from the environment, and $ZDOTDIR/.zshenv is read on EVERY
    # invocation, interactive or not, before any module is wanted.
    mkdir -p "$C/share/zsh/zdotdir"
    cat > "$C/share/zsh/zdotdir/.zshenv" <<'ZSHENV'
# Shipped by rebuild_cryptex.sh. Reached via ZDOTDIR -- see the cryptex's
# printed exports. It exists because zsh's module_path and fpath defaults are
# compiled in as absolute macOS paths, and the cryptex mounts at a different
# (random) place every install, so they can only be corrected at runtime.
if [ -n "$CRYPTEX_MOUNT_PATH" ]; then
module_path=($CRYPTEX_MOUNT_PATH/share/zsh/5.9)
fpath=($CRYPTEX_MOUNT_PATH/share/zsh/5.9/functions $fpath)
fi
# Hand the remaining startup files back to the real home directory, so shipping
# this does not hide a user's own .zshrc. zsh re-reads ZDOTDIR for each startup
# file, so reassigning it here is enough.
ZDOTDIR=${HOME:-/var/root}
ZSHENV
    echo "zsh:  needs  export ZDOTDIR=\$CRYPTEX_MOUNT_PATH/share/zsh/zdotdir"
    echo "             (sets module_path and fpath, which are compiled-in"
    echo "              absolute macOS paths and cannot be patched -- the"
    echo "              mount point is random. MODULE_PATH is NOT tied to"
    echo "              the module_path array and has no effect.)"
fi

# ruby, like perl, is useless without its module tree -- and this was missed for
# several sessions because `ruby -v` works without it. CLAUDE.md recorded
# "ruby 2.6.10" as confirmed on device on the strength of exactly that, while
# `ruby -e 'puts 1'` died in rubygems' bootstrap. Version flags are not tests.
#
# Three separate things are needed, each found by fixing the one before it:
#
#   1. the module tree, staged and on RUBYLIB -- and BOTH directories, the
#      stdlib and its arch subdir, because rbconfig.rb lives in the latter and
#      naming only the top gives "cannot load such file -- rbconfig";
#   2. SDKROOT set to anything. Apple's rbconfig.rb computes CONFIG["includedir"]
#      by backticking `xcode-select --print-path && xcrun --show-sdk-path`, and
#      iOS has no /bin/sh, so the require dies with Errno::ENOENT. The line
#      short-circuits on ENV['SDKROOT'], so this needs no patch to Apple's file;
#   3. the 105 .bundle native extensions, retargeted. Not optional and not just
#      for exotic modules: rubygems' own specification.rb requires `stringio`,
#      so without them even `ruby -e "puts 1"` fails. Only `--disable-gems`
#      avoids it.
#
# Same treatment as perl's XS modules, for the same reasons -- see that step for
# why --no-symbol-check is right here (a bundle is dlopened, so an unresolved
# symbol is ruby's own diagnosable error, not a silent kill) and 20x faster.
RUBYSRC=/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/lib/ruby/2.6.0
RUBYPATH=
if [ -d "$RUBYSRC" ] && [ -e "$C/bin/ruby" ]; then
    rm -rf "$C/share/ruby"
    mkdir -p "$C/share"
    cp -R "$RUBYSRC" "$C/share/ruby"
    chmod -R u+w "$C/share/ruby"
    n=0
    skipped=0
    for b in $(find "$C/share/ruby" -name '*.bundle'); do
        if retarget_module "$b"; then
            n=$((n + 1))
        else
            skipped=$((skipped + 1))
        fi
    done
    ARCHDIR=$(cd "$C/share/ruby" && ls -d *darwin* 2>/dev/null | head -1)
    RUBYPATH="\$CRYPTEX_MOUNT_PATH/share/ruby${ARCHDIR:+:\$CRYPTEX_MOUNT_PATH/share/ruby/$ARCHDIR}"
    echo "ruby: share/ruby, $n native extensions retargeted, $skipped left as-is"
    echo "ruby: needs  export RUBYLIB=$RUBYPATH"
    echo "             export SDKROOT=/    (rbconfig.rb shells out to xcrun"
    echo "                                  otherwise, and iOS has no /bin/sh)"
fi

# Tcl keeps its script library outside the framework binary, and Tcl_Init
# sources init.tcl from it before an interpreter is usable. Without it `expect`
# starts, loads every library correctly, and dies in its own Tcl_Init with
# "Can't find a usable init.tcl" -- which reads like a broken port and is not.
#
# Staged into lib/tcl8.5 rather than share/, and that is the whole point: Tcl
# searches <dir of the executable>/../lib/tcl8.5 on its own, so this needs NO
# environment variable. The mount point's random suffix does not matter because
# the path is derived at runtime. Contrast perl and zsh above, whose paths are
# compiled-in absolutes and do need an export. cryptex.verify walks lib/ with
# os.path.isfile, so a directory there is skipped rather than parsed.
TCLSRC=/System/Library/Frameworks/Tcl.framework/Versions/8.5/Resources/Scripts
if [ -d "$TCLSRC" ] && [ -e "$C/bin/expect" ]; then
    rm -rf "$C/lib/tcl8.5"
    mkdir -p "$C/lib"
    cp -R "$TCLSRC" "$C/lib/tcl8.5"
    chmod -R u+w "$C/lib/tcl8.5"
    echo "tcl:  staged $(find "$C/lib/tcl8.5" -type f | wc -l | tr -d ' ') script files into lib/tcl8.5 (no env var needed)"
fi

# --- 7. a trust store -------------------------------------------------------
# iOS has no /etc/ssl at all, so curl and openssl complete a TLS handshake and
# then cannot verify the chain -- which looks like a crypto failure and is not.
# macOS's curated bundle is the source; openssl.cnf is ours, in data/ssl.
#
# The cryptex mount point carries a per-install random suffix, so the path
# cannot be compiled in; it is picked up from the environment, hence the exports
# printed below. SSL_CERT_FILE is not enough for `openssl s_client`, which does
# not call SSL_CTX_set_default_verify_paths unless given -CAfile.
if [ -f /etc/ssl/cert.pem ]; then
    mkdir -p "$C/share/ssl"
    cp /etc/ssl/cert.pem "$C/share/ssl/cert.pem"
    cp "$ROOT/data/ssl/openssl.cnf" "$C/share/ssl/openssl.cnf"
    echo "tls:  needs  export SSL_CERT_FILE=\$CRYPTEX_MOUNT_PATH/share/ssl/cert.pem"
    echo "             export CURL_CA_BUNDLE=\$SSL_CERT_FILE"
    echo "             export OPENSSL_CONF=\$CRYPTEX_MOUNT_PATH/share/ssl/openssl.cnf"
else
    echo "note: no /etc/ssl/cert.pem; curl and openssl will not verify chains" >&2
fi

# --- 7b. shell startup files that set everything the ported tools need ------
# Five steps above each print a "needs export ..." hint, which is a poor place
# for them: the reader has to keep a build log, and every fresh shell on the
# device starts with none of it.  So the same knowledge is written into the
# cryptex as real shell startup files.
#
# Every path is derived from $CRYPTEX_MOUNT_PATH at runtime, which cryptex-run
# already exports, because the mount carries a per-install random suffix and
# nothing may hardcode it.
#
# Whether these are READ depends on the cryptex's etc/ being path-overlaid onto
# /etc.  A first probe suggested it is not -- the cryptex ships bin/bash while
# /bin/bash is absent, and /private/preboot/Cryptexes/OS holds only System and
# usr -- but overlay behaviour is not uniform across directories, so these are
# cheap to ship and an install settles it.  The fallback, if /etc/profile is not
# read, is the same content reached from one hook in $HOME, which IS writable.
#
# TWO files, and which two is not arbitrary.  zsh never reads /etc/profile at
# all -- that is sh and bash -- and bash never reads /etc/zshenv, so one file
# cannot serve both:
#
#   /etc/profile   bash, LOGIN shells.  (A non-login interactive bash reads
#                  ~/.bashrc and no /etc file; /etc/bashrc is only reached
#                  because macOS's own /etc/profile sources it.)
#   /etc/zshenv    zsh, ALWAYS -- interactive, login, `zsh -c`, scripts -- and
#                  read FIRST, before ~/.zshenv.  That is what makes it the
#                  right hook rather than /etc/zshrc: the failing case is
#                  `zsh -c "zmodload zsh/pcre"`, which is non-interactive, so
#                  /etc/zshrc would never fire for it.  Being read before
#                  ~/.zshenv also matters, because ZDOTDIR has to be set before
#                  zsh goes looking for $ZDOTDIR/.zshenv.
#
# /etc/zprofile and /etc/zshrc are deliberately NOT shipped.  They are read
# AFTER $ZDOTDIR/.zshenv, which reassigns ZDOTDIR=$HOME so the cryptex does not
# hide the user's own dotfiles -- so setting ZDOTDIR again there would send zsh
# looking for the user's .zprofile and .zshrc inside the cryptex.
mkdir -p "$C/etc"
cat > "$C/etc/profile" <<'PROFILE'
# Shipped in the cryptex by rebuild_cryptex.sh.  Sets everything the ported
# tools need: each variable exists because a tool has a compiled-in absolute
# macOS path that is wrong on iOS and cannot be patched, since the cryptex
# mount point carries a different random suffix every install.

[ -n "${CRYPTEX_MOUNT_PATH:-}" ] || return 0
_cx=$CRYPTEX_MOUNT_PATH

# curl and openssl: iOS has no /etc/ssl at all.  They fail differently and
# curl's is the more misleading -- "error setting certificate verify locations"
# reads as a broken build and is a missing file.
if [ -f "$_cx/share/ssl/cert.pem" ]; then
    SSL_CERT_FILE=$_cx/share/ssl/cert.pem
    CURL_CA_BUNDLE=$SSL_CERT_FILE
    export SSL_CERT_FILE CURL_CA_BUNDLE
fi
if [ -f "$_cx/share/ssl/openssl.cnf" ]; then
    OPENSSL_CONF=$_cx/share/ssl/openssl.cnf
    export OPENSSL_CONF
fi

# perl: @INC still names /System/Library/Perl, so anything that loads a module
# fails with "Can't locate POSIX.pm in @INC".
_pl=
[ -d "$_cx/share/perl5" ]        && _pl=$_cx/share/perl5
[ -d "$_cx/share/perl5-extras" ] && _pl=${_pl:+$_pl:}$_cx/share/perl5-extras
if [ -n "$_pl" ]; then
    PERL5LIB=$_pl
    export PERL5LIB
fi

# ruby: BOTH the stdlib and its arch subdir, because rbconfig.rb lives in the
# latter and naming only the top gives "cannot load such file -- rbconfig".
# SDKROOT because Apple's rbconfig.rb backticks `xcode-select --print-path` at
# require time and iOS has no /bin/sh; the line short-circuits on it being set.
if [ -d "$_cx/share/ruby" ]; then
    RUBYLIB=$_cx/share/ruby
    for _a in "$_cx"/share/ruby/*darwin*; do
        [ -d "$_a" ] && RUBYLIB=$RUBYLIB:$_a
    done
    export RUBYLIB
    [ -n "${SDKROOT:-}" ] || SDKROOT=/
    export SDKROOT
fi

# Tcl needs nothing: it finds lib/tcl8.5 relative to the interpreter itself.
# zsh is handled per-file below, because what it needs are ARRAYS, not exports.

unset _cx _pl _a
PROFILE
sh -n "$C/etc/profile" || { echo "generated etc/profile is not valid sh" >&2; exit 1; }
# zsh gets the same exports plus two things that cannot go in an sh-compatible
# file: module_path and fpath are zsh ARRAYS.  Putting them here rather than
# reaching them through ZDOTDIR is what makes this file work as a plain COPY to
# ~/.zshenv -- no indirection, and nothing to go stale, because every path is
# still derived from $CRYPTEX_MOUNT_PATH at runtime.
cp "$C/etc/profile" "$C/etc/zshenv"
cat >> "$C/etc/zshenv" <<'ZSHENV'

# zsh only, and the reason these are not in etc/profile is that they are zsh
# arrays rather than environment variables.  zsh's module_path and fpath
# defaults are compiled in as absolute macOS paths, and exporting MODULE_PATH
# does nothing because it is not one of the arrays tied to an environment
# variable (path/PATH is).  Without them zsh scripts run but every module and
# autoloaded function fails, so there is no line editing.
if [ -n "${CRYPTEX_MOUNT_PATH:-}" ]; then
    module_path=($CRYPTEX_MOUNT_PATH/share/zsh/5.9)
    fpath=($CRYPTEX_MOUNT_PATH/share/zsh/5.9/functions $fpath)
fi
ZSHENV
zsh -n "$C/etc/zshenv" || { echo "generated etc/zshenv is not valid zsh" >&2; exit 1; }

# ZDOTDIR goes in etc/profile ONLY, never in etc/zshenv, and that asymmetry is
# load-bearing.  In etc/profile it is the right mechanism: a bash login shell
# cannot set zsh arrays, so it points a later zsh at the shipped zdotdir/.zshenv
# which sets them and then hands ZDOTDIR back to $HOME.
#
# In etc/zshenv it would be a BUG.  A copy of that file at ~/.zshenv is read
# before .zprofile and .zshrc are looked for, so setting ZDOTDIR there sends zsh
# hunting for the user's own .zprofile and .zshrc inside the cryptex -- and the
# zdotdir/.zshenv that would have reset it has already been passed.  Hence the
# arrays are set directly above instead.
cat >> "$C/etc/profile" <<'ZDOTHOOK'

# zsh's module_path and fpath are arrays, which this sh-compatible file cannot
# set.  ZDOTDIR points a zsh started from here at the shipped startup file that
# does set them; it reassigns ZDOTDIR=$HOME on the way out, so the user's own
# .zshrc is not hidden.  A native zsh gets this from ~/.zshenv instead, which
# sets the arrays directly and must NOT set ZDOTDIR.
if [ -n "${CRYPTEX_MOUNT_PATH:-}" ] && \
   [ -d "$CRYPTEX_MOUNT_PATH/share/zsh/zdotdir" ]; then
    ZDOTDIR=$CRYPTEX_MOUNT_PATH/share/zsh/zdotdir
    export ZDOTDIR
fi
ZDOTHOOK
sh -n "$C/etc/profile" || { echo "generated etc/profile is not valid sh" >&2; exit 1; }
echo "env:  wrote etc/profile (bash login) and etc/zshenv (zsh, always)"
echo "env:  sets SSL_CERT_FILE CURL_CA_BUNDLE OPENSSL_CONF PERL5LIB RUBYLIB"
echo "             SDKROOT, all from \$CRYPTEX_MOUNT_PATH; plus ZDOTDIR in"
echo "             etc/profile and module_path/fpath in etc/zshenv"
# MEASURED 2026-09-02: the cryptex's etc/ is NOT read.  It is not overlaid onto
# /, so /etc/profile and /etc/zshenv stay absent while /etc/hosts (iOS's own) is
# there, and /private/etc is read-only so nothing can be dropped in.  $HOME is
# writable, though, and both ~/.profile and ~/.zshenv are read, so the files are
# still exactly right -- they just have to be copied to the device once.  They
# are kept in the cryptex because that is where they are generated and stay
# current; see the copy step printed at the end of this script.
echo "env:  the cryptex's etc/ is NOT read on iOS (it is not overlaid onto /),"
echo "      so copy these to the device once -- see the end of this script"

# --- 8. check it before installing it ---------------------------------------
# An install cycle costs minutes and a reboot, and most of the mistakes this
# project has actually made are visible in the staged tree first: an install
# name that does not match what binaries ask for, a reference left pointing at
# an absolute macOS path, a bundled library with no fixups, an unsigned binary.
echo
(cd "$ROOT" && $PY -m cryptex.verify --cryptex "$C" --dylib-index "$INDEX" \
    -p "$PLATFORM" -v "$OSVER") || VERIFY_FAILED=1

# --- 8b. predict the symbol failures, on the Mac ----------------------------
# A missing SYMBOL used to be invisible until launch -- CLAUDE.md recorded it
# as the one gap static analysis could not close, and getting curl working cost
# four install-and-probe cycles, each revealing the symbol behind the one just
# fixed. symbol_check closes it: it reads the two-level-namespace ordinal of
# every bind the chained-fixups table actually performs and asks the iPhoneOS
# SDK stubs whether the target exports it.
#
# Validated against 423 real device launches: it flags 39 of the 39 binaries
# that died on a symbol, and 0 of the 384 that ran.
#
# machomorph now applies this DURING the batch and simply does not port a
# binary that cannot launch, so this step should report 0. It is kept as the
# check on that: a non-zero count means something reached the tree that the
# conversion gate should have caught.
echo
(cd "$ROOT" && $PY -m cryptex.symbols --all --cryptex "$C" \
    --dylib-index "$INDEX" $SYMARGS) > "$C/.symbol_check.txt" 2>&1 || true
echo "symbol_check: $(grep -c 'WILL FAIL' "$C/.symbol_check.txt") of $(ls "$C/bin" | wc -l) will fail at launch on a missing symbol"
echo "  full list: $C/.symbol_check.txt"

echo
echo "bin: $(ls "$C/bin" | wc -l)   lib: $(ls "$C/lib" | wc -l)   $(du -sh "$C" | cut -f1)"
if [ -n "${VERIFY_FAILED:-}" ]; then
    echo "verify_cryptex FAILED -- fix the above before installing" >&2
    exit 1
fi
echo "------------------------------------------------"
echo "now: srdtool cryptex install $C"
echo
echo "then, ONCE PER DEVICE (not per install -- both files find the cryptex"
echo "through \$CRYPTEX_MOUNT_PATH, so they survive every later reinstall):"
echo
echo "    SSH=\"ssh -p 2222 root@localhost\"    # via: iproxy 2222 22"
echo "    \$SSH 'cat > ~/.zshenv' < $C/etc/zshenv"
echo "    \$SSH 'cat > ~/.profile' < $C/etc/profile"
echo
echo "Without them every fresh shell starts with none of the variables the"
echo "ported tools need, which shows up as curl failing with error 77, perl"
echo "\"Can't locate POSIX.pm\", ruby \"cannot load such file -- rubygems\""
echo "and zsh \"failed to load module\".  ~/.zshenv is read on EVERY zsh"
echo "invocation including 'zsh -c'; ~/.profile on bash LOGIN shells."
echo "The cryptex cannot do this itself: it is not overlaid onto / and"
echo "/private/etc is read-only."
