#!/usr/bin/env bash
# Launch every ported binary in a cryptex and classify what happens.
#
# Runs ON THE DEVICE, under the cryptex's own bash -- iOS itself ships no shell
# and no coreutils (see ios_native_commands.txt: the whole of /bin and /usr/bin
# is daemons and a handful of diagnostics), so everything this script uses comes
# from the cryptex being tested.
#
# Get it there and run it with:
#
#     ssh root@DEVICE 'cat > /tmp/device_probe.sh' < device_probe.sh
#     ssh root@DEVICE '<cryptex>/bin/bash /tmp/device_probe.sh <cryptex>' \
#         > device_probe.tsv
#
# scp does not work: iOS has no sftp-server. Piping through `cat` does.
#
# Output is one TSV line per binary:
#
#     <name>  <outcome>  <detail>
#
# outcomes:
#   ok          ran and exited (any status -- a usage message is a pass here,
#               the question is whether it got as far as its own main())
#   blocked     still running at the timeout: a daemon or an interactive tool
#   dylib       failed to load: a library is missing
#   symbol      failed to load: a symbol is missing
#   killed      SIGKILL -- not covered by the trust cache, or entitlement denied
#   crash       died on a signal (SIGSEGV/SIGBUS/SIGTRAP): loaded, then faulted.
#               This is the interesting one for a lifted library -- it means the
#               binary got past dyld and then dereferenced something bad
#   skipped     on the denylist below, not run
#
# A binary that fails to load never reaches main(), so the load classification
# is trustworthy. A binary that loads and runs may still be useless; that needs
# a real invocation, not a bare launch.
set -u

CRYPTEX=${1:?usage: device_probe.sh <cryptex> [timeout] [start] [count]}
TIMEOUT=${2:-5}
# Probing a slice at a time, because the transport matters more than it should.
# With no ssh, the only channel is `srdtool research spawn`, and that daemon
# crashes every few minutes (launchd's KeepAlive brings it back). A single
# ten-minute foreground spawn is lost with it, and a detached one is killed when
# the spawn's process group goes away -- nohup included. So the driver walks
# slices and appends, and a crashed slice is just retried.
START=${3:-0}
COUNT=${4:-100000}
BIN=$CRYPTEX/bin

export PATH=$BIN:$CRYPTEX/sbin:/usr/bin:/bin:/usr/sbin:/sbin
export SSL_CERT_FILE=$CRYPTEX/share/ssl/cert.pem
export CURL_CA_BUNDLE=$SSL_CERT_FILE
export OPENSSL_CONF=$CRYPTEX/share/ssl/openssl.cnf
export PERL5LIB=$CRYPTEX/share/perl5:$CRYPTEX/share/perl5-extras
export MODULE_PATH=$CRYPTEX/share/zsh/5.9

# Never launch these. Three reasons, and all of them cost real time to learn:
#   - it changes power, disk or auth state (reboot, newfs_*, unsetpassword)
#   - it is a daemon that will sit there holding a port
#   - it waits on stdin forever, and a bare launch tells us nothing anyway
DENY='
reboot halt shutdown fastboot nvram bless
newfs_apfs newfs_exfat newfs_hfs newfs_msdos newfs_udf mkfile
diskutil fsck fsck_apfs fsck_exfat fsck_hfs fsck_msdos fsck_udf
mount umount mount_apfs mount_hfs mount_nfs mount_msdos mount_ftp mount_webdav
dd rm mv cp chflags chmod chown pax cpio tar ditto
passwd unsetpassword firmwarepasswd dsenableroot csrutil spctl
launchd launchctl sshd dropbear syslogd notifyd distnoted cfprefsd
bluetoothd wifid mDNSResponder racoon rtadvd pppd nfsd rpcbind
httpd postfix master sendmail smtpd snmpd snmptrapd named
vi vim view ex less more head tail sed awk ed
bash sh zsh ksh csh tcsh dash screen tmux script expect
ftp telnet nc socat ssh scp sftp slogin ssh-agent
python python3 perl ruby php tclsh wish node
top vm_stat fs_usage latency sc_usage nettop
su sudo login logout exit env printenv
yes seq sleep wait cat tee

# Added 2026-08-31, when the blocklist was retired and bin/ went 519 -> 841.
# The names above were enough for the blocklisted build; these came in with the
# other ~320 binaries and are all state-changers. Nothing here needs launching
# to be classified -- a tool that partitions a disk tells us nothing useful by
# printing its usage, and one bad argument is unrecoverable on a device that
# takes an hour to restore.
#   disk and volume layout
asr gpt fdisk pdisk newfs_fskit fsck_cs fsck_fskit apfs_unlockfv hdiutil
mount_9p mount_afp mount_devfs mount_fdesc mount_smbfs automount
#   kext loading
kextcache kextload kextunload kextutil
#   auth, config and system state
chpass vipw pwpolicy sysadminctl systemsetup networksetup profiles
softwareupdate scutil
#   process and power state
kill killall pkill purge screencapture
'

# The list above is written several names to a line for readability, so it has
# to be flattened before matching. The first version of this matched against
# "\n$1\n", which only ever hit a name that was alone on its line -- so the
# denylist silently never fired and the whole of it got launched, reboot and
# newfs_* included. Nothing came of it (they need arguments, and most fail to
# load on iOS anyway) but it was luck, not design. Match on whitespace.
DENY_FLAT=" $(printf '%s' "$DENY" | tr '\n' ' ') "
is_denied() {
    case "$DENY_FLAT" in *" $1 "*) return 0 ;; esac
    return 1
}

# Wait for a pid with a deadline. iOS has no timeout(1) and the cryptex's may
# not be trustworthy either, so do it by hand: poll, then SIGKILL.
run_with_timeout() {
    local out=$1; shift
    "$@" > "$out" 2>&1 &
    local pid=$!
    local i=0
    # 0.2s granularity: each tick is a fork of the ported sleep(1), and at 0.1s
    # over ~470 binaries that cost more than the probe itself.
    while [ "$i" -lt "$((TIMEOUT * 5))" ]; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
        i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        return 255          # our marker for "still running"
    fi
    wait "$pid"
    return $?
}

classify() {
    local rc=$1 out=$2
    if [ "$rc" = 255 ]; then echo "blocked"; return; fi
    # dyld writes its reason to stderr and the process dies on SIGABRT/SIGTRAP.
    if grep -q "Library not loaded\|image not found\|no cache image with name" "$out" 2>/dev/null
    then echo "dylib"; return; fi
    # Two spellings, and the second was filed as "crash" for a whole probe.
    # A two-level-namespace miss is reported at launch as
    #     Symbol not found: _foo
    # while a FLAT-namespace miss is reported at first use as
    #     symbol not found in flat namespace '_foo'
    # -- lowercase, different wording, and the process aborts (rc=134) instead
    # of failing to load. That put the whole postfix suite in the crash bucket
    # when what they are missing is libsasl2.
    if grep -qi "Symbol not found\|symbol not found in flat namespace" "$out" \
            2>/dev/null
    then echo "symbol"; return; fi
    case $rc in
        137) echo "killed" ;;                      # 128+9
        139|138|133|134) echo "crash" ;;           # SEGV/BUS/TRAP/ABRT
        *) echo "ok" ;;
    esac
}

TMP=/tmp/.probe.$$
trap 'rm -f "$TMP"' EXIT

idx=-1
for path in "$BIN"/*; do
    name=${path##*/}
    case $name in *.plist) continue ;; esac
    [ -f "$path" ] || continue
    idx=$((idx + 1))
    [ "$idx" -ge "$START" ] || continue
    [ "$idx" -lt "$((START + COUNT))" ] || break
    if is_denied "$name"; then
        printf '%s\tskipped\tdenylisted\n' "$name"
        continue
    fi
    printf 'probing %s\n' "$name" >&2
    run_with_timeout "$TMP" "$path"
    rc=$?
    outcome=$(classify "$rc" "$TMP")
    # One line of detail: the first thing it said that looks like a reason.
    detail=$(grep -m1 "Library not loaded\|Symbol not found\|Referenced from" \
                  "$TMP" 2>/dev/null | tr -d '\r' | cut -c1-160)
    [ -n "$detail" ] || detail="rc=$rc"
    printf '%s\t%s\t%s\n' "$name" "$outcome" "$detail"
done
