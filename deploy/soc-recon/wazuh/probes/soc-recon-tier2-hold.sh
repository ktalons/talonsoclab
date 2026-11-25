#!/bin/bash
# ******************************************************************************
# *Title: soc-recon Tier 2 Hold Probe*
# *Author: Kyle Versluis*
# *Description: Reports a Tier 2 backup hold left in place too long.*
# ******************************************************************************
# Run daily as root by the manager's logcollector (full_command, runbook 09).
# The Tier 2 backup writes the hold marker while it holds config installs and
# removes it when it is done, a few minutes later. A marker left behind means
# every restart of the manager leaves its config uninstalled, silently. The
# probe reads it, writes nothing, and prints one line for rules 100322 and
# 100323 to grade:
#   OK hold=none               no marker
#   OK hold=<d>d<hh>h          a marker at most one hour old (0d00h or 0d01h)
#   STUCK hold=<d>d<hh>h       a marker over one hour old
#   ERROR <reason>
# It never prints the marker's content.

# *--- Configuration ---*

# SECURITY: root must not resolve its commands through a writable directory.
PATH=/usr/sbin:/usr/bin
export PATH
export LC_ALL=C

# The deploy dir's state/tier2, bound read-only. A directory bind, because the
# marker comes and goes and a single-file bind would keep a stale inode.
DIR=/srv/tier2
MARKER=$DIR/HOLD

# A hold normally lasts minutes. Past an hour it alerts at level 10.
HOLD_MAX=3600

# A marker dated further ahead of the clock than this is an error, not a pass:
# a wrong clock would otherwise keep an old hold looking fresh.
SKEW=300

# The whole run gets one limit, so a hung file system cannot hold logcollector.
DEADLINE=8

# The marker is exactly "hold <epoch>" and a newline: 5 + 10 + 1 bytes.
# NOTE: a ten-digit epoch holds until 2286.
MARKER_SIZE=16

# *--- Deadline ---*

# The run starts again under timeout, which signals its whole process group, so
# no reader outlives the limit. Run the probe by its path: $0 is how it finds
# itself, and from stdin it can only say ERROR.
if [ "${1-}" != --run ]; then
    out=$(timeout -k 1 "$DEADLINE" bash -- "$0" --run)
    rc=$?
    if [ "$rc" -eq 0 ] && [ -n "$out" ]; then
        printf '%s\n' "$out"
    elif [ "$rc" -eq 124 ]; then
        printf 'ERROR the probe ran past %d s\n' "$DEADLINE"
    elif [ "$rc" -eq 137 ]; then
        # SIGKILL: timeout's follow-up, or the kernel's OOM killer.
        printf 'ERROR the probe ran past %d s, or was killed\n' "$DEADLINE"
    else
        printf 'ERROR the probe stopped before reporting\n'
    fi
    exit 0
fi

# *--- Output ---*

# One line on stdout is the whole interface. logcollector does not read stderr.
reported=
report() {
    printf '%s\n' "$1"
    reported=1
    exit 0
}

fail() {
    report "ERROR $1"
}

# A crash before the report still prints a line, so rule 100323 sees it.
trap '[ -n "$reported" ] || printf "ERROR the probe stopped before reporting\n"' EXIT

days() {
    printf '%dd%02dh' $(($1 / 86400)) $(($1 % 86400 / 3600))
}

isnum() {
    case $1 in
        '' | *[!0-9]*) return 1 ;;
    esac
}

# *--- Preflight ---*

now=$(date +%s) || fail "cannot read the clock"
isnum "$now" || fail "cannot read the clock"

# SECURITY: a link here would point root at files outside the bind. The live
# path is the mount point of a plain directory.
if [ -L "$DIR" ]; then
    fail "$DIR is a link"
fi
# NOTE: a missing bind is an error, not "no hold". The directory ships in git,
# so a manager without it was started from the wrong compose file.
if ! [ -d "$DIR" ] || ! [ -r "$DIR" ] || ! [ -x "$DIR" ]; then
    fail "cannot read $DIR"
fi

# *--- Marker ---*

# SECURITY: a link, dangling or not, is an error and never "no hold". The
# init treats any entry of this name as a hold, so the probe must not call
# one fine.
if [ -L "$MARKER" ]; then
    fail "the marker is a link"
fi
if ! [ -e "$MARKER" ]; then
    report "OK hold=none"
fi
# NOTE: this also keeps a pipe from blocking the read below.
if ! [ -f "$MARKER" ]; then
    fail "the marker is not a regular file"
fi
if ! [ -r "$MARKER" ]; then
    fail "cannot read the marker"
fi

# NOTE: one byte more than the marker is read, so a longer file shows as
# longer without a size call and without reading all of it. Checked as hex,
# every byte as it is: bash drops NUL bytes, the substitution drops trailing
# newlines, and any mapping of them onto printable bytes collides with those
# bytes. "hold " (68 6f 6c 64 20), ten digits (30..39), then the newline (0a)
# as the 16th byte, and nothing after it.
hex=$(
    set -o pipefail
    head -c $((MARKER_SIZE + 1)) -- "$MARKER" 2>/dev/null | od -An -v -tx1 | tr -d ' \n'
) || fail "cannot read the marker"
if ! [[ $hex =~ ^686f6c6420((3[0-9]){10})0a$ ]]; then
    fail "the marker is not one hold line"
fi
digits=
for ((i = 1; i < 20; i += 2)); do
    digits+=${BASH_REMATCH[1]:i:1}
done
# NOTE: base 10 forced, so a leading zero reads as a very old time, not octal.
epoch=$((10#$digits))

# *--- Report ---*

if [ "$epoch" -gt $((now + SKEW)) ]; then
    fail "the marker is dated after the clock"
fi
age=$((now - epoch))
[ "$age" -ge 0 ] || age=0

if [ "$age" -gt "$HOLD_MAX" ]; then
    report "STUCK hold=$(days "$age")"
fi
report "OK hold=$(days "$age")"
