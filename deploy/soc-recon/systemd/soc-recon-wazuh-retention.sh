#!/bin/sh
# ******************************************************************************
# *Title: Wazuh Manager Log Retention*
# *Author: Kyle Versluis*
# *Description: Deletes dated manager logs past 14 days and proves it.*
# ******************************************************************************
# Run as root by soc-recon-wazuh-retention.service (runbook 08). The manager
# rotates alerts and archives into dated files every night and never deletes
# them. The indexer keeps 45 days through its ISM policy, so the files on disk
# are a short replay buffer, not the record.
#
# Usage: soc-recon-wazuh-retention.sh [--dry-run]

set -eu

# *--- Configuration ---*

# SECURITY: root must not resolve its commands through a writable directory.
PATH=/usr/sbin:/usr/bin
export PATH

# NOTE: compose 5.6 ignores the working directory's compose file and .env for
# `-p ... exec`: a broken file and a failing ${VAR:?} both ran clean on
# 2026-10-13. Other versions or subcommands may not, so a hand run from the
# checkout starts in / like the unit does.
cd /

# The lock is the only file this script creates, and only root may open it.
umask 077

# A dated file goes once its last write is more than this many days old.
KEEP_DAYS=14

# Overrides for the scratch-stack tests only. The unit sets none of them.
PROJECT=${RETENTION_PROJECT:-soc-recon}
DOCKER_UNIT=${RETENTION_DOCKER_UNIT:-docker.service}
LOCK=${RETENTION_LOCK:-/run/soc-recon-wazuh-retention.lock}

LOGS=/var/ossec/logs

# The nightly names only, each in its own tree:
# alerts/<yyyy>/<Mon>/ossec-alerts-<dd> and archives/<yyyy>/<Mon>/ossec-archive-<dd>,
# plain, .gz or .sum. The pattern also rules out whitespace, so the listings
# below are safe to read by line.
NAMES="$LOGS/(alerts/[0-9]{4}/[A-Z][a-z]{2}/ossec-alerts|archives/[0-9]{4}/[A-Z][a-z]{2}/ossec-archive)-[0-9]{2}\.(json|log)(\.gz|\.sum)?"

# *--- Helpers ---*

# -p addresses the running project by name, so root never reads a compose file.
manager() {
    docker compose -p "$PROJECT" exec -T wazuh.manager "$@"
}

# Dated files, then any further find tests and actions. docker exec does not
# forward signals, so the time limit has to run inside the container.
# NOTE: -P (the default) never follows a link, and -type f skips them.
dated() {
    manager timeout -k 5 120 find "$LOGS/alerts" "$LOGS/archives" \
        -mindepth 3 -maxdepth 3 -type f \
        -regextype posix-extended -regex "$NAMES" "$@"
}

# The files a run may delete. -links 1 skips today's file, which is still
# hard-linked as alerts.json; the cutoff is fixed once, so the listing, the
# delete and the proof all judge the same moment.
expired() {
    dated -links 1 ! -newermt "@$cut" "$@"
}

# Old ossec-* files at the dated depth that the pattern does not know. They are
# kept and counted on every run, so a naming change in a manager upgrade shows
# up as a number that grows, not a disk that fills in silence.
strays() {
    manager timeout -k 5 120 find "$LOGS/alerts" "$LOGS/archives" \
        -mindepth 3 -maxdepth 3 -type f -name 'ossec-*' ! -newermt "@$cut" \
        -regextype posix-extended ! -regex "$NAMES" -printf .
}

# Runs on every exit. Wazuh rule 40704 alerts on a failed unit only when the
# journal says status=1/FAILURE, so a timeout's 124 or a signal's 143 would
# fail in silence. Every failure leaves as exit 1.
finish() {
    rc=$?
    trap '' HUP INT QUIT TERM
    trap - EXIT
    if [ "$rc" -ne 0 ]; then
        echo "log retention failed (exit $rc)" >&2
        exit 1
    fi
}
trap finish EXIT
# NOTE: dash dies of an untrapped signal without running the EXIT trap, so each
# signal systemd or an operator is likely to send gets its own. SIGKILL cannot.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

# *--- Preflight ---*

dry=
if [ "$#" -gt 1 ]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 1
fi
case "${1-}" in
    '') ;;
    --dry-run) dry=1 ;;
    *)
        echo "usage: $0 [--dry-run]" >&2
        exit 1
        ;;
esac

# SECURITY: a delete on the live project runs as root, from the unit or a sudo
# hand run. Anyone else reaching docker here is a test that lost its override:
# on 2026-10-13 a scratch suite that set the lock but not the project ran its
# first delete against the live manager as the docker-group user.
# NOTE: the uid is captured on its own line, so a failed id stops the run under
# set -e, and compared as a string, so an empty one is refused, not let through.
uid=$(id -u)
if [ -z "$dry" ] && [ "$PROJECT" = soc-recon ] && [ "$uid" != 0 ]; then
    echo "a delete on the live project needs root, nothing deleted" >&2
    exit 1
fi

# Any docker command would socket-activate a daemon stopped on purpose. Checked
# here because Requisite= skips the run without the status=1/FAILURE line.
if ! systemctl is-active --quiet "$DOCKER_UNIT"; then
    echo "$DOCKER_UNIT is not active, nothing deleted" >&2
    exit 1
fi

# NOTE: /run, where only root can create files. A lock left in the sticky
# /run/lock by another user would refuse root (fs.protected_regular=2).
exec 9>"$LOCK"
if ! flock -n 9; then
    echo "another retention run holds the lock, nothing deleted" >&2
    exit 1
fi

# The cutoff is only as right as the clock. A host that booted days ahead would
# see young files as expired, and the proof, reading the same clock, would pass.
# A dry run only reports, so it skips this.
if [ -z "$dry" ]; then
    synced=$(timedatectl show -p NTPSynchronized --value)
    if [ "$synced" != yes ]; then
        echo "the clock is not NTP-synchronized, nothing deleted" >&2
        exit 1
    fi
fi

cut=$(($(date +%s) - KEEP_DAYS * 86400))

# NOTE: each listing is captured on its own. dash has no pipefail, so a docker
# call that failed inside a pipeline would hide behind the next command.
old=$(expired -printf '%s %p\n')
young=$(dated -newermt "@$cut" -printf '%p\n')
unknown=$(strays)
# Printed before anything can fail, so every run that got this far reports it.
echo "${#unknown} older ossec-* files match no known name and stay"

# Bytes and file counts per month, from "<bytes> <path>" lines. awk's output is
# captured on its own first, so its exit status is checked, not sort's.
summary() {
    table=$(printf '%s\n' "$1" | awk -v logs="$LOGS/" '
        NF == 2 {
            path = substr($2, length(logs) + 1)
            split(path, p, "/")
            key = p[1] "/" p[2] "/" p[3]
            n[key]++; b[key] += $1; tn++; tb += $1
        }
        END {
            for (k in n) printf "  %s  %d files  %d bytes\n", k, n[k], b[k]
            printf "  total  %d files  %d bytes\n", tn, tb
        }')
    printf '%s\n' "$table" | sort
}

if [ -n "$dry" ]; then
    echo "dry run: would delete these dated files, last written $KEEP_DAYS or more days ago"
    summary "$old"
    echo "would keep $(printf '%s\n' "$young" | grep -c .) newer dated files"
    exit 0
fi

# *--- Delete ---*

# SECURITY: root inside the container, where the logs belong to the wazuh user.
# find's -delete removes each entry relative to its open directory, so a
# directory swapped for a link mid-run cannot steer it outside the tree.
# -printf after -delete prints only what was actually unlinked, so the record is
# of the delete, not of the listing, even when it fails partway.
if ! gone=$(expired -delete -printf '%s %p\n'); then
    echo "the delete failed partway; what it removed before failing:" >&2
    summary "$gone" >&2
    exit 1
fi

# *--- Proof ---*

left=$(expired -printf '%p\n')
if [ -n "$left" ]; then
    echo "$(printf '%s\n' "$left" | grep -c .) expired dated files remain after the delete" >&2
    exit 1
fi

# Every file younger than the cutoff before the run is still there.
now=$(dated -printf '%p\n')
missing=$({
    printf '%s\n' "$now" | sed 's/^/A /'
    printf '%s\n' "$young" | sed 's/^/Y /'
} | awk '$1 == "A" { a[$2] = 1; next } $2 != "" && !($2 in a) { m++ } END { print m + 0 }')
# NOTE: a string compare, so a value that is not a number fails the proof
# instead of erroring past it.
if [ "$missing" != 0 ]; then
    echo "$missing dated files younger than $KEEP_DAYS days went missing" >&2
    exit 1
fi

# The live file filebeat reads is still a regular file, not a link.
# shellcheck disable=SC2016 # expands in the container's shell, not here
if ! manager sh -c 'test -f "$1" && ! test -L "$1"' sh "$LOGS/alerts/alerts.json"; then
    echo "alerts.json is missing or not a regular file after the run" >&2
    exit 1
fi

echo "deleted dated files last written $KEEP_DAYS or more days ago:"
summary "$gone"
echo "kept $(printf '%s\n' "$now" | grep -c .) newer dated files; alerts.json in place"
