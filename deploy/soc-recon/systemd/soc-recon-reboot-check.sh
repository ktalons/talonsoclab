#!/bin/sh
# ******************************************************************************
# *Title: soc-recon Reboot Check*
# *Author: Kyle Versluis*
# *Description: Reports whether the SOC box is waiting on a reboot.*
# ******************************************************************************
# Run daily as root by soc-recon-reboot-check.service (runbook 00, section 5).
# unattended-upgrades installs kernels and libraries but never reboots the box
# (Automatic-Reboot stays off, S0.7), so this turns a pending reboot into an
# alert instead of a silent state. It reads two signals and writes nothing:
#   - /run/reboot-required, which update-notifier-common's hooks create
#   - the running kernel against the newest /boot/vmlinuz-*, which still holds
#     if that package is ever removed
# Its last line, on exit 0, is one of:
#   no reboot required: running=<release>
#   reboot required: running=<release> newest=<release> flag=<yes|no> pkgs=<list>
# Rules 100330 and 100331 grade it.

set -eu

# *--- Configuration ---*

# SECURITY: root must not resolve its commands through a writable directory.
PATH=/usr/sbin:/usr/bin
export PATH
export LC_ALL=C

# The overrides exist for the tests. The unit unsets them.
RUN_DIR=${REBOOT_CHECK_RUN:-/run}
BOOT_DIR=${REBOOT_CHECK_BOOT:-/boot}

# A longer package list is cut here, so one big upgrade cannot make a line
# the agent splits.
MAX_PKGS=20

# *--- Helpers ---*

# Runs on every exit. Wazuh rule 40704 alerts on a failed unit only when the
# journal says status=1/FAILURE, so every failure leaves as exit 1.
finish() {
    rc=$?
    trap '' HUP INT QUIT TERM
    trap - EXIT
    set +e
    if [ "$rc" -ne 0 ]; then
        echo "reboot check failed (exit $rc)" >&2
        exit 1
    fi
}
trap finish EXIT
# NOTE: dash dies of an untrapped signal without running the EXIT trap.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

# Keeps only the characters a kernel release or a dpkg name can hold, so
# nothing read from disk can shape the line the rules grade.
clean() {
    tr -cd 'A-Za-z0-9.+_~:-'
}

# *--- Checks ---*

running=${REBOOT_CHECK_RUNNING:-$(uname -r)}
running=$(printf '%s' "$running" | clean)
[ -n "$running" ] || { echo "no running kernel release" >&2; exit 1; }

# Newest installed kernel by version order, not by name order: -9 sorts after
# -38 by name.
newest=$(
    for f in "$BOOT_DIR"/vmlinuz-*; do
        [ -f "$f" ] || continue
        printf '%s\n' "${f##*/vmlinuz-}"
    done | sort -V | tail -n 1 | clean
)
[ -n "$newest" ] || { echo "no kernel found in $BOOT_DIR" >&2; exit 1; }

flag=no
if [ -e "$RUN_DIR/reboot-required" ]; then
    flag=yes
fi

# One name per line, split on anything a dpkg name cannot hold.
pkgs=none
if [ -r "$RUN_DIR/reboot-required.pkgs" ]; then
    list=$(tr -cs 'A-Za-z0-9.+_~:-' '\n' <"$RUN_DIR/reboot-required.pkgs" |
        sed '/^$/d' | sort -u)
    if [ -n "$list" ]; then
        count=$(printf '%s\n' "$list" | wc -l)
        pkgs=$(printf '%s\n' "$list" | head -n "$MAX_PKGS" | paste -sd, -)
        [ "$count" -le "$MAX_PKGS" ] || pkgs="$pkgs,+$((count - MAX_PKGS))more"
    fi
fi

if [ "$flag" = no ] && [ "$newest" = "$running" ]; then
    echo "no reboot required: running=$running"
else
    echo "reboot required: running=$running newest=$newest flag=$flag pkgs=$pkgs"
fi
