#!/bin/sh
# ******************************************************************************
# *Title: Suricata Log Rotation*
# *Author: Kyle Versluis*
# *Description: Rotates the sensor logs and proves eve.json was reopened.*
# ******************************************************************************
# Run as root by soc-recon-suricata-logrotate.service. The image ships
# /etc/logrotate.d/suricata, but nothing inside a container ever runs it
# (runbook 06, section 6).

set -eu

# *--- Configuration ---*

# SECURITY: root must not resolve its commands through a writable directory.
PATH=/usr/sbin:/usr/bin
export PATH

# Host side of the bind mount the Wazuh agent tails.
EVE=/var/log/suricata/eve.json

# *--- Helpers ---*

# -p addresses the running project by name, so root never reads a compose file.
sensor() {
    docker compose -p soc-recon exec -T "$@"
}

inode() {
    stat -c %i "$1" 2>/dev/null || echo none
}

# Runs on every exit. Wazuh rule 40704 alerts on a failed unit only when the
# journal says status=1/FAILURE, so a timeout's 124 or a signal's 143 would
# fail in silence. Every failure leaves as exit 1.
rotating=
finish() {
    rc=$?
    trap '' HUP INT QUIT TERM
    trap - EXIT
    if [ "$rc" -ne 0 ]; then
        # A run stopped between the rename and the reopen leaves the engine
        # writing to eve.json.1 while the agent waits for an eve.json that
        # never comes. SIGHUP reopens the logs through the engine's main loop,
        # a path that does not need the socket the postrotate step uses.
        if [ -n "$rotating" ] && ! [ -e "$EVE" ]; then
            # WARN: signal from inside. `docker kill` on a container whose
            # image sets no STOPSIGNAL cancels its restart policy, HUP or not.
            if timeout -k 5 30 docker compose -p soc-recon exec -T suricata \
                sh -c 'kill -s HUP 1'; then
                echo "eve.json missing: sent SIGHUP, the engine reopens it on its next write" >&2
            else
                echo "eve.json missing and SIGHUP failed: the agent is reading nothing" >&2
            fi
        fi
        echo "log rotation failed (exit $rc)" >&2
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

# Any docker command would socket-activate a daemon stopped on purpose. Checked
# here because Requisite= skips the run without the status=1/FAILURE line.
if ! systemctl is-active --quiet docker.service; then
    echo "docker.service is not active, nothing rotated" >&2
    exit 1
fi

# Fail before any rename when the engine is down. logrotate renames first and
# reopens second, so a dead engine would leave the agent tailing a dead file.
# NOTE: the reply is captured on its own first. dash has no pipefail, so a
# docker call that failed inside the pipeline would hide behind jq's status.
if ! up=$(sensor --user suricata suricata timeout -k 5 30 suricatasc -c uptime) ||
    ! printf '%s' "$up" | jq -e '.return == "OK"' >/dev/null; then
    echo "engine not answering, nothing rotated" >&2
    exit 1
fi
old=$(inode "$EVE")

# *--- Rotate ---*

# NOTE: -f because logrotate's state file lives in the container's writable
# layer and every recreate loses it. On a run with no state, logrotate 3.18
# records the log and rotates nothing. So this timer is the only schedule, and
# every run is a rotation.
# SECURITY: root inside the container, because the image's policy file is
# readable only by root. The policy has no `create`, so root only renames and
# deletes, and neither follows a link the engine user could plant.
# NOTE: the repair runs in here as well as in the trap. docker exec does not
# forward signals, so a run stopped before the rename leaves logrotate to rename
# after the trap has looked. This shell outlives the run, and when logrotate
# fails it sends SIGHUP itself if eve.json is gone.
rotating=1
# shellcheck disable=SC2016 # expands in the container's shell, not here
sensor suricata sh -c '
    timeout -k 10 120 logrotate -f /etc/logrotate.d/suricata && exit 0
    rc=$?
    [ -e /var/log/suricata/eve.json ] || kill -s HUP 1
    exit "$rc"'

# *--- Proof ---*

# No eve.json before the run means a fresh sensor, or an earlier run whose
# reopen never came. Only the new-file check applies then.
if [ "$old" != none ]; then
    moved=$(inode "$EVE.1")
    if [ "$moved" != "$old" ]; then
        echo "eve.json was not rotated: eve.json.1 is inode $moved, expected $old" >&2
        exit 1
    fi
fi

# The postrotate reopen replies OK whether or not anything reopened, so the
# proof is on disk where the agent reads it: a new, non-empty eve.json. The
# sensor wrote eve.json in each of 600 sampled seconds on 2026-10-02, so a
# quiet two minutes means trouble, not a quiet network.
# SECURITY: a regular file, not a link. stat reads a link and `[ -s ]` its
# target, so a link the engine user planted would pass as a new eve.json.
waited=0
until [ -f "$EVE" ] && ! [ -L "$EVE" ] && [ -s "$EVE" ] &&
    [ "$(inode "$EVE")" != "$old" ]; do
    if [ "$waited" -ge 120 ]; then
        echo "no new eve.json within 120 s of the rotation" >&2
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
done
echo "rotated: eve.json.1 holds inode $old, the new eve.json is inode $(inode "$EVE")"
