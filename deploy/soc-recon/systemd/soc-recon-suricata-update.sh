#!/bin/sh
# ******************************************************************************
# *Title: Suricata Rule Update*
# *Author: Kyle Versluis*
# *Description: Updates ET Open, reloads the sensor, and proves the swap.*
# ******************************************************************************
# Run as root by soc-recon-suricata-update.service. Every command inside the
# container runs as the engine's own unprivileged user.

set -eu

# *--- Configuration ---*

# SECURITY: root must not resolve its commands through a writable directory.
PATH=/usr/sbin:/usr/bin
export PATH

# The host lock is the only file this script creates, and only root may open it.
umask 077

# Fewer rules than this fails the run, checked on the staged file before it
# goes live and again on what the engine loaded. ET Open had 53,073 enabled on
# 2026-10-01, so the floor catches an empty or gutted ruleset, not normal drift.
MIN_RULES=${MIN_RULES:-40000}

RULES=/var/lib/suricata/rules

# Taken inside the container by the stage cleanup and by the build.
LOCK=/var/lib/suricata/.update.lock

# *--- Helpers ---*

# -p addresses the running project by name, so root never reads a compose file.
engine() {
    docker compose -p soc-recon exec -T --user suricata suricata "$@"
}

# suricatasc has no read timeout, and killing the docker CLI does not stop a
# process inside the container, so the limit has to run in there.
sc() {
    engine timeout -k 5 "$1" suricatasc -c "$2"
}

# The engine's console log since $1. Errors are "E: " lines on stderr.
engine_log() {
    timeout -k 2 10 docker compose -p soc-recon logs --no-color \
        --no-log-prefix --since "$1" suricata 2>&1
}

# Runs "$@" under the build lock, or fails at once with 75. A build orphaned by
# an interrupted run holds the lock until it ends.
locked() {
    lock_rc=0
    engine flock -n -E 75 "$LOCK" "$@" || lock_rc=$?
    if [ "$lock_rc" -eq 75 ]; then
        echo "another build holds the lock, nothing changed" >&2
    fi
    return "$lock_rc"
}

# Runs on every exit. Wazuh rule 40704 alerts on a failed unit only when the
# journal says status=1/FAILURE, so a timeout's 124 or a signal's 143 would
# fail in silence. Every failure leaves as exit 1.
stage=
finish() {
    rc=$?
    trap '' HUP INT QUIT TERM
    trap - EXIT
    if [ -n "$stage" ]; then
        # Host-side limit: the stage is scratch, and cleanup must not hang.
        if ! timeout -k 5 30 docker compose -p soc-recon exec -T --user suricata \
            suricata rm -rf "$stage"; then
            printf 'could not remove %s\n' "$stage" >&2
            # The next run clears the stage, but a docker call that fails here
            # is trouble worth the alert, even after a good update.
            if [ "$rc" -eq 0 ]; then
                echo "rules updated, but the run left its stage behind" >&2
                exit 1
            fi
        fi
    fi
    if [ "$rc" -ne 0 ]; then
        echo "rule update failed (exit $rc)" >&2
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
    echo "docker.service is not active, nothing ran" >&2
    exit 1
fi

# NOTE: /run, where only root can create files. A lock left in the sticky
# /run/lock by another user would refuse root (fs.protected_regular=2).
exec 9>/run/soc-recon-suricata-update.lock
if ! flock -n 9; then
    echo "another rule update is running" >&2
    exit 1
fi

# Clears stages left by earlier runs. Under the lock, so never one a build is
# still writing.
locked find /var/lib/suricata -maxdepth 1 -name '.stage.*' -exec rm -rf {} +

# *--- Update ---*

# The new rules are built in a stage on the same volume as the live ones, so
# the promote below is a rename. Until then the live rules are untouched, and
# a run killed at any point before it leaves them as they were.
dir=$(engine mktemp -d /var/lib/suricata/.stage.XXXXXX)
case $dir in
    /var/lib/suricata/.stage.??????) stage=$dir ;;
    *)
        echo "unexpected stage path from mktemp" >&2
        exit 1
        ;;
esac

# SECURITY: suricata-update unpacks an archive fetched from the internet.
# --fail: a failed download fails the run instead of silently rebuilding the
#   same rules from the cached archive.
# --no-reload: suricata-update logs a failed reload and still exits 0.
# --output: its `suricata -T` tests the staged file, which fails on any rule
#   the engine cannot parse. An empty stage never matches "No changes
#   detected", so every run is tested.
# oom_score_adj 1000: the build starts at the engine's -400. If the two outgrow
#   the cgroup, the kernel kills the build, not the engine.
locked sh -c 'echo 1000 >/proc/self/oom_score_adj && exec "$@"' \
    sh timeout -k 10 900 suricata-update --fail --no-reload --output "$stage"

# *--- Promote ---*

# Fail closed on anything but the two files suricata-update writes, rather
# than promote an output whose shape has changed. A feed that starts shipping
# datasets or Lua files stops here, and alerts, until the script promotes them.
# NOTE: the listing is captured on its own first. dash has no pipefail, so a
# find that failed inside the pipeline would hide behind tr's exit 0.
list=$(engine find "$stage" -mindepth 1 -maxdepth 1 -printf '%f\n')
files=$(printf '%s\n' "$list" | LC_ALL=C sort | tr '\n' ' ')
if [ "$files" != "classification.config suricata.rules " ]; then
    printf 'unexpected stage contents: %s\n' "$files" >&2
    exit 1
fi

# One rule per line, so the non-comment line count is what the engine will
# load. It matched rules_loaded exactly on 2026-10-02.
staged=$(engine grep -cv -e '^#' -e '^[[:space:]]*$' "$stage/suricata.rules") ||
    staged=0
if ! [ "$staged" -ge "$MIN_RULES" ]; then
    echo "only $staged rules staged, the floor is $MIN_RULES; live rules untouched" >&2
    exit 1
fi

# NOTE: classification.config stays in the stage. The engine and its -T both
# read /etc/suricata/classification.config, where an unknown classtype warns.
# NOTE: no rollback. The file passed `suricata -T`, which fails on any rule that
# does not parse, so a failure past here is the reload, not the rules.
engine mv -f "$stage/suricata.rules" "$RULES/suricata.rules"
echo "promoted $staged rules"

# *--- Reload ---*

# NOTE: reload-rules replies OK once the reload finishes, even when the new
# engine failed to build and the old one kept running. The engine's own reload
# time is the evidence that the swap happened.
before=$(sc 30 ruleset-reload-time | jq -er '.message[0].last_reload')
since=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
reply=$(sc 180 reload-rules)
printf '%s\n' "$reply"
if ! printf '%s' "$reply" | jq -e '.return == "OK"' >/dev/null; then
    echo "reload refused" >&2
    exit 1
fi
after=$(sc 30 ruleset-reload-time | jq -er '.message[0].last_reload')
if [ "$after" = "$before" ]; then
    printf 'reload replied OK but the engine did not swap: last_reload is still %s\n' \
        "$before" >&2
    exit 1
fi
printf 'engine swapped: last_reload %s -> %s\n' "$before" "$after"

# NOTE: a worker thread that fails to take the new engine logs an error, and
# the engine still logs "rule reload complete" and moves last_reload. Only the
# log tells the two apart. Matching the whole completion line also proves the
# log is in the default console format, the one where errors start "E: ".
waited=0
while :; do
    if ! log=$(engine_log "$since"); then
        printf '%s\n' "$log" >&2
        echo "could not read the engine log" >&2
        exit 1
    fi
    if printf '%s\n' "$log" | grep -qx 'i: detect: rule reload complete'; then
        break
    fi
    if [ "$waited" -ge 10 ]; then
        echo "no 'i: detect: rule reload complete' line in the engine log since $since" >&2
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
done
if printf '%s\n' "$log" | grep '^E: ' >&2; then
    echo "the engine logged errors during the reload" >&2
    exit 1
fi

# *--- Ruleset check ---*

stats=$(sc 30 ruleset-stats)
printf '%s\n' "$stats"
loaded=$(printf '%s' "$stats" | jq -er '.message[0].rules_loaded')
failed=$(printf '%s' "$stats" | jq -er '.message[0].rules_failed')
# NOTE: `! [ -ge ]` fails closed. A non-numeric value makes `[` error, which
# this form treats as a failure rather than a pass.
if ! [ "$loaded" -ge "$MIN_RULES" ]; then
    printf 'only %s rules loaded, the floor is %s\n' "$loaded" "$MIN_RULES" >&2
    exit 1
fi
if ! [ "$failed" -eq 0 ]; then
    printf '%s rules failed to load\n' "$failed" >&2
    exit 1
fi
echo "update complete: $loaded rules loaded"
