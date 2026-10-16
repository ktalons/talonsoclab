#!/bin/bash
# ******************************************************************************
# *Title: soc-recon Job Age Probe*
# *Author: Kyle Versluis*
# *Description: Reports how long ago each soc-recon job last succeeded.*
# ******************************************************************************
# Run hourly as root by the manager's logcollector (full_command, runbook 06,
# section 6). It reads the manager's own alert files and dated log tree, writes
# nothing, and prints one line for rules 100310 and 100311 to grade:
#   OK rotation=<h>h<mm>m update=... retention=... oldest_dated=<d>d<hh>h
#   STALE <the same fields> stale=<job>[,<job>...][,dated]
#   ERROR <reason>
# <job>=none means no success alert in the files that can hold the window, and
# oldest_dated=none no dated file at all. Both are STALE.

# *--- Configuration ---*

# SECURITY: root must not resolve its commands through a writable directory.
PATH=/usr/sbin:/usr/bin
export PATH
export LC_ALL=C

LOGS=/var/ossec/logs
ALERTS=$LOGS/alerts/alerts.json

# A daily job is stale 26 h after its last success, about 2 h after one missed
# run. D1 keeps 14 days, so a dated file past 16 days means it missed about two
# runs, or the file has a name D1 does not delete.
JOB_MAX=$((26 * 3600))
DATED_MAX=$((16 * 86400))

# A success dated further ahead of the clock than this is an error, not a pass:
# a wrong clock would otherwise keep a dead job looking fresh.
SKEW=300

# The whole run gets one limit, so a hung file system cannot hold logcollector.
DEADLINE=8

# Success rule ids, in the order the line reports the jobs.
JOBS=(rotation update retention)
declare -A RULE=([rotation]=100300 [update]=100301 [retention]=100302)

# Only the manager's own names are read for alerts. A renamed file is skipped,
# its successes go missing, and the line says STALE.
DATED_JSON="$LOGS/alerts/[0-9]{4}/[A-Z][a-z]{2}/ossec-alerts-[0-9]{2}\.json(\.gz)?"

# The SOC box's agent. Only its journald lines count as a job's success. A box
# enrolled again gets a new id, and every job reads none until this follows.
AGENT=002

# An alert line starts with its timestamp and its rule block, in that order. The
# anchor keeps a rule id quoted inside another alert's full_log from counting.
# Prints "<rule id> <epoch>" for each job's newest success, "CUT" when a success
# alert does not end as every alert does, or "BAD" when a time in it does not
# parse.
# NOTE: a last line with no newline is skipped, not CUT. The manager may still
# be writing it, and the next run reads it whole.
# shellcheck disable=SC2016 # gawk program, not shell
SCAN='
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M)
    for (i = 1; i <= 12; i++) mon[M[i]] = i
    # The program each success rule names, as local_job_age.xml does.
    prog["100300"] = "soc-recon-suricata-logrotate.sh"
    prog["100301"] = "soc-recon-suricata-update.sh"
    prog["100302"] = "soc-recon-wazuh-retention.sh"
}
index($0, "\"id\":\"10030") &&
match($0, /^\{"timestamp":"([^"]*)","rule":\{"level":[0-9]+,"description":"[^"]*","id":"(10030[012])",/, m) {
    if ($0 !~ /,"location":"[^"]*"[}]$/) {
        if (RT == "") next
        print "CUT"; next
    }
    # A success line from another agent or input still alerts, but never makes
    # a job here look fresh. Quotes inside a string are escaped, so this text
    # can only be the agent of the alert itself.
    if (!index($0, ",\"agent\":{\"id\":\"" agent "\",") || $0 !~ /,"location":"journald"[}]$/) next
    t = m[1]
    if (t !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?[+-][0-9]{4}$/) {
        print "BAD"; next
    }
    # mktime rolls Apr 31 into May 1, so the time must print back unchanged.
    f = substr(t, 1, 19)
    g = f
    gsub(/[-T:]/, " ", g)
    e = mktime(g, 1)
    if (e < 0 || strftime("%Y-%m-%dT%H:%M:%S", e, 1) != f) { print "BAD"; next }
    z = substr(t, length(t) - 4)
    zh = substr(z, 2, 2) + 0; zm = substr(z, 4, 2) + 0
    if (zh * 60 + zm > 840 || zm > 59) { print "BAD"; next }
    e -= (zh * 3600 + zm * 60) * (substr(z, 1, 1) == "-" ? -1 : 1)
    # The age runs from the journal time of the job line, not from when the
    # manager got it, so a line the agent sends again later still reads old.
    # The journal writes no year: take the year of the alert, or the one before
    # when that lands after the line arrived.
    if (!match($0, /,"predecoder":\{"program_name":"[^"]*","timestamp":"([A-Z][a-z]{2}) ([0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})"/, p) || !(p[1] in mon)) {
        print "BAD"; next
    }
    j = p[1] " " p[2] " " p[3]
    # Both copies of the time, and the job behind the rule id, must agree, so one
    # damaged field can neither move a success nor hand it to another job.
    if (!index($0, ",\"predecoder\":{\"program_name\":\"" prog[m[2]] "\",") || !index($0, ",\"full_log\":\"" j " ")) {
        print "BAD"; next
    }
    hms = p[3]
    gsub(/:/, " ", hms)
    y = substr(t, 1, 4)
    ev = mktime(y " " mon[p[1]] " " p[2] " " hms, 1)
    if (ev > e + 300) ev = mktime((y - 1) " " mon[p[1]] " " p[2] " " hms, 1)
    if (ev < 0 || ev > e + 300 || strftime("%b %d %H:%M:%S", ev, 1) != j) { print "BAD"; next }
    if (!(m[2] in best) || ev > best[m[2]]) best[m[2]] = ev
}
END { for (id in best) print id, best[id] }'

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

# A crash before the report still prints a line, so rule 100311 sees it.
trap '[ -n "$reported" ] || printf "ERROR the probe stopped before reporting\n"' EXIT

# Seconds as <h>h<mm>m, or <d>d<hh>h for the dated tree.
hours() {
    printf '%dh%02dm' $(($1 / 3600)) $(($1 % 3600 / 60))
}

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

# SECURITY: a tree that is a link would point root at files outside the logs.
# The live trees are plain directories in the logs volume.
for d in "$LOGS/alerts" "$LOGS/archives"; do
    if [ -L "$d" ]; then
        fail "$d is a link"
    fi
done
if ! [ -d "$LOGS/alerts" ] || ! [ -r "$LOGS/alerts" ] || ! [ -x "$LOGS/alerts" ]; then
    fail "cannot read $LOGS/alerts"
fi
# NOTE: not left to the reads below. Without alerts.json, today's dated name
# drops to one link and is read as a dated file, so the reads alone would pass
# while filebeat has nothing to ship.
if ! [ -f "$ALERTS" ] || ! [ -r "$ALERTS" ]; then
    fail "cannot read $ALERTS"
fi
# SECURITY: a link here would point root at any file, and at successes that are
# not the manager's. The live file is a regular file with two names.
if [ -L "$ALERTS" ]; then
    fail "$ALERTS is a link"
fi

# *--- Job successes ---*

# A file is last written after every alert in it, so a dated file last written
# before the window opened holds no alert from inside it. -links 1 skips
# today's dated name, a hard link to alerts.json.
start=$((now - JOB_MAX))
if ! dated=$(find "$LOGS/alerts" -mindepth 3 -maxdepth 3 \
    -type f -links 1 -newermt "@$start" \
    -regextype posix-extended -regex "$DATED_JSON" -print); then
    fail "cannot list $LOGS/alerts"
fi

declare -A best=()
while IFS= read -r f; do
    [ -n "$f" ] || continue
    # NOTE: zcat without -f, so a .gz that is not gzip fails instead of being
    # read as plain text that matches nothing.
    case $f in
        *.gz) reader='zcat' ;;
        *) reader='cat' ;;
    esac
    if ! found=$(set -o pipefail
        "$reader" -- "$f" | gawk -v agent="$AGENT" "$SCAN"); then
        fail "cannot read $f"
    fi
    while read -r id epoch; do
        [ -n "$id" ] || continue
        [ "$id" != CUT ] || fail "a success alert in $f is cut short"
        # A BAD line carries no epoch, so this check catches it too.
        isnum "$epoch" || fail "a success alert in $f has a timestamp that does not parse"
        if [ -z "${best[$id]-}" ] || [ "$epoch" -gt "${best[$id]}" ]; then
            best[$id]=$epoch
        fi
    done <<<"$found"
done <<<"$ALERTS
$dated"

# *--- Dated tree ---*

# Every regular file below the top of each tree, whatever its name. A file D1
# does not know by name is never deleted, and its age is what gives that away.
# NOTE: neither tree is a link (checked above), and -type f skips any link
# inside one. Prints the oldest and the newest mtime: a file dated ahead of the
# clock is one D1 never deletes, and the oldest alone would never show it.
if ! span=$(set -o pipefail
    find "$LOGS/alerts" "$LOGS/archives" -mindepth 2 -type f \
        -printf '%T@\n' |
        gawk 'NR == 1 || $1 < min { min = $1 } NR == 1 || $1 > max { max = $1 }
            END { if (NR) printf "%d %d\n", min, max }'); then
    fail "cannot list the dated tree under $LOGS"
fi
oldest=${span% *}
newest=${span#* }

# *--- Report ---*

fields=
stale=
for job in "${JOBS[@]}"; do
    epoch=${best[${RULE[$job]}]-}
    if [ -z "$epoch" ]; then
        fields="$fields $job=none"
        stale="$stale,$job"
        continue
    fi
    if [ "$epoch" -gt $((now + SKEW)) ]; then
        fail "the newest $job success is dated after the clock"
    fi
    age=$((now - epoch))
    [ "$age" -ge 0 ] || age=0
    fields="$fields $job=$(hours "$age")"
    [ "$age" -ge "$JOB_MAX" ] && stale="$stale,$job"
done

if [ -z "$oldest" ]; then
    # NOTE: never right on a live manager. Today's dated name is a hard link to
    # alerts.json, so no dated file means the manager stopped writing them.
    fields="$fields oldest_dated=none"
    stale="$stale,dated"
else
    # NOTE: an mtime before 1970 prints negative, and is simply very old.
    if ! [[ $oldest =~ ^-?[0-9]+$ ]] || ! [[ $newest =~ ^-?[0-9]+$ ]]; then
        fail "the dated tree has an mtime that does not parse"
    fi
    if [ "$newest" -gt $((now + SKEW)) ]; then
        fail "a file in the dated tree is dated after the clock"
    fi
    age=$((now - oldest))
    [ "$age" -ge 0 ] || age=0
    fields="$fields oldest_dated=$(days "$age")"
    [ "$age" -gt "$DATED_MAX" ] && stale="$stale,dated"
fi

if [ -n "$stale" ]; then
    report "STALE${fields} stale=${stale#,}"
fi
report "OK${fields}"
