#!/usr/bin/env bash
# ******************************************************************************
# *Title: tier2-backup*
# *Author: Kyle Versluis*
# *Description: Takes, copies and verifies a Tier 2 backup, then marks it.*
# ******************************************************************************
# Run on the Mac (runbook 09). It runs tier2-snapshot on the box, copies the
# encrypted archives to MacbookXD, proves each one decrypts and lists, compares
# the backed-up config with the live manager's, and only then writes the marker
# the SIEM watches (rules 100320 and 100321). Plaintext exists only in pipes.
# Before it promotes a copy, it signs what it verified (the seal), which
# tools/tier2-restore.sh requires.
# The overrides below are for the scratch suite; a real run needs none.

# *--- Configuration ---*

set -u -o pipefail
export LC_ALL=C
# NOTE: an exported CDPATH makes cd print the directory inside $(...).
unset CDPATH
umask 077

BOX=${TIER2_BOX:-talonsoc}
# The deploy dir on the box, relative to talon's home.
REMOTE=${TIER2_REMOTE:-talonsoclab/deploy/soc-recon}
VOLUME=${TIER2_VOLUME:-/Volumes/MacbookXD}
DEST=$VOLUME/talonsoclab/tier2
IDENTITY=${TIER2_IDENTITY:-$HOME/.config/talon/tier2-identity.txt}
SIGNKEY=${TIER2_SIGNKEY:-$HOME/.config/talon/tier2-sign}
SIGNERS=${TIER2_SIGNERS:-$HOME/.config/talon/tier2-allowed-signers}
# Every sealed and marked stamp, kept off the drive and off the box, so a restore
# after losing either can tell the newest genuine snapshot (runbook 09 section 4).
SEALLOG=${TIER2_SEALLOG:-$HOME/.config/talon/tier2-sealed.log}
LOCK=$HOME/.config/talon/tier2-backup.lock

# MacbookXD keeps the newest three verified snapshots (PHOENIX, Tier 2).
KEEP=3
MIN_FREE_KB=$((4 * 1024 * 1024))

STAMP_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z$'
PROJECT_RE='^[a-z0-9][a-z0-9_-]*$'
VOLUMES=(indexer_data wazuh_etc wazuh_queue wazuh_api_configuration)

say() {
    printf '%s\n' "$*" >&2
}

die() {
    say "tier2-backup: $*"
    exit 1
}

# sign <statement>: prints its signature by SIGNKEY in the tier2 namespace. The
# statement goes in on stdin, never through a file on the drive, so the bytes
# signed are the bytes this run built.
sign() {
    printf '%s\n' "$1" | ssh-keygen -Y sign -q -n tier2 -f "$SIGNKEY" 2>/dev/null
}

# sealed <statement> <signature>: the signature is the tier2 signer's, in
# SIGNERS, over exactly this statement.
sealed() {
    printf '%s\n' "$1" | ssh-keygen -Y verify -q -f "$SIGNERS" -I tier2 -n tier2 -s <(printf '%s\n' "$2") >/dev/null 2>&1
}

# SECURITY: an unmounted drive must not turn into a folder on the boot disk, and
# a link must not carry the copy off the drive. A mounted volume is a different
# device from /Volumes itself. Checked before the box is touched and again
# before each write, since the drive can go away during the 3 to 4 minutes.
on_drive() {
    local p dev
    if ! [ -d "$VOLUME" ] || [ -L "$VOLUME" ]; then
        die "$VOLUME is not mounted"
    fi
    dev=$(stat -f %d "$VOLUME") || die "$VOLUME is not mounted"
    [ "$dev" != "$(stat -f %d /Volumes)" ] || die "$VOLUME is not a mounted volume"
    for p in "$@"; do
        [ -L "$p" ] && die "$p is a link"
        [ -e "$p" ] || continue
        [ -d "$p" ] || die "$p is not a directory"
        [ "$(stat -f %d "$p")" = "$dev" ] || die "$p is not on $VOLUME"
    done
}

# *--- Preflight ---*

# Nothing below touches the box until the snapshot, so a refusal here costs no
# downtime.

for c in age age-keygen rsync ssh ssh-keygen shasum tar stat df; do
    command -v "$c" >/dev/null || die "$c is not installed"
done

if ! [ -f "$IDENTITY" ] || [ -L "$IDENTITY" ]; then
    die "no identity at $IDENTITY (runbook 09, Setup)"
fi
[ "$(stat -f %Lp "$IDENTITY")" = 600 ] || die "$IDENTITY must be mode 600"
[ "$(stat -f %u "$IDENTITY")" = "$(id -u)" ] || die "$IDENTITY must be yours"
pub=$(age-keygen -y "$IDENTITY" 2>/dev/null) || die "$IDENTITY is not an age identity"

# SECURITY: age proves nothing about who wrote an archive: the recipient is
# public, so anyone who can write the drive can encrypt to it. The seal is a
# signature over what this run verified, by a key only this Mac holds, and the
# restore reads nothing that does not carry it. A key the restore would refuse
# is caught here, before the box stops anything.
if ! [ -f "$SIGNKEY" ] || [ -L "$SIGNKEY" ]; then
    die "no signing key at $SIGNKEY (runbook 09, Setup)"
fi
[ "$(stat -f %Lp "$SIGNKEY")" = 600 ] || die "$SIGNKEY must be mode 600"
[ "$(stat -f %u "$SIGNKEY")" = "$(id -u)" ] || die "$SIGNKEY must be yours"
# NOTE: with a terminal, ssh-keygen would ask for a passphrase, after the stack
# had already been stopped once; with -P '' it refuses at once instead.
ssh-keygen -y -P '' -f "$SIGNKEY" >/dev/null 2>&1 || die "$SIGNKEY has a passphrase or is not a key (runbook 09, Setup)"
if ! [ -f "$SIGNERS" ] || [ -L "$SIGNERS" ]; then
    die "no allowed-signers file at $SIGNERS (runbook 09, Setup)"
fi
[ "$(stat -f %u "$SIGNERS")" = "$(id -u)" ] || die "$SIGNERS must be yours"
# The signers file is what the restore trusts, so no one else may write it.
[ $((8#$(stat -f %Lp "$SIGNERS") & 8#022)) -eq 0 ] || die "$SIGNERS must not be writable by group or others"
sig=$(sign 'tier2 preflight') && sealed 'tier2 preflight' "$sig" ||
    die "$SIGNKEY does not sign as the tier2 signer in $SIGNERS (runbook 09, Setup)"

# An archive this identity cannot open is not a backup, so check before the
# box stops anything.
# shellcheck disable=SC2016 # expands on the box
rcpt=$(ssh -o BatchMode=yes "$BOX" bash -s -- "$REMOTE" <<<'grep -v -e "^#" -e "^[[:space:]]*$" -- "$1/tier2.recipient"') ||
    die "cannot read the box's tier2.recipient"
[ "$rcpt" = "$pub" ] || die "the box encrypts to a key $IDENTITY cannot open"

on_drive "$VOLUME/talonsoclab" "$DEST"
free=$(df -Pk "$VOLUME" | awk 'NR == 2 { print $4 }')
[ "${free:-0}" -ge "$MIN_FREE_KB" ] || die "less than 4 GB free on $VOLUME"

part=
locked=
bg=
cleanup() {
    local rc=$?
    # A second signal would cut the cleanup short.
    trap '' INT TERM HUP
    if [ -n "$bg" ]; then
        pkill -TERM -P "$bg" 2>/dev/null
        kill "$bg" 2>/dev/null
        wait "$bg" 2>/dev/null
    fi
    # SECURITY: only on the drive: a partial path that now resolves elsewhere is left.
    if [ -n "$part" ] && [ -d "$part" ] && ! [ -L "$part" ] &&
        [ "$(stat -f %d "$part" 2>/dev/null)" = "$(stat -f %d "$VOLUME" 2>/dev/null)" ] &&
        [ "$(stat -f %d "$VOLUME" 2>/dev/null)" != "$(stat -f %d /Volumes)" ]; then
        rm -rf -- "$part"
    fi
    [ -n "$locked" ] && rmdir -- "$LOCK" 2>/dev/null
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# One run at a time: a second one would stop the stack under the first one's
# restore test, or prune its partial copy. mkdir is atomic, also in bash 3.2.
mkdir -p -- "${LOCK%/*}" || die "cannot create ${LOCK%/*}"
mkdir -- "$LOCK" 2>/dev/null || die "another tier2-backup is running, or one was killed: remove $LOCK if none is"
locked=1

# *--- Snapshot ---*

say "running tier2-snapshot on $BOX; the stack stops for about 3 to 4 minutes"
# Exit 3 from the box: its snapshot is complete but its own retention failed.
box_kept=
rc=0
out=$(ssh -o BatchMode=yes "$BOX" "$REMOTE/bin/tier2-snapshot") || rc=$?
if [ "$rc" -eq 3 ]; then
    box_kept=1
elif [ "$rc" -ne 0 ]; then
    die "the box half failed; see ~/tier2/<project>/last-run.log on $BOX"
fi
last=${out##*$'\n'}
read -r word stamp dir extra <<<"$last"
if [ "$word" != snapshot ] || [ -n "$extra" ] || ! [[ $stamp =~ $STAMP_RE ]]; then
    die "the box half printed no snapshot line"
fi
project=${dir%/*}
project=${project##*/}
if ! [[ $project =~ $PROJECT_RE ]] || [ "${dir##*/}" != "$stamp" ]; then
    die "unexpected snapshot path $dir"
fi

dirs=("$VOLUME/talonsoclab" "$DEST" "$DEST/$project")
part=$DEST/$project/.$stamp.partial
final=$DEST/$project/$stamp
# NOTE: one level at a time, each checked, because mkdir -p follows links.
for d in "${dirs[@]}"; do
    on_drive "${dirs[@]}"
    [ -d "$d" ] || mkdir -- "$d" || die "cannot create $d"
done
on_drive "${dirs[@]}" "$part" "$final"
[ -e "$final" ] && die "$final already exists"

# *--- Copy ---*

say "copying $stamp to $final"
on_drive "${dirs[@]}" "$part"
rsync -a --chmod=Du=rwx,Dgo=,Fu=rw,Fgo= -- "$BOX:$dir/" "$part/" || die "the copy failed"

# SECURITY: rsync -a copies links as links, and the box picks the path; every
# entry must be a plain file, checked first, so nothing reads through a link.
for p in "$part"/* "$part"/.*; do
    n=${p##*/}
    case $n in
        . | ..) ;;
        MANIFEST | INFO | *.tar.gz.age)
            if [ -L "$p" ] || ! [ -f "$p" ]; then
                die "not a plain file in the snapshot: $n"
            fi
            ;;
        *) if [ -e "$p" ] || [ -L "$p" ]; then die "unexpected file in the snapshot: $n"; fi ;;
    esac
done

# The box's MANIFEST names exactly the four archives, and nothing else came.
(cd -- "$part" && shasum -a 256 -c --quiet MANIFEST) || die "the copy does not match the box's MANIFEST"
want=$(for v in "${VOLUMES[@]}"; do printf '%s\n' "${project}_${v}_$stamp.tar.gz.age"; done | sort)
have=$(awk '{ print $2 }' "$part/MANIFEST" | sort)
[ "$want" = "$have" ] || die "MANIFEST does not name exactly the four archives"
# SECURITY: the drive is not this run's alone (it mounted with noowners until
# 2026-10-21, and root can always write it). The box's own hashes of MANIFEST and INFO
# are the pin: the copy must match them now, and again when it is sealed, so
# the seal can only ever name what the box wrote.
# shellcheck disable=SC2016 # expands on the box
pin=$(ssh -o BatchMode=yes "$BOX" bash -s -- "$dir" <<<'cd -- "$1" && sha256sum MANIFEST INFO') || die "cannot read the box's hashes of MANIFEST and INFO"
[ "$(cd -- "$part" && shasum -a 256 MANIFEST INFO)" = "$pin" ] || die "the copy of MANIFEST or INFO is not the box's"

# *--- Verify ---*

# D2: encrypted at rest. Each archive opens only through age, and lists.
# NOTE: the pipeline runs in a background subshell this shell waits on, as in
# tier2-restore.sh: a signal landing while the shell builds a pipeline itself
# can deadlock its EXIT trap (bash 5.3.20).
for f in $want; do
    say "verifying $f"
    if tar -tzf "$part/$f" >/dev/null 2>&1; then
        die "$f lists without decryption"
    fi
    (age -d -i "$IDENTITY" -- "$part/$f" | tar -tzf - >/dev/null) &
    bg=$!
    wait "$bg" || die "$f does not decrypt and list"
    bg=
done

# *--- Restore test ---*

# The config the manager runs, as backed up, must equal what it runs now. The
# box refused to snapshot unless the running manager matched the checkout, and
# the recreate copied the same files back, so any difference is a bad backup.
etc=$part/${project}_wazuh_etc_$stamp.tar.gz.age
# NOTE: one pattern picks the files on both sides, dotfiles included, so a file
# present on one side only shows as a difference instead of being skipped.
# NOTE: rules/custom at any depth; tar lists dirs with a trailing slash, and
# they are not files to compare.
CONF_RE='\./(ossec\.conf|rules/custom/.*[^/]|shared/[^/]+/agent\.conf)'
members=$(age -d -i "$IDENTITY" -- "$etc" | tar -tzf - | grep -E -x "$CONF_RE") ||
    die "cannot list the config in the wazuh_etc archive"
backed=$(while IFS= read -r m; do
    h=$(age -d -i "$IDENTITY" -- "$etc" | tar -xzOf - "$m" | shasum -a 256) || exit 1
    printf '%s %s\n' "${h%% *}" "${m#./}"
done <<<"$members" | sort) || die "cannot hash the config in the wazuh_etc archive"

# shellcheck disable=SC2016 # expands on the box
# NOTE: the path is everything after the 64 hex digits and two spaces, so a
# name with spaces compares whole. GNU sha256sum escapes a name holding a
# newline or backslash and prefixes the line with "\"; that line is passed
# through as it is and can equal no archive line (those start with a hex
# digit), so such a file fails the test even when only the live side has it.
# The Mac's tar escapes a tab, newline or backslash in its listing, and the
# extract of that name then fails the run.
live=$(ssh -o BatchMode=yes "$BOX" bash -s -- "$REMOTE" <<<'cd -- "$1" && docker compose exec -T wazuh.manager sh -c "cd /var/ossec/etc && find ./ossec.conf ./rules/custom ./shared -type f -exec sha256sum {} +"' |
    RE="^($CONF_RE)\$" awk '/^\\/ { print; next } { p = substr($0, 67) } p ~ ENVIRON["RE"] { sub(/^\.\//, "", p); print $1, p }' | sort) || die "cannot hash the live manager's config"

grep -q ' ossec\.conf$' <<<"$backed" || die "the wazuh_etc archive holds no ossec.conf"
grep -q ' shared/[^/]*/agent\.conf$' <<<"$backed" || die "the wazuh_etc archive holds no agent.conf"
if [ "$backed" != "$live" ]; then
    say "restore test failed: the backed-up config differs from the live manager's:"
    diff <(cut -c66- <<<"$backed") <(cut -c66- <<<"$live") >&2
    awk 'NR == FNR { h[substr($0, 66)] = substr($0, 1, 64); next }
        (substr($0, 66) in h) && h[substr($0, 66)] != substr($0, 1, 64) { print "  changed " substr($0, 66) }' \
        <(printf '%s\n' "$backed") <(printf '%s\n' "$live") >&2
    die "no marker written"
fi
say "restore test: $(wc -l <<<"$backed" | tr -d ' ') config files match the live manager"

# *--- Seal ---*

# Only now, after the copy, the decrypt-and-list and the restore test passed.
# The copy check above refused any file the box sent besides MANIFEST, INFO
# and the archives, so the box cannot supply a seal of its own. The copy is
# checked against MANIFEST and the pin once more, since the drive can change
# during the run; what is signed is built here from the pin, never read back.
on_drive "${dirs[@]}" "$part"
(cd -- "$part" && shasum -a 256 -c --quiet MANIFEST) || die "the copy changed during the run: it no longer matches MANIFEST"
[ "$(cd -- "$part" && shasum -a 256 MANIFEST INFO)" = "$pin" ] || die "the copy changed during the run: MANIFEST or INFO is not the box's"
stmt=$(printf 'tier2 seal v1\nproject %s\nstamp %s\n%s' "$project" "$stamp" "$pin")
sig=$(sign "$stmt") && sealed "$stmt" "$sig" || die "cannot sign the seal"
# SECURITY: nothing may already sit under either name, and the writes use
# noclobber, so a file or a link planted there is refused, not written through.
for f in VERIFIED VERIFIED.sig; do
    if [ -e "$part/$f" ] || [ -L "$part/$f" ]; then
        die "cannot write the seal: VERIFIED or VERIFIED.sig is already in $part"
    fi
done
if ! (set -C && printf '%s\n' "$stmt" >"$part/VERIFIED" && printf '%s\n' "$sig" >"$part/VERIFIED.sig"); then
    die "cannot write the seal: VERIFIED or VERIFIED.sig is already in $part"
fi
# NOTE: noclobber still opens an existing FIFO or device, or a link to one, so
# the seal must now be two plain files holding exactly what was built.
for f in VERIFIED VERIFIED.sig; do
    if ! [ -f "$part/$f" ] || [ -L "$part/$f" ]; then
        die "cannot write the seal: $part/$f is not a plain file"
    fi
done
[ "$(<"$part/VERIFIED")" = "$stmt" ] && [ "$(<"$part/VERIFIED.sig")" = "$sig" ] ||
    die "cannot write the seal: what $part holds is not what was signed"
say "sealed $stamp"

# *--- Mark ---*

on_drive "${dirs[@]}" "$part" "$final"
mv -- "$part" "$final" || die "cannot promote $part"
# NOTE: macOS mv has no -T. A $final made since the check above would take the
# partial inside it; checked after the rename, where no race remains.
if ! [ -f "$final/MANIFEST" ] || [ -e "$final/.$stamp.partial" ]; then
    die "cannot promote $part: $final was not the copy"
fi
on_drive "${dirs[@]}" "$final"

# The box's clock writes the marker, so the probe compares it with the same
# clock. Replaced by rename, so the probe never reads half a marker.
# shellcheck disable=SC2016 # expands on the box
marker=$(ssh -o BatchMode=yes "$BOX" bash -s -- "$REMOTE" <<<'
d=$1/state/tier2
[ -d "$d" ] && ! [ -L "$d" ] || exit 1
m="verified $(date +%s)"
[[ $m =~ ^verified\ [0-9]{10}$ ]] || exit 1
printf "%s\n" "$m" >"$d/.verified.tmp" && mv -f -- "$d/.verified.tmp" "$d/verified" && cat -- "$d/verified"') ||
    die "the backup verified, but the marker was not written"
[[ $marker =~ ^verified\ [0-9]{10}$ ]] || die "the marker reads back wrong"
# The off-box record: the stamp, the seal's hash, and the box's marker time.
if ! printf '%s %s %s %s\n' "$stamp" "$project" "$(printf '%s\n' "$stmt" | shasum -a 256 | cut -c1-64)" "${marker#verified }" >>"$SEALLOG"; then
    say "tier2-backup: WARN: the backup verified, but $SEALLOG was not written"
fi

# *--- Prune ---*

# Only what this script wrote is touched: stamp-named dirs past the newest KEEP,
# and partial copies left by failed runs, each holding the box's MANIFEST. A
# failed delete leaves the marker in place (the backup verified) but exits 3.
# The drive again, right before anything is deleted from it.
if ! (on_drive "${dirs[@]}" "$final") 2>/dev/null; then
    say "tier2-backup: the backup verified, but $VOLUME is not the drive any more; retention skipped (exit 3)"
    exit 3
fi
stamps=()
stale=()
for p in "$DEST/$project"/* "$DEST/$project"/.*.partial; do
    n=${p##*/}
    if ! [ -d "$p" ] || [ -L "$p" ] || ! [ -f "$p/MANIFEST" ] || [ -L "$p/MANIFEST" ]; then
        continue
    elif [ "$n" = "$stamp" ]; then
        # This run's copy is the one the marker now vouches for: never pruned,
        # whatever names a clock step left on the drive.
        continue
    elif [[ $n =~ $STAMP_RE ]]; then
        stamps+=("$n")
    elif [[ $n =~ ^\.(.*)\.partial$ ]] && [[ ${BASH_REMATCH[1]} =~ $STAMP_RE ]]; then
        stale+=("$n")
    fi
done
# NOTE: stamps sort as text in time order, so the oldest come first.
# NOTE: ${a[@]+"${a[@]}"}, because bash 3.2 (/bin/bash) calls an empty array
# unbound under set -u.
old=$(printf '%s\n' ${stamps[@]+"${stamps[@]}"} | sort | awk -v keep="$((KEEP - 1))" '{ a[NR] = $0 } END { for (i = 1; i <= NR - keep; i++) print a[i] }')
kept=
for n in $old ${stale[@]+"${stale[@]}"}; do
    if rm -rf -- "${DEST:?}/$project/$n"; then
        say "pruned $n"
    else
        say "WARN: cannot prune $n"
        kept=1
    fi
done

say "Tier 2 backup $stamp verified in $final; marker written on $BOX"
if [ -n "$kept" ]; then
    say "tier2-backup: the backup verified, but retention on the drive failed (exit 3)"
    exit 3
fi
if [ -n "$box_kept" ]; then
    say "tier2-backup: the backup verified, but retention on $BOX failed; see its last-run.log (exit 3)"
    exit 3
fi
