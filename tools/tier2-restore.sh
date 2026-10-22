#!/usr/bin/env bash
# ******************************************************************************
# *Title: tier2-restore*
# *Author: Kyle Versluis*
# *Description: Restores a Tier 2 snapshot into new volumes on the box.*
# ******************************************************************************
# Run on the Mac (runbook 09 section 4, PHOENIX Stage 2 Path A):
#   tools/tier2-restore.sh <drive>/talonsoclab/tier2/<project>/<stamp>
# Only a snapshot tools/tier2-backup.sh sealed is read: its signature must
# verify against the allowed-signers file. Every archive is checked before the
# box is touched. Then each one is decrypted
# on the Mac and streamed over ssh into a new volume, so no plaintext archive
# lands on either disk. It never starts the stack and never writes into a volume
# that already exists. Last, it records the finished restore on the box, which
# bin/tier2-start requires. The overrides below are for the scratch suite.

# *--- Configuration ---*

set -euo pipefail
export LC_ALL=C
# NOTE: an exported CDPATH makes cd print the directory inside $(...).
unset CDPATH
umask 077

BOX=${TIER2_BOX:-talonsoc}
# The deploy dir on the box, relative to talon's home.
REMOTE=${TIER2_REMOTE:-talonsoclab/deploy/soc-recon}
IDENTITY=${TIER2_IDENTITY:-$HOME/.config/talon/tier2-identity.txt}
SIGNERS=${TIER2_SIGNERS:-$HOME/.config/talon/tier2-allowed-signers}
# tier2-backup.sh's record of every stamp it sealed; lost with the Mac.
SEALLOG=${TIER2_SEALLOG:-$HOME/.config/talon/tier2-sealed.log}

STAMP_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z$'
PROJECT_RE='^[a-z0-9][a-z0-9_-]*$'
VOLUMES=(indexer_data wazuh_etc wazuh_queue wazuh_api_configuration)

say() {
    printf '%s\n' "$*" >&2
}

die() {
    say "tier2-restore: $*"
    exit 1
}

# *--- The snapshot ---*

[ "$#" -eq 1 ] || die "usage: tier2-restore.sh <snapshot dir>"
src=${1%/}
stamp=${src##*/}
project=${src%/*}
project=${project##*/}
[[ $stamp =~ $STAMP_RE ]] || die "$src is not a snapshot dir (<project>/<stamp>)"
[[ $project =~ $PROJECT_RE ]] || die "unexpected project name in $src"
if ! [ -d "$src" ] || [ -L "$src" ]; then
    die "$src is not a directory"
fi
if ! [ -f "$IDENTITY" ] || [ -L "$IDENTITY" ]; then
    die "no identity at $IDENTITY"
fi

# SECURITY: age proves nothing about who wrote an archive: the recipient is
# public, so anyone who can write the drive can encrypt to it and write a
# matching MANIFEST. The seal is tier2-backup.sh's signature over the project,
# the stamp and the box's hashes of MANIFEST and INFO, made after its restore
# test; nothing here reads an archive until the seal verifies and matches.
if ! [ -f "$SIGNERS" ] || [ -L "$SIGNERS" ]; then
    die "no allowed-signers file at $SIGNERS (runbook 09, Setup; PHOENIX Tier 3)"
fi
[ "$(stat -f %u "$SIGNERS")" = "$(id -u)" ] || die "$SIGNERS must be yours"
[ $((8#$(stat -f %Lp "$SIGNERS") & 8#022)) -eq 0 ] || die "$SIGNERS must not be writable by group or others"
want=$(for v in "${VOLUMES[@]}"; do printf '%s\n' "${project}_${v}_$stamp.tar.gz.age"; done | sort)
names=(VERIFIED VERIFIED.sig MANIFEST INFO)
while IFS= read -r f; do
    names+=("$f")
done <<<"$want"
size=0
sizes=()
for f in "${names[@]}"; do
    if ! [ -f "$src/$f" ] || [ -L "$src/$f" ]; then
        die "no $f in $src: not a snapshot tier2-backup.sh sealed (runbook 09 section 4)"
    fi
    z=$(stat -f %z "$src/$f") || die "cannot read the size of $f"
    sizes+=("$z")
    size=$((size + z))
done

# SECURITY: the drive is an external volume another account may write (it
# mounted with noowners until 2026-10-21, and root can always write it), and a
# file checked there could change before it is read again. Each file is copied
# once into a private dir on this Mac, ciphertext only, and every check below
# and the stream read that copy. The seal files go first: no archive is read
# from the drive until the seal verifies. A SIGKILLed run leaves the copy in
# $TMPDIR; any other exit removes it.
stage=
check=
unstage() {
    trap '' INT TERM HUP
    if [ -n "$check" ]; then
        pkill -TERM -P "$check" 2>/dev/null || true
        kill "$check" 2>/dev/null || true
        wait "$check" 2>/dev/null || true
    fi
    if [ -n "$stage" ]; then
        rm -rf -- "$stage"
    fi
}
trap unstage EXIT
trap 'exit 130' INT TERM HUP
stage=$(mktemp -d "${TMPDIR:-/tmp}/tier2-restore.XXXXXX") || die "cannot make a staging dir"
chmod 700 "$stage" || die "cannot make $stage private"
free=$(df -Pk "$stage" | awk 'NR == 2 { print $4 }')
[ $((${free:-0} * 1024)) -ge $((size + 512 * 1024 * 1024)) ] || die "less than the snapshot plus 512 MB free for $stage"
say "staging $src in $stage"
# stage_one <index>: copies names[i], at most the size seen above, so a file
# swapped on the drive for something endless cannot fill the disk.
stage_one() {
    local n=${names[$1]} z=${sizes[$1]}
    head -c "$z" -- "$src/$n" >"$stage/$n" || die "cannot copy $n"
    [ "$(stat -f %z "$stage/$n")" = "$z" ] || die "$n changed size on the drive while it was copied"
}
for i in 0 1 2 3; do
    stage_one "$i"
done
if ! ssh-keygen -Y verify -q -f "$SIGNERS" -I tier2 -n tier2 -s "$stage/VERIFIED.sig" <"$stage/VERIFIED" >/dev/null 2>&1; then
    die "the seal on $src does not verify: not signed by the tier2 key in $SIGNERS"
fi
seal=$(printf 'tier2 seal v1\nproject %s\nstamp %s\n' "$project" "$stamp" && cd -- "$stage" && shasum -a 256 MANIFEST INFO) ||
    die "cannot hash $src's MANIFEST and INFO"
[ "$(<"$stage/VERIFIED")" = "$seal" ] ||
    die "the seal does not match $src: its MANIFEST, INFO, project or stamp is not the one the backup verified"
have=$(awk '{ print $2 }' "$stage/MANIFEST" | sort)
[ "$want" = "$have" ] || die "MANIFEST does not name exactly the four archives"
# The seal proves where a snapshot came from, not that it is the newest. The
# backup's own record says which stamp is; without it, check the SIEM.
if [ -f "$SEALLOG" ] && ! [ -L "$SEALLOG" ]; then
    h=$(shasum -a 256 <"$stage/VERIFIED" | cut -c1-64)
    newest=$(awk -v p="$project" '$2 == p { s = $1 } END { print s }' "$SEALLOG")
    if ! awk -v s="$stamp" -v p="$project" -v h="$h" '$1 == s && $2 == p && $3 == h { f = 1 } END { exit !f }' "$SEALLOG"; then
        say "WARN: $SEALLOG has no record of this seal; check that $stamp is the newest snapshot the SIEM saw verified"
    elif [ "$newest" != "$stamp" ]; then
        say "WARN: $SEALLOG names a newer snapshot, $newest; this restores $stamp"
    fi
else
    say "WARN: no $SEALLOG on this Mac; check that $stamp is the newest snapshot the SIEM saw verified"
fi

# Only now the archives, then the same checks the backup ran, on the copy.
i=4
while [ "$i" -lt "${#names[@]}" ]; do
    stage_one "$i"
    i=$((i + 1))
done
(cd -- "$stage" && shasum -a 256 -c --quiet MANIFEST) || die "the snapshot does not match its MANIFEST"
for v in "${VOLUMES[@]}"; do
    f=${project}_${v}_$stamp.tar.gz.age
    say "checking $f"
    # NOTE: in a waited-on subshell, as the stream below, so a signal never
    # lands while this shell builds the pipeline.
    (age -d -i "$IDENTITY" -- "$stage/$f" | tar -tzf - >/dev/null) &
    check=$!
    wait "$check" || die "$f does not decrypt and list"
    check=
done

# *--- The box ---*

# Refuses unless the box's compose project is the snapshot's, the stack has no
# containers, and none of the four volumes exists. Prints the image ID whose
# tar unpacks the archives; nothing is pulled.
# shellcheck disable=SC2016 # expands on the box
image=$(ssh -o BatchMode=yes "$BOX" bash -s -- "$REMOTE" "$project" "${VOLUMES[@]}" <<<'
set -euo pipefail
cd -- "$1"
p=$2
shift 2
docker compose config -q
name=$(docker compose config | awk "NR == 1 && \$1 == \"name:\" { print \$2 }")
if [ "$name" != "$p" ]; then
    echo "the box compose project is \"$name\", the snapshot is from $p" >&2
    exit 1
fi
if [ -n "$(docker compose ps -a -q)" ]; then
    echo "the $p stack has containers; a restore goes into a stack with none (docker compose down)" >&2
    exit 1
fi
for v in "$@"; do
    if docker volume inspect "${p}_$v" >/dev/null 2>&1; then
        t=$(docker volume inspect -f "{{index .Labels \"tier2.restore\"}}" "${p}_$v")
        if [ -n "$t" ]; then
            echo "volume ${p}_$v was made by a restore (tier2.restore=$t), maybe one that was killed; remove it on purpose first (runbook 09, Restore)" >&2
            h=$(docker ps -aq --filter "label=tier2.holder=$t" | tr "\n" " ")
            [ -z "$h" ] || echo "its holder containers go first: docker rm -f $h" >&2
        else
            echo "volume ${p}_$v already exists; remove it on purpose first (runbook 09, Restore)" >&2
        fi
        exit 1
    fi
done
img=$(docker compose config --images wazuh.manager)
if ! docker image inspect -f "{{.Id}}" "$img" 2>/dev/null; then
    echo "the image $img is not on the box (docker compose pull)" >&2
    exit 1
fi') || die "the box is not ready for a restore"
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || die "unexpected image ID from the box: $image"

# A snapshot from another manager version restores, and the manager upgrades
# what it finds on start, but that should never pass unnoticed.
taken=$(awk '$1 == "image" { print $3 }' "$stage/INFO" 2>/dev/null || true)
if [ "$taken" != "$image" ]; then
    say "WARN: the snapshot was taken under image ${taken:-unknown}; the box's manager image is $image"
fi

# *--- Restore ---*

# A failed run removes the volumes it created, so the next try starts clean.
# SECURITY: this run's token labels every volume it creates, and a volume is
# this run's to write into or remove only when it carries the token. Existence
# alone proves nothing: docker volume create succeeds on an existing name.
token=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
[[ $token =~ ^[0-9a-f]{16}$ ]] || die "cannot make a restore token"
created=()
stream=
cleanup() {
    local rc=$? v i
    trap '' INT TERM HUP
    # The stream goes first: a container still unpacking holds its volume.
    if [ -n "$stream" ]; then
        pkill -TERM -P "$stream" 2>/dev/null || true
        kill "$stream" 2>/dev/null || true
        wait "$stream" 2>/dev/null || true
    fi
    if [ "$rc" -ne 0 ] && [ "${#created[@]}" -gt 0 ]; then
        say "removing the volumes this run created: ${created[*]}" || true
        for v in "${created[@]}"; do
            # NOTE: retried, because the box's container exits a moment after
            # its stream is cut, and holds the volume until then.
            for i in 1 2 3; do
                # NOTE: this run's holder goes first; a volume a container
                # still references cannot be removed.
                # shellcheck disable=SC2029 # checked names, expanded here on purpose
                if ssh -o BatchMode=yes "$BOX" "docker rm -f t2hold-$token-$v >/dev/null 2>&1
                    t=\$(docker volume inspect -f '{{index .Labels \"tier2.restore\"}}' $v 2>/dev/null) || exit 0
                    [ \"\$t\" = $token ] || exit 0
                    docker volume rm $v >/dev/null 2>&1"; then
                    break
                elif [ "$i" -eq 3 ]; then
                    say "WARN: cannot remove $v on $BOX" || true
                else
                    sleep 3
                fi
            done
        done
    fi
    unstage
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

for v in "${VOLUMES[@]}"; do
    vol=${project}_$v
    f=${project}_${v}_$stamp.tar.gz.age
    say "restoring $vol"
    # NOTE: recorded before the create, because a signal lands only after the
    # ssh returns, and the volume exists by then; the cleanup removes it only
    # if it carries this run's token. After the create, the box reads the label
    # back: on a volume that already existed, create keeps the old labels, so a
    # missing token means it is not this run's (exit 3). The project and volume
    # labels make compose adopt it: up uses it, down -v removes it (compose
    # 5.6.0, measured 2026-10-19).
    # SECURITY: a stopped holder container attaches the volume before its
    # label is read back. Docker refuses to remove a volume any container
    # references, so the name keeps meaning this volume until the holder goes:
    # the stream below cannot land in a volume swapped in after the check.
    created+=("$vol")
    rc=0
    # shellcheck disable=SC2029 # checked names, expanded here on purpose
    ssh -o BatchMode=yes "$BOX" "if docker volume inspect $vol >/dev/null 2>&1; then exit 3; fi
        docker volume create --label com.docker.compose.project=$project --label com.docker.compose.volume=$v \
            --label tier2.restore=$token $vol >/dev/null || exit 1
        docker create --pull never --name t2hold-$token-$vol --label tier2.holder=$token --network none \
            -v $vol:/held --entrypoint true $image >/dev/null || exit 1
        [ \"\$(docker volume inspect -f '{{index .Labels \"tier2.restore\"}}' $vol)\" = $token ] || exit 3" ||
        rc=$?
    if [ "$rc" -eq 3 ]; then
        die "volume $vol existed before this run created it; it is not this run's to write into (remove it on purpose first)"
    fi
    [ "$rc" -eq 0 ] || die "cannot create $vol"
    # WARN: the stream runs in a background subshell the main shell waits on.
    # A signal interrupts wait at once, while one that lands as the main shell
    # builds a pipeline deadlocked its EXIT trap on the half-built pipe (bash
    # 5.3.20, measured 2026-10-19).
    (
        age -d -i "$IDENTITY" -- "$stage/$f" |
            ssh -o BatchMode=yes "$BOX" docker run --rm -i --network none -v "$vol:/to" --entrypoint tar "$image" xzf - -C /to
    ) &
    stream=$!
    wait "$stream" || die "the restore of $vol failed"
    stream=
done
# All four are filled. Signals end here, so nothing but a failed write can stop
# the record, and a failed write still runs the cleanup. The record names this
# run's token, which bin/tier2-start checks on every volume before it starts
# the stack; a run cut off before this line leaves volumes with no record.
trap '' INT TERM HUP
# shellcheck disable=SC2016 # expands on the box
ssh -o BatchMode=yes "$BOX" bash -s -- "$REMOTE" "$stamp" "$token" <<<'
set -euo pipefail
cd -- "$1"
printf "restored %s %s\n" "$2" "$3" >state/.tier2-restored.tmp
mv -f -- state/.tier2-restored.tmp state/tier2-restored' ||
    die "the volumes were filled, but the completion record was not written"
trap - EXIT
created=()
unstage
# The holders were only for this run; bin/tier2-start pins the volumes again.
# shellcheck disable=SC2029 # checked token, expanded here on purpose
if ! ssh -o BatchMode=yes "$BOX" "set -o pipefail; docker ps -aq --filter label=tier2.holder=$token | xargs -r docker rm -f >/dev/null"; then
    say "WARN: the restore is complete, but its holder containers are still on $BOX; remove them: docker rm -f \$(docker ps -aq --filter label=tier2.holder=$token)"
fi

say "restored $stamp into the four ${project} volumes. Next, on the box:"
say "  bin/tier2-start"
say "then want 0-wazuh-init: exited 0 in docker compose logs wazuh.manager (PHOENIX Stage 2)"
