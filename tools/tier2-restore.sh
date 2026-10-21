#!/usr/bin/env bash
# ******************************************************************************
# *Title: tier2-restore*
# *Author: Kyle Versluis*
# *Description: Restores a Tier 2 snapshot into new volumes on the box.*
# ******************************************************************************
# Run on the Mac (runbook 09 section 4, PHOENIX Stage 2 Path A):
#   tools/tier2-restore.sh <drive>/talonsoclab/tier2/<project>/<stamp>
# Every archive is checked before the box is touched. Then each one is decrypted
# on the Mac and streamed over ssh into a new volume, so no plaintext archive
# lands on either disk. It never starts the stack and never writes into a volume
# that already exists. Last, it records the finished restore on the box, which
# bin/tier2-start requires. The overrides below are for the scratch suite.

# *--- Configuration ---*

set -euo pipefail
export LC_ALL=C
umask 077

BOX=${TIER2_BOX:-talonsoc}
# The deploy dir on the box, relative to talon's home.
REMOTE=${TIER2_REMOTE:-talonsoclab/deploy/soc-recon}
IDENTITY=${TIER2_IDENTITY:-$HOME/.config/talon/tier2-identity.txt}

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

# The same checks the backup ran, again: the drive may have rotted since.
(cd -- "$src" && shasum -a 256 -c --quiet MANIFEST) || die "the snapshot does not match its MANIFEST"
want=$(for v in "${VOLUMES[@]}"; do printf '%s\n' "${project}_${v}_$stamp.tar.gz.age"; done | sort)
have=$(awk '{ print $2 }' "$src/MANIFEST" | sort)
[ "$want" = "$have" ] || die "MANIFEST does not name exactly the four archives"
for v in "${VOLUMES[@]}"; do
    f=${project}_${v}_$stamp.tar.gz.age
    say "checking $f"
    if ! age -d -i "$IDENTITY" -- "$src/$f" | tar -tzf - >/dev/null; then
        die "$f does not decrypt and list"
    fi
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
taken=$(awk '$1 == "image" { print $3 }' "$src/INFO" 2>/dev/null || true)
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
        age -d -i "$IDENTITY" -- "$src/$f" |
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
# The holders were only for this run; bin/tier2-start pins the volumes again.
# shellcheck disable=SC2029 # checked token, expanded here on purpose
if ! ssh -o BatchMode=yes "$BOX" "set -o pipefail; docker ps -aq --filter label=tier2.holder=$token | xargs -r docker rm -f >/dev/null"; then
    say "WARN: the restore is complete, but its holder containers are still on $BOX; remove them: docker rm -f \$(docker ps -aq --filter label=tier2.holder=$token)"
fi

say "restored $stamp into the four ${project} volumes. Next, on the box:"
say "  bin/tier2-start"
say "then want 0-wazuh-init: exited 0 in docker compose logs wazuh.manager (PHOENIX Stage 2)"
