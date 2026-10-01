#!/usr/bin/env bash
# ******************************************************************************
# *Title: install*
# *Author: Kyle Versluis*
# *Description: Install the leakcheck git hooks as fail-closed stubs.*
# ******************************************************************************

# *--- Configuration ---*

# Each stub in .git/hooks runs the matching file under tools/hooks and blocks the
# operation when that file is missing or not executable. A symlink would skip
# silently in that case, because git ignores a hook it cannot run.
#
# NOTE: a repo-level core.hooksPath is never set here, and one already set is
# refused: it replaces the hooks dir outright, so nothing could chain back to the
# stubs. A global dispatcher that chains to .git/hooks is fine, and the probe at
# the end proves the chain instead of assuming it.
set -euo pipefail

hooks="pre-commit commit-msg pre-push"
marker="leakcheck-stub"

# *--- Helper Functions ---*

# Write one stub, or replace a stub or a symlink to tools/hooks that this script
# installed earlier. Anything else in the way is someone else's hook: stop.
install_stub() {
  local dir="$1" name="$2" path="$1/$2"
  if [ -L "$path" ]; then
    case "$(readlink "$path")" in
      *tools/hooks/"$name") rm -f "$path" ;;
      *) echo "install.sh: $path is a symlink to something else. Not touching it." >&2; return 1 ;;
    esac
  elif [ -e "$path" ] && ! grep -q "$marker" "$path"; then
    echo "install.sh: $path exists and is not a leakcheck stub. Not touching it." >&2
    return 1
  fi
  cat > "$path" <<STUB
#!/usr/bin/env bash
# $marker: written by tools/hooks/install.sh. Edit tools/hooks/$name instead.
# The installer sets LEAKCHECK_PROBE to prove that git stops when this stub fails.
if [ -n "\${LEAKCHECK_PROBE:-}" ]; then echo "leakcheck-probe \$LEAKCHECK_PROBE" >&2; exit 97; fi
hook="\$(git rev-parse --show-toplevel)/tools/hooks/$name"
if ! [ -x "\$hook" ]; then
  echo "$name: \$hook is missing or not executable. Blocked." >&2
  echo "Restore tools/hooks, or bypass once with --no-verify." >&2
  exit 1
fi
exec "\$hook" "\$@"
STUB
  chmod +x "$path"
  echo "installed $path"
}

# Run one hook through git with the arguments git gives it. $msg and $common are set
# before the verification below calls this.
run_hook() {
  case "$1" in
    commit-msg) git hook run "$1" -- "$msg" ;;
    pre-push)   git hook run "$1" -- origin "$common" ;;
    *)          git hook run "$1" ;;
  esac
}

# Add a hooks dir to the list once.
add_dir() {
  local d
  for d in "${dirs[@]}"; do
    [ "$d" = "$1" ] && return 0
  done
  dirs+=("$1")
}

# *--- Entry Point ---*

# The common dir holds the hooks git runs directly. A dispatcher looks in each
# worktree's own git dir instead, so every linked worktree gets stubs as well.
common=$(git rev-parse --path-format=absolute --git-common-dir)
dirs=("$common/hooks")
while IFS= read -r line; do
  case "$line" in
    "worktree "*)
      wt=${line#worktree }
      own=$(git -C "$wt" rev-parse --absolute-git-dir 2>/dev/null) || continue
      add_dir "$own/hooks" ;;
  esac
done < <(git worktree list --porcelain)

# SECURITY: a core.hooksPath replaces the hooks dir outright. At local or worktree
# scope nothing can chain back to the stubs, so refuse before writing anything.
# At global or system scope a dispatcher may chain; the probe below settles that.
effective=$(git rev-parse --path-format=absolute --git-path hooks)
case " ${dirs[*]} " in
  *" $effective "*) ;;
  *)
    scope=$(git config --show-scope --get core.hooksPath | cut -f1)
    origin=$(git config --show-origin --get core.hooksPath | cut -f1)
    case "$scope" in
      global|system) ;;
      *)
        echo "install.sh: core.hooksPath=$effective is set at $scope scope ($origin)." >&2
        echo "git never reads $common/hooks while it is set. Unset it, or chain to $common/hooks from there. Nothing installed." >&2
        exit 2 ;;
    esac ;;
esac

status=0
for dir in "${dirs[@]}"; do
  mkdir -p "$dir"
  for name in $hooks; do
    install_stub "$dir" "$name" || status=1
  done
done
[ "$status" -eq 0 ] || exit "$status"

# Verify end to end, through whatever hooksPath is in effect. First the probe: each
# stub, told to fail, must make git fail with the stub's own exit code, so a
# dispatcher that runs the stub and then exits 0 is caught. Then a real run: the stub,
# the hook and the scanner each name leakcheck or tools/hooks in their output, and a
# foreign hook prints neither.
if ! git hook run -h 2>&1 | grep -q "git hook run"; then
  echo "install.sh: this git has no 'git hook run', so the chain was not verified. Confirm core.hooksPath ($effective) reaches $common/hooks." >&2
  exit 0
fi
msg=$(mktemp)
echo "leakcheck install probe" > "$msg"
nonce="$$-$RANDOM"
for name in $hooks; do
  rc=0
  out=$(export LEAKCHECK_PROBE="$nonce"; run_hook "$name" 2>&1 </dev/null) || rc=$?
  case "$out" in
    *"leakcheck-probe $nonce"*) ;;
    *)
      echo "install.sh: git does not run the $name stub. core.hooksPath=$effective takes its place and does not chain to it." >&2
      echo "Unset core.hooksPath, or make $effective/$name run $common/hooks/$name. The hooks are NOT active." >&2
      status=2
      continue ;;
  esac
  if [ "$rc" -ne 97 ]; then
    echo "install.sh: git runs the $name stub, but the stub's failure (exit 97) came back as exit $rc, so a finding would not stop git." >&2
    echo "Make $effective/$name exit with the status of $common/hooks/$name. The hooks are NOT active." >&2
    status=2
    continue
  fi
  out=$(run_hook "$name" 2>&1 </dev/null || true)
  case "$out" in
    *leakcheck*|*tools/hooks/*) ;;
    *)
      echo "install.sh: the $name stub did not reach tools/hooks/$name or the scanner. The hooks are NOT active." >&2
      status=2 ;;
  esac
done
rm -f "$msg"
[ "$status" -eq 0 ] && echo "verified: git reaches the stubs through $effective, and a failing stub fails git"
exit "$status"
