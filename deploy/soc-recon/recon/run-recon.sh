#!/usr/bin/env bash
# Recon pipeline: subdomain enum -> live probe -> template scan -> diff -> triage.
# Runs against IN-SCOPE targets only. Writes deltas to the triage queue.
# Nothing here submits anywhere — a human reviews the queue.
#
# Flag names track ProjectDiscovery's current CLIs. If a flag errors after a tool
# update, check `<tool> -h`. Pin tool versions in the Dockerfile for stability.
set -euo pipefail

SCOPE_FILE="${SCOPE_FILE:-/scope/domains.txt}"
OUT_DIR="${OUT_DIR:-/data/recon}"
TRIAGE_DIR="${TRIAGE_DIR:-/data/triage}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"

# --- sanity: scope must exist and contain at least one non-comment entry ---
if [[ ! -s "${SCOPE_FILE}" ]] || ! grep -qvE '^[[:space:]]*(#|$)' "${SCOPE_FILE}"; then
  echo "[recon] refusing to run: ${SCOPE_FILE} is empty or has no targets." >&2
  exit 1
fi

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_DIR}/${RUN_TS}"
LATEST="${OUT_DIR}/latest"
mkdir -p "${RUN_DIR}" "${TRIAGE_DIR}"

echo "[recon] ${RUN_TS} — enumerating subdomains"
subfinder -dL "${SCOPE_FILE}" -all -silent -o "${RUN_DIR}/subdomains.txt"

echo "[recon] probing live hosts"
httpx -l "${RUN_DIR}/subdomains.txt" -silent \
      -status-code -title -tech-detect -json -o "${RUN_DIR}/httpx.jsonl"
jq -r 'select(.url != null) | .url' "${RUN_DIR}/httpx.jsonl" > "${RUN_DIR}/live.txt" || true

echo "[recon] template scan (severity: ${NUCLEI_SEVERITY})"
# nuclei may exit non-zero to signal findings; don't let that abort the run.
nuclei -l "${RUN_DIR}/live.txt" -severity "${NUCLEI_SEVERITY}" \
       -jsonl -o "${RUN_DIR}/nuclei.jsonl" || true

echo "[recon] diffing against previous run"
if [[ -L "${LATEST}" ]]; then
  PREV="$(readlink -f "${LATEST}")"
else
  PREV="/dev/null"   # first run -> baseline, no flood
fi
python3 /opt/recon/diff.py \
  --current "${RUN_DIR}" --previous "${PREV}" \
  --triage-dir "${TRIAGE_DIR}" --run-ts "${RUN_TS}"

ln -sfn "${RUN_DIR}" "${LATEST}"
echo "[recon] done — review new items in ${TRIAGE_DIR}"
