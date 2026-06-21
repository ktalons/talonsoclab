#!/usr/bin/env python3
"""SOC digest + CASA intake builder (TalonSocLab data plane).

Pulls two streams into a human-readable digest AND a structured intake artifact:
  1. Detections — high-severity Wazuh alerts from the indexer (OpenSearch).
  2. Attack surface — the newest recon delta(s) from the triage queue.

Division of labor (this is the architecture — don't blur it):
  * THIS script (TalonSocLab) is deterministic infrastructure. It collects, filters,
    cites, and emits artifacts. It does NOT reason and does NOT decide.
  * CASA (github.com/ktalons/casa-ai-agent) is the separate reasoning plane — a
    PAI-based multi-agent system (Overseer / LogAnalyst / NetworkAnalyst /
    PurpleTeamMapper / Pentester) that consumes the {date}-intake.json written here
    and produces explainable, NIST-aligned, human-in-the-loop analysis. THAT is the
    capstone — not an LLM call buried in this file.

Outputs per run:
  * {date}-digest.md   — deterministic human-readable digest (no LLM).
  * {date}-intake.json — structured handoff CASA reasons over.

--alerts-file replays recorded attack data for repeatable evals: feed the same intake
to CASA and measure its reasoning. stdlib only — no pip install, same as diff.py.

The optional --summarize / DIGEST_LLM path is a STANDALONE convenience (a quick inline
Claude rewrite of the markdown). It is NOT the CASA integration and does no agentic
reasoning — the real reasoning layer is CASA consuming the intake JSON.
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from pathlib import Path

SEV_LABEL = [(15, "critical"), (12, "high"), (7, "medium"), (0, "low")]


def level_label(level: int) -> str:
    for floor, name in SEV_LABEL:
        if level >= floor:
            return name
    return "low"


# ─────────────────────────── detections (Wazuh) ───────────────────────────
def fetch_alerts_from_indexer(url, user, password, min_level, lookback):
    """Query wazuh-alerts-* for level>=min_level within the lookback window.

    Returns a list of normalized dicts. Self-signed certs are expected on a
    single-node lab indexer, so verification is disabled deliberately here —
    do NOT copy this ssl context into anything internet-facing.
    """
    query = {
        "size": 200,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": f"now-{lookback}"}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
    }
    req = urllib.request.Request(
        f"{url.rstrip('/')}/wazuh-alerts-*/_search",
        data=json.dumps(query).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + b64encode(f"{user}:{password}".encode()).decode(),
        },
        method="POST",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        hits = json.loads(resp.read()).get("hits", {}).get("hits", [])
    return [normalize_alert(h.get("_source", {})) for h in hits]


def normalize_alert(src: dict) -> dict:
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    return {
        "level": int(rule.get("level", 0)),
        "description": rule.get("description", "?"),
        "rule_id": rule.get("id", "?"),
        "agent": agent.get("name", "?"),
        "mitre": (rule.get("mitre", {}) or {}).get("id", []),
        "timestamp": src.get("@timestamp", "?"),
    }


def load_alerts_file(path: Path) -> list:
    """Offline mode: read recorded alerts (JSON list or JSONL) for repeatable evals."""
    text = path.read_text()
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else data.get("hits", {}).get("hits", [])
    except json.JSONDecodeError:
        records = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    out = []
    for rec in records:
        out.append(normalize_alert(rec.get("_source", rec)))
    return out


# ─────────────────────────── attack surface (recon) ───────────────────────────
def latest_recon_delta(triage_dir: Path) -> str:
    deltas = sorted(triage_dir.glob("*_delta.md"))
    if deltas:
        return deltas[-1].read_text().strip()
    baselines = sorted(triage_dir.glob("*_baseline.md"))
    if baselines:
        return baselines[-1].read_text().strip()
    return "_No recon runs found in the triage queue yet._"


# ─────────────────────────── rendering ───────────────────────────
def render_detections(alerts: list) -> str:
    if not alerts:
        return "- No alerts at or above the severity floor in the window. _(verify the pipeline is live.)_"
    buckets = {"critical": [], "high": [], "medium": [], "low": []}
    for a in alerts:
        buckets[level_label(a["level"])].append(a)
    lines = []
    for sev in ("critical", "high", "medium", "low"):
        items = buckets[sev]
        if not items:
            continue
        lines.append(f"- **{len(items)} {sev}-severity** "
                     f"({'rolled up' if sev in ('medium', 'low') else 'see detail'}):")
        for a in items[:8 if sev in ("critical", "high") else 0]:
            mitre = f" [{', '.join(a['mitre'])}]" if a["mitre"] else ""
            lines.append(f"  - `{a['agent']}` — {a['description']} "
                         f"(rule {a['rule_id']}, level {a['level']}){mitre}")
    return "\n".join(lines)


def build_intake(date_str, alerts, recon_text) -> dict:
    """The structured handoff CASA reasons over. Deterministic collection only —
    no analysis, no scoring, no decisions. CASA's agents add all of that."""
    return {
        "schema": "talonsoclab.soc-intake/v1",
        "generated": date_str,
        "source": "talonsoclab",
        "consumer": "casa-ai-agent (github.com/ktalons/casa-ai-agent)",
        "detections": alerts,            # normalized Wazuh alerts, already cited
        "recon_delta": recon_text,       # newest triage delta, verbatim
        "note": "Deterministic intake. Reasoning happens in CASA, not here.",
    }


def build_template_digest(date_str, detections_md, recon_md) -> str:
    return (
        f"# Daily digest — {date_str}\n\n"
        "_Built by the TalonSocLab digest collector from two sources: the Wazuh alert "
        "stream and the recon diff output. Deterministic summary — every item links back "
        "to the raw record. Agentic analysis is CASA's job; this is its intake._\n\n"
        "## Attack surface (recon)\n"
        f"{recon_md}\n\n"
        "## Detections (Wazuh)\n"
        f"{detections_md}\n\n"
        "## Suggested focus\n"
        "1. Triage the newest recon delta in `triage/` — is anything actually exposed?\n"
        "2. Confirm the top detection isn't your own admin activity before escalating.\n\n"
        "---\n"
        "_Sources: `data/recon/<run>/`, Wazuh indexer query "
        "`rule.level>=12 AND @timestamp>now-24h`._\n"
    )


def summarize(date_str, detections_md, recon_md) -> str:
    """Optional inline LLM rewrite. Off unless DIGEST_LLM=1 and a key is present.

    STANDALONE CONVENIENCE ONLY — this is a one-shot Claude rewrite of the digest
    markdown for quick reading. It is NOT the CASA integration and does no agentic
    reasoning; the model only ever sees data already filtered + cited above. The real
    reasoning layer is CASA consuming {date}-intake.json. Keep this dumb on purpose."""
    if os.getenv("DIGEST_LLM", "0") != "1":
        return build_template_digest(date_str, detections_md, recon_md)

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("[digest] DIGEST_LLM=1 but ANTHROPIC_API_KEY is empty — "
              "falling back to deterministic template.", file=sys.stderr)
        return build_template_digest(date_str, detections_md, recon_md)

    raw = build_template_digest(date_str, detections_md, recon_md)
    prompt = (
        "You are a SOC shift-lead writing the morning digest. Below is a machine-built "
        "digest of overnight detections and attack-surface changes. Rewrite it to be "
        "tighter and prioritized. RULES: invent nothing; every claim must trace to the "
        "input; keep all rule IDs, hostnames, and source links; if something is "
        "ambiguous say so rather than guessing. Output markdown only.\n\n"
        f"---\n{raw}\n---"
    )
    body = json.dumps({
        "model": os.getenv("DIGEST_LLM_MODEL", "claude-haiku-4-5-20251001"),
        "max_tokens": 1500,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.loads(resp.read())
        return "".join(b.get("text", "") for b in out.get("content", [])) or raw
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"[digest] LLM call failed ({e}); using deterministic template.", file=sys.stderr)
        return raw


def main():
    ap = argparse.ArgumentParser(
        description="Build the deterministic SOC digest + CASA intake artifact.")
    ap.add_argument("--triage-dir", default="triage")
    ap.add_argument("--out-dir", default="digest")
    ap.add_argument("--alerts-file", help="Offline: read alerts from this JSON/JSONL "
                                          "instead of the live indexer (for evals).")
    ap.add_argument("--summarize", action="store_true",
                    help="Inline LLM rewrite of the markdown (standalone convenience, "
                         "NOT the CASA integration). Equivalent to DIGEST_LLM=1.")
    ap.add_argument("--stdout", action="store_true", help="Print digest instead of writing files.")
    args = ap.parse_args()
    if args.summarize:
        os.environ["DIGEST_LLM"] = "1"

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if args.alerts_file:
        alerts = load_alerts_file(Path(args.alerts_file))
    else:
        url = os.getenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
        user = os.getenv("WAZUH_INDEXER_USER", "admin")
        password = os.getenv("WAZUH_INDEXER_PASS", "")
        if not password:
            print("[digest] WAZUH_INDEXER_PASS is empty — set it in .env or use "
                  "--alerts-file for offline mode.", file=sys.stderr)
            sys.exit(2)
        try:
            alerts = fetch_alerts_from_indexer(
                url, user, password,
                int(os.getenv("DIGEST_MIN_LEVEL", "12")),
                os.getenv("DIGEST_LOOKBACK", "24h"),
            )
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"[digest] could not reach indexer: {e}", file=sys.stderr)
            sys.exit(1)

    detections_md = render_detections(alerts)
    recon_md = latest_recon_delta(Path(args.triage_dir))
    digest = summarize(date_str, detections_md, recon_md)
    intake = build_intake(date_str, alerts, recon_md)

    if args.stdout:
        print(digest)
        return
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    digest_path = out_dir / f"{date_str}-digest.md"
    intake_path = out_dir / f"{date_str}-intake.json"
    digest_path.write_text(digest)
    intake_path.write_text(json.dumps(intake, indent=2) + "\n")
    print(f"[digest] wrote {digest_path} + {intake_path} ({len(alerts)} alerts, "
          f"mode={'llm' if os.getenv('DIGEST_LLM') == '1' else 'template'}) "
          f"— hand the intake to CASA for reasoning")


if __name__ == "__main__":
    main()
