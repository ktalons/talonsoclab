#!/usr/bin/env python3
"""Compare today's recon output against the previous run.
Emits ONLY new assets / findings into the triage queue. A human reviews the
queue; nothing here auto-submits anywhere."""
import argparse
import json
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def load_lines(path: Path) -> set:
    if not path.exists():
        return set()
    return {ln.strip() for ln in path.read_text().splitlines() if ln.strip()}


def load_nuclei(path: Path) -> dict:
    """Return {signature: record}. Signature = template-id + where it matched."""
    findings = {}
    if not path.exists():
        return findings
    for ln in path.read_text().splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        tid = rec.get("template-id") or rec.get("templateID") or "unknown"
        matched = rec.get("matched-at") or rec.get("host") or ""
        findings[f"{tid}::{matched}"] = rec
    return findings


def severity_of(rec: dict) -> str:
    return (rec.get("info", {}).get("severity") or "unknown").lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--current", required=True)
    ap.add_argument("--previous", required=True)
    ap.add_argument("--triage-dir", required=True)
    ap.add_argument("--run-ts", required=True)
    args = ap.parse_args()

    cur = Path(args.current)
    prev = Path(args.previous) if args.previous != "/dev/null" else None
    triage = Path(args.triage_dir)
    triage.mkdir(parents=True, exist_ok=True)

    cur_subs = load_lines(cur / "subdomains.txt")
    cur_find = load_nuclei(cur / "nuclei.jsonl")

    # First run: record a baseline, don't flood the queue with everything.
    if prev is None:
        (triage / f"{args.run_ts}_baseline.md").write_text(
            f"# Recon baseline — {args.run_ts}\n\n"
            f"- Subdomains tracked: {len(cur_subs)}\n"
            f"- Nuclei findings tracked: {len(cur_find)}\n\n"
            "_Baseline run. Future runs queue only deltas._\n"
        )
        print(f"[diff] baseline: {len(cur_subs)} subs, {len(cur_find)} findings")
        return

    prev_subs = load_lines(prev / "subdomains.txt")
    prev_find = load_nuclei(prev / "nuclei.jsonl")

    new_subs = sorted(cur_subs - prev_subs)
    new_keys = [k for k in cur_find if k not in prev_find]

    if not new_subs and not new_keys:
        print("[diff] no new assets or findings since last run")
        return

    lines = [f"# New since last run — {args.run_ts}", ""]

    if new_subs:
        lines.append(f"## New subdomains ({len(new_subs)})")
        lines += [f"- [ ] `{s}`" for s in new_subs]
        lines.append("")

    if new_keys:
        new_keys.sort(key=lambda k: SEV_ORDER.get(severity_of(cur_find[k]), 9))
        lines.append(f"## New nuclei findings ({len(new_keys)})")
        for k in new_keys:
            rec = cur_find[k]
            info = rec.get("info", {})
            name = info.get("name", "?")
            sev = severity_of(rec).upper()
            matched = rec.get("matched-at") or rec.get("host") or "?"
            tid = rec.get("template-id", "?")
            lines.append(f"- [ ] **[{sev}]** {name} — `{matched}`  \n  `{tid}`")
        lines.append("")

    out = triage / f"{args.run_ts}_delta.md"
    out.write_text("\n".join(lines))
    print(f"[diff] queued {len(new_subs)} subs, {len(new_keys)} findings -> {out}")


if __name__ == "__main__":
    main()
