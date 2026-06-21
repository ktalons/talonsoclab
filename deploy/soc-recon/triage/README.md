# Triage queue

The human checkpoint. Recon's `diff.py` drops one markdown file per run here,
containing **only what changed since the last run**. Nothing is auto-submitted
anywhere — you review, you decide, you write up what's worth reporting.

## File naming

- `YYYYMMDDTHHMMSSZ_baseline.md` — first run; records counts, no deltas (avoids day-one flood).
- `YYYYMMDDTHHMMSSZ_delta.md`    — subsequent runs; new subdomains + new nuclei findings.

## Delta file shape

```markdown
# New since last run — 20260620T030000Z

## New subdomains (3)
- [ ] `staging.example.com`
- [ ] `vpn-test.example.com`
- [ ] `grafana.example.com`

## New nuclei findings (2)
- [ ] **[MEDIUM]** Exposed Grafana login — `https://grafana.example.com/login`
  `grafana-detect`
- [ ] **[LOW]** Git config exposure — `https://staging.example.com/.git/config`
  `git-config`
```

Check the box when you've triaged an item. New does not mean reportable: dedupe against
what you've already submitted, confirm it's in scope, and verify it's a real issue before
writing anything up.

## Upgrade path

When markdown-in-a-folder gets cramped, the same `diff.py` output maps cleanly onto a
lightweight board (single-table SQLite + a small web view, or a Kanban tool). Keep the
human gate regardless of the UI.
