# soc-recon

Single Docker host — the HP EliteDesk 800 G4 Mini (i5-8500T, 16 GB RAM, 256 GB NVMe)
that TalonSocLab now owns outright. Two workloads, unequal priority:

- **Wazuh SOC stack** — always-on. Memory *reservation* + OOM protection.
- **Recon pipeline** — cron-launched, ephemeral. Hard memory *cap* + OOM-preferred. Yields to Wazuh.

Endpoints are **Wazuh agents on real devices** (your daily Windows box w/ Sysmon, your
Mac, the Ubuntu host itself) — no endpoint VMs run on this box, so the 16 GB budget stays
clear for the SOC stack. The recon pipeline starts pointed at **your own assets only**;
external/bug-bounty scope is a later, separately-authorized expansion (see `scope/`).

## Why Wazuh wins under pressure

Four mechanisms stack — `mem_reservation` alone is only a soft hint:

1. `mem_reservation` on Wazuh = soft floor the kernel honors under contention.
2. `mem_limit` on recon = hard ceiling; a runaway scan is OOM-killed, never the host.
3. `oom_score_adj` (−700 Wazuh / +800 recon) = if memory gets tight, recon dies first.
4. **Recon isn't running most of the time.** `profiles:` keeps it out of `docker compose up`;
   cron invokes `docker compose run --rm recon-runner`, which exists only while the job runs
   and leaves zero footprint afterward.

(3) + (4) are the real guarantee. (1) just biases the kernel; don't lean on it alone.

## Layout

```
docker-compose.yml          resource limits + recon profile + indexer healthcheck
.env.example                WAZUH_VERSION, INDEXER_HEAP, digest config
recon/
  Dockerfile                subfinder + httpx + nuclei + diff, one slim image
  run-recon.sh              the pipeline (enum -> probe -> scan -> diff -> triage)
  diff.py                   today vs last run; queues only what's new
scope/
  domains.txt.example       copy to domains.txt (gitignored) — IN-SCOPE targets only
triage/README.md            what the human-review queue looks like
digest/
  example-digest.md         target output of the daily digest
  generate_digest.py        deterministic digest + CASA intake builder (see "CASA" below)
wazuh/custom-rules/         Sigma-converted rule XML mounts here (Phase B)
crontab.example             host cron lines (recon + digest)
```

## Resource budget — 16 GB host

Tuned so Wazuh always wins and nothing swaps. Hard ceilings (`mem_limit`):

| Service | heap | reservation | hard cap | notes |
|---|---|---|---|---|
| wazuh.indexer | 2g | 2g | 4g | the hog; `INDEXER_HEAP` in `.env`, keep == reservation |
| wazuh.manager | — | 1g | 1.5g | modest with a handful of real-device agents |
| wazuh.dashboard | — | 512m | 1g | UI only |
| recon-runner | — | — | 2g | ephemeral; runs, exits, frees |

Always-on ≈ **6.5 GB cap** + ~1.5 GB OS ≈ 8 GB, leaving ~8 GB headroom for the recon
burst and the occasional Atomic Red Team run. Raise `INDEXER_HEAP` only after a RAM upgrade.

**Disk (256 GB) is the tighter limit.** The `indexer_data` volume grows with alert volume.
Set a Wazuh ISM retention policy (delete `wazuh-alerts-*` older than ~45 days) and watch
`df -h`. This is the first thing that bites on the stock NVMe.

## Host prerequisites

- `sysctl -w vm.max_map_count=262144` (persist in /etc/sysctl.conf) — the Wazuh indexer needs it.
- `cp .env.example .env` and set `WAZUH_INDEXER_PASS` (digest needs it); keep `.env` out of git.
- `cp scope/domains.txt.example scope/domains.txt` — start with your own assets only.
- The recon container runs as uid 10001; make the bind mount writable: `chown -R 10001 data`
  (or run Docker rootless) so writes to `./data` succeed.
- This skeleton overlays the **resource model**. For a complete Wazuh single-node deploy
  (cert generation, indexer security config, dashboard), start from the official
  `wazuh-docker` single-node compose and fold these constraints + the recon service into it.

## Run

```bash
cp .env.example .env          # set WAZUH_VERSION, INDEXER_HEAP, WAZUH_INDEXER_PASS
cp scope/domains.txt.example scope/domains.txt   # your own assets only, to start
mkdir -p data && chown -R 10001 data

docker compose up -d                       # always-on stack (recon excluded by profile)
docker compose run --rm recon-runner       # recon, one-shot — this is what cron runs

# Daily digest + CASA intake: live indexer mode writes {date}-digest.md + {date}-intake.json
python3 digest/generate_digest.py
# ...or offline, replaying recorded attack data (the intake CASA then reasons over):
python3 digest/generate_digest.py --alerts-file samples/attack-day.json --stdout
```

Nothing auto-submits anywhere. Recon writes deltas to `triage/`; the digest only
collects and cites — you review and decide.

## CASA — where the reasoning actually happens

This bundle is the **data plane**. It is deterministic on purpose: it collects, filters,
cites, and emits `digest/{date}-intake.json`. It does not analyze.

**[CASA](https://github.com/ktalons/casa-ai-agent)** (Cybersecurity Analysis Support Agent)
is the separate **reasoning plane** — a PAI-based multi-agent system on Claude/Claude Code
(Overseer, LogAnalyst, NetworkAnalyst, PurpleTeamMapper, Pentester) that consumes the intake
artifact and produces explainable, NIST-aligned, human-in-the-loop analysis. That integration
is CASA's roadmap item; TalonSocLab's job is to hand it clean, well-cited telemetry.

The `--alerts-file` offline mode is the eval harness: feed CASA recorded attack data and
measure its reasoning against ground truth. The inline `--summarize` / `DIGEST_LLM` toggle is
*not* CASA — it's a throwaway one-shot rewrite for quick reading. Don't confuse the two.

### Future direction — a local reasoning + egress-privacy tier (not built yet)

The digest is deliberately a deterministic chokepoint, which makes it the natural place to
grow a **guarded middle tier** between this data plane and any external reasoning agent. Two
jobs, one layer, recorded here so the design intent isn't lost:

1. **Environment-aware local model** — a small, fine-tuned model that learns *this* network's
   baseline (familiar hosts, services, artifacts) so it can pre-triage locally: recognize
   "normal for us" vs. genuinely anomalous, and shrink what ever needs to leave the box.
2. **Egress privacy gateway** — before any artifact is handed to an external agent
   (Claude / OpenAI / Gemini), encrypt / redact / tokenize sensitive and protected data.
   The external agent reasons over sanitized artifacts; raw PII, secrets, and internal
   identifiers never cross the perimeter.

This sits cleanly on the `intake.json` path without disturbing the two-plane split — it just
becomes a sanitizing, locally-aware stage the intake passes through on its way out. Deferred
to a later phase; the current deterministic, well-cited intake is what makes it addable later
instead of a rewrite.

## Scheduling alternative

If you'd rather keep everything in Docker instead of host cron, run a tiny always-on
scheduler (e.g. Ofelia) that triggers `recon-runner` on a schedule via the Docker socket.
Trade-off: a small persistent scheduler container vs. one line in the host crontab.
