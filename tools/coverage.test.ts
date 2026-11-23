// *****************************************************************************
// *Title: coverage.test*
// *Author: Kyle Versluis*
// *Description: Tests for coverage: each refusal planted, each side of a count*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { EXIT } from "./art-harness.ts";
import {
  ATTACK_SHA256,
  buildAttackTsv,
  CoverageError,
  editJson,
  fetchAll,
  layoutFor,
  makeScratch,
  msearchBody,
  NAVIGATOR_VERSION,
  PLANTS,
  buildSection,
  parseAttackTsv,
  parseInstant,
  parseRecord,
  rehash,
  run,
  type Remote,
} from "./coverage.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const EV1 = "20261122T035219Z-95651d";
const EV2 = "20261122T035737Z-cb8eb2";
const T_PASSWORD = "56506854-89d6-46a3-9804-b7fde90791f9";
const T_WHOAMI = "aab580c7-cc30-4a7c-b5a9-46a29066b022";
const COVERAGE = "phase-b-detection/coverage";
const VALIDATION = "phase-b-detection/validation";
const RECORDS = "phase-b-detection/art-runs";
const MISSES = `${VALIDATION}/misses.json`;
const WRITEUP = "phase-b-detection/README.md";
const LITERALS = "phase-b-detection/claims-literals.json";
const FOUR = [100400, 100407, 100410, 100411];
// The rules the second session's fixture evidence validates; edits to the first session leave them.
const SECOND = [100400, 100407];
const PACK_IDS = [100340, 100341, 100342, 100343, 100344, 100400, 100401, 100402, 100403, 100404, 100405, 100406, 100407, 100408, 100409, 100410, 100411, 100412];
const roots: string[] = [];
const quiet = { log: () => {}, err: () => {} };

afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

// *--- Helper Functions ---*

const scratch = (withEvidence = true) => {
  const r = makeScratch(withEvidence);
  roots.push(r);
  return r;
};
const read = (root: string, p: string) => JSON.parse(readFileSync(join(root, p), "utf8"));
const build = (root: string) => run(["build", "--root", root], quiet);
const summaryOf = (root: string) => read(root, `${COVERAGE}/coverage.json`);
const evPath = (s: string) => `${VALIDATION}/${s}.alerts.json`;
const recPath = (s: string) => `${RECORDS}/${s}.json`;

/** The error a call throws, or the exit it returns, so one test can assert on the refusal. */
function refusal(argv: string[]): CoverageError {
  const r = run(argv, quiet);
  if (!r.error) throw new Error(`expected a refusal, got exit ${r.exit}`);
  return r.error;
}

const missEntry = (root: string, e: Record<string, unknown>) => editJson(root, MISSES, (m) => m.entries.push(e));

/** An evidence alert shaped like the fixtures, with the fields a test overrides. */
const alert = (over: Record<string, unknown>) => ({
  index: "wazuh-alerts-4.x-2026.11.22",
  id: "FIXTUREDOCID00000050",
  ruleId: 100410,
  ruleLevel: 12,
  mitre: ["T1003.005"],
  agentId: "001",
  timestamp: "2026-11-22T03:52:41.255Z",
  eventTime: "2026-11-22T03:52:40.014Z",
  systemTime: "2026-11-22T03:52:40.0187207Z",
  eventId: 1,
  channel: "Microsoft-Windows-Sysmon/Operational",
  image: "cmdkey.exe",
  ...over,
});

/** Replace the alerts of one evidence file in a scratch root. */
const setAlerts = (root: string, session: string, alerts: unknown[]) => editJson(root, evPath(session), (e) => (e.alerts = alerts));

/** The raw _msearch answer the index gives for a list of fixture-shaped alerts. */
function answerFor(alerts: ReturnType<typeof alert>[], control: number, shardsFailed = 0): string {
  const shards = { total: 3, successful: 3 - shardsFailed, skipped: 0, failed: shardsFailed };
  const hits = alerts.map((a) => ({
    _index: a.index,
    _id: a.id,
    _source: {
      timestamp: a.timestamp.replace("Z", "+0000"),
      rule: { id: String(a.ruleId), level: a.ruleLevel, mitre: { id: a.mitre } },
      agent: { id: a.agentId },
      data: { win: { system: { eventID: String(a.eventId), channel: a.channel, systemTime: a.systemTime }, eventdata: { utcTime: a.eventTime.replace("T", " ").replace("Z", ""), image: `C:\\Windows\\System32\\${a.image}` } } },
    },
  }));
  const res = (total: number, h: unknown[]) => ({ status: 200, timed_out: false, _shards: shards, hits: { total: { value: total, relation: "eq" }, hits: h } });
  return JSON.stringify({ responses: [res(hits.length, hits), res(control, [])] });
}

const fixtureAlerts = (session: string) => read(ROOT, `tools/fixtures/coverage/${session}.alerts.json`).alerts;

/** A remote that answers each session's query from the fixtures, recording what it was sent. */
function fakeRemote(seen: string[] = []): Remote {
  return (ndjson) => {
    seen.push(ndjson);
    const q = JSON.parse(ndjson.split("\n")[1]);
    const from = q.query.bool.filter[2].range.timestamp.gte as string;
    // Only the two fixture sessions are known; any other span is a test set-up error, not EV2.
    if (!from.startsWith("2026-11-22T03:51") && !from.startsWith("2026-11-22T03:56")) throw new Error(`fakeRemote has no fixture for a span from ${from}`);
    const session = from.startsWith("2026-11-22T03:51") ? EV1 : EV2;
    return { code: 0, out: answerFor(fixtureAlerts(session), 9), timedOut: false };
  };
}

const noScan = () => {};

// *--- Tests ---*

describe("instants", () => {
  test("seven decimals compare exactly", () => {
    const a = parseInstant("2026-11-22T03:52:40.0864581Z", "x", "a");
    const b = parseInstant("2026-11-22T03:52:40.0864582Z", "x", "b");
    expect(b - a).toBe(100n);
  });
  test("a shorter fraction is the same instant padded", () => {
    expect(parseInstant("2026-11-22T03:52:40.014Z", "x", "a")).toBe(parseInstant("2026-11-22T03:52:40.0140000Z", "x", "a"));
  });
  test("a time with no zone is refused", () => {
    expect(() => parseInstant("2026-11-22T03:52:40", "bad", "a")).toThrow(CoverageError);
  });
  test("a date that is not on the calendar is refused", () => {
    expect(() => parseInstant("2026-02-30T03:52:40Z", "bad", "a")).toThrow(CoverageError);
  });
});

describe("technique list", () => {
  const tsv = readFileSync(join(ROOT, "phase-b-detection/attack/enterprise-19.2-techniques.tsv"), "utf8");
  const list = parseAttackTsv(tsv);
  test("holds the counts of the 19.2 bundle", () => {
    expect(list.counts).toEqual({ total: 858, active: 697, revoked: 149, deprecated: 12 });
  });
  test("T1562.001 is revoked by T1685, which is active under defense-impairment", () => {
    expect(list.byId.get("T1562.001")).toMatchObject({ status: "revoked", successor: "T1685" });
    expect(list.byId.get("T1685")).toMatchObject({ status: "active" });
    expect(list.byId.get("T1685")?.tactics).toContain("defense-impairment");
  });
  test("T1027 is active under stealth", () => {
    expect(list.byId.get("T1027")?.tactics).toContain("stealth");
    expect(list.byId.get("T1027")?.status).toBe("active");
  });
  test("a header that no longer matches the rows is refused", () => {
    const bad = tsv.replace("active=697", "active=698");
    expect(() => parseAttackTsv(bad)).toThrow(/header/);
  });
  test("a row out of order is refused", () => {
    const lines = tsv.split("\n");
    const i = lines.findIndex((x) => x.startsWith("T1001\t"));
    [lines[i], lines[i + 1]] = [lines[i + 1], lines[i]];
    expect(() => parseAttackTsv(lines.join("\n"))).toThrow(/order/);
  });
  test("a revoked row with no successor is refused", () => {
    const bad = tsv.replace("T1562.001\trevoked\tT1685", "T1562.001\trevoked\t");
    expect(() => parseAttackTsv(bad)).toThrow(/successor/);
  });
  test("a CRLF file is refused", () => {
    expect(() => parseAttackTsv(tsv.replace("\n", "\r\n"))).toThrow(CoverageError);
  });
});

describe("refresh-attack", () => {
  const bundle = (over: Record<string, unknown> = {}) => {
    const pattern = (id: string, ext: string, extra: Record<string, unknown> = {}) => ({ type: "attack-pattern", id, name: `Name ${ext}`, external_references: [{ source_name: "mitre-attack", external_id: ext }], kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "stealth" }], ...extra });
    return JSON.stringify({
      objects: [
        { type: "x-mitre-collection", x_mitre_version: "19.2", ...over },
        pattern("attack-pattern--a", "T1001"),
        pattern("attack-pattern--b", "T1002", { revoked: true }),
        pattern("attack-pattern--c", "T1003", { x_mitre_deprecated: true }),
        { type: "relationship", relationship_type: "revoked-by", source_ref: "attack-pattern--b", target_ref: "attack-pattern--a" },
      ],
    });
  };
  const sha = (s: string) => new Bun.CryptoHasher("sha256").update(s).digest("hex");
  test("a bundle with the expected hash makes a list that reads back", () => {
    const b = bundle();
    const text = buildAttackTsv(new TextEncoder().encode(b), sha(b));
    expect(text).toContain("T1002\trevoked\tT1001\tstealth\tName T1002");
    expect(text).toContain("T1003\tdeprecated\t\t");
  });
  test("a hash that is not the expected one is refused", () => {
    const b = bundle();
    expect(() => buildAttackTsv(new TextEncoder().encode(b), "0".repeat(64))).toThrow(/SHA-256/);
  });
  test("the pinned hash refuses a different bundle", () => {
    expect(() => buildAttackTsv(new TextEncoder().encode(bundle()), ATTACK_SHA256)).toThrow(/SHA-256/);
  });
  test("a bundle of another collection version is refused", () => {
    const b = bundle({ x_mitre_version: "19.1" });
    expect(() => buildAttackTsv(new TextEncoder().encode(b), sha(b))).toThrow(/19\.1/);
  });
  test("a revoked pattern with no revoked-by is refused", () => {
    const b = bundle().replace('"relationship_type":"revoked-by"', '"relationship_type":"subtechnique-of"');
    expect(() => buildAttackTsv(new TextEncoder().encode(b), sha(b))).toThrow(/successor/);
  });
  test("the real bundle regenerates the checked-in list byte for byte", () => {
    const path = join(process.env.HOME ?? "", "code/attack-stix-data/enterprise-attack-19.2.json");
    // A missing bundle fails here: a test that returns early would pass without checking anything.
    expect(existsSync(path)).toBe(true);
    const text = buildAttackTsv(readFileSync(path), ATTACK_SHA256);
    expect(text).toBe(readFileSync(join(ROOT, "phase-b-detection/attack/enterprise-19.2-techniques.tsv"), "utf8"));
  });
});

describe("the checked-in outputs", () => {
  test("check passes on the repo as it stands", () => {
    expect(run(["check"], quiet).exit).toBe(EXIT.ok);
  });
  // These read the repo as it stands, so they hold whatever a live fetch has or has not added.
  test("the summary is self-consistent and validates only what has evidence", () => {
    const s = read(ROOT, `${COVERAGE}/coverage.json`);
    const evidence = readdirSync(join(ROOT, VALIDATION)).filter((n) => n.endsWith(".alerts.json"));
    expect(s.packSize).toBe(18);
    expect(s.ratio).toEqual({ validated: s.validatedRules.length, of: 18 });
    if (evidence.length === 0) expect(s.validatedRules).toEqual([]);
    for (const id of s.validatedRules) expect(PACK_IDS).toContain(id);
    expect(s.complete).toBe(s.unclassified.length === 0);
    expect(s.unclassified.filter((id: number) => s.validatedRules.includes(id))).toEqual([]);
  });
  test("the validation folder holds only the miss list and evidence files", () => {
    for (const n of readdirSync(join(ROOT, VALIDATION)).filter((x) => !x.startsWith("."))) expect(n === "misses.json" || n.endsWith(".alerts.json")).toBe(true);
  });
  test("the crosswalk is sixteen identity entries", () => {
    const c = read(ROOT, "phase-b-detection/attack/crosswalk.json");
    expect(c.entries).toHaveLength(16);
    for (const e of c.entries) expect(e).toMatchObject({ how: "unchanged", to: e.from });
  });
});

describe("real data", () => {
  test("four live alerts and two real records validate exactly four of eighteen", () => {
    const root = scratch();
    expect(build(root).exit).toBe(EXIT.ok);
    const s = summaryOf(root);
    expect(s.validatedRules).toEqual(FOUR);
    expect(s.ratio).toEqual({ validated: 4, of: 18 });
    expect(s.packSize).toBe(18);
    expect(s.complete).toBe(false);
    expect(s.unclassified).toHaveLength(14);
    expect(s.unclassified).not.toContain(100410);
    expect(s.uncounted).toEqual([]);
  });
  test("each validated row names its session, test, index, document and both times", () => {
    const root = scratch();
    build(root);
    const row = summaryOf(root).rules.find((r: { rule: number }) => r.rule === 100410);
    expect(row.status).toBe("validated");
    expect(row.validation).toEqual({
      session: EV1,
      test: T_PASSWORD,
      art: "T1003.005 #1",
      alertIndex: "wazuh-alerts-4.x-2026.11.22",
      docId: "FIXTUREDOCID00000001",
      eventTime: "2026-11-22T03:52:40.014Z",
      indexTime: "2026-11-22T03:52:41.255Z",
    });
    expect(row.miss).toBeNull();
  });
  test("the validated layer scores the four techniques and carries each art test", () => {
    const root = scratch();
    build(root);
    const layer = read(root, `${COVERAGE}/layer-validated.json`);
    const t = (id: string) => layer.techniques.find((x: { techniqueID: string }) => x.techniqueID === id);
    expect(t("T1003.005").score).toBe(1);
    expect(t("T1003.005").comment).toContain("art:T1003.005 #1");
    expect(t("T1033").score).toBe(1);
    expect(t("T1037.001").score).toBe(1);
    expect(t("T1547.001").score).toBe(1);
    expect(t("T1105")).toBeUndefined();
  });
});

describe("what counts as validated", () => {
  test("an index time inside the window but an event time after the end does not count", () => {
    const root = scratch();
    // The run ends 03:52:40.0864581; the event is 03:52:41 but was indexed at 03:52:40.05.
    setAlerts(root, EV1, [alert({ eventTime: "2026-11-22T03:52:41.000Z", timestamp: "2026-11-22T03:52:40.050Z" })]);
    expect(build(root).exit).toBe(EXIT.ok);
    const s = summaryOf(root);
    expect(s.validatedRules).not.toContain(100410);
    expect(s.uncounted[0]).toMatchObject({ rule: 100410, reason: "outside-run-window" });
  });
  test("an event time inside the window with an index time after it does count", () => {
    const root = scratch();
    setAlerts(root, EV1, [alert({ eventTime: "2026-11-22T03:52:40.014Z", timestamp: "2026-11-22T03:52:43.900Z" })]);
    build(root);
    expect(summaryOf(root).validatedRules).toEqual([...SECOND, 100410]);
  });
  test("an event at the exact start instant counts and one a tenth of a microsecond before does not", () => {
    const root = scratch();
    setAlerts(root, EV1, [
      alert({ id: "FIXTUREDOCID00000060", eventTime: "2026-11-22T03:52:39.2612243Z" }),
      alert({ id: "FIXTUREDOCID00000061", ruleId: 100411, eventTime: "2026-11-22T03:52:45.5162034Z" }),
    ]);
    build(root);
    const s = summaryOf(root);
    expect(s.validatedRules).toEqual([...SECOND, 100410]);
    expect(s.uncounted.map((u: { id: string }) => u.id)).toEqual(["FIXTUREDOCID00000061"]);
  });
  test("an event at the exact end instant counts and one a tenth of a microsecond after does not", () => {
    const root = scratch();
    setAlerts(root, EV1, [
      alert({ id: "FIXTUREDOCID00000060", eventTime: "2026-11-22T03:52:40.0864581Z" }),
      alert({ id: "FIXTUREDOCID00000061", ruleId: 100411, eventTime: "2026-11-22T03:52:46.5268895Z" }),
    ]);
    build(root);
    const s = summaryOf(root);
    expect(s.validatedRules).toEqual([...SECOND, 100410]);
    expect(s.uncounted[0]).toMatchObject({ id: "FIXTUREDOCID00000061", reason: "outside-run-window" });
  });
  test("an alert in the cleanup window does not count", () => {
    const root = scratch();
    setAlerts(root, EV1, [alert({ eventTime: "2026-11-22T03:52:42.500Z" })]);
    build(root);
    expect(summaryOf(root).uncounted[0].reason).toBe("outside-run-window");
  });
  test("an alert in the gap between two tests does not count", () => {
    const root = scratch();
    setAlerts(root, EV1, [alert({ eventTime: "2026-11-22T03:52:44.000Z" })]);
    build(root);
    expect(summaryOf(root).validatedRules).toEqual(SECOND);
  });
  test("a rule that the test in whose window it fired does not list does not count", () => {
    const root = scratch();
    // 100411 fired inside the first test's window, whose rules list only 100410.
    setAlerts(root, EV1, [alert({ ruleId: 100411, eventTime: "2026-11-22T03:52:40.014Z" })]);
    build(root);
    const s = summaryOf(root);
    expect(s.validatedRules).toEqual(SECOND);
    expect(s.uncounted[0]).toMatchObject({ rule: 100411, reason: "rule-not-in-test-rules" });
  });
  test("a record that says pass while it lists a failure is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.failures.push("planted failure"));
    rehash(root);
    expect(refusal(["build", "--root", root]).code).toBe("record-verdict");
  });
  test("a millisecond event time counts only when the whole millisecond is inside the window", () => {
    const root = scratch();
    // The window's end is moved to fall inside the alert's own millisecond: .014 could be up to .014999999.
    const ev = read(root, evPath(EV1));
    const a = ev.alerts.find((x: { ruleId: number }) => x.ruleId === 100410);
    const ms = a.eventTime.replace("Z", "");
    editJson(root, recPath(EV1), (r) => {
      const t = r.tests.find((x: { rules: number[] }) => x.rules.includes(100410));
      t.run.endUtc = `${ms}5000Z`;
      t.cleanup.startUtc = `${ms}6000Z`;
    });
    rehash(root);
    build(root);
    expect(summaryOf(root).validatedRules).toEqual([100400, 100407, 100411]);
    // Seven decimals cannot reach the last nanosecond of that millisecond, so .0149999 still does not hold it.
    editJson(root, recPath(EV1), (r) => {
      const t = r.tests.find((x: { rules: number[] }) => x.rules.includes(100410));
      t.run.endUtc = `${ms}9999Z`;
      t.cleanup.startUtc = `${ms}9999Z`;
    });
    rehash(root);
    build(root);
    expect(summaryOf(root).validatedRules).toEqual([100400, 100407, 100411]);
    // An end in the next millisecond holds all of it, and the alert counts.
    const next = `${ms.slice(0, -3)}${String(Number(ms.slice(-3)) + 1).padStart(3, "0")}`;
    editJson(root, recPath(EV1), (r) => {
      const t = r.tests.find((x: { rules: number[] }) => x.rules.includes(100410));
      t.run.endUtc = `${next}0000Z`;
      t.cleanup.startUtc = `${next}0000Z`;
    });
    rehash(root);
    build(root);
    expect(summaryOf(root).validatedRules).toEqual(FOUR);
  });
  test("a pack rule with no mitre id is refused", () => {
    const root = scratch();
    const p = join(root, "deploy/soc-recon/wazuh/custom-rules/local_eid22_pack.xml");
    const xml = readFileSync(p, "utf8");
    const cut = xml.replace(/\s*<mitre>[\s\S]*?<\/mitre>/, "");
    expect(cut).not.toBe(xml);
    writeFileSync(p, cut);
    expect(refusal(["build", "--root", root]).code).toBe("pack-rule-no-mitre");
  });
  test("a folder with a record's name is refused by name", () => {
    const root = scratch();
    mkdirSync(join(root, "phase-b-detection/art-runs/20261122T999999Z-aaaaaa.json"));
    const r = refusal(["build", "--root", root]);
    expect(r.item).toContain("20261122T999999Z-aaaaaa.json");
  });
  test("a session whose verdict is fail counts nothing", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => {
      r.verdict = "fail";
      r.failures.push("planted failure");
    });
    rehash(root);
    build(root);
    const s = summaryOf(root);
    expect(s.validatedRules).toEqual([100400, 100407]);
    expect(s.uncounted.map((u: { reason: string }) => u.reason)).toEqual(["session-verdict-not-pass", "session-verdict-not-pass"]);
  });
  test("a Defender alert is never a pack alert and is not listed as one", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => e.alerts.push(alert({ id: "FIXTUREDOCID00000070", ruleId: 62123, ruleLevel: 7, mitre: [], image: null })));
    build(root);
    expect(summaryOf(root).uncounted).toEqual([]);
  });
  test("when two alerts count for one rule the earliest is the row's", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => e.alerts.push(alert({ id: "FIXTUREDOCID00000071", eventTime: "2026-11-22T03:52:39.900Z" })));
    build(root);
    expect(summaryOf(root).rules.find((r: { rule: number }) => r.rule === 100410).validation.docId).toBe("FIXTUREDOCID00000071");
  });
  test("an alert for a pack-range rule that is not in the XML and fired in a window is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => {
      e.query.rules.push(100499);
      e.alerts.push(alert({ id: "FIXTUREDOCID00000072", ruleId: 100499 }));
    });
    const e = refusal(["build", "--root", root]);
    expect(e.code).toBe("validated-not-subset");
  });
  test("the same alert outside every window for a rule not in the XML is listed, not refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => {
      e.query.rules.push(100499);
      e.alerts.push(alert({ id: "FIXTUREDOCID00000072", ruleId: 100499, eventTime: "2026-11-22T03:52:50.500Z", timestamp: "2026-11-22T03:52:51.000Z" }));
    });
    expect(build(root).exit).toBe(EXIT.ok);
    expect(summaryOf(root).uncounted[0]).toMatchObject({ rule: 100499, reason: "rule-not-in-xml" });
  });
});

describe("misses", () => {
  const allNotRun = (root: string, except: number[] = []) => {
    for (const id of PACK_IDS.filter((x) => !FOUR.includes(x) && !except.includes(x))) missEntry(root, { rule: id, class: "not-run", evidence: "No ART test stages this rule.", ruling: "Kyle ruled it out of B.5." });
  };
  test("complete is false while any not-validated rule has no entry", () => {
    const root = scratch();
    allNotRun(root, [100344]);
    build(root);
    const s = summaryOf(root);
    expect(s.complete).toBe(false);
    expect(s.unclassified).toEqual([100344]);
    expect(run(["check", "--final", "--root", root], quiet).exit).toBe(EXIT.refused);
  });
  test("complete is true only when every not-validated rule has a valid entry", () => {
    const root = scratch();
    allNotRun(root);
    expect(build(root).exit).toBe(EXIT.ok);
    const s = summaryOf(root);
    expect(s.complete).toBe(true);
    expect(s.unclassified).toEqual([]);
    expect(s.rules.find((r: { rule: number }) => r.rule === 100344).miss).toMatchObject({ class: "not-run", ruling: "Kyle ruled it out of B.5." });
  });
  test("check --final passes once the outputs are current and complete", () => {
    const root = scratch();
    allNotRun(root);
    build(root);
    expect(run(["check", "--final", "--root", root], quiet).exit).toBe(EXIT.ok);
  });
  test("an unclassified rule is not a refusal", () => {
    const root = scratch();
    expect(build(root).exit).toBe(EXIT.ok);
  });
  test("a blocked-by-defender entry that cites a Defender alert inside the run window is accepted", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.tests[0].rules.push(100405));
    rehash(root);
    editJson(root, evPath(EV1), (e) => e.alerts.push(alert({ id: "FIXTUREDOCID00000080", ruleId: 62123, ruleLevel: 7, mitre: [], image: null, eventTime: "2026-11-22T03:52:39.500Z" })));
    missEntry(root, { rule: 100405, class: "blocked-by-defender", evidence: "Defender blocked the image at 03:52:39.", session: EV1, test: T_PASSWORD, alertId: "FIXTUREDOCID00000080" });
    expect(build(root).exit).toBe(EXIT.ok);
    expect(summaryOf(root).rules.find((r: { rule: number }) => r.rule === 100405).miss).toMatchObject({ class: "blocked-by-defender", alertId: "FIXTUREDOCID00000080", test: T_PASSWORD });
  });
  test("a blocked-by-defender entry whose Defender alert is outside the run window is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.tests[0].rules.push(100405));
    rehash(root);
    editJson(root, evPath(EV1), (e) => e.alerts.push(alert({ id: "FIXTUREDOCID00000080", ruleId: 62123, ruleLevel: 7, mitre: [], image: null, eventTime: "2026-11-22T03:52:42.500Z" })));
    missEntry(root, { rule: 100405, class: "blocked-by-defender", evidence: "x", session: EV1, test: T_PASSWORD, alertId: "FIXTUREDOCID00000080" });
    expect(refusal(["build", "--root", root]).code).toBe("misses-defender-evidence");
  });
  test("a blocked-by-defender entry that cites a pack alert in place of a Defender one is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.tests[0].rules.push(100405));
    rehash(root);
    missEntry(root, { rule: 100405, class: "blocked-by-defender", evidence: "x", session: EV1, test: T_PASSWORD, alertId: "FIXTUREDOCID00000001" });
    expect(refusal(["build", "--root", root]).code).toBe("misses-defender-evidence");
  });
  test("a miss entry for a rule that is validated is refused", () => {
    const root = scratch();
    missEntry(root, { rule: 100410, class: "sensor-gap", evidence: "x", session: EV1, test: T_PASSWORD });
    expect(refusal(["build", "--root", root]).code).toBe("misses-rule-validated");
  });
  test("a sensor-gap entry for a rule that did not validate, citing a test that ran and lists it, is accepted", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.tests[0].rules.push(100405));
    rehash(root);
    missEntry(root, { rule: 100405, class: "sensor-gap", evidence: "x", session: EV1, test: T_PASSWORD });
    build(root);
    const row = summaryOf(root).rules.find((r: { rule?: number; id?: number }) => (r.rule ?? r.id) === 100405);
    expect(JSON.stringify(row)).toContain("sensor-gap");
    expect(summaryOf(root).unclassified).not.toContain(100405);
  });
  test("an alert in an index named for another day than its timestamp is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.alerts[0].index = "wazuh-alerts-4.x-2026.99.99"));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-index");
    const root2 = scratch();
    editJson(root2, evPath(EV1), (e) => (e.alerts[0].index = "wazuh-alerts-4.x-2026.11.21"));
    expect(refusal(["build", "--root", root2]).code).toBe("evidence-index");
  });
  test("a query that left out the rule of a test that was never sent is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => {
      r.tests.push({ ...r.tests[0], guid: "00000000-0000-4000-8000-000000000002", rules: [100412], run: { startUtc: null, endUtc: null, status: "not-sent", exitCode: null }, cleanup: { startUtc: null, endUtc: null, status: "not-sent", exitCode: null } });
    });
    rehash(root);
    editJson(root, evPath(EV1), (e) => (e.query.rules = e.query.rules.filter((x: number) => x !== 100412)));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-query");
  });
  test("shard counts the index could not report are refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.shards.alerts = { total: 1, successful: 1, skipped: 2, failed: 0 }));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-shards");
  });
  test("a miss that cites a test which was never sent is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => {
      r.tests.push({ ...r.tests[0], guid: "00000000-0000-4000-8000-000000000001", rules: [100405], run: { startUtc: null, endUtc: null, status: "not-sent", exitCode: null }, cleanup: { startUtc: null, endUtc: null, status: "not-sent", exitCode: null } });
    });
    rehash(root);
    missEntry(root, { rule: 100405, class: "rule-gap", evidence: "x", session: EV1, test: "00000000-0000-4000-8000-000000000001" });
    expect(refusal(["build", "--root", root]).code).toBe("misses-test-not-run");
  });
  test("a miss that cites a session with no evidence file is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.tests[0].rules.push(100405));
    rmSync(join(root, evPath(EV1)));
    missEntry(root, { rule: 100405, class: "sensor-gap", evidence: "x", session: EV1, test: T_PASSWORD });
    expect(refusal(["build", "--root", root]).code).toBe("misses-no-evidence");
  });
  test("a technique list edited so its counts still agree is refused by its content pin", () => {
    const root = scratch();
    const p = join(root, "phase-b-detection/attack/enterprise-19.2-techniques.tsv");
    const text = readFileSync(p, "utf8");
    // One revoked row made active and one active row made revoked: the header's counts still match.
    const swapped = text.replace("T1013\trevoked\tT1547.010\t", "T1013\tactive\t\t").replace(/^T1001\tactive\t\t/m, "T1001\trevoked\tT1001.001\t");
    expect(swapped).not.toBe(text);
    writeFileSync(p, swapped);
    expect(refusal(["build", "--root", root]).code).toBe("attack-tsv-pin");
  });
  test("a not-run entry carries no session and a sensor-gap entry may not carry a ruling", () => {
    const root = scratch();
    missEntry(root, { rule: 100405, class: "not-run", evidence: "x", ruling: "y", session: EV1 });
    expect(refusal(["build", "--root", root]).code).toBe("misses-shape");
    const root2 = scratch();
    editJson(root2, recPath(EV1), (r) => r.tests[0].rules.push(100405));
    rehash(root2);
    missEntry(root2, { rule: 100405, class: "sensor-gap", evidence: "x", session: EV1, test: T_PASSWORD, ruling: "y" });
    expect(refusal(["build", "--root", root2]).code).toBe("misses-shape");
  });
  test("bad JSON in the miss list is refused", () => {
    const root = scratch();
    writeFileSync(join(root, MISSES), "{nope");
    expect(refusal(["build", "--root", root]).code).toBe("bad-json");
  });
});

describe("evidence refusals", () => {
  test("a missing field is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => delete e.control);
    expect(refusal(["build", "--root", root]).code).toBe("evidence-shape");
  });
  test("a non-ISO event time is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.alerts[0].eventTime = "2026-11-22 03:52:40.014"));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-time");
  });
  test("a second evidence file for one session is refused", () => {
    const root = scratch();
    cpSync(join(root, evPath(EV1)), join(root, `${VALIDATION}/${EV1}.alerts.json.bak`));
    expect(refusal(["build", "--root", root]).code).toBe("validation-file");
  });
  test("an alert listed twice is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => e.alerts.push(e.alerts[0]));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-duplicate");
  });
  test("a query that does not cover the session's windows is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.query.fromUtc = "2026-11-22T03:52:41.000Z"));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-span");
  });
  test("an alert from a rule the query never asked for is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => {
      // 100412 is no test's rule in this session, so only the per-alert check can catch it.
      e.query.rules = e.query.rules.filter((r: number) => r !== 100412);
      e.alerts.push({ ...e.alerts[0], id: "PLANTEDxUNASKEDxRULE", ruleId: 100412 });
    });
    expect(refusal(["build", "--root", root]).code).toBe("evidence-alerts");
  });
  test("more alerts than the control counted is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.control.agent001Alerts = 1));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-control");
  });
  test("shards that did not all answer are refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.shards.control.successful = 2));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-shards");
  });
  test("a key beyond the closed set is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.alerts[0].message = "full log"));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-alerts");
  });
  test("an index that is a copy of the live one is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.alerts[0].index = "wazuh-alerts-4.x-2026.11.22.bak"));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-index");
  });
  test("the real logtest transcript is refused wherever the tool reads it", () => {
    const transcript = join(ROOT, "tools/fixtures/logtest/transcript-20261106.txt");
    for (const target of [evPath(EV1), MISSES, recPath(EV1), "phase-b-detection/attack/crosswalk.json"]) {
      const root = scratch();
      cpSync(transcript, join(root, target));
      expect(refusal(["build", "--root", root]).code).toBe("logtest-transcript");
    }
  });
  test("the real logtest transcript as the technique list is refused", () => {
    const root = scratch();
    cpSync(join(ROOT, "tools/fixtures/logtest/transcript-20261106.txt"), join(root, "phase-b-detection/attack/enterprise-19.2-techniques.tsv"));
    expect(refusal(["build", "--root", root]).code).toBe("logtest-transcript");
  });
});

describe("record refusals", () => {
  test("a record named for another session is refused", () => {
    const root = scratch();
    cpSync(join(root, recPath(EV1)), join(root, `${RECORDS}/20261122T000000Z-000000.json`));
    rmSync(join(root, recPath(EV1)));
    expect(refusal(["build", "--root", root]).code).toBe("record-name");
  });
  test("a test listed twice is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.tests.push(r.tests[0]));
    expect(refusal(["build", "--root", root]).code).toBe("record-duplicate-guid");
  });
  test("a rule outside the pack ranges in a test is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => r.tests[0].rules.push(5710));
    expect(refusal(["build", "--root", root]).code).toBe("record-rules");
  });
  test("a window with a null start and a real end is refused", () => {
    const root = scratch();
    editJson(root, recPath(EV1), (r) => (r.tests[0].run.startUtc = null));
    expect(refusal(["build", "--root", root]).code).toBe("record-time");
  });
  test("a stray file in art-runs is refused", () => {
    const root = scratch();
    writeFileSync(join(root, `${RECORDS}/notes.txt`), "x");
    expect(refusal(["build", "--root", root]).code).toBe("record-file");
  });
  test("a real record parses into run windows", () => {
    const text = readFileSync(join(ROOT, recPath(EV1)), "utf8");
    const s = parseRecord(recPath(EV1), text);
    expect(s.windows).toHaveLength(2);
    expect(s.windows[0].guid).toBe(T_PASSWORD);
    expect(s.windows[1].guid).toBe(T_WHOAMI);
  });
});

describe("crosswalk refusals", () => {
  const entry = (root: string, from: string, patch: Record<string, unknown>) => editJson(root, "phase-b-detection/attack/crosswalk.json", (c) => Object.assign(c.entries.find((e: { from: string }) => e.from === from), patch));
  test("a missing entry names the id", () => {
    const root = scratch();
    editJson(root, "phase-b-detection/attack/crosswalk.json", (c) => (c.entries = c.entries.filter((e: { from: string }) => e.from !== "T1590")));
    const e = refusal(["build", "--root", root]);
    expect(e.code).toBe("crosswalk-missing");
    expect(e.item).toBe("T1590");
  });
  test("a revoked target is refused", () => {
    const root = scratch();
    entry(root, "T1027", { to: "T1562.001" });
    const e = refusal(["build", "--root", root]);
    expect(e.code).toBe("crosswalk-target-inactive");
    expect(e.item).toBe("T1562.001");
  });
  test("a revoked-by that names the real successor is accepted and moves the rule", () => {
    const root = scratch();
    editJson(root, "phase-b-detection/attack/crosswalk.json", (c) => c.entries.push({ from: "T1562.001", to: "T1685", how: "revoked-by" }));
    expect(build(root).exit).toBe(EXIT.ok);
  });
  test("a duplicate entry is refused", () => {
    const root = scratch();
    editJson(root, "phase-b-detection/attack/crosswalk.json", (c) => c.entries.push(c.entries[0]));
    expect(refusal(["build", "--root", root]).code).toBe("crosswalk-duplicate");
  });
  test("an extra key is refused", () => {
    const root = scratch();
    entry(root, "T1027", { note: "x" });
    expect(refusal(["build", "--root", root]).code).toBe("crosswalk-shape");
  });
});

describe("outputs", () => {
  test("two builds are byte identical", () => {
    const a = scratch();
    const b = scratch();
    build(a);
    build(b);
    for (const n of ["layer-rule-exists.json", "layer-validated.json", "coverage.json"]) {
      expect(readFileSync(join(a, COVERAGE, n), "utf8")).toBe(readFileSync(join(b, COVERAGE, n), "utf8"));
    }
  });
  test("the layers are Navigator 4.5 for enterprise-attack 19 and name no tactic", () => {
    const root = scratch();
    build(root);
    for (const n of ["layer-rule-exists.json", "layer-validated.json"]) {
      const l = read(root, `${COVERAGE}/${n}`);
      expect(l.versions).toEqual({ attack: "19", navigator: NAVIGATOR_VERSION, layer: "4.5" });
      expect(l.domain).toBe("enterprise-attack");
      for (const t of l.techniques) expect(t.tactic).toBeUndefined();
    }
  });
  test("a scored sub-technique brings an unscored parent with its sub-techniques shown", () => {
    const root = scratch();
    build(root);
    const l = read(root, `${COVERAGE}/layer-rule-exists.json`);
    const parent = l.techniques.find((t: { techniqueID: string }) => t.techniqueID === "T1003");
    expect(parent).toMatchObject({ techniqueID: "T1003", showSubtechniques: true });
    expect(parent.score).toBeUndefined();
  });
  test("a parent that is itself mapped keeps its score", () => {
    const root = scratch();
    build(root);
    const l = read(root, `${COVERAGE}/layer-rule-exists.json`);
    const t1105 = l.techniques.find((t: { techniqueID: string }) => t.techniqueID === "T1105");
    expect(t1105.score).toBe(3);
    expect(t1105.comment).toContain("100340, 100343, 100344");
  });
  test("the exists layer scores every one of the 16 mapped techniques", () => {
    const root = scratch(false);
    build(root);
    const l = read(root, `${COVERAGE}/layer-rule-exists.json`);
    expect(l.techniques.filter((t: { score?: number }) => t.score !== undefined)).toHaveLength(16);
  });
  test("the validated layer is a subset of the exists layer", () => {
    const root = scratch();
    build(root);
    const ex = new Map(read(root, `${COVERAGE}/layer-rule-exists.json`).techniques.map((t: { techniqueID: string; score?: number }) => [t.techniqueID, t.score]));
    for (const t of read(root, `${COVERAGE}/layer-validated.json`).techniques) {
      expect(ex.has(t.techniqueID)).toBe(true);
      if (t.score !== undefined) expect(t.score).toBeLessThanOrEqual(ex.get(t.techniqueID) as number);
    }
  });
  test("each rule row carries its ids as written and as 19.2", () => {
    const root = scratch(false);
    build(root);
    const row = summaryOf(root).rules.find((r: { rule: number }) => r.rule === 100406);
    expect(row.attackAsWritten).toEqual(["T1204.002", "T1547.001"]);
    expect(row.attack19).toEqual(["T1204.002", "T1547.001"]);
    expect(row.level).toBe(12);
  });
  test("a refused build leaves the outputs as they were", () => {
    const root = scratch();
    build(root);
    const before = readFileSync(join(root, COVERAGE, "coverage.json"), "utf8");
    editJson(root, evPath(EV1), (e) => (e.alerts[0].agentId = "002"));
    expect(run(["build", "--root", root], quiet).exit).toBe(EXIT.refused);
    expect(readFileSync(join(root, COVERAGE, "coverage.json"), "utf8")).toBe(before);
  });
  test("check fails when the evidence changes after the outputs were built", () => {
    const root = scratch();
    build(root);
    editJson(root, evPath(EV1), (e) => (e.alerts = []));
    const r = run(["check", "--root", root], quiet);
    expect(r.exit).toBe(EXIT.failed);
    expect(r.error?.code).toBe("output-differs");
  });
  test("a missing technique list is a setup problem", () => {
    const root = scratch();
    rmSync(join(root, "phase-b-detection/attack/enterprise-19.2-techniques.tsv"));
    expect(run(["build", "--root", root], quiet).exit).toBe(EXIT.setup);
  });
});

describe("pack reading", () => {
  test("a pack rule defined twice is refused", () => {
    const root = scratch();
    const dir = join(root, "deploy/soc-recon/wazuh/custom-rules");
    const xml = readFileSync(join(dir, "local_eid3_pack.xml"), "utf8");
    writeFileSync(join(dir, "local_eid3_copy.xml"), xml);
    expect(["pack-rule-duplicate", "rules-xml"]).toContain(refusal(["build", "--root", root]).code);
  });
  test("a pack-range rule that carries no crosswalk entry for its mitre id is refused", () => {
    const root = scratch();
    editJson(root, "phase-b-detection/attack/crosswalk.json", (c) => (c.entries = c.entries.filter((e: { from: string }) => e.from !== "T1033")));
    expect(refusal(["build", "--root", root]).item).toBe("T1033");
  });
});

describe("overlapping fetches", () => {
  test("an alert that counted in its own session is not listed as a miss in a neighbouring session's evidence", () => {
    const root = scratch();
    // EV2's fetch span is stretched back over EV1's windows and given a copy of EV1's two alerts.
    const one = read(root, evPath(EV1));
    editJson(root, evPath(EV2), (e) => {
      e.query.fromUtc = one.query.fromUtc;
      e.alerts = [...one.alerts, ...e.alerts];
      e.control.agent001Alerts += one.alerts.length;
    });
    build(root);
    const s = summaryOf(root);
    expect(s.validatedRules).toEqual(FOUR);
    expect(s.uncounted).toEqual([]);
  });
  test("an alert outside every window in two overlapping fetches is listed once", () => {
    const root = scratch();
    const stray = { ...read(root, evPath(EV1)).alerts[0], id: "STRAYxOUTSIDExWINDOW", eventTime: "2026-11-22T03:53:30.000Z", timestamp: "2026-11-22T03:53:31.000Z" };
    editJson(root, evPath(EV1), (e) => e.alerts.push(stray));
    editJson(root, evPath(EV2), (e) => {
      e.query.fromUtc = read(root, evPath(EV1)).query.fromUtc;
      e.alerts = [stray, ...e.alerts];
    });
    build(root);
    const u = summaryOf(root).uncounted;
    expect(u).toHaveLength(1);
    expect(u[0].reason).toBe("outside-run-window");
    expect(u[0].session).toBe(EV1);
  });
});

describe("fetch", () => {
  test("evidence whose query never asked for a rule its session's tests list is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => {
      e.query.rules = e.query.rules.filter((r: number) => r !== 100410);
      e.alerts = e.alerts.filter((a: { ruleId: number }) => a.ruleId !== 100410);
    });
    expect(refusal(["build", "--root", root]).code).toBe("evidence-query");
  });
  test("evidence whose query left out a Defender rule is refused", () => {
    const root = scratch();
    editJson(root, evPath(EV1), (e) => (e.query.rules = e.query.rules.filter((r: number) => r !== 62124)));
    expect(refusal(["build", "--root", root]).code).toBe("evidence-query");
  });
  test("the query is one _msearch body of two queries after the index header", () => {
    const s = parseRecord(recPath(EV1), readFileSync(join(ROOT, recPath(EV1)), "utf8"));
    const { text, query } = msearchBody(s, [100344, 100410, 100411]);
    const lines = text.split("\n");
    expect(query.rules).toEqual([62123, 62124, 100344, 100410, 100411]);
    expect(lines).toHaveLength(5);
    expect(JSON.parse(lines[0])).toEqual({ index: "wazuh-alerts-*" });
    expect(JSON.parse(lines[2])).toEqual({ index: "wazuh-alerts-*" });
    expect(query.fromUtc).toBe("2026-11-22T03:51:39.261Z");
    expect(query.toUtc).toBe("2026-11-22T03:53:49.550Z");
    expect(query.rules).toContain(62123);
    expect(query.rules).toContain(100344);
    const alerts = JSON.parse(lines[1]);
    expect(alerts.query.bool.filter[0]).toEqual({ term: { "agent.id": "001" } });
    expect(JSON.parse(lines[3]).size).toBe(0);
  });
  test("the padding is on the query and the fetched evidence still matches on event time", () => {
    const root = scratch(false);
    const seen: string[] = [];
    const written = fetchAll(layoutFor(root), fakeRemote(seen), noScan);
    expect(written).toHaveLength(2);
    expect(seen).toHaveLength(2);
    for (const s of [EV1, EV2]) expect(read(root, evPath(s)).alerts).toEqual(fixtureAlerts(s));
    build(root);
    expect(summaryOf(root).validatedRules).toEqual(FOUR);
  });
  test("an index time later than the event time by a second is carried through", () => {
    const root = scratch(false);
    fetchAll(layoutFor(root), fakeRemote(), noScan);
    const a = read(root, evPath(EV1)).alerts[0];
    expect(a.timestamp).toBe("2026-11-22T03:52:41.255Z");
    expect(a.eventTime).toBe("2026-11-22T03:52:40.014Z");
    expect(a.systemTime).toBe("2026-11-22T03:52:40.0187207Z");
    expect(a.image).toBe("cmdkey.exe");
  });
  test("a failed shard refuses and writes nothing", () => {
    const root = scratch(false);
    const remote: Remote = () => ({ code: 0, out: answerFor(fixtureAlerts(EV1), 9, 1), timedOut: false });
    expect(() => fetchAll(layoutFor(root), remote, noScan)).toThrow(/shard/);
    expect(readdirSync(join(root, VALIDATION)).filter((n) => n.endsWith(".alerts.json"))).toEqual([]);
  });
  test("a truncated answer refuses and writes nothing", () => {
    const root = scratch(false);
    const remote: Remote = () => {
      const doc = JSON.parse(answerFor(fixtureAlerts(EV1), 9));
      doc.responses[0].hits.total.value = 5;
      return { code: 0, out: JSON.stringify(doc), timedOut: false };
    };
    expect(() => fetchAll(layoutFor(root), remote, noScan)).toThrow(/matched 5/);
    expect(readdirSync(join(root, VALIDATION)).filter((n) => n.endsWith(".alerts.json"))).toEqual([]);
  });
  test("a lower-bound total is refused", () => {
    const root = scratch(false);
    const remote: Remote = () => {
      const doc = JSON.parse(answerFor(fixtureAlerts(EV1), 9));
      doc.responses[1].hits.total.relation = "gte";
      return { code: 0, out: JSON.stringify(doc), timedOut: false };
    };
    expect(() => fetchAll(layoutFor(root), remote, noScan)).toThrow(/exact count/);
  });
  test("an ssh failure is a setup problem and writes nothing", () => {
    const root = scratch(false);
    const remote: Remote = () => ({ code: 255, out: "", timedOut: false });
    try {
      fetchAll(layoutFor(root), remote, noScan);
      throw new Error("did not throw");
    } catch (e) {
      expect(e).toBeInstanceOf(CoverageError);
      expect((e as CoverageError).exit).toBe(EXIT.setup);
    }
    expect(readdirSync(join(root, VALIDATION)).filter((n) => n.endsWith(".alerts.json"))).toEqual([]);
  });
  test("a session answered after another failed writes nothing for either", () => {
    const root = scratch(false);
    let n = 0;
    const remote: Remote = (nd) => (++n === 1 ? fakeRemote()(nd, 1) : { code: 1, out: "", timedOut: false });
    expect(() => fetchAll(layoutFor(root), remote, noScan)).toThrow(CoverageError);
    expect(readdirSync(join(root, VALIDATION)).filter((n) => n.endsWith(".alerts.json"))).toEqual([]);
  });
  test("an alert from another agent in the answer is refused", () => {
    const root = scratch(false);
    const remote: Remote = () => ({ code: 0, out: answerFor(fixtureAlerts(EV1).map((a: ReturnType<typeof alert>) => ({ ...a, agentId: "002" })), 9), timedOut: false });
    expect(() => fetchAll(layoutFor(root), remote, noScan)).toThrow(/agent/);
  });
  test("Sysmon's unknown-process image is kept as that one literal, and build reads it back", () => {
    const root = scratch(false);
    const withImage = (image: string): Remote => (nd, t) => {
      const real = fakeRemote()(nd, t);
      const doc = JSON.parse(real.out);
      doc.responses[0].hits.hits[0]._source.data.win.eventdata.image = image;
      return { ...real, out: JSON.stringify(doc) };
    };
    // The index holds the value HTML-escaped; that is the form seen live on event 22.
    fetchAll(layoutFor(root), withImage("&lt;unknown process&gt;"), noScan);
    expect(read(root, evPath(EV1)).alerts[0].image).toBe("<unknown process>");
    build(root);
    expect(summaryOf(root).validatedRules).toEqual(FOUR);
    // An answer with no channel is refused; it is never written as the text "undefined".
    const noChannel: Remote = (nd, t) => {
      const real = fakeRemote()(nd, t);
      const doc = JSON.parse(real.out);
      delete doc.responses[0].hits.hits[0]._source.data.win.system.channel;
      return { ...real, out: JSON.stringify(doc) };
    };
    expect(() => fetchAll(layoutFor(scratch(false)), noChannel, noScan)).toThrow(/channel/);
    // Any other value with markup in it is still outside the pattern.
    expect(() => fetchAll(layoutFor(scratch(false)), withImage("&lt;another value&gt;"), noScan)).toThrow(/image/);
  });
  test("the real leak scan stops a planted identifier and nothing is written", () => {
    const root = scratch(false);
    const remote: Remote = (nd, t) => {
      const real = fakeRemote()(nd, t);
      if (!nd.includes("2026-11-22T03:51:39")) return real;
      // The planted private address is joined at run time, so this file carries no literal one.
      const planted = ["192", "168", "50", "7"].join(".");
      const alerts = fixtureAlerts(EV1).map((a: ReturnType<typeof alert>, i: number) => (i === 0 ? { ...a, channel: `Microsoft-Windows-Sysmon/Operational host ${planted}` } : a));
      return { code: 0, out: answerFor(alerts, 9), timedOut: false };
    };
    const err = (() => {
      try {
        fetchAll(layoutFor(root), remote);
        return null;
      } catch (e) {
        return e as CoverageError;
      }
    })();
    expect(err?.code).toBe("leak-scan");
    expect(readdirSync(join(root, VALIDATION)).filter((n) => n.endsWith(".alerts.json"))).toEqual([]);
  });
  test("the real leak scan passes the fixture evidence", () => {
    const root = scratch(false);
    expect(() => fetchAll(layoutFor(root), fakeRemote())).not.toThrow();
    expect(existsSync(join(root, evPath(EV1)))).toBe(true);
  });
  test("an unsafe host alias is refused before ssh is reached", () => {
    for (const host of ["a b", "-oProxyCommand=x", "a;b", "$(id)", ""]) {
      const r = run(["fetch", "--host", host, "--root", scratch(false)], quiet);
      expect(r.exit).toBe(EXIT.refused);
    }
  });
  test("fetch with no host is refused", () => {
    expect(run(["fetch", "--root", scratch(false)], quiet).exit).toBe(EXIT.refused);
  });
});

describe("entry point", () => {
  test("no arguments prints usage as a refusal", () => {
    const r = run([], quiet);
    expect(r.exit).toBe(EXIT.refused);
    expect(r.error?.code).toBe("usage");
  });
  test("an unknown command is refused", () => {
    expect(run(["bake"], quiet).exit).toBe(EXIT.refused);
  });
  test("an unknown flag is refused", () => {
    expect(run(["build", "--force"], quiet).exit).toBe(EXIT.refused);
  });
  test("--help exits 0", () => {
    expect(run(["--help"], quiet).exit).toBe(EXIT.ok);
  });
  test("refresh-attack with a wrong hash writes nothing", () => {
    const dir = mkdtempSync(join(tmpdir(), "coverage-bundle-"));
    roots.push(dir);
    const bundle = join(dir, "b.json");
    writeFileSync(bundle, '{"objects":[]}');
    const out = join(dir, "out.tsv");
    const r = run(["refresh-attack", bundle, "--out", out], quiet);
    expect(r.exit).toBe(EXIT.refused);
    expect(r.error?.code).toBe("bundle-sha256");
    expect(existsSync(out)).toBe(false);
  });
  test("the CLI prints the command line a person would read and exits with the code", () => {
    const p = Bun.spawnSync(["bun", join(ROOT, "tools/coverage.ts"), "check"], { stdout: "pipe", stderr: "pipe" });
    expect(p.exitCode).toBe(0);
    expect(p.stdout.toString()).toMatch(/\d+ of 18 validated/);
  });
  test("the CLI exits 3 on a refusal", () => {
    const p = Bun.spawnSync(["bun", join(ROOT, "tools/coverage.ts"), "bake"], { stdout: "pipe", stderr: "pipe" });
    expect(p.exitCode).toBe(EXIT.refused);
  });
});

describe("self-test plants", () => {
  for (const plant of PLANTS) {
    test(`${plant.name}`, () => {
      const control = scratch();
      expect(build(control).exit).toBe(EXIT.ok);
      const root = mkdtempSync(join(tmpdir(), "coverage-plant-test-"));
      roots.push(root);
      cpSync(control, root, { recursive: true });
      plant.mutate(root);
      const outputs = () => [...["layer-rule-exists.json", "layer-validated.json", "coverage.json"].map((n) => join(COVERAGE, n)), WRITEUP].map((n) => (existsSync(join(root, n)) ? readFileSync(join(root, n), "utf8") : null));
      const before = outputs();
      const r = run([...(plant.args ? plant.args(root) : (plant.argv ?? ["build"])), "--root", root], quiet);
      expect(r.exit).toBe(plant.exit);
      expect(r.error?.code).toBe(plant.code);
      expect(r.error?.item).toBe(plant.item);
      expect(outputs()).toEqual(before);
    });
  }
  test("the self-test command exits 0 and prints one OK line per plant", () => {
    const p = Bun.spawnSync(["bun", join(ROOT, "tools/coverage.ts"), "--self-test"], { stdout: "pipe", stderr: "pipe", timeout: 300_000 });
    const lines = p.stdout.toString().trim().split("\n");
    expect(p.exitCode).toBe(0);
    expect(lines.every((l) => l.startsWith("OK  "))).toBe(true);
    expect(lines).toHaveLength(PLANTS.length + 3);
  });
});

// *--- The writeup number gate ---*

const HEADING = "## Validation results";
const SOURCE = /^Source: `coverage\.json`, SHA-256 [0-9a-f]{64}\.$/;
const readText = (root: string, p: string) => readFileSync(join(root, p), "utf8");

/** The results section of a text, found independently of the tool: its lines, bounds and the text around it. */
function sectionOf(text: string, heading = HEADING) {
  const lines = text.split("\n");
  const a = lines.indexOf(heading);
  const b = lines.findIndex((l, i) => i > a && SOURCE.test(l));
  return { lines, a, b, section: lines.slice(a, b + 1).join("\n"), before: lines.slice(0, a).join("\n"), after: lines.slice(b + 1).join("\n") };
}

/** The sentences and the table of one built section, read back as data. */
function readSection(root: string) {
  const s = sectionOf(readText(root, WRITEUP));
  const rows = s.lines.filter((l) => /^\| 100\d{3} \|/.test(l)).map((l) => l.split("|").slice(1, -1).map((c) => c.trim()));
  return { ...s, rows };
}

function capture() {
  const errs: string[] = [];
  const logs: string[] = [];
  return { io: { log: (l: string) => logs.push(l), err: (l: string) => errs.push(l) }, errs, logs };
}

const mdFile = (root: string, name: string, body: string) => {
  writeFileSync(join(root, "phase-b-detection", name), body);
  return `phase-b-detection/${name}`;
};
const claimsRun = (root: string, files: string[], extra: string[] = []) => {
  const c = capture();
  const r = run(["claims", ...extra, "--root", root, ...files.map((f) => join(root, f))], c.io);
  return { ...r, errs: c.errs, logs: c.logs };
};
// The percentage in the section is one decimal, so a test that plants a one-digit change moves that decimal.
const bumpPercent = (text: string) => text.replace(/\((\d+\.\d) percent\)/, (_m, n) => `(${(Number(n) + 1).toFixed(1)} percent)`);
const tenths = (v: number, of: number) => Math.floor((2000 * v + of) / (2 * of));
const addLiteral = (root: string, text: string, source: string) => editJson(root, LITERALS, (x) => x.literals.push({ text, source }));

// ISC-185: the results section is a fourth output, built from the same data as coverage.json.
describe("results section", () => {
  test("build writes the section, its sentences and one table row per pack rule", () => {
    const root = scratch();
    expect(build(root).exit).toBe(EXIT.ok);
    const s = readSection(root);
    const sum = summaryOf(root);
    expect(s.a).toBeGreaterThanOrEqual(0);
    expect(s.b).toBeGreaterThan(s.a);
    expect(s.section).toContain(`${sum.ratio.validated} of ${sum.ratio.of} pack rules are validated (${Math.floor(tenths(sum.ratio.validated, sum.ratio.of) / 10)}.${tenths(sum.ratio.validated, sum.ratio.of) % 10} percent)`);
    expect(s.rows).toHaveLength(18);
    expect(s.rows.map((r) => Number(r[0]))).toEqual(sum.rules.map((r: any) => r.rule));
    for (const [i, r] of s.rows.entries()) {
      const row = sum.rules[i];
      expect(r[1]).toBe(String(row.level));
      expect(r[2]).toBe(row.attack19.join(", "));
      expect(r[3]).toBe(row.status === "validated" ? "validated" : "not validated");
      expect(r[4]).toBe(row.validation ? row.validation.art : row.miss ? row.miss.class : "unclassified");
      expect(r[5]).toBe(row.validation ? row.validation.session : (row.miss?.session ?? "none"));
    }
  });

  test("the section ends with the SHA-256 of coverage.json, as the bytes stand", () => {
    const root = scratch();
    build(root);
    const s = readSection(root);
    const hash = new Bun.CryptoHasher("sha256").update(readFileSync(join(root, COVERAGE, "coverage.json"))).digest("hex");
    expect(s.lines[s.b]).toBe(`Source: \`coverage.json\`, SHA-256 ${hash}.`);
  });

  test("the section is plain ASCII with no wall-clock time, and a rebuild is byte-identical", () => {
    const root = scratch();
    build(root);
    const first = readText(root, WRITEUP);
    expect(/^[\x20-\x7e\n]*$/.test(readSection(root).section)).toBe(true);
    build(root);
    expect(readText(root, WRITEUP)).toBe(first);
  });

  test("the three existing outputs keep the bytes they had before the section existed", () => {
    const real = [`${COVERAGE}/layer-rule-exists.json`, `${COVERAGE}/layer-validated.json`].map((p) => new Bun.CryptoHasher("sha256").update(readFileSync(join(ROOT, p))).digest("hex"));
    expect(real[0].startsWith("9aafa1cf")).toBe(true);
    expect(real[1].startsWith("33443c6a")).toBe(true);
  });

  test("build changes only the section and leaves every byte outside it", () => {
    const root = scratch();
    build(root);
    const first = readText(root, WRITEUP);
    const parts = sectionOf(first);
    const edited = `# Edited title\n\nProse before the section.\n\n${parts.section}\n\nProse after the section.\n\n- a list\n`;
    writeFileSync(join(root, WRITEUP), edited);
    // A new miss entry changes the totals, so the section has to change.
    missEntry(root, { rule: 100344, class: "not-run", evidence: "x", ruling: "x" });
    expect(build(root).exit).toBe(EXIT.ok);
    const now = sectionOf(readText(root, WRITEUP));
    expect(now.section).not.toBe(parts.section);
    expect(now.before).toBe("# Edited title\n\nProse before the section.\n");
    expect(now.after).toBe("\nProse after the section.\n\n- a list\n");
  });

  test("build appends the section to a writeup that has none, keeping what was there", () => {
    const root = scratch();
    writeFileSync(join(root, WRITEUP), "# Title\n\nDraft prose.\n");
    expect(build(root).exit).toBe(EXIT.ok);
    const text = readText(root, WRITEUP);
    expect(text.startsWith("# Title\n\nDraft prose.\n\n## Validation results\n")).toBe(true);
    expect(text.endsWith("\n")).toBe(true);
    expect(run(["check", "--root", root], quiet).exit).toBe(EXIT.ok);
  });

  test("the miss classes are counted by class in a sentence, and an unclassified rule is named", () => {
    const root = scratch();
    missEntry(root, { rule: 100344, class: "not-run", evidence: "x", ruling: "x" });
    missEntry(root, { rule: 100343, class: "not-run", evidence: "x", ruling: "x" });
    build(root);
    const s = readSection(root).section;
    expect(s).toContain("2 not run");
    expect(s).toMatch(/12 rules have no miss class yet/);
  });

  test("check passes when the section matches and fails on one digit changed", () => {
    const root = scratch();
    build(root);
    expect(run(["check", "--root", root], quiet).exit).toBe(EXIT.ok);
    const text = readText(root, WRITEUP);
    writeFileSync(join(root, WRITEUP), bumpPercent(text));
    const r = run(["check", "--root", root], quiet);
    expect(r.exit).toBe(EXIT.failed);
    expect(r.error?.code).toBe("output-differs");
    expect(r.error?.item).toBe(WRITEUP);
  });

  test("check passes when only the prose outside the section changes", () => {
    const root = scratch();
    build(root);
    writeFileSync(join(root, WRITEUP), `${readText(root, WRITEUP)}\nMore prose after.\n`);
    expect(run(["check", "--root", root], quiet).exit).toBe(EXIT.ok);
  });

  test("a missing writeup, a missing section, two sections and an unterminated section are refused", () => {
    const root = scratch();
    build(root);
    const good = readText(root, WRITEUP);
    const sec = sectionOf(good).section;
    const want = (text: string | null, code: string) => {
      if (text === null) rmSync(join(root, WRITEUP));
      else writeFileSync(join(root, WRITEUP), text);
      for (const cmd of [["check"], ["claims", join(root, WRITEUP)]]) {
        // claims needs a file; a missing one is its own setup problem
        if (text === null && cmd[0] === "claims") continue;
        const r = run([...cmd, "--root", root], quiet);
        expect(r.exit).toBe(EXIT.refused);
        expect(r.error?.code).toBe(code);
      }
    };
    want(null, "writeup-missing");
    want("# Title\n", "section-missing");
    want(`${good}\n${sec}\n`, "section-duplicate");
    want(`# Title\n\n${HEADING}\n\nNo source line here.\n`, "section-unterminated");
    want(`# Title\n\n${HEADING}\n\nText.\n\n## Another heading\n\nSource: \`coverage.json\`, SHA-256 ${"0".repeat(64)}.\n`, "section-unterminated");
  });

  test("a refused build writes neither the layers nor the writeup", () => {
    const root = scratch();
    build(root);
    const before = [readText(root, WRITEUP), readText(root, `${COVERAGE}/coverage.json`)];
    writeFileSync(join(root, WRITEUP), `${before[0]}\n${sectionOf(before[0]).section}\n`);
    const bad = readText(root, WRITEUP);
    editJson(root, "phase-b-detection/attack/crosswalk.json", (c) => (c.entries = c.entries.filter((e: any) => e.from !== "T1027")));
    expect(build(root).exit).toBe(EXIT.refused);
    expect(readText(root, WRITEUP)).toBe(bad);
    // The duplicate is refused on its own, too, with a good crosswalk.
    const again = scratch();
    build(again);
    writeFileSync(join(again, WRITEUP), bad);
    const r = run(["build", "--root", again], quiet);
    expect(r.error?.code).toBe("section-duplicate");
    expect(readText(again, WRITEUP)).toBe(bad);
  });

  test("a heading inside a code fence is not a section", () => {
    const root = scratch();
    writeFileSync(join(root, WRITEUP), `# Title\n\n\`\`\`\n${HEADING}\n\`\`\`\n`);
    expect(build(root).exit).toBe(EXIT.ok);
    expect(readText(root, WRITEUP)).toContain(`\`\`\`\n${HEADING}\n\`\`\`\n\n${HEADING}\n`);
  });

  test("the writeup in the repo holds its section, and it is the rebuild", () => {
    const s = sectionOf(readFileSync(join(ROOT, WRITEUP), "utf8"));
    expect(s.a).toBeGreaterThanOrEqual(0);
    expect(run(["check"], quiet).exit).toBe(EXIT.ok);
    expect(s.before).toContain("draft");
    expect(s.section).toContain("12 of 18 pack rules are validated (66.7 percent)");
  });

  // The public bar is 60 percent, and a whole-number round can cross it: the figure keeps one decimal, rounded
  // to nearest (halves up) with integer arithmetic.
  test("the percentage carries one decimal, rounded to nearest", () => {
    const facts = (validated: number, packSize: number) => ({ rows: [], packSize, validated, unclassified: 0, existsTechniques: 0, validatedTechniques: 0, summaryText: "x" });
    const read = (v: number, p: number) => /\((\S+) percent\)/.exec(buildSection(facts(v, p)))?.[1];
    expect(read(12, 18)).toBe("66.7");
    expect(read(1, 3)).toBe("33.3");
    expect(read(2, 3)).toBe("66.7");
    expect(read(0, 18)).toBe("0.0");
    expect(read(18, 18)).toBe("100.0");
    expect(read(1, 8)).toBe("12.5");
    expect(read(1, 16)).toBe("6.3");
    expect(read(1, 6)).toBe("16.7");
    expect(read(11, 18)).toBe("61.1");
  });
});

// ISC-186: any number outside the section must be an identifier or a listed literal.
describe("claims: numbers in prose", () => {
  const PROSE = "phase-b-detection/notes.md";
  const planted = (root: string, line: string) => {
    mdFile(root, "notes.md", `# Notes\n\n${line}\n`);
    return claimsRun(root, [PROSE]);
  };
  for (const [token, code, line] of [
    ["13 of 18", "claim-number", "The pack validated 13 of 18 rules."],
    ["70%", "claim-number", "Coverage is 70% overall."],
    ["twelve of eighteen", "claim-number-word", "We validated twelve of eighteen rules."],
    ["twelve percent", "claim-number-word", "About twelve percent were blocked."],
    ["12 out of 18", "claim-number", "Only 12 out of 18 fired."],
    ["19", "claim-number", "There were 19 attempts."],
    ["19.2", "claim-number", "ATT&CK 19.2 is pinned."],
    ["1,000", "claim-number", "About 1,000 events."],
  ] as const) {
    test(`${token} typed in prose is refused, naming file, line and token`, () => {
      const root = scratch();
      build(root);
      const r = planted(root, line);
      expect(r.exit).toBe(EXIT.refused);
      expect(r.error?.code).toBe(code);
      expect(r.error?.item).toBe(`${PROSE}:3 ${token}`);
      expect(r.errs.join("\n")).toContain(`${PROSE}:3 ${token}`);
    });
  }

  test("every refused token is reported, not only the first", () => {
    const root = scratch();
    build(root);
    mdFile(root, "notes.md", "# Notes\n\nA 13 of 18 and a 70% and twelve of eighteen.\n\nAnd 5 more.\n");
    const r = claimsRun(root, [PROSE]);
    const items = r.errs.filter((l) => l.includes("claim-")).join("\n");
    for (const token of ["13 of 18", "70%", "twelve of eighteen", "5"]) expect(items).toContain(token);
  });

  test("identifiers pass: pack rule IDs, Defender rule IDs, ATT&CK IDs, session IDs, dates, times, digests, list markers", () => {
    const root = scratch();
    build(root);
    const digest = "a".repeat(64);
    const body = [
      "# Notes",
      "",
      "1. Rule 100410 and rule 100411 fired, and Defender rule 62123 blocked one.",
      "2. T1105 #26 sits under T1105, T1218.010 and TA0011.",
      `3. Session ${EV1} ran on 2026-11-22 at 03:52:39.123Z.`,
      "4. The stamp 2026-11-22T03:52:39.0000000Z and 2026-11-22T03:52:39-07:00 are exact.",
      `5. The digest ${digest} and a commit ${"b".repeat(40)} are named.`,
      "6. Versions v19.2.1 and 4.14.9 are named.",
      "",
    ].join("\n");
    mdFile(root, "notes.md", body);
    const r = claimsRun(root, [PROSE]);
    expect(r.errs).toEqual([]);
    expect(r.exit).toBe(EXIT.ok);
  });

  test("an identifier must be in its registry", () => {
    for (const [line, code, token] of [
      ["Rule 100499 fired.", "claim-rule-unknown", "100499"],
      ["Rule 100339 fired.", "claim-number", "100339"],
      ["The technique T9999 maps.", "claim-technique-unknown", "T9999"],
      ["The test T9999 #4 ran.", "claim-technique-unknown", "T9999 #4"],
      ["Session 20261122T000000Z-000000 ran.", "claim-session-unknown", "20261122T000000Z-000000"],
      ["Rule 62125 fired.", "claim-number", "62125"],
    ] as const) {
      const root = scratch();
      build(root);
      const r = planted(root, line);
      expect(r.exit).toBe(EXIT.refused);
      expect(r.error?.code).toBe(code);
      expect(r.error?.item).toBe(`${PROSE}:3 ${token}`);
    }
  });

  test("a date that is not a real day, a time that is not a clock time and an address are refused", () => {
    for (const [line, token] of [
      ["Seen on 2026-13-45.", "2026-13-45"],
      ["Seen at 25:99.", "25:99"],
      ["Seen at 203.0.113.7.", "203.0.113.7"],
    ] as const) {
      const root = scratch();
      build(root);
      const r = planted(root, line);
      expect(r.exit).toBe(EXIT.refused);
      expect(r.error?.item).toBe(`${PROSE}:3 ${token}`);
    }
  });

  test("fenced code and inline code are not exempt", () => {
    const root = scratch();
    build(root);
    mdFile(root, "notes.md", "# Notes\n\n```\nvalidated 13 of 18\n```\n\nand `70%` inline.\n");
    const r = claimsRun(root, [PROSE]);
    expect(r.errs.join("\n")).toContain(`${PROSE}:4 13 of 18`);
    expect(r.errs.join("\n")).toContain(`${PROSE}:7 70%`);
  });

  test("number words other than the refused ratio forms pass, as stated in the limits", () => {
    const root = scratch();
    build(root);
    expect(planted(root, "We ran twelve tests and fixed three rules.").exit).toBe(EXIT.ok);
  });

  test("a file with no section is still prose-checked, and the lab writeup passes", () => {
    const root = scratch();
    build(root);
    expect(claimsRun(root, [WRITEUP]).exit).toBe(EXIT.ok);
    expect(run(["claims", join(ROOT, WRITEUP)], quiet).exit).toBe(EXIT.ok);
    const r = claimsRun(root, [WRITEUP]);
    expect(r.logs.join("\n")).toMatch(/claims/);
  });

  test("a number typed into the lab writeup outside the section is refused", () => {
    const root = scratch();
    build(root);
    writeFileSync(join(root, WRITEUP), `${readText(root, WRITEUP)}\nWe got 13 of 18.\n`);
    const r = claimsRun(root, [WRITEUP]);
    expect(r.exit).toBe(EXIT.refused);
    expect(r.error?.code).toBe("claim-number");
  });

  test("a number inside the generated section is not prose", () => {
    const root = scratch();
    build(root);
    expect(sectionOf(readText(root, WRITEUP)).section).toMatch(/\d+ of 18/);
    expect(claimsRun(root, [WRITEUP]).exit).toBe(EXIT.ok);
  });

  test("a claims run with no file, or a file that is not Markdown, is refused", () => {
    const root = scratch();
    build(root);
    expect(run(["claims", "--root", root], quiet).error?.code).toBe("usage");
    writeFileSync(join(root, "phase-b-detection", "notes.txt"), "x\n");
    expect(claimsRun(root, ["phase-b-detection/notes.txt"]).error?.code).toBe("claims-file");
    expect(claimsRun(root, ["phase-b-detection/missing.md"]).error?.code).toBe("input-missing");
  });

  // A URL is an address, not a claim: digits in its destination are not refused. The text of a link is prose.
  test("digits inside a URL are not claims, in a link destination or bare, and link text is still scanned", () => {
    const root = scratch();
    build(root);
    mdFile(root, "notes.md", [
      "# Notes",
      "",
      "[the technique](https://attack.mitre.org/techniques/T1547/001/) and https://example.org/post-2026/a1, then (http://example.net/x7).",
      "<https://example.net/p9> and [wiki](https://en.wikipedia.org/wiki/Foo_(bar2)).",
      "",
    ].join("\n"));
    const ok = claimsRun(root, [PROSE]);
    expect(ok.errs).toEqual([]);
    expect(ok.exit).toBe(EXIT.ok);
    const r = planted(root, "[13 of 18](https://example.org/)");
    expect(r.error).toMatchObject({ code: "claim-number", item: `${PROSE}:3 13 of 18` });
    // A number just after the URL is not part of it.
    expect(planted(root, "See https://example.org/a1 and 5 rules.").error?.item).toBe(`${PROSE}:3 5`);
    // Without a scheme the destination is prose.
    expect(planted(root, "[page](post-2026.md)").error?.code).toBe("claim-number");
  });

  test("a decimal digit outside ASCII is refused, whatever script it is written in", () => {
    const root = scratch();
    build(root);
    const r = planted(root, "Only \uff11\uff12 of \uff11\uff18 fired.");
    expect(r.exit).toBe(EXIT.refused);
    expect(r.error).toMatchObject({ code: "claim-number", item: `${PROSE}:3 \uff11\uff12` });
    expect(r.errs.join("\n")).toContain(`${PROSE}:3 \uff11\uff18`);
    for (const line of ["Arabic-Indic \u0661\u0662 here.", "Devanagari \u0967\u0968 here.", "Mixed 1\uff12 here.", "Astral \u{1d7d0} here."]) {
      expect(planted(root, line).error?.code, line).toBe("claim-number");
    }
  });

  describe("the literals file", () => {
    const withLiteral = (text: string, source: string) => {
      const root = scratch();
      build(root);
      addLiteral(root, text, source);
      return root;
    };

    test("a listed phrase passes where it is used, and a number next to it still fails", () => {
      const root = withLiteral("ATT&CK 19.2", "ATTACK_VERSION in tools/coverage.ts");
      mdFile(root, "notes.md", "# Notes\n\nATT&CK 19.2 is pinned.\n");
      expect(claimsRun(root, [PROSE]).exit).toBe(EXIT.ok);
      mdFile(root, "notes.md", "# Notes\n\nATT&CK 19.2 is pinned, and 5 rules.\n");
      expect(claimsRun(root, [PROSE]).error?.item).toBe(`${PROSE}:3 5`);
      mdFile(root, "notes.md", "# Notes\n\nATT&CK 119.25 is not it.\n");
      expect(claimsRun(root, [PROSE]).error?.code).toBe("claim-number");
    });

    // A literal excuses the digits inside the phrase as written and nothing else: listing "event 3" must not let
    // "3 rules fired" through.
    test("only the digits inside a matched phrase are excused", () => {
      const root = withLiteral("event 3", "Sysmon event ID for a network connection");
      mdFile(root, "notes.md", "# Notes\n\nSysmon event 3 fired and 3 rules did not.\n");
      const r = claimsRun(root, [PROSE]);
      expect(r.error).toMatchObject({ code: "claim-number", item: `${PROSE}:3 3` });
      expect(r.errs.filter((l) => l.includes("claim-number:") && l.includes(PROSE))).toHaveLength(1);
      mdFile(root, "notes.md", "# Notes\n\nSysmon event 3 fired. A second event 3 followed (event 3).\n");
      expect(claimsRun(root, [PROSE]).exit).toBe(EXIT.ok);
      mdFile(root, "notes.md", "# Notes\n\n3 rules fired.\n");
      expect(claimsRun(root, [PROSE]).error?.item).toBe(`${PROSE}:3 3`);
    });

    test("a phrase is matched whole, at token boundaries", () => {
      const root = withLiteral("event 3", "Sysmon event ID for a network connection");
      for (const [line, token] of [
        ["The event 33 fired.", "33"],
        ["The prevent 3 case.", "3"],
        ["An event 3.5 case.", "3.5"],
        ["An event-3 case.", "event-3"],
      ] as const) {
        mdFile(root, "notes.md", `# Notes\n\n${line}\n`);
        expect(claimsRun(root, [PROSE]).error, line).toMatchObject({ code: "claim-number", item: `${PROSE}:3 ${token}` });
      }
      mdFile(root, "notes.md", "# Notes\n\nAn event 3, then event 3.\n");
      expect(claimsRun(root, [PROSE]).exit).toBe(EXIT.ok);
    });

    test("phrases from the brief pass as written", () => {
      const root = withLiteral("event 3", "s");
      for (const text of ["Sysmon 15.21", "level 12", "port 443"]) addLiteral(root, text, "a source");
      mdFile(root, "notes.md", "# Notes\n\nSysmon 15.21 saw a level 12 rule on port 443 and event 3.\n");
      expect(claimsRun(root, [PROSE]).exit).toBe(EXIT.ok);
    });

    test("a literal with an empty source, no word, no digit, or a repeat is refused", () => {
      const a = withLiteral("ATT&CK 19.2", "   ");
      expect(claimsRun(a, [WRITEUP]).error).toMatchObject({ code: "literal-source", item: `${LITERALS} ATT&CK 19.2` });
      for (const text of ["3", "19.2", "nineteen", "event", "12 34", "event  3", " event 3", "event 3 ", "T1105 3", "event \uff13"]) {
        const b = withLiteral(text, "a source");
        expect(claimsRun(b, [WRITEUP]).error, text).toMatchObject({ code: "literals-shape" });
      }
      const c = withLiteral("ATT&CK 19.2", "one");
      addLiteral(c, "ATT&CK 19.2", "two");
      expect(claimsRun(c, [WRITEUP]).error).toMatchObject({ code: "literal-duplicate", item: `${LITERALS} ATT&CK 19.2` });
    });

    test("a literal the writeup never uses is refused when the lab writeup is checked", () => {
      const root = withLiteral("ATT&CK 19.2", "ATTACK_VERSION in tools/coverage.ts");
      const r = claimsRun(root, [WRITEUP]);
      expect(r.exit).toBe(EXIT.refused);
      expect(r.error).toMatchObject({ code: "literal-unused", item: `${LITERALS} ATT&CK 19.2` });
      mdFile(root, "notes.md", "# Notes\n\nATT&CK 19.2.\n");
      expect(claimsRun(root, [WRITEUP, PROSE]).exit).toBe(EXIT.ok);
      // A single other file does not report literals it may not use.
      expect(claimsRun(root, [PROSE]).exit).toBe(EXIT.ok);
    });

    test("a literals file in the wrong shape, or missing, is refused", () => {
      const root = scratch();
      build(root);
      editJson(root, LITERALS, (x) => (x.format = "talonsoclab-claims-literals/2"));
      expect(claimsRun(root, [WRITEUP]).error?.code).toBe("literals-shape");
      rmSync(join(root, LITERALS));
      const r = claimsRun(root, [WRITEUP]);
      expect(r.exit).toBe(EXIT.setup);
      expect(r.error?.code).toBe("input-missing");
    });
  });
});

// ISC-187: a copy of the section elsewhere must be the lab's current section, byte for byte.
describe("claims: a copy of the section", () => {
  const COPY = "phase-b-detection/copy.md";
  const lab = scratch();
  build(lab);
  const older = scratch(false);
  build(older);
  const sectionText = (root: string) => sectionOf(readText(root, WRITEUP)).section;

  test("an exact copy passes, at the same heading level and at another", () => {
    for (const level of ["##", "###", "####", "#"]) {
      mdFile(lab, "copy.md", `# Blog post\n\nProse.\n\n${sectionText(lab).replace(HEADING, `${level} Validation results`)}\n\nMore prose.\n`);
      const r = claimsRun(lab, [COPY], ["--against", lab]);
      expect(r.errs).toEqual([]);
      expect(r.exit).toBe(EXIT.ok);
    }
  });

  test("a copy cut from an older build is refused, naming the file and heading line", () => {
    expect(sectionText(older)).not.toBe(sectionText(lab));
    mdFile(lab, "copy.md", `# Blog post\n\n${sectionText(older)}\n`);
    const r = claimsRun(lab, [COPY], ["--against", lab]);
    expect(r.exit).toBe(EXIT.refused);
    expect(r.error?.code).toBe("claim-section-differs");
    expect(r.error?.item).toBe(`${COPY}:3 Validation results`);
  });

  test("the older copy passes against the older lab", () => {
    mdFile(lab, "copy.md", `# Blog post\n\n${sectionText(older)}\n`);
    expect(claimsRun(lab, [COPY], ["--against", older]).exit).toBe(EXIT.ok);
  });

  test("one changed character in a copy is refused", () => {
    mdFile(lab, "copy.md", `${sectionText(lab).replace("pack rules", "pack rule")}\n`);
    expect(claimsRun(lab, [COPY], ["--against", lab]).error?.code).toBe("claim-section-differs");
  });

  test("two sections in a copy, or one without its source line, are refused", () => {
    mdFile(lab, "copy.md", `${sectionText(lab)}\n\n${sectionText(lab)}\n`);
    expect(claimsRun(lab, [COPY], ["--against", lab]).error?.code).toBe("section-duplicate");
    mdFile(lab, "copy.md", `${HEADING}\n\nText.\n`);
    expect(claimsRun(lab, [COPY], ["--against", lab]).error?.code).toBe("section-unterminated");
  });

  test("the lab root defaults to --root, and the rest of the copy's file is still prose-checked", () => {
    mdFile(lab, "copy.md", `# Post\n\nWe saw 13 of 18.\n\n${sectionText(lab)}\n`);
    const r = claimsRun(lab, [COPY]);
    expect(r.error?.code).toBe("claim-number");
    expect(r.error?.item).toBe(`${COPY}:3 13 of 18`);
  });
});

// The hook end to end in a scratch repo (ISA ISC-169): the check reads the index, so the
// working tree can neither hide a bad staged output nor block a good one.
describe("pre-commit hook", () => {
  const LAYER = `${COVERAGE}/layer-validated.json`;
  const MATCH = "coverage: the checked-in outputs match the rebuild";
  const DIFFERS = `coverage: ${LAYER} differs from the rebuild`;
  let repo: string;
  let home: string;
  let env: Record<string, string>;
  const git = (...args: string[]) => {
    const r = Bun.spawnSync(["git", ...args], { cwd: repo, env, stdout: "pipe", stderr: "pipe" });
    return { code: r.exitCode, out: `${r.stdout.toString()}${r.stderr.toString()}` };
  };
  const hook = (path: string) => {
    const r = Bun.spawnSync(["bash", "tools/hooks/pre-commit"], { cwd: repo, env: { ...env, PATH: path }, stdout: "pipe", stderr: "pipe" });
    return { code: r.exitCode, out: `${r.stdout.toString()}${r.stderr.toString()}` };
  };
  // One changed letter in the layer name; returns the good text.
  const plant = () => {
    const good = readFileSync(join(repo, LAYER), "utf8");
    const bad = good.replace("validated by a live alert", "validated by a live alerT");
    expect(bad).not.toBe(good);
    writeFileSync(join(repo, LAYER), bad);
    return good;
  };
  const notRun = (rule: number) => ({ rule, class: "not-run", evidence: "No test is run for this rule in the scratch repo.", ruling: "scratch, 2026-11-23: not run." });
  // A git that fails for one subcommand when the call names the coverage folder or an export prefix.
  const brokenGit = (name: string, sub: string) => {
    const bin = join(home, name);
    mkdirSync(bin, { recursive: true });
    const real = Bun.which("git") ?? "";
    expect(real).not.toBe("");
    writeFileSync(join(bin, "git"), `#!/usr/bin/env bash\ncase " $* " in *" ${sub} "*) echo "fatal: injected" >&2; exit 128 ;; esac\nexec "${real}" "$@"\n`);
    chmodSync(join(bin, "git"), 0o755);
    return `${bin}:${env.PATH}`;
  };

  beforeAll(() => {
    repo = scratch();
    expect(build(repo).exit).toBe(EXIT.ok);
    home = mkdtempSync(join(tmpdir(), "coverage-hook-"));
    roots.push(home);
    writeFileSync(join(home, "gitconfig"), "[user]\n\tname = hook test\n\temail = test@example.test\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n");
    env = { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", GIT_CONFIG_GLOBAL: join(home, "gitconfig"), GIT_CONFIG_NOSYSTEM: "1" };
    // The hook and every tool it runs, kept untracked as in the leakcheck tests.
    mkdirSync(join(repo, "tools"));
    for (const f of readdirSync(resolve(ROOT, "tools"))) if (f.endsWith(".ts") && !f.endsWith(".test.ts")) cpSync(resolve(ROOT, "tools", f), join(repo, "tools", f));
    cpSync(resolve(ROOT, "tools/hooks"), join(repo, "tools/hooks"), { recursive: true });
    writeFileSync(join(repo, "tools/leak-denylist.txt"), "zq-scratch-only-literal\n");
    expect(git("init", "-q").code).toBe(0);
    const installed = Bun.spawnSync(["bash", "tools/hooks/install.sh"], { cwd: repo, env, stdout: "pipe", stderr: "pipe" });
    expect(installed.exitCode).toBe(0);
    writeFileSync(join(repo, ".gitignore"), "/tools/\n");
    writeFileSync(join(repo, "README.md"), "# scratch\n");
  });

  test("a commit of a tree whose outputs match the rebuild runs the check and goes through", () => {
    expect(git("add", "-A").code).toBe(0);
    const r = git("commit", "-q", "-m", "initial");
    expect(r.out).toContain("leakcheck: clean");
    expect(r.out).toContain(MATCH);
    expect(r.code).toBe(0);
  });

  test("a commit that touches nothing the build reads or writes does not run the check", () => {
    writeFileSync(join(repo, "README.md"), "# scratch\n\nnotes\n");
    expect(git("add", "-A").code).toBe(0);
    const r = git("commit", "-q", "-m", "notes");
    expect(r.out).toContain("leakcheck: clean");
    expect(r.out).not.toContain("coverage:");
    expect(r.code).toBe(0);
  });

  test("a one-byte change staged in a layer is blocked, even with the good file back in the working tree", () => {
    const good = plant();
    expect(git("add", LAYER).code).toBe(0);
    writeFileSync(join(repo, LAYER), good);
    const r = git("commit", "-q", "-m", "planted");
    expect(r.out).toContain(DIFFERS);
    expect(r.code).not.toBe(0);
    expect(git("reset", "-q", "--", LAYER).code).toBe(0);
  });

  // ISC-188: the writeup is a built output, so the hook reads its staged copy like a layer.
  test("a staged results section that differs from the rebuild is blocked, even with the good writeup back in the working tree", () => {
    const good = readFileSync(join(repo, WRITEUP), "utf8");
    const bad = bumpPercent(good);
    expect(bad).not.toBe(good);
    writeFileSync(join(repo, WRITEUP), bad);
    expect(git("add", WRITEUP).code).toBe(0);
    writeFileSync(join(repo, WRITEUP), good);
    try {
      const r = git("commit", "-q", "-m", "planted section");
      expect(r.out).toContain(`coverage: ${WRITEUP} differs from the rebuild`);
      expect(r.code).not.toBe(0);
    } finally {
      expect(git("reset", "-q", "--", WRITEUP).code).toBe(0);
      writeFileSync(join(repo, WRITEUP), good);
    }
  });

  test("a writeup edit outside the section commits, and one that lands only in the working tree does not block", () => {
    const good = readFileSync(join(repo, WRITEUP), "utf8");
    writeFileSync(join(repo, WRITEUP), `${good}\nMore prose.\n`);
    expect(git("add", WRITEUP).code).toBe(0);
    writeFileSync(join(repo, WRITEUP), bumpPercent(good));
    try {
      const r = git("commit", "-q", "-m", "prose");
      expect(r.out).toContain(MATCH);
      expect(r.code).toBe(0);
    } finally {
      writeFileSync(join(repo, WRITEUP), `${good}\nMore prose.\n`);
    }
  });

  // ISC-189: check reads only the section, so the hook also holds the staged prose to claims.
  test("a count typed in the staged writeup outside the section is blocked, even with the good writeup back in the working tree", () => {
    const good = readFileSync(join(repo, WRITEUP), "utf8");
    const bad = good.replace("## Validation results", "We validated 13 of 18 rules.\n\n## Validation results");
    expect(bad).not.toBe(good);
    writeFileSync(join(repo, WRITEUP), bad);
    expect(git("add", WRITEUP).code).toBe(0);
    writeFileSync(join(repo, WRITEUP), good);
    try {
      const r = git("commit", "-q", "-m", "a typed count");
      expect(r.out).toContain(MATCH);
      expect(r.out).toContain(`coverage: claim-number: ${WRITEUP}:`);
      expect(r.out).toContain("13 of 18");
      expect(r.code).not.toBe(0);
    } finally {
      expect(git("reset", "-q", "--", WRITEUP).code).toBe(0);
      writeFileSync(join(repo, WRITEUP), good);
    }
  });

  test("a staged literal that the staged writeup never uses is blocked, even with the good list back in the working tree", () => {
    const LIST = "phase-b-detection/claims-literals.json";
    const good = readFileSync(join(repo, LIST), "utf8");
    editJson(repo, LIST, (x) => x.literals.push({ text: "event 3", source: "the Sysmon event id" }));
    expect(git("add", LIST).code).toBe(0);
    writeFileSync(join(repo, LIST), good);
    try {
      const r = git("commit", "-q", "-m", "a literal nobody uses");
      expect(r.out).toContain(`coverage: literal-unused: ${LIST} event 3`);
      expect(r.code).not.toBe(0);
    } finally {
      expect(git("reset", "-q", "--", LIST).code).toBe(0);
      writeFileSync(join(repo, LIST), good);
    }
  });

  test("a staged input change is blocked until the rebuilt outputs are staged with it, whatever the working tree holds", () => {
    editJson(repo, MISSES, (m) => m.entries.push(notRun(100344)));
    expect(git("add", MISSES).code).toBe(0);
    const stale = git("commit", "-q", "-m", "a miss class");
    expect(stale.out).toContain(`coverage: ${COVERAGE}/coverage.json differs from the rebuild`);
    expect(stale.code).not.toBe(0);
    expect(build(repo).exit).toBe(EXIT.ok);
    expect(git("add", "-A").code).toBe(0);
    // A bad layer left unstaged must not block the commit: the index is what lands.
    const good = plant();
    try {
      const r = git("commit", "-q", "-m", "a miss class");
      expect(r.out).toContain(MATCH);
      expect(r.code).toBe(0);
    } finally {
      writeFileSync(join(repo, LAYER), good);
    }
  });

  test("a replace ref cannot pass off the staged layer as the committed one", () => {
    const goodBlob = git("rev-parse", `HEAD:${LAYER}`).out.trim();
    const good = plant();
    expect(git("add", LAYER).code).toBe(0);
    const plantedBlob = git("rev-parse", `:${LAYER}`).out.trim();
    expect(git("replace", plantedBlob, goodBlob).code).toBe(0);
    try {
      expect(git("cat-file", "blob", plantedBlob).out).toBe(good);
      const r = git("commit", "-q", "-m", "planted behind a replace ref");
      expect(r.out).toContain(DIFFERS);
      expect(r.code).not.toBe(0);
    } finally {
      expect(git("replace", "-d", plantedBlob).code).toBe(0);
      expect(git("reset", "-q", "--", LAYER).code).toBe(0);
      writeFileSync(join(repo, LAYER), good);
    }
  });

  test("a git failure while listing or exporting the staged paths blocks the commit", () => {
    const good = plant();
    try {
      expect(git("add", LAYER).code).toBe(0);
      // With a working git the planted layer blocks it.
      const ok = hook(env.PATH);
      expect(ok.out).toContain(DIFFERS);
      expect(ok.code).not.toBe(0);
      const listing = hook(brokenGit("no-listing", `${COVERAGE}/`));
      expect(listing.out).toContain("leakcheck: clean");
      expect(listing.out).toContain("could not list the staged paths, so the coverage outputs cannot be checked");
      expect(listing.code).not.toBe(0);
      const exporting = hook(brokenGit("no-export", "checkout-index"));
      expect(exporting.out).toContain("could not copy the index, so the coverage outputs cannot be checked");
      expect(exporting.code).not.toBe(0);
    } finally {
      git("reset", "-q", "--", LAYER);
      writeFileSync(join(repo, LAYER), good);
    }
  });
});
