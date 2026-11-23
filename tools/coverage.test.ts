// *****************************************************************************
// *Title: coverage.test*
// *Author: Kyle Versluis*
// *Description: Tests for coverage: each refusal planted, each side of a count*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, describe, expect, test } from "bun:test";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
      const before = ["layer-rule-exists.json", "layer-validated.json", "coverage.json"].map((n) => (existsSync(join(root, COVERAGE, n)) ? readFileSync(join(root, COVERAGE, n), "utf8") : null));
      const r = run([...(plant.argv ?? ["build"]), "--root", root], quiet);
      expect(r.exit).toBe(plant.exit);
      expect(r.error?.code).toBe(plant.code);
      expect(r.error?.item).toBe(plant.item);
      const after = ["layer-rule-exists.json", "layer-validated.json", "coverage.json"].map((n) => (existsSync(join(root, COVERAGE, n)) ? readFileSync(join(root, COVERAGE, n), "utf8") : null));
      expect(after).toEqual(before);
    });
  }
  test("the self-test command exits 0 and prints one OK line per plant", () => {
    const p = Bun.spawnSync(["bun", join(ROOT, "tools/coverage.ts"), "--self-test"], { stdout: "pipe", stderr: "pipe", timeout: 300_000 });
    const lines = p.stdout.toString().trim().split("\n");
    expect(p.exitCode).toBe(0);
    expect(lines.every((l) => l.startsWith("OK  "))).toBe(true);
    expect(lines).toHaveLength(PLANTS.length + 2);
  });
});
