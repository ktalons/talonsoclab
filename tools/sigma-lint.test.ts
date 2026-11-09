// *****************************************************************************
// *Title: sigma-lint.test*
// *Author: Kyle Versluis*
// *Description: Planted YAML and XML disagreements that sigma-lint must catch.*
// *****************************************************************************

// *--- Imports ---*

import { Database } from "bun:sqlite";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, spyOn, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { DEFAULTS, lintPack, main, readMitreIds, readSigma, readSigmahqIds, type SigmaRule } from "./sigma-lint.ts";
import { parseRules, readRulesDir, type WazuhRule } from "./wazuh-rules.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const MITRE = readMitreIds(readFileSync(resolve(ROOT, "phase-b-detection/mitre-db-ids.txt"), "utf8"));
const SIGMAHQ = readSigmahqIds(readFileSync(resolve(ROOT, "phase-b-detection/sigmahq-ids.txt"), "utf8"));
// A real SigmaHQ rule (Uncommon Network Connection Initiated By Certutil.EXE), active in the list.
const UPSTREAM = "0dba975d-a193-4ed1-a067-424df57570d1";
// Ids for the fake SigmaHQ checkout the refresh test builds.
const ACTIVE = "0f0f0f0f-aaaa-4bbb-8ccc-000000000001";
const RETIRED = "0f0f0f0f-aaaa-4bbb-8ccc-000000000002";
// A Sigma id for a second pack YAML, unlike doc()'s.
const OTHER_ID = "2c1f4f0e-8a5b-4d3c-9e7f-6a5b4c3d2e20";
const doc = () => ({
  title: "Certutil download",
  id: "2c1f4f0e-8a5b-4d3c-9e7f-6a5b4c3d2e1f",
  related: [{ id: UPSTREAM, type: "derived" }],
  status: "test",
  description: "Certutil reaching out with -urlcache.",
  level: "high",
  tags: ["attack.command-and-control", "attack.t1105"],
  logsource: { category: "network_connection", product: "windows" },
  detection: { selection: { Image: "\\certutil.exe" }, condition: "selection" },
  custom: { wazuh: { id: 100340, if_sid: 61605, level: 12, mitre: ["T1105"] } },
});
// An empty ifSid leaves the element out: an empty <if_sid> makes Wazuh skip the rule.
const xmlRule = (id = 100340, level = 12, ifSid = "61605", mitre = ["T1105"]) =>
  `<group name="pack,"><rule id="${id}" level="${level}">${ifSid ? `<if_sid>${ifSid}</if_sid>` : ""}` +
  `<field name="win.eventdata.image" type="pcre2">(?i)\\\\certutil\\.exe$</field>` +
  `<description>t</description><mitre>${mitre.map((m) => `<id>${m}</id>`).join("")}</mitre></rule></group>`;
const tree = (rules: WazuhRule[], skippedRules: WazuhRule[] = [], skippedFiles: string[] = []) => ({ rules, skippedRules, skippedFiles });
const sig = (d: unknown, file = "s.yml"): SigmaRule => ({ file, doc: d });
const problems = (s: SigmaRule[], xml: string) => lintPack(s, tree(parseRules(xml, "x.xml")), MITRE, SIGMAHQ).map((f) => f.problem);
const twice = (xml: string) => tree([...parseRules(xml, "a.xml"), ...parseRules(xml, "b.xml")]);

// *--- Tests ---*

describe("sigma-lint", () => {
  // A one-element sequence would otherwise compare as the scalar inside it after String()
  // or Number(), so each field is held to its type first.
  test("refuses a scalar field written as a sequence, naming the field", () => {
    const cases: [string, (d: any) => void, string[]][] = [
      ["id", (d) => (d.id = [d.id]), ["id is not a string"]],
      ["level", (d) => (d.level = ["high"]), ["level is not a string"]],
      ["tags", (d) => (d.tags = [["attack.t1105"]]), ["tags[0] is not a string"]],
      ["related id", (d) => (d.related = [{ id: [UPSTREAM], type: "derived" }]), ["related[0].id is not a string"]],
      ["custom.wazuh.id", (d) => (d.custom.wazuh.id = [100340]), ["custom.wazuh.id is not a number", "pack rule with no Sigma YAML"]],
      ["custom.wazuh.id as text", (d) => (d.custom.wazuh.id = "100340"), ["custom.wazuh.id is not a number", "pack rule with no Sigma YAML"]],
      ["custom.wazuh.level", (d) => (d.custom.wazuh.level = [12]), ["custom.wazuh.level is not a number"]],
      ["custom.wazuh.if_sid", (d) => (d.custom.wazuh.if_sid = [61605]), ["custom.wazuh.if_sid is not a number or string"]],
      ["custom.wazuh.mitre", (d) => (d.custom.wazuh.mitre = [["T1105"]]), ["custom.wazuh.mitre[0] is not a string"]],
    ];
    for (const [, change, want] of cases) {
      const d = doc();
      change(d);
      expect(problems([sig(d)], xmlRule())).toEqual(want);
    }
  });

  // Sigma's tags is a sequence. A scalar would otherwise be wrapped into a one-item list and
  // lint clean, so it is one finding and the tag checks after it are skipped.
  test("refuses a tags that is not a list", () => {
    for (const scalar of ["attack.t1105", null, 5, { t: "attack.t1105" }]) {
      const d: Record<string, unknown> = doc();
      d.tags = scalar;
      expect(problems([sig(d)], xmlRule())).toEqual(["tags is not a list"]);
    }
    const listed = doc();
    listed.tags = ["attack.t1105"];
    expect(problems([sig(listed)], xmlRule())).toEqual([]);
    const missing: Record<string, unknown> = doc();
    missing.tags = undefined;
    expect(problems([sig(missing)], xmlRule())).toEqual(["no ATT&CK technique tag"]);
    // Only tags is held to a list; custom.wazuh.mitre keeps the scalar wrap it had.
    const scalarMitre: any = doc();
    scalarMitre.custom.wazuh.mitre = "T1105";
    expect(problems([sig(scalarMitre)], xmlRule())).toEqual([]);
  });

  // Every related entry is held to its shape, not only the derived ones the lint looks up.
  test("refuses a related entry of any type that is not a mapping of string type and id", () => {
    const derived = { id: UPSTREAM, type: "derived" };
    for (const [extra, want] of [
      [{ type: "similar", id: 123 }, "related[1].id is not a string"],
      [{ type: "similar" }, "related[1].id is not a string"],
      [{ type: 5, id: UPSTREAM }, "related[1].type is not a string"],
      ["text", "related[1] is not a mapping"],
    ] as const) {
      const d: any = doc();
      d.related = [derived, extra];
      expect(problems([sig(d)], xmlRule())).toEqual([want]);
    }
  });

  // Several parents go in one comma string, as the XML <if_sid> writes them.
  test("reads custom.wazuh.if_sid as a number or a comma string", () => {
    const d: any = doc();
    d.custom.wazuh.if_sid = "61603, 61605";
    expect(problems([sig(d)], xmlRule(100340, 12, "61603,61605"))).toEqual([]);
    d.custom.wazuh.if_sid = "61605";
    expect(problems([sig(d)], xmlRule())).toEqual([]);
  });

  test("a matching YAML and XML pair passes", () => {
    expect(problems([sig(doc())], xmlRule())).toEqual([]);
  });

  // ISA ISC-123: the planted YAML/XML level mismatch.
  test("refuses an XML level that disagrees with the YAML", () => {
    expect(problems([sig(doc())], xmlRule(100340, 10))).toEqual(["XML level 10 does not match custom.wazuh.level 12"]);
  });

  test("refuses a custom.wazuh.level that disagrees with the Sigma level", () => {
    const d = doc();
    d.level = "medium";
    expect(problems([sig(d)], xmlRule())).toEqual(["custom.wazuh.level 12 does not match Sigma level medium (10)"]);
  });

  test("refuses a Sigma level that is not a pack level", () => {
    const d = doc();
    d.level = "low";
    expect(problems([sig(d)], xmlRule())).toContain("Sigma level low is not a pack level (medium, high, critical)");
    // An inherited name such as toString is not a pack level either.
    d.level = "toString";
    expect(problems([sig(d)], xmlRule())).toEqual(["Sigma level toString is not a pack level (medium, high, critical)"]);
  });

  test("refuses mismatched if_sid and mitre", () => {
    expect(problems([sig(doc())], xmlRule(100340, 12, "61603"))).toEqual([
      "XML if_sid 61603 does not match custom.wazuh.if_sid 61605",
    ]);
    expect(problems([sig(doc())], xmlRule(100340, 12, "61605", ["T1105", "T1071"]))).toEqual([
      "XML mitre T1105,T1071 does not match custom.wazuh.mitre T1105",
    ]);
  });

  // The if_sid lists compare as sets both ways: each side holding a parent the other lacks,
  // one way round and then the other, so a compare that looks one way only misses one.
  test("refuses an XML if_sid that names more or fewer parents than custom.wazuh.if_sid", () => {
    const d: any = doc();
    d.custom.wazuh.if_sid = "61603, 61605";
    expect(problems([sig(d)], xmlRule(100340, 12, "61605"))).toEqual(["XML if_sid 61605 does not match custom.wazuh.if_sid 61603,61605"]);
    expect(problems([sig(doc())], xmlRule(100340, 12, "61603, 61605"))).toEqual(["XML if_sid 61603,61605 does not match custom.wazuh.if_sid 61605"]);
    d.custom.wazuh.if_sid = "61600, 61605";
    expect(problems([sig(d)], xmlRule(100340, 12, "61603, 61605"))).toEqual(["XML if_sid 61603,61605 does not match custom.wazuh.if_sid 61600,61605"]);
  });

  // ISA Decisions 2026-10-26: an ID mitre.db lacks is dropped, and rule.mitre empties.
  test("refuses a MITRE ID missing from mitre.db, and a revoked one", () => {
    const d = doc();
    d.tags = ["attack.t1685"];
    d.custom.wazuh.mitre = ["T1685"];
    expect(problems([sig(d)], xmlRule(100340, 12, "61605", ["T1685"]))).toEqual([
      "MITRE ID T1685 is not in Wazuh's mitre.db, so the alert would drop it",
    ]);
    const revoked = [...MITRE].find(([, s]) => s === "revoked")?.[0] ?? "";
    d.tags = [`attack.${revoked.toLowerCase()}`];
    d.custom.wazuh.mitre = [revoked];
    expect(problems([sig(d)], xmlRule(100340, 12, "61605", [revoked]))).toEqual([`MITRE ID ${revoked} is revoked in mitre.db`]);
  });

  test("refuses a deprecated MITRE ID", () => {
    const dep = [...MITRE].find(([, s]) => s === "deprecated")?.[0] ?? "";
    expect(dep).not.toBe("");
    const d = doc();
    d.tags = [`attack.${dep.toLowerCase()}`];
    d.custom.wazuh.mitre = [dep];
    expect(problems([sig(d)], xmlRule(100340, 12, "61605", [dep]))).toEqual([`MITRE ID ${dep} is deprecated in mitre.db`]);
  });

  // A later line would overwrite the earlier status, so "revoked" then active reads as active.
  test("refuses a MITRE list that names an ID twice", () => {
    expect(() => readMitreIds("T1105 revoked\nT1105\n")).toThrow("T1105");
    expect(() => readMitreIds("T1105\n# T1105 revoked\nT1071 deprecated\n")).not.toThrow();
  });

  // A refresh writes an id and at most one status word, so anything more on a line is a hand
  // edit the reader would otherwise take as a withdrawn status.
  test("refuses an id line with more than an id and a status", () => {
    expect(() => readMitreIds("T1105 active extra\n")).toThrow("MITRE ID T1105 has more than an id and a status on its line");
    expect(() => readMitreIds("T1105 revoked extra\n")).toThrow("MITRE ID T1105 has more than an id and a status on its line");
    expect(() => readSigmahqIds(`${UPSTREAM} deprecated extra\n`)).toThrow(`SigmaHQ id ${UPSTREAM} has more than an id and a status on its line`);
  });

  test("refuses a status word its own refresh command never writes", () => {
    for (const s of ["active", "Revoked", "DEPRECATED", "withdrawn"]) {
      expect(() => readMitreIds(`T1105 ${s}\n`)).toThrow(`MITRE ID T1105 has status ${s}, which the refresh never writes (revoked, deprecated)`);
    }
    for (const s of ["revoked", "Deprecated", "active"]) {
      expect(() => readSigmahqIds(`${UPSTREAM} ${s}\n`)).toThrow(`SigmaHQ id ${UPSTREAM} has status ${s}, which the refresh never writes (deprecated)`);
    }
  });

  test("reads each status its refresh writes, and both checked-in lists whole", () => {
    expect([...readMitreIds("T1003 revoked\nT1071 deprecated\nT1105\n")]).toEqual([
      ["T1003", "revoked"],
      ["T1071", "deprecated"],
      ["T1105", ""],
    ]);
    expect([...readSigmahqIds(`${ACTIVE}\n${RETIRED.toUpperCase()} deprecated\n`)]).toEqual([
      [ACTIVE, ""],
      [RETIRED, "deprecated"],
    ]);
    // Each header states how many ids its refresh wrote, so a dropped line would show.
    for (const [file, read, statuses] of [
      ["phase-b-detection/mitre-db-ids.txt", MITRE, ["", "revoked", "deprecated"]],
      ["phase-b-detection/sigmahq-ids.txt", SIGMAHQ, ["", "deprecated"]],
    ] as const) {
      const count = /, (\d+) in all\.$/m.exec(readFileSync(resolve(ROOT, file), "utf8"))?.[1];
      expect(read.size).toBe(Number(count));
      expect(new Set(read.values())).toEqual(new Set(statuses));
    }
  });

  test("refuses Sigma technique tags that disagree with custom.wazuh.mitre", () => {
    const d = doc();
    d.tags = ["attack.command-and-control", "attack.t1071"];
    expect(problems([sig(d)], xmlRule())).toEqual(["Sigma tags T1071 do not match custom.wazuh.mitre T1105"]);
    d.tags = ["attack.t1105", "attack.t1071"];
    expect(problems([sig(d)], xmlRule())).toEqual(["Sigma tags T1105,T1071 do not match custom.wazuh.mitre T1105"]);
  });

  test("compares technique tags to custom.wazuh.mitre without regard to case", () => {
    const d = doc();
    d.custom.wazuh.mitre = ["T1059.001"];
    for (const tags of [["attack.execution", "attack.T1059.001"], ["attack.T1059.001", "attack.t1059.001"]]) {
      d.tags = tags;
      expect(problems([sig(d)], xmlRule(100340, 12, "61605", ["T1059.001"]))).toEqual([]);
    }
    d.tags = ["attack.T1071"];
    expect(problems([sig(d)], xmlRule(100340, 12, "61605", ["T1059.001"]))).toEqual(["Sigma tags T1071 do not match custom.wazuh.mitre T1059.001"]);
  });

  // A malformed tag beside a valid one would otherwise drop out of the comparison unseen.
  test("refuses a malformed technique tag, even beside a valid one", () => {
    for (const bad of ["attack.t1059.1", "attack.t105", "attack.T1059.0011", "attack.t1105x", "attack.tBAD", "attack.T"]) {
      const d = doc();
      d.tags = ["attack.t1105", bad];
      expect(problems([sig(d)], xmlRule())).toEqual([`ATT&CK technique tag ${bad} is malformed (attack.tNNNN or attack.tNNNN.NNN)`]);
    }
  });

  // A falsy or list detection used to pass the key check and skip the condition checks.
  test("refuses a detection that is not a mapping", () => {
    for (const det of [false, 0, "", [{ selection: {} }, "selection"]]) {
      const d: any = doc();
      d.detection = det;
      expect(problems([sig(d)], xmlRule())).toEqual(["detection is not a mapping"]);
    }
  });

  test("refuses an empty condition", () => {
    for (const c of ["", "  ", null]) {
      const d = doc();
      (d.detection as Record<string, unknown>).condition = c;
      expect(problems([sig(d)], xmlRule())).toEqual(["detection condition is empty"]);
    }
  });

  test("compares sub-technique tags, as a set", () => {
    const d = doc();
    d.tags = ["attack.execution", "attack.t1059.001", "attack.t1059.001"];
    d.custom.wazuh.mitre = ["T1059.001"];
    expect(problems([sig(d)], xmlRule(100340, 12, "61605", ["T1059.001"]))).toEqual([]);
  });

  test("refuses an id outside the pack, a duplicate id, and a missing XML rule", () => {
    const d = doc();
    d.custom.wazuh.id = 100200;
    expect(problems([sig(d)], xmlRule(100200))).toEqual(["custom.wazuh.id is outside the pack ranges"]);
    const copy = doc();
    copy.id = OTHER_ID;
    expect(problems([sig(doc(), "a.yml"), sig(copy, "b.yml")], xmlRule())).toEqual(["custom.wazuh.id also used in a.yml"]);
    expect(problems([sig(doc())], xmlRule(100341))).toEqual(["no XML rule with this id", "pack rule with no Sigma YAML"]);
  });

  // UUIDs compare without regard to case. An id that fails the shape check is already a
  // finding, so only a UUID is compared.
  test("refuses a Sigma id used by two YAMLs, in any case", () => {
    const pair = (first: string, second: string) => {
      const a = doc();
      const b = doc();
      a.id = first;
      b.id = second;
      b.custom.wazuh.id = 100341;
      const xml = tree([...parseRules(xmlRule(), "a.xml"), ...parseRules(xmlRule(100341), "b.xml")]);
      return lintPack([sig(a, "a.yml"), sig(b, "b.yml")], xml, MITRE, SIGMAHQ);
    };
    const id = doc().id;
    expect(pair(id.toUpperCase(), id)).toEqual([{ file: "b.yml", rule: 100341, problem: "id also used in a.yml" }]);
    expect(pair(id, OTHER_ID)).toEqual([]);
    expect(pair("not-a-uuid", "not-a-uuid")).toEqual([
      { file: "a.yml", rule: 100340, problem: "id is not a UUID" },
      { file: "b.yml", rule: 100341, problem: "id is not a UUID" },
    ]);
  });

  test("refuses two top-level XML rules with the same pack id, once", () => {
    expect(lintPack([sig(doc())], twice(xmlRule()), MITRE, SIGMAHQ).map((f) => f.problem)).toEqual(["XML rule defined 2 times (a.xml, b.xml)"]);
  });

  test("refuses two top-level XML rules with the same non-pack id", () => {
    expect(lintPack([], twice(xmlRule(100200, 0)), MITRE, SIGMAHQ)).toEqual([
      { file: "a.xml", rule: 100200, problem: "XML rule defined 2 times (a.xml, b.xml)" },
    ]);
  });

  // The second <mitre> block is read too, as Wazuh appends it to the alert, and the second
  // <if_sid> is joined to the first with no separator, as Wazuh joins it. A join past six
  // digits is refused by the reader before the lint runs.
  test("refuses a pack XML rule with a second <mitre> or <if_sid> element", () => {
    const extra = (xml: string) => xml.replace("</rule>", "<if_sid>3</if_sid><mitre><id>T1071</id></mitre></rule>");
    expect(problems([sig(doc())], extra(xmlRule()))).toEqual([
      "XML if_sid 616053 does not match custom.wazuh.if_sid 61605",
      "XML mitre T1105,T1071 does not match custom.wazuh.mitre T1105",
      "XML has more than one <mitre> element",
      "XML has more than one <if_sid> element",
    ]);
    expect(problems([], extra(xmlRule(100200, 0)))).toEqual([]);
  });

  // The XML and custom.wazuh.mitre compare as sets both ways, so an XML <mitre> that names
  // only part of the YAML's list fails as one that names more does.
  test("refuses an XML <mitre> that names only some of custom.wazuh.mitre", () => {
    const d = doc();
    d.tags = ["attack.command-and-control", "attack.t1105", "attack.t1071"];
    d.custom.wazuh.mitre = ["T1105", "T1071"];
    expect(problems([sig(d)], xmlRule(100340, 12, "61605", ["T1105", "T1071"]))).toEqual([]);
    expect(problems([sig(d)], xmlRule())).toEqual(["XML mitre T1105 does not match custom.wazuh.mitre T1105,T1071"]);
  });

  // The reader keeps <id> text as os_xml stores it, and whether the alert-time lookup trims
  // it is unknown, so a pack rule may carry only the bare technique form.
  test("refuses a padded or non-canonical MITRE id in a pack XML rule", () => {
    const padded = xmlRule().replace("<id>T1105</id>", "<id> T1105 </id>");
    expect(problems([sig(doc())], padded)).toEqual([
      "XML mitre  T1105  does not match custom.wazuh.mitre T1105",
      'MITRE id " T1105 " has surrounding whitespace',
    ]);
    for (const bad of ["t1105", "T1105.1", "TA0011"]) {
      expect(problems([], xmlRule(100340, 12, "61605", [bad]))).toEqual([
        "pack rule with no Sigma YAML",
        `MITRE id ${JSON.stringify(bad)} is not a technique id (TNNNN or TNNNN.NNN)`,
      ]);
    }
    expect(problems([], xmlRule(100200, 0, "61605", [" T1105 "]))).toEqual([]);
  });

  // rules.c 1522-1525 discards a <mitre> block that mixes <id> with tacticID or techniqueID,
  // and 1488-1493 one with an empty <id>, so the rule loads with no MITRE ID at all.
  test("refuses a pack rule whose <mitre> block Wazuh discards, as a MITRE mismatch", () => {
    const d = doc();
    d.tags = ["attack.execution", "attack.t1059.001"];
    d.custom.wazuh.mitre = ["T1059.001"];
    const mixed = xmlRule().replace("<mitre><id>T1105</id></mitre>", "<mitre><id>T1059.001</id><tacticID>TA0002</tacticID><techniqueID>T1027</techniqueID></mitre>");
    expect(mixed).toContain("<tacticID>TA0002</tacticID>");
    expect(problems([sig(d)], mixed)).toEqual(["XML mitre (none) does not match custom.wazuh.mitre T1059.001"]);
    expect(problems([sig(doc())], xmlRule(100340, 12, "61605", [""]))).toEqual(["XML mitre (none) does not match custom.wazuh.mitre T1105"]);
    expect(problems([], xmlRule(100340, 12, "61605", [""]))).toEqual(["pack rule with no Sigma YAML"]);
  });

  // Wazuh keeps a tacticID/techniqueID pair apart from the <id> list, and whether the alert
  // shows its technique turns on the tactic too, which mitre-db-ids.txt does not record.
  test("refuses a pack rule that gives its technique as a tacticID/techniqueID pair", () => {
    const d = doc();
    d.tags = ["attack.execution", "attack.t1059.001"];
    d.custom.wazuh.mitre = ["T1059.001"];
    const paired = xmlRule().replace("<mitre><id>T1105</id></mitre>", "<mitre><tacticID>TA0002</tacticID><techniqueID>T1059.001</techniqueID></mitre>");
    expect(paired).toContain("<techniqueID>T1059.001</techniqueID>");
    expect(problems([sig(d)], paired)).toEqual([
      "XML mitre (none) does not match custom.wazuh.mitre T1059.001",
      'XML <mitre> pairs tacticID "TA0002" with techniqueID "T1059.001", a form the lint does not check (pack rules use <id>)',
    ]);
    expect(problems([], paired.replace('<rule id="100340" level="12">', '<rule id="100200" level="0">'))).toEqual([]);
  });

  test("refuses a pack XML rule with no YAML, and leaves other rules alone", () => {
    expect(problems([], xmlRule())).toEqual(["pack rule with no Sigma YAML"]);
    expect(problems([], xmlRule(100200, 0))).toEqual([]);
  });

  // A <group> option inside a pack rule is ordinary Wazuh syntax, not a nested group.
  test("lints clean a pack rule that carries a <group> option", () => {
    const withGroup = xmlRule().replace("<description>", "<group>attack.t1105,</group><description>");
    expect(withGroup).toContain("<group>attack.t1105,</group>");
    expect(problems([sig(doc())], withGroup)).toEqual([]);
  });

  // Wazuh loads <RULE ID=...> (strcasecmp), so the lint must see it too.
  test("sees a pack rule written in upper case", () => {
    const upper = xmlRule().replace("<rule id=", "<RULE ID=").replace("</rule>", "</RULE>");
    expect(problems([], upper)).toEqual(["pack rule with no Sigma YAML"]);
  });

  test("refuses a subfolder pack rule with no YAML", () => {
    const sub = parseRules(xmlRule(), "custom-rules/pack/x.xml");
    expect(lintPack([], tree([], sub, ["custom-rules/pack/x.xml"]), MITRE, SIGMAHQ)).toEqual([
      { file: "custom-rules/pack/x.xml", rule: 0, problem: "XML in a subfolder, which rule_dir never reads" },
      { file: "custom-rules/pack/x.xml", rule: 100340, problem: "pack rule with no Sigma YAML" },
    ]);
  });

  // ISA ISC-121's static half: rule_dir does not recurse.
  test("refuses XML in a subfolder", () => {
    const sub = parseRules(xmlRule(), "custom-rules/pack/x.xml");
    expect(lintPack([sig(doc())], tree([], sub, ["custom-rules/pack/x.xml"]), MITRE, SIGMAHQ).map((f) => f.problem)).toEqual([
      "XML in a subfolder, which rule_dir never reads",
      "XML rule is in custom-rules/pack/x.xml, a subfolder rule_dir never reads",
    ]);
  });

  test("refuses missing attribution, tags, condition and custom block", () => {
    const d: Record<string, unknown> = doc();
    d.related = [{ id: UPSTREAM, type: "similar" }];
    d.tags = ["attack.command-and-control"];
    d.detection = { selection: {} };
    expect(problems([sig(d)], xmlRule())).toEqual([
      "detection has no condition",
      "no ATT&CK technique tag",
      "no upstream attribution (related: type derived, with the upstream id)",
    ]);
    const bare: Record<string, unknown> = doc();
    bare.custom = undefined;
    expect(problems([sig(bare)], "")).toEqual(["no custom.wazuh block"]);
  });

  test("the SigmaHQ list holds the test's upstream id, active", () => {
    expect(SIGMAHQ.get(UPSTREAM)).toBe("");
  });

  // The lookup lowercases, so a duplicate in another case must not slip past the reader.
  test("reads SigmaHQ ids in lower case and refuses one listed twice in two cases", () => {
    expect(readSigmahqIds(`${UPSTREAM.toUpperCase()}\n`).get(UPSTREAM)).toBe("");
    expect(() => readSigmahqIds(`${UPSTREAM}\n${UPSTREAM.toUpperCase()} deprecated\n`)).toThrow(`SigmaHQ id ${UPSTREAM} is listed twice`);
  });

  test("refuses a derived id that is not a SigmaHQ rule id", () => {
    const made = "e0b9c3a1-5d2f-4c6e-9a7b-1f2e3d4c5b6a";
    const d = doc();
    d.related = [{ id: made, type: "derived" }];
    expect(problems([sig(d)], xmlRule())).toEqual([`upstream id ${made} is not a SigmaHQ rule id`]);
  });

  test("refuses a derived id SigmaHQ has deprecated", () => {
    const dep = [...SIGMAHQ].find(([, s]) => s === "deprecated")?.[0] ?? "";
    expect(dep).not.toBe("");
    const d = doc();
    d.related = [{ id: dep, type: "derived" }];
    expect(problems([sig(d)], xmlRule())).toEqual([`upstream id ${dep} is deprecated in SigmaHQ`]);
  });

  // UUIDs compare without regard to case; only derived entries are held to the list.
  test("passes a listed derived id in either case, and ignores other relation types", () => {
    const d = doc();
    d.related = [
      { id: UPSTREAM.toUpperCase(), type: "derived" },
      { id: "e0b9c3a1-5d2f-4c6e-9a7b-1f2e3d4c5b6a", type: "similar" },
    ];
    expect(problems([sig(d)], xmlRule())).toEqual([]);
  });

  test("refuses YAML missing any required key", () => {
    for (const k of ["title", "status", "description", "logsource", "detection"]) {
      const d: Record<string, unknown> = doc();
      delete d[k];
      expect(problems([sig(d)], xmlRule())).toEqual([`no ${k}`]);
    }
  });

  test("refuses a Sigma id that is not a UUID", () => {
    const d = doc();
    d.id = "certutil-download";
    expect(problems([sig(d)], xmlRule())).toEqual(["id is not a UUID"]);
  });

  // Both sides agreeing on nothing is still a rule with no parent.
  test("refuses a rule with no if_sid on either side", () => {
    const d = doc();
    const w: Record<string, unknown> = d.custom.wazuh;
    delete w.if_sid;
    expect(problems([sig(d)], xmlRule(100340, 12, ""))).toEqual(["no custom.wazuh.if_sid"]);
  });

  test("refuses a rule with no MITRE ID on either side", () => {
    const d = doc();
    d.custom.wazuh.mitre = [];
    expect(problems([sig(d)], xmlRule(100340, 12, "61605", []))).toEqual(["no custom.wazuh.mitre"]);
  });

  // readSigma throws on YAML that does not parse; an empty file or a multi-document one parses.
  test("refuses YAML that is not a single mapping", () => {
    for (const d of [null, "text", [doc(), doc()]]) {
      expect(lintPack([sig(d)], tree([]), MITRE, SIGMAHQ).map((f) => f.problem)).toEqual(["YAML is not a single mapping"]);
    }
  });

  test("the checked-in tree is clean", () => {
    const rules = readRulesDir(resolve(ROOT, "deploy/soc-recon/wazuh/custom-rules"), ROOT);
    expect(lintPack(readSigma(resolve(ROOT, "phase-b-detection/sigma")), rules, MITRE, SIGMAHQ)).toEqual([]);
  });

  test("the logtest self-test rules carry IDs mitre.db has", () => {
    const { rules } = readRulesDir(resolve(ROOT, "tools/fixtures/logtest/rules"), ROOT);
    expect(rules.length).toBe(2);
    for (const r of rules) {
      expect(r.mitre.length).toBeGreaterThan(0);
      for (const m of r.mitre) expect(MITRE.get(m)).toBe("");
    }
  });
});

describe("readSigma", () => {
  let dir = "";
  const at = (p: string) => join(dir, p);
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "sigma-read-t-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test("a missing folder holds no rules", () => {
    expect(readSigma(at("none"))).toEqual([]);
  });

  test("reads .yml and .yaml in any letter case, and nothing else", () => {
    for (const n of ["a.yml", "B.YAML", "c.Yml", "notes.txt", "d.yml.bak"]) writeFileSync(at(n), "title: t\n");
    expect(readSigma(dir).map((s) => basename(s.file))).toEqual(["B.YAML", "a.yml", "c.Yml"]);
  });

  // A rule one folder down would never be linted or logtested, so it stops both.
  test("throws naming YAML in a subfolder", () => {
    writeFileSync(at("a.yml"), "title: t\n");
    mkdirSync(at("pack/deeper"), { recursive: true });
    writeFileSync(at("pack/deeper/Deep.YAML"), "title: t\n");
    expect(() => readSigma(dir)).toThrow("pack/deeper/Deep.YAML");
    expect(() => readSigma(dir)).toThrow("subfolder");
  });

  test("throws naming a file that does not parse", () => {
    writeFileSync(at("good.yml"), "title: t\n");
    writeFileSync(at("bad.yml"), "title: [unclosed\n");
    expect(() => readSigma(dir)).toThrow("bad.yml");
    expect(() => readSigma(dir)).toThrow("does not parse");
  });
});

// Spawned, so the exit code and stderr are what a shell sees.
describe("sigma-lint entry point", () => {
  let dir = "";
  const at = (p: string) => join(dir, p);
  const lint = (o: { sigma?: string; rules?: string; mitre?: string; sigmahq?: string } = {}) => {
    const args = ["--sigma", o.sigma ?? at("sigma"), "--rules", o.rules ?? at("rules"), "--mitre", o.mitre ?? at("mitre.txt"), "--sigmahq", o.sigmahq ?? at("sigmahq.txt")];
    const p = Bun.spawnSync([process.execPath, "tools/sigma-lint.ts", ...args], { cwd: ROOT });
    return { code: p.exitCode, out: p.stdout.toString(), err: p.stderr.toString().trim() };
  };

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "sigma-lint-t-"));
    for (const d of ["rules", "pack-rules", "bad-rules", "early-rules", "sigma", "sigma-sub/pack", "sigma-bad", "odd-rules"]) mkdirSync(at(d), { recursive: true });
    writeFileSync(at("rules/local.xml"), xmlRule(100200, 0));
    writeFileSync(at("pack-rules/pack.xml"), xmlRule());
    writeFileSync(at("bad-rules/bad.xml"), xmlRule().replace('id="100340"', "id='abc'"));
    // Shapes os_xml or rules.c refuse, each in a folder of its own beside a good file.
    const odd: Record<string, string> = {
      "mitre-child": xmlRule(100200, 0).replace("</mitre>", "<tactic>TA0011</tactic></mitre>"),
      "nbsp-tag": xmlRule(100200, 0).replace("<rule id=", "<rule\u00a0id="),
      "gt-value": xmlRule(100200, 0).replace('<group name="pack,">', '<group name="pack,>">'),
      "empty-group": `${xmlRule(100200, 0)}<group name="empty,"></group>`,
    };
    for (const [name, xml] of Object.entries(odd)) {
      mkdirSync(at(`odd-rules/${name}`));
      writeFileSync(at(`odd-rules/${name}/a-local.xml`), xmlRule(100201, 0));
      writeFileSync(at(`odd-rules/${name}/${name}.xml`), xml);
    }
    writeFileSync(at("early-rules/local.xml"), xmlRule(100200, 0));
    writeFileSync(at("early-rules/0599-x.xml"), xmlRule(100201, 0));
    writeFileSync(at("mitre.txt"), "T1105\n");
    writeFileSync(at("sigmahq.txt"), `${UPSTREAM}\n`);
    writeFileSync(at("sigmahq-twice.txt"), `${UPSTREAM}\n${UPSTREAM} deprecated\n`);
    writeFileSync(at("mitre-twice.txt"), "T1105 revoked\nT1105\n");
    writeFileSync(at("mitre-extra.txt"), "T1105 active extra\n");
    writeFileSync(at("sigmahq-status.txt"), `${UPSTREAM} revoked\n`);
    writeFileSync(at("sigma-sub/pack/deep.yml"), "title: t\n");
    writeFileSync(at("sigma-bad/broken.yml"), "title: [unclosed\n");
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  test("exits 0 when the lint runs clean", () => {
    expect(lint()).toMatchObject({ code: 0, err: "sigma-lint: 0 finding(s)" });
  });

  // The default paths read both checked-in lists, so a reader that refuses either exits 2 here.
  test("exits 0 on the checked-in tree with no flags", () => {
    const p = Bun.spawnSync([process.execPath, "tools/sigma-lint.ts"], { cwd: ROOT });
    expect(p.exitCode).toBe(0);
    expect(p.stderr.toString().trim()).toEndWith("sigma-lint: 0 finding(s)");
  });

  test("exits 1 for lint findings", () => {
    const r = lint({ rules: at("pack-rules") });
    expect(r.code).toBe(1);
    expect(r.out).toContain("rule 100340: pack rule with no Sigma YAML");
  });

  const cannotRun: [string, () => Parameters<typeof lint>[0], string][] = [
    ["the rules folder is missing", () => ({ rules: at("none") }), "none"],
    ["the rules path is a file", () => ({ rules: at("mitre.txt") }), "mitre.txt"],
    ["a given Sigma folder is missing", () => ({ sigma: at("none") }), "none"],
    ["a given MITRE list is missing", () => ({ mitre: at("none.txt") }), "none.txt"],
    ["a given SigmaHQ list is missing", () => ({ sigmahq: at("none-hq.txt") }), "none-hq.txt"],
    ["the SigmaHQ list names an id twice", () => ({ sigmahq: at("sigmahq-twice.txt") }), UPSTREAM],
    ["a rule cannot be read", () => ({ rules: at("bad-rules") }), "bad.xml"],
    ["a rules file name would load among the stock files", () => ({ rules: at("early-rules") }), "0599-x.xml: a rules file name must start with a letter"],
    ["the MITRE list names an ID twice", () => ({ mitre: at("mitre-twice.txt") }), "T1105"],
    ["a MITRE list line has more than an id and a status", () => ({ mitre: at("mitre-extra.txt") }), "MITRE ID T1105 has more than"],
    ["a SigmaHQ list status is one its refresh never writes", () => ({ sigmahq: at("sigmahq-status.txt") }), `${UPSTREAM} has status revoked`],
    ["a Sigma YAML sits in a subfolder", () => ({ sigma: at("sigma-sub") }), "pack/deep.yml"],
    ["a Sigma YAML does not parse", () => ({ sigma: at("sigma-bad") }), "broken.yml"],
    ["a <mitre> child is not id, tacticID or techniqueID", () => ({ rules: at("odd-rules/mitre-child") }), "mitre-child.xml: <tactic> inside <mitre>"],
    ["a tag uses a no-break space as a space", () => ({ rules: at("odd-rules/nbsp-tag") }), "U+00A0, which os_xml does not read as a space"],
    ['an attribute value holds ">"', () => ({ rules: at("odd-rules/gt-value") }), 'gt-value.xml: attribute name holds ">"'],
    ["a rules file holds an empty <group>", () => ({ rules: at("odd-rules/empty-group") }), 'empty-group.xml: <group name="empty,"> holds no <rule>'],
  ];
  for (const [when, opts, names] of cannotRun) {
    test(`exits 2 with one line when ${when}`, () => {
      const r = lint(opts());
      expect(r.code).toBe(2);
      expect(r.err.split("\n")).toHaveLength(1);
      expect(r.err).toStartWith("sigma-lint: ");
      expect(r.err).toContain(names);
    });
  }

  // --out keeps the checked-in lists untouched while the command runs whole.
  const refresh = (...args: string[]) => {
    const p = Bun.spawnSync([process.execPath, "tools/sigma-lint.ts", ...args], { cwd: ROOT });
    return { code: p.exitCode, err: p.stderr.toString().trim() };
  };

  // The query reads reference.source/external_id joined to technique.deprecated/revoked_by.
  test("--refresh-mitre writes every mitre-attack technique with its status", () => {
    const db = new Database(at("mitre.db"));
    db.run("create table technique (id text, deprecated integer, revoked_by text)");
    db.run("create table reference (id text, source text, external_id text)");
    for (const [id, dep, rev] of [["ap-1", 0, null], ["ap-2", 1, null], ["ap-3", 0, "ap-9"], ["ap-4", 0, null]] as const) {
      db.run("insert into technique values (?, ?, ?)", [id, dep, rev]);
    }
    for (const [id, src, ext] of [
      ["ap-1", "mitre-attack", "T1105"],
      ["ap-2", "mitre-attack", "T1071"],
      ["ap-3", "mitre-attack", "T1003"],
      ["ap-4", "capec", "CAPEC-1"],
      ["ap-4", "mitre-attack", null],
      ["ta-1", "mitre-attack", "TA0011"],
    ] as const) {
      db.run("insert into reference values (?, ?, ?)", [id, src, ext]);
    }
    db.close();
    expect(refresh("--refresh-mitre", at("mitre.db"), "test image", "--out", at("mitre-out.txt"))).toMatchObject({ code: 0 });
    expect(readFileSync(at("mitre-out.txt"), "utf8").split("\n")).toEqual([
      "# Technique IDs in Wazuh's mitre.db (test image), 3 in all.",
      "# A <mitre> ID missing here is dropped from rule.mitre at alert time (ISA Decisions 2026-10-26).",
      '# Regenerate: bun tools/sigma-lint.ts --refresh-mitre <path to mitre.db> "<label>"',
      "T1003 revoked",
      "T1071 deprecated",
      "T1105",
      "",
    ]);
    // What the refresh writes, the reader must take back whole.
    expect([...readMitreIds(readFileSync(at("mitre-out.txt"), "utf8"))]).toEqual([
      ["T1003", "revoked"],
      ["T1071", "deprecated"],
      ["T1105", ""],
    ]);
  });

  // A one-commit git repo, unsigned and hook-free whatever the global git config says.
  const checkout = (name: string, files: Record<string, string>) => {
    const co = at(name);
    for (const [p, text] of Object.entries(files)) {
      mkdirSync(dirname(join(co, p)), { recursive: true });
      writeFileSync(join(co, p), text);
    }
    const git = (...a: string[]) =>
      Bun.spawnSync(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.name=t", "-c", "user.email=t@example.invalid", ...a], { cwd: co })
        .stdout.toString()
        .trim();
    git("init", "-q");
    git("add", "-A");
    git("commit", "-q", "--no-verify", "-m", "t");
    return { co, head: git("rev-parse", "--short", "HEAD") };
  };

  // The lint refuses a list that names an id twice, so the refresh must not write one.
  test("--refresh-mitre exits 2 naming an id the database returns twice, writing nothing", () => {
    const db = new Database(at("mitre-dup.db"));
    db.run("create table technique (id text, deprecated integer, revoked_by text)");
    db.run("create table reference (id text, source text, external_id text)");
    for (const id of ["ap-1", "ap-2", "ap-3"]) db.run("insert into technique values (?, 0, null)", [id]);
    for (const [id, ext] of [["ap-1", "T1105"], ["ap-2", "T1071"], ["ap-3", "T1105"]]) db.run("insert into reference values (?, 'mitre-attack', ?)", [id, ext]);
    db.close();
    const r = refresh("--refresh-mitre", at("mitre-dup.db"), "dup image", "--out", at("mitre-dup.txt"));
    expect(r.code).toBe(2);
    expect(r.err).toStartWith("sigma-lint: ");
    expect(r.err).toContain("T1105");
    expect(existsSync(at("mitre-dup.txt"))).toBe(false);
  });

  // The header records HEAD, which only describes the files read when nothing has changed since.
  test("--refresh-sigmahq exits 2 on a checkout that is not clean, writing nothing", () => {
    const files = { "rules/a.yml": `title: a\nid: ${ACTIVE}\n` };
    const edited = checkout("sigma-dirty-edit", files);
    writeFileSync(join(edited.co, "rules/a.yml"), `title: a2\nid: ${ACTIVE}\n`);
    const added = checkout("sigma-dirty-add", files);
    writeFileSync(join(added.co, "rules/new.yml"), `title: n\nid: ${RETIRED}\n`);
    for (const { co } of [edited, added]) {
      const out = at(`dirty-${basename(co)}.txt`);
      const r = refresh("--refresh-sigmahq", co, "fake sigma", "--out", out);
      expect(r.code).toBe(2);
      expect(r.err).toStartWith("sigma-lint: ");
      expect(r.err).toContain("checkout is not clean");
      expect(existsSync(out)).toBe(false);
    }
  });

  // The walk reads an ignored YAML like any other, so its id would land in the list unseen.
  test("--refresh-sigmahq exits 2 when an ignored file sits in the checkout, writing nothing", () => {
    const files = { "rules/a.yml": `title: a\nid: ${ACTIVE}\n` };
    const excluded = checkout("sigma-ignored-exclude", files);
    mkdirSync(join(excluded.co, ".git/info"), { recursive: true });
    writeFileSync(join(excluded.co, ".git/info/exclude"), "rules/hidden.yml\n");
    // The .gitignore goes into the commit, so the planted file is the only change after it.
    const ignored = checkout("sigma-ignored-gitignore", { ...files, ".gitignore": "rules/hidden.yml\n" });
    for (const { co } of [excluded, ignored]) {
      writeFileSync(join(co, "rules/hidden.yml"), `title: h\nid: ${RETIRED}\n`);
      expect(Bun.spawnSync(["git", "-C", co, "check-ignore", "-q", "rules/hidden.yml"]).exitCode).toBe(0);
      const out = at(`ignored-${basename(co)}.txt`);
      const r = refresh("--refresh-sigmahq", co, "fake sigma", "--out", out);
      expect(r.code).toBe(2);
      expect(r.err).toStartWith("sigma-lint: ");
      expect(r.err).toContain("checkout is not clean");
      expect(existsSync(out)).toBe(false);
    }
  });

  test("--refresh-sigmahq writes the top-level ids of rules*/ and deprecated/, marking deprecated ones", () => {
    const { co, head } = checkout("sigma-checkout", {
      "rules/windows/a.yml": `title: a\nid: ${ACTIVE}\nrelated:\n  - id: 11111111-1111-4111-8111-111111111111\n    type: derived\n`,
      "deprecated/windows/b.yml": `title: b\nid: ${RETIRED.toUpperCase()} # old\n`,
      "unsupported/c.yml": "title: c\nid: 22222222-2222-4222-8222-222222222222\n",
      "rules/README.md": "id: 33333333-3333-4333-8333-333333333333\n",
    });
    expect(head).toMatch(/^[0-9a-f]{7,}$/);
    expect(refresh("--refresh-sigmahq", co, "fake sigma", "--out", at("sigmahq-out.txt"))).toMatchObject({ code: 0 });
    const lines = readFileSync(at("sigmahq-out.txt"), "utf8").split("\n");
    expect(lines.filter((l) => !l.startsWith("#"))).toEqual([ACTIVE, `${RETIRED} deprecated`, ""]);
    expect([...readSigmahqIds(lines.join("\n"))]).toEqual([
      [ACTIVE, ""],
      [RETIRED, "deprecated"],
    ]);
    expect(lines[0]).toBe(`# Rule ids in a SigmaHQ/sigma checkout (fake sigma), HEAD ${head}, 2 in all.`);
    expect(lines.filter((l) => l.startsWith("#")).join("\n")).toContain(
      '# Regenerate: bun tools/sigma-lint.ts --refresh-sigmahq <path to a SigmaHQ/sigma checkout> "<label>"',
    );
  });

  // A line break in the label would write extra header lines, fake ids among them.
  test("both refresh commands refuse a label holding a line break, writing nothing", () => {
    for (const cmd of ["--refresh-mitre", "--refresh-sigmahq"]) {
      for (const label of ["a\nT9999", "a\rb"]) {
        const out = at(`label-${cmd.slice(2)}-${label.length}.txt`);
        const r = refresh(cmd, at("none-src"), label, "--out", out);
        expect(r.code).toBe(2);
        expect(r.err).toStartWith(`usage: bun tools/sigma-lint.ts ${cmd}`);
        expect(existsSync(out)).toBe(false);
      }
    }
  });

  // A root mapping indented as a whole is valid YAML, so the id is read by parsing the file.
  test("--refresh-sigmahq reads the id of a rule whose root mapping is indented", () => {
    const { co } = checkout("sigma-indented", {
      "rules/a.yml": `  title: a\n  id: ${ACTIVE}\n`,
      "deprecated/b.yml": `title: b\nid: "${RETIRED}" # quoted\n`,
    });
    expect(refresh("--refresh-sigmahq", co, "fake sigma", "--out", at("sigmahq-indented.txt"))).toMatchObject({ code: 0 });
    const ids = readFileSync(at("sigmahq-indented.txt"), "utf8").split("\n").filter((l) => !l.startsWith("#"));
    expect(ids).toEqual([ACTIVE, `${RETIRED} deprecated`, ""]);
  });

  test("--refresh-sigmahq exits 2 naming a rule that does not parse, is not a mapping or has no UUID id", () => {
    for (const [name, text] of [
      ["broken.yml", "title: [unclosed\n"],
      ["list.yml", `- id: ${ACTIVE}\n`],
      ["number.yml", "title: n\nid: 123\n"],
      ["plain.yml", "title: p\nid: not-a-uuid\n"],
    ]) {
      const { co } = checkout(`sigma-bad-${name}`, { [`rules/${name}`]: text });
      const r = refresh("--refresh-sigmahq", co, "fake sigma", "--out", at(`sigmahq-bad-${name}.txt`));
      expect(r.code).toBe(2);
      expect(r.err).toStartWith("sigma-lint: ");
      expect(r.err).toContain(name);
    }
  });

  test("--refresh-sigmahq exits 2 naming a rule with no top-level id", () => {
    const { co } = checkout("sigma-no-id", { "rules/x.yml": "title: x\nrelated:\n  - id: 11111111-1111-4111-8111-111111111111\n" });
    const r = refresh("--refresh-sigmahq", co, "fake sigma", "--out", at("sigmahq-none.txt"));
    expect(r.code).toBe(2);
    expect(r.err).toStartWith("sigma-lint: ");
    expect(r.err).toContain("x.yml");
  });

  // In process, so the default folder can point somewhere absent whatever the repo holds.
  test("lints only the XML, with one notice line, when the default Sigma folder is absent", () => {
    const err = spyOn(console, "error").mockImplementation(() => {});
    const log = spyOn(console, "log").mockImplementation(() => {});
    try {
      const run = (rules: string) => main(["--rules", at(rules), "--mitre", at("mitre.txt"), "--sigmahq", at("sigmahq.txt")], { ...DEFAULTS, sigma: at("absent") });
      expect(run("rules")).toBe(0);
      expect(run("pack-rules")).toBe(1);
      const notices = err.mock.calls.map((c) => String(c[0])).filter((l) => !l.endsWith("finding(s)"));
      expect(notices).toHaveLength(2);
      for (const n of notices) expect(n).toStartWith("sigma-lint: no Sigma folder at ");
      expect(log.mock.calls.map((c) => String(c[0]))).toEqual([expect.stringContaining("rule 100340: pack rule with no Sigma YAML")]);
    } finally {
      err.mockRestore();
      log.mockRestore();
    }
  });
});
