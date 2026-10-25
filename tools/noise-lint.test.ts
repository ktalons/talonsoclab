// *****************************************************************************
// *Title: noise-lint.test*
// *Author: Kyle Versluis*
// *Description: Planted bad suppressions that noise-lint must refuse.*
// *****************************************************************************

// *--- Imports ---*

import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { lint, lintDir } from "./noise-lint.ts";

// *--- Configuration ---*

const f = (name: string, pattern: string) => `<field name="${name}" type="pcre2">${pattern}</field>`;
const GOOD = [
  "<if_sid>80792</if_sid>",
  f("audit.auid", "^4294967295$"),
  f("audit.tty", "^\\(none\\)$"),
  f("audit.exe", "^/usr/bin/curl$"),
  f("audit.cwd", "^/usr/share/wazuh-indexer$"),
  f("audit.uid", "^1000$"),
  f("audit.euid", "^1000$"),
  f("audit.gid", "^1000$"),
  '<regex type="pcre2">subj=docker-default key="audit-wazuh-c".*argc=2 a0="curl" a1="-sf" type=</regex>',
].join("\n");
const rule = (id: number, level: number, inner: string, attrs = "") =>
  `<group name="t,"><rule id="${id}" level="${level}"${attrs}>${inner}</rule></group>`;
const problems = (xml: string) => lint(xml, "t.xml").map((x) => x.problem);
const swap = (from: string, to: string) => GOOD.replace(from, to);

// *--- Tests ---*

describe("noise-lint", () => {
  test("a well-keyed suppression passes", () => {
    expect(problems(rule(100150, 0, GOOD))).toEqual([]);
  });

  // ISA ISC-112: the planted 1-field suppression.
  test("refuses a suppression with one field constraint", () => {
    const one = `<if_sid>80792</if_sid>${f("audit.exe", "^/usr/bin/curl$")}`;
    expect(problems(rule(100150, 0, one))).toContain("1 field constraint(s), need at least 2");
  });

  test("refuses a suppression keyed on rule ID alone", () => {
    expect(problems(rule(100150, 0, "<if_sid>80792</if_sid>"))).toContain(
      "0 field constraint(s), need at least 2",
    );
  });

  test("refuses a suppression with no image field", () => {
    const noImage = `<if_sid>80792</if_sid>${f("audit.cwd", "^/$")}${f("audit.auid", "^4294967295$")}`;
    expect(problems(rule(100150, 0, noImage))).toContain(
      "no image field (audit.exe or win.eventdata.image)",
    );
  });

  test("refuses an unanchored field", () => {
    expect(problems(rule(100150, 0, swap("^/usr/bin/curl$", "/usr/bin/curl")))).toContain(
      "audit.exe is not anchored ^...$",
    );
  });

  // Forge audit 2026-10-25: each of these passed the first lint.
  for (const any of ["^.*$", "^(.*)$", "^|$", "^[^\\n]*$", "^.{0,}$", "^(curl|)$", "^.+$"]) {
    test(`refuses a field that matches anything: ${any}`, () => {
      expect(problems(rule(100150, 0, swap("^/usr/share/wazuh-indexer$", any)))).toContain(
        "audit.cwd matches anything",
      );
    });
  }

  test("refuses a negated field", () => {
    const neg = swap('name="audit.exe" type="pcre2"', 'name="audit.exe" type="pcre2" negate="yes"');
    expect(problems(rule(100150, 0, neg))).toContain("audit.exe is negated");
  });

  test("refuses a field that is not pcre2", () => {
    expect(problems(rule(100150, 0, swap('name="audit.exe" type="pcre2"', 'name="audit.exe"')))).toContain(
      'audit.exe is not type="pcre2"',
    );
  });

  test("refuses an auditd suppression with no full_log regex", () => {
    expect(problems(rule(100150, 0, GOOD.replace(/<regex[\s\S]*<\/regex>/, "")))).toContain("no full_log regex");
  });

  test("refuses an auditd suppression missing a keying field", () => {
    expect(problems(rule(100150, 0, swap(f("audit.gid", "^1000$"), "")))).toContain("no audit.gid field");
  });

  test("refuses a regex that does not pin argc or the label", () => {
    const loose = GOOD.replace(/<regex[\s\S]*<\/regex>/, '<regex type="pcre2">a0="curl" a1="-sf"</regex>');
    expect(problems(rule(100150, 0, loose))).toEqual(
      expect.arrayContaining(["regex does not pin argc", "regex does not pin the AppArmor label"]),
    );
  });

  test("refuses a parent that is not listed", () => {
    expect(problems(rule(100150, 0, swap("<if_sid>80792</if_sid>", "<if_sid>1</if_sid>")))).toContain(
      "if_sid 1 is not a listed parent",
    );
  });

  test("refuses an if_group parent", () => {
    const grp = swap("<if_sid>80792</if_sid>", "<if_group>audit</if_group>");
    expect(problems(rule(100150, 0, grp))).toEqual(expect.arrayContaining(["no if_sid parent", "<if_group> parent"]));
  });

  test("refuses a noise-range rule that is not level 0", () => {
    expect(problems(rule(100150, 3, GOOD))).toContain("noise-range rule is not level 0");
  });

  test("refuses a noise-range rule with no if_sid", () => {
    expect(problems(rule(100150, 0, swap("<if_sid>80792</if_sid>", "")))).toContain("no if_sid parent");
  });

  // Anything below log_alert_level, noalert or no_log never reaches the index.
  test("refuses a silencing rule outside the noise range", () => {
    const out = "silencing rule outside 100100-100199";
    expect(problems(rule(100340, 0, GOOD))).toContain(out);
    expect(problems(rule(100340, 2, GOOD))).toContain(out);
    expect(problems(rule(100340, 5, GOOD, ' noalert="1"'))).toContain(out);
    expect(problems(rule(100340, 5, `${GOOD}<options>no_log</options>`))).toContain(out);
  });

  test("refuses CDATA in a rules file", () => {
    expect(problems(rule(100150, 0, swap("^/usr/bin/curl$", "<![CDATA[^/usr/bin/curl$]]>")))).toContain(
      "CDATA in a rules file",
    );
  });

  test("keeps the grandfathered Suricata rule and ignores alerting rules", () => {
    expect(problems(rule(100200, 0, "<if_sid>86601</if_sid>"))).toEqual([]);
    expect(problems(rule(100330, 3, "<program_name>x</program_name>"))).toEqual([]);
  });

  test("ignores a commented-out rule", () => {
    expect(problems(`<!-- ${rule(100150, 0, "<if_sid>1</if_sid>")} -->`)).toEqual([]);
  });

  test("the live rules folder is clean", () => {
    expect(lintDir(resolve(import.meta.dir, "../deploy/soc-recon/wazuh/custom-rules"))).toEqual([]);
  });
});
