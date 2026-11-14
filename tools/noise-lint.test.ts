// *****************************************************************************
// *Title: noise-lint.test*
// *Author: Kyle Versluis*
// *Description: Planted bad suppressions that noise-lint must refuse.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { lint, lintDir, outsideSubset } from "./noise-lint.ts";

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
  '<regex type="pcre2">subj=soc-recon-indexer key="audit-wazuh-c".*argc=2 a0="curl" a1="-sf" type=</regex>',
].join("\n");
const TAIL = ' key="audit-wazuh-c".*argc=2 a0="curl" a1="-sf" type=';
// GOOD with its full_log regex replaced.
const withRegex = (pattern: string) => GOOD.replace(/<regex[\s\S]*<\/regex>/, `<regex type="pcre2">${pattern}</regex>`);
const rule = (id: number, level: number, inner: string, attrs = "") =>
  `<group name="t,"><rule id="${id}" level="${level}"${attrs}>${inner}</rule></group>`;
const problems = (xml: string) => lint(xml, "t.xml").map((x) => x.problem);
// True when the lint refuses the named matcher as outside the pattern subset.
const outside = (xml: string, label: string) => problems(xml).some((x) => x.startsWith(`${label} is outside the pattern subset: `));
// NOTE: split and join, not String.replace: a "$&" in the new text would paste the match back in.
const swap = (from: string, to: string) => GOOD.split(from).join(to);

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

  // ISA ISC-116: docker-default names every container, so no suppression may pin it.
  test("refuses a suppression that pins docker-default", () => {
    expect(problems(rule(100150, 0, withRegex(`subj=docker-default${TAIL}`)))).toEqual([
      "regex pins docker-default, the label every other container shares",
    ]);
  });

  for (const label of ["runc", "unconfined", "soc-recon-indexer", "soc-recon-manager", "soc-recon-dashboard", "soc-recon-suricata"]) {
    test(`accepts the label ${label}`, () => {
      expect(problems(rule(100150, 0, withRegex(`subj=${label}${TAIL}`)))).toEqual([]);
    });
  }

  for (const label of ["\\S+", "soc-recon-.*", "(runc|docker-default)", "soc-recon-manager2", "lxc-container-default", "[a-z-]+", "."]) {
    test(`refuses the label pattern ${label}`, () => {
      const got = problems(rule(100150, 0, withRegex(`subj=${label}${TAIL}`)));
      expect(got).toContain(`regex pins the label ${label}, not runc, unconfined or a service profile`);
    });
  }

  test("refuses a label that is not the first thing the regex matches", () => {
    expect(problems(rule(100150, 0, withRegex(`.*subj=runc${TAIL}`)))).toContain("regex does not pin the AppArmor label");
    expect(problems(rule(100150, 0, withRegex(`exe="/x" subj=runc${TAIL}`)))).toContain("regex does not pin the AppArmor label");
  });

  test("refuses a regex that names subj= twice", () => {
    const twice = withRegex(`subj=runc key="audit-wazuh-c".*( subj=docker-default key=)?.*argc=2 a0="curl" type=`);
    expect(problems(rule(100150, 0, twice))).toEqual(["regex names subj= more than once"]);
  });

  // An alternation outside a group gives the rule a second pattern with no label and no anchor.
  test("refuses a regex that alternates outside a group", () => {
    expect(problems(rule(100150, 0, withRegex(`subj=runc${TAIL}|argc=2 a0="curl" type=`)))).toEqual([
      "<regex> alternates outside a group",
    ]);
  });

  test("refuses a field that alternates outside a group", () => {
    const got = problems(rule(100150, 0, swap(f("audit.exe", "^/usr/bin/curl$"), f("audit.exe", "^/usr/bin/curl$|^/tmp/x$"))));
    expect(got).toEqual(["audit.exe alternates outside a group"]);
  });

  test("keeps an alternation inside a group", () => {
    const grouped = swap(f("audit.exe", "^/usr/bin/curl$"), f("audit.exe", "^(/usr/bin/curl|/usr/bin/wget)$"));
    expect(problems(rule(100150, 0, grouped))).toEqual([]);
  });

  for (const [what, pattern] of [
    ["a quoted run", `subj=runc${TAIL}\\Q(\\E|x`],
    ["an inline option", `subj=runc${TAIL}(?i)x`],
    ["a non-capturing group", `subj=runc${TAIL}(?:x|y)`],
  ]) {
    test(`refuses ${what}`, () => {
      expect(outside(rule(100150, 0, withRegex(pattern)), "<regex>")).toBe(true);
    });
  }

  // Audit 2026-11-14: PCRE2 reads a "]" straight after "[" or "[^" as a literal, so the class
  // runs on, while JS closes it at once. The scans follow JS, so a "(" that PCRE2 holds inside
  // the class looked like an open group and hid the "|" after it. pcre2test 10.49 matched a
  // docker-default record with the first pattern and "/tmp/evil" with the field.
  for (const [what, pattern] of [
    ["a class that opens with ]", `subj=soc-recon-manager${TAIL}[](]|type=SYSCALL msg=audit\\(\\d+\\.\\d+:\\d+[])]`],
    ["a negated class that opens with ]", `subj=soc-recon-manager${TAIL}[^](]|type=SYSCALL [^])]`],
  ]) {
    test(`refuses ${what} in the regex`, () => {
      expect(outside(rule(100150, 0, withRegex(pattern)), "<regex>")).toBe(true);
    });
  }

  test("refuses a class that opens with ] in a field", () => {
    const got = problems(rule(100150, 0, swap(f("audit.exe", "^/usr/bin/curl$"), f("audit.exe", "^[](]|[])]?$"))));
    expect(got.some((x) => x.startsWith("audit.exe is outside the pattern subset: "))).toBe(true);
  });

  // Audit 2026-11-14: an XML parser that decodes entities turns "&#124;" into "|" after the
  // lint has read the text. Whether Wazuh's parser decodes or not, no matcher needs a "&":
  // the indexer healthcheck writes the one in its URL as \x26.
  for (const entity of ["&#124;", "&#x7c;", "&amp;", "&"]) {
    test(`refuses ${entity} in the regex`, () => {
      expect(problems(rule(100150, 0, withRegex(`subj=runc${TAIL}${entity}.*`)))).toEqual([
        'holds "&" outside a comment; write it as \\x26 in a pattern',
        `<regex> is outside the pattern subset: character "&" at character ${`subj=runc${TAIL}`.length + 1}`,
      ]);
    });
  }

  test("refuses an entity in a field", () => {
    const got = problems(rule(100150, 0, swap(f("audit.exe", "^/usr/bin/curl$"), f("audit.exe", "^/usr/bin/curl$&#124;^/tmp/x$"))));
    expect(got.some((x) => x.startsWith("audit.exe "))).toBe(true);
  });

  // One regex and one constraint per field, so no second element can widen the first.
  test("refuses a second full_log regex", () => {
    const two = GOOD + '\n<regex type="pcre2">subj=runc key="audit-wazuh-c".*argc=2 a0="x" type=</regex>';
    expect(problems(rule(100150, 0, two))).toContain("2 full_log regexes, need 1");
  });

  test("refuses a <match> beside the regex", () => {
    expect(problems(rule(100150, 0, GOOD + '\n<match type="pcre2">^type=SYSCALL$</match>'))).toContain("<match> is not an element a suppression may use");
  });

  test("refuses a field named twice", () => {
    expect(problems(rule(100150, 0, GOOD + "\n" + f("audit.exe", "^/usr/bin/wget$")))).toContain("audit.exe is constrained twice");
  });

  // Audit 2026-11-14: OSSEC-style parsers may compare element and attribute names without
  // case (not measured here), and the lint read them with it. Anything outside one plain tag shape is refused, in any
  // rule of the file, so a tag the lint would skip cannot carry a matcher or a silencer.
  for (const [what, xml] of [
    ["an upper-case matcher element", rule(100150, 0, GOOD + '\n<REGEX type="pcre2">|type=SYSCALL</REGEX>')],
    ["an upper-case rule element", '<group name="t,"><RULE id="100150" level="0">' + GOOD + "</RULE></group>"],
    ["an upper-case attribute", rule(100150, 0, GOOD.split('<regex type="pcre2">').join('<regex type="pcre2" NEGATE="yes">'))],
    ["a single-quoted attribute", rule(100150, 0, GOOD.split('<regex type="pcre2">').join("<regex type='pcre2'>"))],
    ["an attribute given twice", '<group name="t,"><rule id="100150" level="5" level="0">' + GOOD + "</rule></group>"],
    ["a space before the closing bracket", rule(5000, 5, "<if_sid>80792</if_sid><options >no_log</options>")],
    ["a self-closing tag", rule(100150, 0, GOOD + "\n<same_source_ip />")],
  ] as [string, string][]) {
    test(`refuses ${what}`, () => {
      expect(lint(xml, "t.xml").some((x) => x.problem.startsWith("tag the lint cannot read: "))).toBe(true);
    });
  }

  test("refuses a grandfathered rule whose body changed", () => {
    const widened = '<group name="t,"><rule id="100200" level="0"><if_sid>80792</if_sid><regex type="pcre2">.</regex></rule></group>';
    expect(problems(widened)).toEqual(["grandfathered rule 100200 is not the rule that was kept"]);
  });

  // Audit round 2, 2026-11-14: a POSIX class. JS closes the outer class at the "]" of
  // "[:alpha:]", so the "(" after it looked like an open group and hid the "|". pcre2test
  // 10.49 matched a docker-default record with the second branch.
  test("refuses a POSIX class in the regex and in a field", () => {
    const posix = 'subj=soc-recon-manager key=[[:alpha:](]|type=SYSCALL msg=audit\\(\\d+\\.\\d+:\\d+[[:alpha:])] argc=2 a0="curl" type=';
    expect(outside(rule(100150, 0, withRegex(posix)), "<regex>")).toBe(true);
    const field = swap(f("audit.exe", "^/usr/bin/curl$"), f("audit.exe", "^/usr/bin/[[:alpha:](]|[[:alpha:])]$"));
    expect(outside(rule(100150, 0, field), "audit.exe")).toBe(true);
  });

  // The subset is an allowlist: these name what is inside it and a sample of what is not.
  for (const p of [
    "^/usr/bin/curl$", "^4294967295$", "^\\(none\\)$", "^(/var/ossec/bin/wazuh-modulesd|/usr/bin/xargs)$",
    "^/var/lib/docker/rootfs/overlayfs/[0-9a-f]{64}$", 'a0="rpm" a1="-q" a2="[A-Za-z0-9][A-Za-z0-9._+-]*"',
    "a2=2F62(3[0-9])+20 type=", 'a2="\\{\\}" x\\?y\\x26z', ".*type=EXECVE msg=audit\\(\\d+\\.\\d+:\\d+\\): argc=2",
  ]) {
    test(`inside the subset: ${p}`, () => {
      expect(outsideSubset(p)).toBeNull();
    });
  }

  for (const [p, why] of [
    ["a|b", "alternates outside a group"], ["^a$|^b$", "alternates outside a group"], ["(a|b)|c", "alternates outside a group"],
    ["a[]b]", "class"], ["a[^b]", "class"], ["a[[:alpha:]]", "class"], ["a[b|c]", "class"], ["a[\\d]", "class"], ["a[b", "class"],
    ["a\\Qb\\E", "escape \\Q"], ["a\\s", "escape \\s"], ["a\\Kb", "escape \\K"], ["a\\1", "escape \\1"], ["a\\x2", "escape \\x"], ["a\\", "escape \\"],
    ["(?i)a", "character \"?\""], ["(?:a|b)", "character \"?\""], ["(*ACCEPT)a", "character \"*\""], ["()", "empty branch"], ["(a|)", "empty branch"], ["(|a)", "empty branch"], ["(a||b)", "empty branch"], ["(a", "group never closed"], ["a)", "unopened )"],
    ["a*?", "second quantifier"], ["a++", "second quantifier"], ["a{2}{3}", "second quantifier"], ["a{,3}", "brace"], ["a{0}", "brace"], ["a{2,3}", "brace"], ["a}", "character \"}\""], ["a]", "character \"]\""],
    ["a^b", "^ inside the pattern"], ["a$b", "$ inside the pattern"], ["*a", "character \"*\""],
    ["a&b", "character \"&\""], ["a'b", "character \"'\""], ["a\tb", "character \"\\t\""], ["a\nb", "character \"\\n\""], ["aéb", "character \"é\""], ["a<b", "character \"<\""], ["a#b", "character \"#\""],
  ] as [string, string][]) {
    test(`outside the subset: ${JSON.stringify(p)}`, () => {
      expect(outsideSubset(p)?.startsWith(why)).toBe(true);
    });
  }

  // Nothing in a suppression but its parent, its matchers and a description.
  for (const [what, extra, msg] of [
    ["a same_source_ip element", "<same_source_ip></same_source_ip>", "<same_source_ip> is not an element a suppression may use"],
    ["an options element", "<options>no_full_log</options>", "<options> is not an element a suppression may use"],
    ["a list lookup", '<list field="audit.exe" lookup="match_key">etc/lists/x</list>', "<list> is not an element a suppression may use"],
  ] as [string, string, string][]) {
    test(`refuses ${what} in a suppression`, () => {
      expect(problems(rule(100150, 0, GOOD + "\n" + extra))).toContain(msg);
    });
  }

  for (const attr of ["noalert", "frequency", "ignore", "maxsize", "timeframe"]) {
    test(`refuses the rule attribute ${attr} on a suppression`, () => {
      expect(problems(rule(100150, 0, GOOD, ` ${attr}="1"`))).toContain(`rule attribute ${attr} is not one a suppression may use`);
    });
  }

  // Audit round 2, 2026-11-14 (Claude leg). Each of these passed the lint of the day.
  test("refuses \\c, which swallows the next character in PCRE2 only", () => {
    expect(outside(rule(100150, 0, withRegex(`subj=soc-recon-manager key=\\c[|argc=2 a0="curl" type=]?`)), "<regex>")).toBe(true);
    const gid = swap(f("audit.gid", "^1000$"), f("audit.gid", "^1000\\c[|]?$"));
    expect(outside(rule(100150, 0, gid), "audit.gid")).toBe(true);
  });

  for (const letter of ["N", "X", "H", "V", "R", "s", "S", "w", "W", "D", "b", "K", "G"]) {
    test(`refuses \\${letter}, which PCRE2 gives a meaning the lint has not vetted`, () => {
      expect(outside(rule(100150, 0, withRegex(`subj=soc-recon-manager key=\\${letter}*(argc=1 )?`)), "<regex>")).toBe(true);
      expect(outsideSubset(`a\\${letter}`)).toBe(`escape \\${letter} at character 2`);
    });
  }

  // os_xml substitutes <var> into the text that follows, after the lint has read it.
  test("refuses a var element and a variable in a matcher", () => {
    const withVar = '<group name="t,"><var name="ALT">|argc=2 a0="curl"</var><rule id="100150" level="0">' + GOOD + "</rule></group>";
    expect(problems(withVar)).toEqual(["var element: Wazuh would substitute it into text the lint reads as written"]);
    expect(outside(rule(100150, 0, withRegex("subj=soc-recon-manager key=$ALT(argc=1 )?")), "<regex>")).toBe(true);
  });

  // An overwrite changes a rule defined elsewhere, a stock one included.
  test("refuses overwrite on any rule, in or out of the noise range", () => {
    const stock = '<group name="t,"><rule id="80792" level="3" overwrite="yes"><if_sid>80700</if_sid><field name="audit.exe" type="pcre2">^/nonexistent$</field></rule></group>';
    expect(problems(stock)).toEqual(["overwrite replaces a rule defined elsewhere, which this lint does not follow"]);
    expect(problems(rule(100150, 0, GOOD, ' overwrite="yes"'))).toContain("overwrite replaces a rule defined elsewhere, which this lint does not follow");
  });

  // If Wazuh ends a comment somewhere the lint does not, a rule the lint stripped is live.
  for (const [what, xml] of [
    ["a comment that holds !>", '<group name="t,"><!-- note !><rule id="100150" level="0"><if_sid>80792</if_sid></rule><!-- --></group>'],
    ["a comment opened and shut as <!-->", '<group name="t,"><!--><rule id="100150" level="0"><if_sid>80792</if_sid></rule><!-- --></group>'],
    ["a comment opened and shut as <!--->", '<group name="t,"><!---><rule id="100150" level="0"><if_sid>80792</if_sid></rule><!-- --></group>'],
    ["a declaration", '<!DOCTYPE x><group name="t,">' + '<rule id="100330" level="3"><description>x</description></rule></group>'],
    ["a comment that never ends", '<group name="t,"><rule id="100330" level="3"><description>x</description></rule></group><!-- open'],
  ] as [string, string][]) {
    test(`refuses ${what}`, () => {
      expect(lint(xml, "t.xml").length).toBeGreaterThan(0);
    });
  }

  test("a plain comment with > and < in it is still a comment", () => {
    expect(problems("<!-- /bin/ps -p <pid> > /dev/null 2>&1 -->" + rule(100150, 0, GOOD))).toEqual([]);
  });

  // Audit round 3, 2026-11-14. Wazuh reads id and level with C integer parsing, so a value
  // the lint took for one number could be another to Wazuh, and the rule went unchecked.
  for (const [id, level] of [["100300", "0003"], ["100300", "4294967296"], ["1001500", "00003"], ["1001500", "0"], ["1000000", "3"], ["0", "3"], ["4295067446", "4294967296"], ["0100150", "0"], ["100150", "+0"], ["100150", " 0"], ["100150", "17"], ["100150", "-1"], ["100150", "0x0"], ["100150", ""]]) {
    test(`refuses id ${JSON.stringify(id)} with level ${JSON.stringify(level)}`, () => {
      const xml = `<group name="t,"><rule id="${id}" level="${level}"><if_sid>80792</if_sid><description>x</description></rule></group>`;
      expect(problems(xml)).toContain("rule without a plain id (1 to 999999) and level (0 to 16)");
    });
  }

  test("accepts the largest plain id and level, and every option the lint knows", () => {
    expect(problems('<group name="t,"><rule id="999999" level="16"><description>x</description></rule></group>')).toEqual([]);
    expect(problems('<group name="t,"><rule id="1" level="3"><description>x</description></rule></group>')).toEqual([]);
    for (const o of ["no_full_log", "alert_by_email", "no_email_alert", "no_counter"]) {
      expect(problems(`<group name="t,"><rule id="100300" level="12"><options>${o}</options></rule></group>`)).toEqual([]);
    }
  });

  // Closing pass, 2026-11-14: PCRE2 copies a group once per repeat, so nested {n} multiplies
  // the compiled size past its limit (error 120 in 10.49) while every single cap is met.
  for (const p of ["((ab){99}){99}", "((((a){9}){9}){9}){9}", "(ab){2}", "a(b|c){3}d"]) {
    test(`outside the subset, a counted repeat of a group: ${p}`, () => {
      expect(outsideSubset(p)?.startsWith("counted repeat of a group")).toBe(true);
    });
  }

  for (const p of ["(3[0-9])+20", "(ab)*", "(a|b)?c", "a{3}(b)+", "[0-9a-f]{64}"]) {
    test(`inside the subset: ${p}`, () => {
      expect(outsideSubset(p)).toBeNull();
    });
  }

  test("refuses & anywhere outside a comment, and an option the lint does not know", () => {
    const entity = '<group name="t,"><rule id="100300" level="12"><if_sid>80792</if_sid><options>no&#95;log</options></rule></group>';
    expect(problems(entity)).toEqual(['holds "&" outside a comment; write it as \\x26 in a pattern', 'option "no&#95;log" is not one the lint knows']);
    const upper = '<group name="t,"><rule id="100300" level="12"><if_sid>80792</if_sid><options>NO_LOG</options></rule></group>';
    expect(problems(upper)).toEqual(['option "NO_LOG" is not one the lint knows']);
    const spaced = '<group name="t,"><rule id="100300" level="12"><if_sid>80792</if_sid><options> no_log</options></rule></group>';
    expect(problems(spaced)).toEqual(['option " no_log" is not one the lint knows', "silencing rule outside 100100-100199"]);
    expect(problems("<!-- 2>&1 -->" + rule(100150, 0, GOOD))).toEqual([]);
  });

  test("still refuses no_log outside the noise range when it is spelled plainly", () => {
    const plain = '<group name="t,"><rule id="100300" level="12"><if_sid>80792</if_sid><options>no_log</options></rule></group>';
    expect(problems(plain)).toEqual(["silencing rule outside 100100-100199"]);
  });

  for (const [what, xml] of [
    ["a rule inside a rule", '<group name="t,"><rule id="100300" level="5"><if_sid>80792</if_sid><rule id="100150" level="0"><if_sid>80792</if_sid></rule></rule></group>'],
    ["a rule that is never closed", '<group name="t,"><rule id="100150" level="0"><if_sid>80792</if_sid></group>'],
    ["a second rule that is never closed", '<group name="t,">' + '<rule id="100330" level="3"><description>x</description></rule><rule id="100150" level="0"><if_sid>80792</if_sid></group>'],
    ["a stray closing rule tag", '<group name="t,"><rule id="100330" level="3"><description>x</description></rule></rule></group>'],
  ] as [string, string][]) {
    test(`refuses ${what}`, () => {
      expect(problems(xml)).toContain("a rule is unclosed or sits inside another rule");
    });
  }

  test("refuses a closing tag that carries attributes", () => {
    const xml = '<group name="t,"><rule id="100330" level="3"><description>x</description></rule x="1"></group>';
    expect(lint(xml, "t.xml").some((x) => x.problem.startsWith("tag the lint cannot read: </rule"))).toBe(true);
  });

  // PCRE2 refuses these to compile and JS takes them (pcre2test 10.49: errors 113, 105, 120, 119).
  for (const [p, why] of [
    ["a[.a.]", "class"], ["a[.0-9.]+", "class"], ["a[..]", "class"],
    ["a{1000}", "brace"], ["a{65536}", "brace"], ["(ab){40000}", "counted repeat of a group"],
    ["(((((a)))))", "group nested too deep"], ["a".repeat(1001), "longer than 1000 characters"],
  ] as [string, string][]) {
    test(`outside the subset: ${JSON.stringify(p.slice(0, 20))}`, () => {
      expect(outsideSubset(p)?.startsWith(why)).toBe(true);
    });
  }

  for (const p of ["a[.]", "a[.a]", "a[a.]", "a{999}", "((((a))))", "a".repeat(1000)]) {
    test(`inside the subset: ${JSON.stringify(p.slice(0, 20))}`, () => {
      expect(outsideSubset(p)).toBeNull();
    });
  }

  describe("lintDir", () => {
    const made: string[] = [];
    afterAll(() => {
      for (const d of made) rmSync(d, { recursive: true, force: true });
    });
    const folder = (files: Record<string, string>) => {
      const dir = mkdtempSync(join(tmpdir(), "noise-lint-"));
      made.push(dir);
      for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
      return lintDir(dir).map((x) => x.problem);
    };
    const OK = '<group name="t,"><rule id="100330" level="3"><description>x</description></rule></group>';
    const SILENT = '<group name="t,"><rule id="100300" level="5" noalert="1"><if_sid>80792</if_sid></rule></group>';

    // The whole folder is mounted into the manager, whatever a file is called.
    for (const name of ["zz_extra.XML", "zz_extra.xml.bak", "notes.txt", "extra"]) {
      test(`refuses ${name} in the rules folder`, () => {
        expect(folder({ "ok.xml": OK, [name]: SILENT })).toEqual(["not a .xml file: the manager gets it and the lint does not read it"]);
      });
    }

    test("reads every .xml file and allows a .gitkeep", () => {
      expect(folder({ "ok.xml": OK, ".gitkeep": "" })).toEqual([]);
      expect(folder({ "ok.xml": OK, "zz.xml": SILENT })).toEqual(["silencing rule outside 100100-100199"]);
    });
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

  test("keeps the grandfathered Suricata rule as committed and ignores alerting rules", () => {
    const tuning = readFileSync(resolve(import.meta.dir, "../deploy/soc-recon/wazuh/custom-rules/local_suricata_tuning.xml"), "utf8");
    expect(tuning).toContain('<rule id="100200" level="0">');
    expect(problems(tuning)).toEqual([]);
    expect(problems(rule(100330, 3, "<program_name>x</program_name>"))).toEqual([]);
  });

  test("refuses the grandfathered id on any other body", () => {
    expect(problems(rule(100200, 0, "<if_sid>86601</if_sid>"))).toEqual(["grandfathered rule 100200 is not the rule that was kept"]);
  });

  test("ignores a commented-out rule", () => {
    expect(problems(`<!-- ${rule(100150, 0, "<if_sid>1</if_sid>")} -->`)).toEqual([]);
  });

  test("no live suppression pins docker-default", () => {
    const xml = readFileSync(resolve(import.meta.dir, "../deploy/soc-recon/wazuh/custom-rules/local_noise_baseline.xml"), "utf8");
    const labels = [...xml.replace(/<!--[\s\S]*?-->/g, "").matchAll(/<regex type="pcre2">subj=(\S+) key=/g)].map((m) => m[1]);
    expect(labels.length).toBe(23);
    expect(labels).not.toContain("docker-default");
    expect(new Set(labels)).toEqual(new Set(["runc", "unconfined", "soc-recon-indexer", "soc-recon-manager", "soc-recon-suricata"]));
  });

  test("the live rules folder is clean", () => {
    expect(lintDir(resolve(import.meta.dir, "../deploy/soc-recon/wazuh/custom-rules"))).toEqual([]);
  });
});
