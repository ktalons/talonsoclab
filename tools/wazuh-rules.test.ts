// *****************************************************************************
// *Title: wazuh-rules.test*
// *Author: Kyle Versluis*
// *Description: Rule parsing, and the top-level-only load that rule_dir does.*
// *****************************************************************************

// *--- Imports ---*

import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isPack, parseRules, RulesError, readRulesDir } from "./wazuh-rules.ts";

// *--- Configuration ---*

const rule = (id: number) => `<group name="t,"><rule id="${id}" level="10"><if_sid>61605</if_sid><description>t</description></rule></group>`;
const body = "<if_sid>61605</if_sid><description>t</description>";
// Wazuh loads a rule only inside a top-level <group>, so fixtures sit in one.
const grp = (xml: string) => `<group name="t,">${xml}</group>`;

// *--- Tests ---*

describe("parseRules", () => {
  // os_xml keeps element text as written, so a padded <id> is stored padded and sigma-lint
  // reports it rather than the reader guessing what the alert-time lookup does with it.
  test("reads id, level, if_sid list and MITRE IDs as written, and skips commented-out rules", () => {
    const xml = `<!-- <rule id="100341" level="3"></rule> -->
      <group name="t,"><rule id="100340" level="12"><if_sid>61603, 61605</if_sid>
      <description> d </description><mitre><id>T1105</id> <id> T1071 </id></mitre></rule></group>`;
    expect(parseRules(xml, "x.xml")).toEqual([
      {
        file: "x.xml",
        id: 100340,
        level: 12,
        ifSid: ["61603", "61605"],
        group: "t,",
        ifGroup: "",
        ifMatchedGroup: "",
        mitre: ["T1105", " T1071 "],
        mitrePairs: [],
        description: "d",
        repeated: [],
      },
    ]);
  });

  test("knows the pack range", () => {
    expect([100339, 100340, 100399, 100400].map(isPack)).toEqual([false, true, true, false]);
  });

  // os_xml takes either quote and spaces after "=" but not before it (os_xml.c 580-625).
  test("reads id and level in either quote, with spaces after = and before >", () => {
    const xml = grp(`<rule id='100340' level='12'>${body}</rule><rule id= "100341"\n level=\t'10' >${body}</rule>`);
    expect(parseRules(xml, "x.xml").map((r) => [r.id, r.level])).toEqual([
      [100340, 12],
      [100341, 10],
    ]);
  });

  test("throws RulesError naming the file and tag when id or level is not a whole number", () => {
    for (const tag of [`<rule id="abc" level="12">`, `<rule id="100340">`, `<rule id="100340" level="1.5">`, `<rule level="3">`]) {
      const read = () => parseRules(`<group name="t,">${tag}${body}</rule></group>`, "pack.xml");
      expect(read).toThrow(RulesError);
      expect(read).toThrow(`pack.xml: `);
      expect(read).toThrow(tag);
    }
  });

  // rules.c 2258-2264: an id is at most 6 characters, so a leading zero counts toward it.
  test("throws naming the file and tag for an id longer than 6 digits", () => {
    for (const id of ["1003400", "0100340"]) {
      const tag = `<rule id="${id}" level="12">`;
      const read = () => parseRules(grp(`${tag}${body}</rule>`), "pack.xml");
      expect(read).toThrow(RulesError);
      expect(read).toThrow(`pack.xml: id ${id} is longer than 6 digits in ${tag}`);
    }
    expect(parseRules(grp(`<rule id="999999" level="12">${body}</rule>`), "x.xml").map((r) => r.id)).toEqual([999999]);
  });

  // rules.c 2266-2272: Wazuh reads the level with atoi and refuses one outside 0 to 16.
  test("throws naming the file and tag for a level outside 0 to 16", () => {
    for (const level of ["17", "99"]) {
      const tag = `<rule id="100340" level="${level}">`;
      const read = () => parseRules(grp(`${tag}${body}</rule>`), "pack.xml");
      expect(read).toThrow(RulesError);
      expect(read).toThrow(`pack.xml: level ${level} is outside 0 to 16 in ${tag}`);
    }
    const levels = ["0", "16", "016"].map((l) => `<rule id="100340" level="${l}">${body}</rule>`);
    expect(levels.map((x) => parseRules(grp(x), "x.xml")[0].level)).toEqual([0, 16, 16]);
  });

  test("trims a long start tag in the error", () => {
    const tag = `<rule id="x" level="3" timeframe="${"1".repeat(150)}">`;
    try {
      parseRules(grp(`${tag}${body}</rule>`), "x.xml");
      throw new Error("did not throw");
    } catch (e) {
      expect(e).toBeInstanceOf(RulesError);
      expect((e as Error).message.length).toBeLessThan(140);
    }
  });

  // A rule the element pattern cannot consume would otherwise vanish without a finding.
  test("throws when a rule start tag has no closing tag", () => {
    const unclosed = `<rule id="100340" level="12">${body}`;
    const before = grp(`${unclosed}<rule id="100341" level="12">${body}</rule>`);
    expect(() => parseRules(before, "x.xml")).toThrow(RulesError);
    expect(() => parseRules(before, "x.xml")).toThrow('<rule id="100340" level="12"> has no closing </rule>');
    expect(() => parseRules(grp(`<rule id="100341" level="12">${body}</rule>${unclosed}`), "x.xml")).toThrow(
      '<rule id="100340" level="12"> has no closing </rule>',
    );
  });

  // A second <if_sid> or <mitre> stays visible to the lint. Wazuh appends every <mitre>
  // block (rules.c 1463-1610), so the reader does too.
  test("notes a repeated mitre or if_sid element, and reads every mitre block", () => {
    const xml = grp(
      `<rule id="100340" level="12">${body}<if_sid>,61603</if_sid><mitre><id>T1105</id></mitre><mitre><id>T1071</id></mitre></rule>` +
        `<rule id="100341" level="12">${body}<mitre><id>T1105</id></mitre></rule>`,
    );
    expect(parseRules(xml, "x.xml").map((r) => [r.id, r.repeated, r.ifSid, r.mitre])).toEqual([
      [100340, ["mitre", "if_sid"], ["61605", "61603"], ["T1105", "T1071"]],
      [100341, [], ["61605"], ["T1105"]],
    ]);
  });

  // loadmemory (rules.c 968, 2026-2065) appends each <if_sid> with strcat and no separator,
  // so the parents are the joined text split on commas: a union only when a comma divides them.
  // A join past six digits is refused below, as any parent over six digits is.
  test("reads every <if_sid> as Wazuh joins them, in order, without repeats", () => {
    const sids = (...texts: string[]) =>
      parseRules(grp(`<rule id="100340" level="12">${texts.map((t) => `<if_sid>${t}</if_sid>`).join("")}<description>t</description></rule>`), "x.xml")[0];
    expect(sids("61605,", "61603")).toMatchObject({ ifSid: ["61605", "61603"], repeated: ["if_sid"] });
    expect(sids("61605, 61603,", "61605")).toMatchObject({ ifSid: ["61605", "61603"], repeated: ["if_sid"] });
    expect(sids("616", "05")).toMatchObject({ ifSid: ["61605"], repeated: ["if_sid"] });
    expect(() => sids("61605", "61603")).toThrow("x.xml: if_sid parent 6160561603 is over six digits");
  });

  // os_xml fails the whole file on an unclosed element, so the manager loads none of it.
  test("throws naming the file when <group> tags do not balance", () => {
    const r = `<rule id="100340" level="12">${body}</rule>`;
    for (const xml of [
      `<group name="t,">${r}`,
      `<group name="t,">${r}</group></group>`,
      `</group><group name="t,">${r}</group>`,
      `<group name="a,"><group name="b,">${r}</group>`,
      `<group name="t,">${r}<!-- </group> -->`,
    ]) {
      expect(() => parseRules(xml, "pack.xml")).toThrow(RulesError);
      expect(() => parseRules(xml, "pack.xml")).toThrow("pack.xml: ");
    }
    expect(() => parseRules(`<!-- <group name="x,"> --><group name="t,">${r}</group>`, "x.xml")).not.toThrow();
  });

  // Every root element must be <group> (rules.c 299), so a bare rule stops the file loading.
  test("throws naming the file for a <rule> outside any <group>", () => {
    const r = `<rule id="100341" level="12">${body}</rule>`;
    for (const xml of [r, `${grp(`<rule id="100340" level="12">${body}</rule>`)}${r}`, `${r}${grp(`<rule id="100340" level="12">${body}</rule>`)}`]) {
      expect(() => parseRules(xml, "pack.xml")).toThrow(RulesError);
      expect(() => parseRules(xml, "pack.xml")).toThrow('pack.xml: <rule id="100341" level="12"> is outside any <group>');
    }
    expect(() => parseRules(`<!-- ${r} -->${grp(`<rule id="100340" level="12">${body}</rule>`)}`, "x.xml")).not.toThrow();
  });

  // Each child of a <group> must be a <rule> (rules.c 339), so a nested group is refused.
  test("throws naming the file for a <group> inside a <group>", () => {
    const xml = grp(`<group name="inner,"><rule id="100340" level="12">${body}</rule></group>`);
    expect(() => parseRules(xml, "pack.xml")).toThrow(RulesError);
    expect(() => parseRules(xml, "pack.xml")).toThrow('pack.xml: <group name="inner,"> is inside a <group> but is not a <rule>');
    expect(() => parseRules(grp(`<rule id="100340" level="12">${body}</rule>`) + grp(`<rule id="100341" level="12">${body}</rule>`), "x.xml")).not.toThrow();
  });

  // Wazuh checks the joined if_sid text against ^[\d, ]+$ and skips the rule when it fails
  // (rules.c 1625-1641); os_xml decodes no character references, so &#49; is not "1".
  test("throws naming the file when if_sid holds anything but digits, commas and spaces", () => {
    for (const sid of ["&#49;", "61605a", "61605;61603", "", "61603,\n61605", "\t61605"]) {
      const read = () => parseRules(`<group name="t,"><rule id="100340" level="12"><if_sid>${sid}</if_sid><description>t</description></rule></group>`, "pack.xml");
      expect(read).toThrow(RulesError);
      expect(read).toThrow("pack.xml: ");
    }
    const two = grp(`<rule id="100340" level="12"><if_sid>61605</if_sid><if_sid>&#49;</if_sid><description>t</description></rule>`);
    expect(() => parseRules(two, "pack.xml")).toThrow("&#49;");
    expect(parseRules(grp(`<rule id="100340" level="12"><if_sid>61603, 61605,61600</if_sid><description>t</description></rule>`), "x.xml")[0].ifSid).toEqual([
      "61603",
      "61605",
      "61600",
    ]);
  });
});

// Wazuh compares rule element and attribute names with strcasecmp (rules.c 299, 339, 662,
// 967, 1463-1510, 2258), while os_xml wants each closing tag spelled as its opening (379).
describe("parseRules letter case", () => {
  test("reads element and attribute names in any case", () => {
    const xml = `<GROUP name="t,"><RULE ID="100340" Level="12"><IF_SID>61605</IF_SID><Description> d </Description><MITRE><ID>T1105</ID></MITRE></RULE></GROUP>`;
    expect(parseRules(xml, "x.xml")).toEqual([
      { file: "x.xml", id: 100340, level: 12, ifSid: ["61605"], group: "t,", ifGroup: "", ifMatchedGroup: "", mitre: ["T1105"], mitrePairs: [], description: "d", repeated: [] },
    ]);
  });

  test("reads <GROUP>, <IF_GROUP>, <IF_MATCHED_GROUP> and <IF_MATCHED_SID> in any case", () => {
    const xml = grp(
      `<rule id="100340" level="0"><IF_GROUP>a</IF_GROUP><If_Matched_Group>b</If_Matched_Group><IF_MATCHED_SID>100397</IF_MATCHED_SID><GROUP>c,</GROUP><description>t</description></rule>`,
    );
    expect(parseRules(xml, "x.xml")[0]).toMatchObject({ group: "t,c,", ifGroup: "a", ifMatchedGroup: "b", ifMatchedSid: 100397 });
  });

  test("throws when a closing tag is spelled differently from its opening", () => {
    for (const xml of [
      `<group name="t,"><rule id="100340" level="12">${body}</RULE></group>`,
      `<GROUP name="t,"><rule id="100340" level="12">${body}</rule></group>`,
      grp(`<rule id="100340" level="12"><if_sid>61605</IF_SID><description>t</description></rule>`),
      grp(`<rule id="100340" level="12">${body}<mitre><ID>T1105</id></mitre></rule>`),
      grp(`<rule id="100340" level="12">${body}<Mitre><id>T1105</id></mitre></rule>`),
    ]) {
      expect(() => parseRules(xml, "pack.xml")).toThrow(RulesError);
      expect(() => parseRules(xml, "pack.xml")).toThrow("pack.xml: ");
    }
  });

  test("sees a second parent written <IF_SID>, and an upper-case first one", () => {
    const second = grp(`<rule id="100340" level="12"><if_sid>61605,</if_sid><IF_SID>61603</IF_SID><description>t</description></rule>`);
    expect(parseRules(second, "x.xml").map((r) => [r.ifSid, r.repeated])).toEqual([[["61605", "61603"], ["if_sid"]]]);
    const first = grp(`<rule id="100340" level="12"><IF_SID>61603,</IF_SID><if_sid>61605</if_sid><description>t</description></rule>`);
    expect(parseRules(first, "x.xml").map((r) => [r.ifSid, r.repeated])).toEqual([[["61603", "61605"], ["if_sid"]]]);
  });

  test("notes a second <MITRE> block, and reads it", () => {
    const xml = grp(`<rule id="100340" level="12">${body}<mitre><id>T1105</id></mitre><MITRE><ID>T1071</ID></MITRE></rule>`);
    expect(parseRules(xml, "x.xml").map((r) => [r.mitre, r.repeated])).toEqual([[["T1105", "T1071"], ["mitre"]]]);
  });

  // The mitre loop reads <id> content and never looks at its attributes.
  test("ignores attributes on <id> inside <mitre>, and a rule-level <id> field", () => {
    const xml = grp(`<rule id="100340" level="12">${body}<id>^4625$</id><mitre><id type="x">T1105</id><Id foo='1'>T1071</Id></mitre></rule>`);
    expect(parseRules(xml, "x.xml")[0].mitre).toEqual(["T1105", "T1071"]);
  });
});

// Attributes are name="value" or name='value' pairs and nothing else (os_xml.c 560-660);
// rules.c 2250-2350 refuses any rule attribute it does not know, and 302-305 any but name on a group.
describe("parseRules start tags", () => {
  const ruleWith = (attrs: string) => grp(`<rule ${attrs}>${body}</rule>`);

  test("reads id and level from real attributes, not from text inside another value", () => {
    const xml = ruleWith(`noalert=" id='100340' level='12'" id="100341" level="3"`);
    expect(parseRules(xml, "x.xml").map((r) => [r.id, r.level])).toEqual([[100341, 3]]);
  });

  test("refuses a rule attribute Wazuh does not know, naming it", () => {
    const read = () => parseRules(ruleWith(`note=" id='100340' level='12'" id="999" level="1"`), "pack.xml");
    expect(read).toThrow(RulesError);
    expect(read).toThrow("pack.xml: ");
    expect(read).toThrow("attribute note");
    const known = `id="100340" level="12" maxsize="10" TIMEFRAME="60" frequency="8" accuracy="1" noalert="1" ignore="60" overwrite="no"`;
    expect(parseRules(ruleWith(known), "x.xml").map((r) => r.id)).toEqual([100340]);
  });

  test("refuses a start tag that does not tokenize", () => {
    for (const attrs of [
      `id = "100340" level="12"`,
      `id=100340 level="12"`,
      `id="100340"level="12"`,
      `id="100340" level="12" noalert`,
      `id="100340 level="12"`,
      `id="100340" level="12" ID="100341"`,
    ]) {
      const read = () => parseRules(ruleWith(attrs), "pack.xml");
      expect(read).toThrow(RulesError);
      expect(read).toThrow("pack.xml: ");
    }
  });

  // os_xml fails the file on an attribute name that a space, ">" or "/" ends before any "="
  // ("has no value", os_xml.c 568-578, 621-627). Read past that, noalert "1" would load as
  // noalert="1".
  test("refuses an attribute with no =, naming it", () => {
    for (const [attrs, seen] of [
      ['id="100340" level="12" noalert "1"', 'attribute noalert has no value in <rule id="100340" level="12" noalert '],
      ['id="100340" level="12" noalert', 'attribute noalert has no value in <rule id="100340" level="12" noalert>'],
      ['id="100340" level="12" noalert/', 'attribute noalert has no value in <rule id="100340" level="12" noalert/'],
      ['id = "100340" level="12"', "attribute id has no value in <rule id "],
    ]) {
      const parse = () => parseRules(ruleWith(attrs), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: ${seen}`);
    }
  });

  test("refuses a <group> attribute other than name, and a group with no name", () => {
    const r = `<rule id="100340" level="12">${body}</rule>`;
    expect(() => parseRules(`<group name="t," note="x">${r}</group>`, "pack.xml")).toThrow("attribute note");
    expect(() => parseRules(`<group>${r}</group>`, "pack.xml")).toThrow(RulesError);
    expect(parseRules(`<GROUP NAME="t,">${r}</GROUP>`, "x.xml").map((x) => x.id)).toEqual([100340]);
  });

  // os_xml refuses a value with no quote after "=" (os_xml.c 600-618). Read without that
  // check, id=x100340x would take "x" as its quote and load as id 100340.
  test("refuses an attribute value with no quote, naming the attribute", () => {
    for (const [xml, named] of [
      [`<group name=xtx>${`<rule id="100340" level="12">${body}</rule>`}</group>`, "attribute name is not followed by a quote in <group name=x"],
      [grp(`<rule id=x100340x level="12">${body}</rule>`), "attribute id is not followed by a quote in <rule id=x"],
    ]) {
      expect(() => parseRules(xml, "pack.xml")).toThrow(RulesError);
      expect(() => parseRules(xml, "pack.xml")).toThrow(`pack.xml: ${named}`);
    }
  });

  // os_xml strips a "/" that ends an element name, takes the element as closed, and then
  // reads what follows as attributes up to ">" (os_xml.c 332-370, 560-660). Spaces alone may
  // sit between, so <name/ > is <name/>; anything else there is refused rather than read.
  test("reads <name/ > as a closed element, and refuses anything else after a / that ends a name", () => {
    // The ">" ends the tag, as the tag an error names shows.
    const leaf = () => parseRules(grp(`<rule id="100340" level="12"><if_sid>61605<b/ ></if_sid><description>t</description></rule>`), "pack.xml");
    expect(leaf).toThrow('pack.xml: <if_sid> holds the element <b/ >, and Wazuh reads only the text after it in <rule id="100340" level="12">');
    expect(parseRules(grp(`<rule id="100340" level="12">${body}<field/ ><x/\t\r\n></rule>`), "x.xml").map((r) => r.id)).toEqual([100340]);
    for (const [inner, seen] of [
      ['<field/ name="win.eventdata.image">junk', "<field/ n"],
      ["<field/ x>", "<field/ x"],
      ["<field/ />", "<field/ /"],
      ["<field/\tname='a'/>", "<field/ n"],
    ]) {
      const parse = () => parseRules(grp(`<rule id="100340" level="12">${body}${inner}</rule>`), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: the / that closes ${seen} is followed by more than spaces before >, which os_xml reads as attributes of a closed element`);
    }
    const open = () => parseRules(`<group name="t,"><rule id="100340" level="12">${body}<field/ `, "pack.xml");
    expect(open).toThrow(RulesError);
    expect(open).toThrow(/^pack\.xml: <field\/ +has no closing >$/);
  });

  // os_xml reads a "/" after an attribute as the end of the tag and leaves what follows it as
  // text (os_xml.c 560-660), so a "/" not directly followed by ">" is refused.
  test("refuses a / among the attributes that is not followed by >", () => {
    for (const [attrs, seen] of [
      ['id="100340" level="12" / ', '<rule id="100340" level="12" /'],
      ['id="100340" level="12"/x', '<rule id="100340" level="12"/'],
    ]) {
      const parse = () => parseRules(grp(`<rule ${attrs}>${body}</rule>`), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: a / not followed by > in ${seen}`);
    }
  });

  // os_xml stores "<>" or "< a='1'>" as an element named "", and rules.c fails the file on
  // it wherever it sits in a rule ("Invalid option ''", rules.c 1617-1621).
  test("refuses an element with no name, inside a rule as well", () => {
    for (const [inner, seen] of [
      ["<></>", "<>"],
      [`< a="1"></>`, "< "],
    ]) {
      const read = () => parseRules(grp(`<rule id="100340" level="12">${body}${inner}</rule>`), "pack.xml");
      expect(read).toThrow(RulesError);
      expect(read).toThrow(`pack.xml: an element with no name at ${seen}`);
    }
  });
});

// os_xml refuses the whole file when any element is unclosed or closed by another name.
describe("parseRules well-formedness", () => {
  test("refuses an unclosed or mismatched element anywhere in a rule, naming it", () => {
    const rule = (inner: string) => grp(`<rule id="100340" level="12">${inner}</rule>`);
    for (const [inner, named] of [
      [`<field name="a">x${body}`, `<field name="a">`],
      [`<field name="a">x</match>${body}`, `<field name="a">`],
      [`<if_sid>61605<description>t</description>`, "<if_sid>"],
    ]) {
      const read = () => parseRules(rule(inner), "pack.xml");
      expect(read).toThrow(RulesError);
      expect(read).toThrow(`pack.xml: ${named}`);
    }
  });

  // rules.c 339: every child of a <group> must be a <rule>.
  test("refuses a child of <group> that is not a <rule>", () => {
    for (const [child, named] of [
      ["<decoder/>", "<decoder/>"],
      [`<var name="x">y</var>`, `<var name="x">`],
    ]) {
      const xml = grp(`${child}<rule id="100340" level="12">${body}</rule>`);
      expect(() => parseRules(xml, "pack.xml")).toThrow(`pack.xml: ${named} is inside a <group> but is not a <rule>`);
    }
  });

  // <group> inside a <rule> is a rule option that names alert groups, used by most stock
  // rules; only a <group> directly inside a <group> is refused.
  test("reads a rule that carries a <group> option", () => {
    const xml = grp(`<rule id="100340" level="12"><if_sid>61603</if_sid><group>attack.t1105,</group><description>d</description><mitre><id>T1105</id></mitre></rule>`);
    expect(parseRules(xml, "x.xml")).toEqual([
      {
        file: "x.xml",
        id: 100340,
        level: 12,
        ifSid: ["61603"],
        group: "t,attack.t1105,",
        ifGroup: "",
        ifMatchedGroup: "",
        mitre: ["T1105"],
        mitrePairs: [],
        description: "d",
        repeated: [],
      },
    ]);
  });

  // A backslash before "<" makes it text in os_xml, so it opens no element.
  test("reads a backslash-escaped < in text as text", () => {
    const xml = grp(`<rule id="100340" level="12"><match>\\<script</match>${body}</rule>`);
    expect(parseRules(xml, "x.xml").map((r) => r.id)).toEqual([100340]);
  });

  // os_xml checks for a comment on every "<", escaped or not (os_xml.c 307), and the
  // continue after it skips the escape reset (422-424), so the escape outlives the comment.
  // With the newline reset, the group closes holding only the comment, and is empty.
  test("keeps a backslash escape across a comment, as os_xml does", () => {
    const rule = `<rule id="100340" level="12">${body}</rule>`;
    const read = () => parseRules(`<group name="t,">\\<!--${rule}--></group>`, "pack.xml");
    expect(read).toThrow(RulesError);
    expect(read).toThrow('pack.xml: <group name="t,"> has no closing </group>');
    expect(() => parseRules(`<group name="t,">\\<!--${rule}-->\n</group>`, "x.xml")).toThrow('x.xml: <group name="t,"> holds no <rule>');
  });

  test("refuses a comment that does not close", () => {
    expect(() => parseRules(`<!-- open ${grp(`<rule id="100340" level="12">${body}</rule>`)}`, "pack.xml")).toThrow("pack.xml: ");
  });
});

// os_xml starts an element's text over after each child element (os_xml.c 403-411), and
// rules.c reads a rule's own children only, so Wazuh keeps just the text after the last
// child, silently. <if_sid>61603 <b/>61605</if_sid> is the one parent 61605.
describe("parseRules leaf text", () => {
  test("refuses an element inside any element whose text is read, naming both", () => {
    const refused: [string, string][] = [
      ["<if_sid>61603 <b/>61605</if_sid><description>t</description>", "<if_sid> holds the element <b/>"],
      ["<IF_SID>61603 <B/>61605</IF_SID><description>t</description>", "<IF_SID> holds the element <B/>"],
      [`${body}<if_group>a<x>y</x>b</if_group>`, "<if_group> holds the element <x>"],
      [`${body}<if_matched_sid>1<!-- c --><b/>100397</if_matched_sid>`, "<if_matched_sid> holds the element <b/>"],
      [`${body}<if_matched_group><b/>pack_a</if_matched_group>`, "<if_matched_group> holds the element <b/>"],
      ["<if_level>1<b/>0</if_level><description>t</description>", "<if_level> holds the element <b/>"],
      [`${body}<group>a,<b/>b,</group>`, "<group> holds the element <b/>"],
      ["<if_sid>61605</if_sid><description>t<b/></description>", "<description> holds the element <b/>"],
      [`${body}<mitre><id>T1105 <b/>T1071</id></mitre>`, "<id> holds the element <b/>"],
      [`${body}<mitre><tacticID>TA0002<b/></tacticID><techniqueID>T1059</techniqueID></mitre>`, "<tacticID> holds the element <b/>"],
      [`${body}<mitre><tacticID>TA0002</tacticID><TECHNIQUEID><b/>T1059</TECHNIQUEID></mitre>`, "<TECHNIQUEID> holds the element <b/>"],
    ];
    for (const [inner, named] of refused) {
      const parse = () => parseRules(grp(`<rule id="100340" level="12">${inner}</rule>`), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: ${named}, and Wazuh reads only the text after it in <rule id="100340" level="12">`);
    }
  });

  test("reads plain text in those elements, and a <mitre> of <id> elements", () => {
    const xml = grp(
      `<rule id="100340" level="12"><if_sid>61603,<!-- c -->61605</if_sid><if_group>a</if_group><group>b,</group><description>d</description><mitre><id>T1105</id><id>T1071</id></mitre></rule>`,
    );
    expect(parseRules(xml, "x.xml")[0]).toMatchObject({ ifSid: ["61603", "61605"], ifGroup: "a", group: "t,b,", description: "d", mitre: ["T1105", "T1071"] });
  });
});

// rules.c 1463-1613 reads each <mitre> block on its own. A block of <id> elements (the old
// form) adds to the id list; a block of one <tacticID> and one <techniqueID> (the new form)
// adds a pair kept apart from it, and discards every <id> the rule had or later gives.
// Any other block is warned about and dropped, and a child of any other name is an error.
describe("parseRules <mitre> blocks", () => {
  const read = (inner: string) => parseRules(grp(`<rule id="100340" level="12">${body}${inner}</rule>`), "x.xml")[0];
  const both = (inner: string) => {
    const r = read(inner);
    return [r.mitre, r.mitrePairs];
  };
  const pair = (tactic: string, technique: string) => `<mitre><tacticID>${tactic}</tacticID><techniqueID>${technique}</techniqueID></mitre>`;

  test("keeps one tacticID and one techniqueID as a pair, apart from the <id> list", () => {
    expect(both(pair("TA0002", "T1059.001"))).toEqual([[], [["TA0002", "T1059.001"]]]);
    expect(both("<MITRE><TechniqueId>T1059.001</TechniqueId><TACTICID>TA0002</TACTICID></MITRE>")).toEqual([[], [["TA0002", "T1059.001"]]]);
    // Each distinct pair once, as Wazuh compares both halves before adding one (1592-1611).
    expect(both(pair("TA0002", "T1059.001") + pair("TA0002", "T1059.001") + pair("TA0005", "T1027"))).toEqual([
      [],
      [
        ["TA0002", "T1059.001"],
        ["TA0005", "T1027"],
      ],
    ]);
  });

  // 1522-1525: "combined old and new Mitre formats in the same block", so none of it is kept.
  test("drops a block that mixes <id> with tacticID or techniqueID", () => {
    expect(both("<mitre><id>T1059.001</id><tacticID>TA0002</tacticID><techniqueID>T1027</techniqueID></mitre>")).toEqual([[], []]);
    expect(both("<mitre><id>T1059.001</id><techniqueID>T1027</techniqueID></mitre>")).toEqual([[], []]);
    expect(both("<mitre><id>T1105</id></mitre><mitre><tacticID>TA0002</tacticID><id>T1071</id></mitre>")).toEqual([["T1105"], []]);
  });

  // 1488-1512 and 1540-1565: an empty child fails its block, and so does a tactic or a
  // technique alone, or more than one of either.
  test("drops a lone tacticID or techniqueID, more than one of either, and a block with an empty child", () => {
    for (const inner of [
      "<mitre><tacticID>TA0002</tacticID></mitre>",
      "<mitre><techniqueID>T1027</techniqueID></mitre>",
      "<mitre><tacticID>TA0002</tacticID><tacticID>TA0005</tacticID><techniqueID>T1027</techniqueID></mitre>",
      "<mitre><tacticID>TA0005</tacticID><techniqueID>T1027</techniqueID><techniqueID>T1059</techniqueID></mitre>",
      "<mitre><tacticID></tacticID><techniqueID>T1027</techniqueID></mitre>",
      "<mitre><tacticID>TA0005</tacticID><techniqueID/></mitre>",
      "<mitre><id>T1105</id><id></id></mitre>",
      "<mitre><id><!-- c --></id></mitre>",
      "<mitre></mitre>",
      "<mitre> </mitre>",
      "<mitre/>",
    ]) {
      expect([inner, both(inner)]).toEqual([inner, [[], []]]);
    }
    // A dropped block leaves the others standing.
    expect(both("<mitre><id>T1105</id></mitre><mitre><id/></mitre><mitre><id>T1071</id></mitre>")).toEqual([["T1105", "T1071"], []]);
  });

  test("a pair discards every <id>, from a block before it or after it", () => {
    expect(both(`<mitre><id>T1105</id></mitre>${pair("TA0002", "T1059.001")}<mitre><id>T1071</id></mitre>`)).toEqual([[], [["TA0002", "T1059.001"]]]);
    expect(both(`${pair("TA0002", "T1059.001")}<mitre><id>T1105</id></mitre>`)).toEqual([[], [["TA0002", "T1059.001"]]]);
    // A block Wazuh drops sets no new form, so the <id> blocks around it stand.
    expect(both("<mitre><id>T1105</id></mitre><mitre><tacticID>TA0002</tacticID></mitre><mitre><id>T1071</id></mitre>")).toEqual([["T1105", "T1071"], []]);
  });

  // 1571-1584: an <id> already in the list, by strcmp, is not added again.
  test("keeps each <id> once, in a block or across blocks, as written", () => {
    expect(read("<mitre><id>T1105</id><id>T1105</id><id> T1105</id></mitre>").mitre).toEqual(["T1105", " T1105"]);
    expect(read("<mitre><id>T1105</id></mitre><mitre><id>T1071</id><id>T1105</id></mitre>")).toMatchObject({ mitre: ["T1105", "T1071"], repeated: ["mitre"] });
  });

  // 1513-1516: smerror "Invalid option", so the reader refuses rather than drop it quietly.
  test("refuses a <mitre> child that is not id, tacticID or techniqueID, naming it", () => {
    for (const [inner, named] of [
      ["<mitre><id>T1105</id><technique>T1105</technique></mitre>", "<technique>"],
      ["<mitre><tactic_id>TA0002</tactic_id><techniqueID>T1059</techniqueID></mitre>", "<tactic_id>"],
      ['<mitre><id/><field name="x">y</field></mitre>', '<field name="x">'],
    ]) {
      const parse = () => parseRules(grp(`<rule id="100340" level="12">${body}${inner}</rule>`), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: ${named} inside <mitre> is not <id>, <tacticID> or <techniqueID>, and Wazuh errors on it in <rule id="100340" level="12">`);
    }
  });
});

// os_xml splits a tag with C isspace (os_xml.c 332, 605-607, 628, 645), which is the six
// ASCII spaces only, so a no-break or other Unicode space is a name or value character to it.
describe("parseRules spaces in a tag", () => {
  // NEL is not a JavaScript space either, but os_xml reads it as two name bytes all the same.
  const ODD = ["\u00a0", "\u2003", "\u3000", "\ufeff", "\u202f", "\u0085"];

  test("refuses a Unicode space used as one inside a tag, naming it", () => {
    for (const s of ODD) {
      const code = `U+${s.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}`;
      for (const xml of [
        grp(`<rule${s}id="100340" level="12">${body}</rule>`),
        grp(`<rule id="100340"${s}level="12">${body}</rule>`),
        grp(`<rule id="100340" ${s}level="12">${body}</rule>`),
        grp(`<rule id=${s}"100340" level="12">${body}</rule>`),
        grp(`<rule id="100340" level="12"${s}>${body}</rule>`),
        `<group${s}name="t,"><rule id="100340" level="12">${body}</rule></group>`,
        grp(`<rule id="100340" level="12"><if_sid${s}>61605</if_sid><description>t</description></rule>`),
      ]) {
        const parse = () => parseRules(xml, "pack.xml");
        expect(parse).toThrow(RulesError);
        expect(parse).toThrow(`, which os_xml does not read as a space`);
        expect(parse).toThrow(code);
      }
    }
  });

  test("reads the six ASCII spaces as spaces, and a Unicode space in a value or text as text", () => {
    const xml = `<group\fname="t,\u00a0x"><rule\vid="100340"\r\nlevel="12"\t><if_sid>61605</if_sid><description>a\u00a0b</description></rule></group>`;
    expect(parseRules(xml, "x.xml").map((r) => [r.id, r.level, r.group, r.description])).toEqual([[100340, 12, "t,\u00a0x", "a\u00a0b"]]);
  });
});

// os_xml ends an attribute value only at its own quote and refuses a ">" before it
// ("Attribute not closed", os_xml.c 569-573), so the whole file fails to load.
describe("parseRules attribute values", () => {
  test('refuses a ">" inside any attribute value, naming the attribute', () => {
    for (const [xml, named] of [
      [grp(`<rule id="100340" level="12" noalert="a>b">${body}</rule>`), "attribute noalert"],
      [`<group name="a>b,"><rule id="100340" level="12">${body}</rule></group>`, "attribute name"],
      [grp(`<rule id="100340" level="12">${body}<field name='x>y'>z</field></rule>`), "attribute name"],
    ]) {
      const parse = () => parseRules(xml, "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: ${named} holds ">", which os_xml refuses in a value`);
    }
    expect(parseRules(grp(`<rule id="100340" level="12">${body}<field name="a/b&lt;c">z</field></rule>`), "x.xml").map((r) => r.id)).toEqual([100340]);
  });
});

// rules.c 323-327: "Group without any rule" fails the whole file, so its other rules never load.
describe("parseRules empty groups", () => {
  test("refuses a <group> with no element inside, naming it", () => {
    const r = grp(`<rule id="100340" level="12">${body}</rule>`);
    for (const [xml, named] of [
      ['<group name="t,"></group>', '<group name="t,">'],
      ['<group name="t,"/>', '<group name="t,"/>'],
      ['<group name="t,">\n  <!-- <rule id="100341" level="3"></rule> -->\n</group>', '<group name="t,">'],
      ['<group name="t,">text</group>', '<group name="t,">'],
      [`${r}<group name="empty,"></group>`, '<group name="empty,">'],
    ]) {
      const parse = () => parseRules(xml, "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: ${named} holds no <rule>, and Wazuh fails the whole file on it`);
    }
  });
});

// rules.c 418 starts a rule's group text with its <group name> value, and 572-579 append
// each rule-level <group> with loadmemory (strcat, no separator), then drop newlines.
// OS_WordMatch matches a pattern against that whole text, commas included.
describe("parseRules group text", () => {
  const groupOf = (name: string, inner = "") => parseRules(`<group name="${name}"><rule id="100340" level="12">${inner}${body}</rule></group>`, "x.xml")[0].group;

  test("starts from the enclosing group name as written", () => {
    expect(groupOf("pack_a,windows,")).toBe("pack_a,windows,");
    expect(groupOf(",,Pack_A, x")).toBe(",,Pack_A, x");
  });

  test("appends every rule-level <group> with no separator", () => {
    expect(groupOf("pack_a,", "<group>attack.t1105,</group>")).toBe("pack_a,attack.t1105,");
    expect(groupOf("pack_a,", "<group>a,</group><group>b</group>")).toBe("pack_a,a,b");
    // strcat with no separator: a name with no trailing comma runs into the next group.
    expect(groupOf("pack_a", "<group>x,</group>")).toBe("pack_ax,");
  });

  // wstr_replace (576) runs on the whole text, name included, and only once a <group> is read.
  test("drops newlines once a rule-level <group> is read, from the name as well", () => {
    expect(groupOf("pack_a,", "<group>a\nb,</group>")).toBe("pack_a,ab,");
    expect(groupOf("p\nq,", "<group>a,</group>")).toBe("pq,a,");
    expect(groupOf("p\nq,")).toBe("p\nq,");
  });
});

// rules.c 988-1017: <if_group> and <if_matched_group> append with loadmemory (strcat, no
// separator); <if_matched_sid> must be digits (OS_StrIsNum, or the rule is skipped), is
// read with atoi, and a later one replaces an earlier one.
describe("parseRules parent links", () => {
  const read = (inner: string) => parseRules(grp(`<rule id="100340" level="0">${inner}<description>t</description></rule>`), "x.xml")[0];

  test("reads none when a rule has no group or matched parent", () => {
    expect(read("<if_sid>61605</if_sid>")).toMatchObject({ ifGroup: "", ifMatchedGroup: "" });
    expect(read("<if_sid>61605</if_sid>").ifMatchedSid).toBeUndefined();
  });

  test("reads <if_group> and <if_matched_group> text, every element joined with no separator", () => {
    expect(read("<if_group>pack_a</if_group>")).toMatchObject({ ifGroup: "pack_a", ifMatchedGroup: "" });
    expect(read("<if_group>a,</if_group><if_group>b</if_group>").ifGroup).toBe("a,b");
    expect(read("<if_group>a</if_group><if_group>b</if_group>").ifGroup).toBe("ab");
    expect(read("<if_matched_group>pack_a|other</if_matched_group>")).toMatchObject({ ifGroup: "", ifMatchedGroup: "pack_a|other" });
    expect(read("<if_matched_group>a</if_matched_group><if_matched_group>b</if_matched_group>").ifMatchedGroup).toBe("ab");
  });

  test("reads <if_matched_sid> as atoi does, the last element winning", () => {
    expect(read("<if_matched_sid>100397</if_matched_sid>").ifMatchedSid).toBe(100397);
    expect(read("<if_matched_sid>0100397</if_matched_sid>").ifMatchedSid).toBe(100397);
    expect(read("<if_matched_sid>100396</if_matched_sid><if_matched_sid>100397</if_matched_sid>").ifMatchedSid).toBe(100397);
    // OS_StrIsNum passes empty text (os_regex_str.c 20-34), which atoi reads as 0.
    expect(read("<if_matched_sid></if_matched_sid><if_matched_sid>100397</if_matched_sid>").ifMatchedSid).toBe(100397);
    expect(read("<if_matched_sid>100397</if_matched_sid><if_matched_sid></if_matched_sid>").ifMatchedSid).toBeUndefined();
  });

  // Wazuh skips a rule whose <if_matched_sid> is not digits, so it never fires, and 0 is no parent.
  test("reads no matched parent from text that is not digits, or from 0", () => {
    for (const sid of ["100397a", " 100397", "100397 ", "", "0", "-1"]) {
      expect([sid, read(`<if_matched_sid>${sid}</if_matched_sid>`).ifMatchedSid]).toEqual([sid, undefined]);
    }
    expect(read("<if_matched_sid>x</if_matched_sid><if_matched_sid>100397</if_matched_sid>").ifMatchedSid).toBeUndefined();
  });

  // rules_list.c 148 and rules.c 1017 read a parent id with atoi into an int, which wraps
  // past 2^31: 4295067646 is read as 100350. No rule id runs past six digits (rules.c 2258).
  test("refuses an if_sid or if_matched_sid parent over six digits, a join included", () => {
    const refused: [string, string][] = [
      ["<if_sid>4295067646</if_sid>", "if_sid parent 4295067646"],
      ["<if_sid>61605, 1000000</if_sid>", "if_sid parent 1000000"],
      ["<if_sid>42950</if_sid><if_sid>67646</if_sid>", "if_sid parent 4295067646"],
      ["<if_sid>61605</if_sid><if_matched_sid>4295067646</if_matched_sid>", "if_matched_sid parent 4295067646"],
      ["<if_matched_sid>100397</if_matched_sid><if_matched_sid>1000000</if_matched_sid>", "if_matched_sid parent 1000000"],
    ];
    for (const [inner, named] of refused) {
      const parse = () => parseRules(grp(`<rule id="100340" level="0">${inner}<description>t</description></rule>`), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: ${named} is over six digits in <rule id="100340" level="0">`);
    }
    // atoi reads leading zeros as nothing, so only the value counts.
    expect(read("<if_sid>999999, 0000061605</if_sid>").ifSid).toEqual(["999999", "0000061605"]);
    expect(read("<if_matched_sid>0000999999</if_matched_sid>").ifMatchedSid).toBe(999999);
    // An element Wazuh replaces, or a rule it skips, sets no parent.
    expect(read("<if_matched_sid>4295067646</if_matched_sid><if_matched_sid>100397</if_matched_sid>").ifMatchedSid).toBe(100397);
    expect(read("<if_matched_sid>x</if_matched_sid><if_matched_sid>4295067646</if_matched_sid>").ifMatchedSid).toBeUndefined();
  });

  // rules.c 973-986: each <if_level> must pass OS_StrIsNum (digits, or empty) or the rule is
  // skipped, and loadmemory joins them with no separator. rules_list.c 178-186 reads the
  // joined text with atoi and refuses the rule when that is 0.
  test("reads <if_level> as atoi reads the joined text", () => {
    expect(read("<if_sid>61605</if_sid>").ifLevel).toBeUndefined();
    expect(read("<if_level>10</if_level>").ifLevel).toBe(10);
    expect(read("<IF_LEVEL>5</IF_LEVEL>").ifLevel).toBe(5);
    expect(read("<if_level>010</if_level>").ifLevel).toBe(10);
    expect(read("<if_level>1</if_level><if_level>0</if_level>").ifLevel).toBe(10);
    expect(read("<if_level></if_level><if_level>7</if_level>").ifLevel).toBe(7);
    for (const level of ["", "0", "00", "x", " 10", "10a", "-1"]) {
      expect([level, read(`<if_level>${level}</if_level>`).ifLevel]).toEqual([level, undefined]);
    }
    expect(read("<if_level>x</if_level><if_level>10</if_level>").ifLevel).toBeUndefined();
    // Each element is checked, not the joined text, which Number() would read as 1e1.
    expect(read("<if_level>1</if_level><if_level>e1</if_level>").ifLevel).toBeUndefined();
  });

  // rules_list.c 181-188 multiplies the atoi value by 100 in an int, so 21474837 turns
  // negative and every earlier rule becomes a parent. A rule's own level runs 0 to 16.
  test("refuses an if_level over 16, a join included", () => {
    for (const [inner, shown] of [
      ["<if_level>17</if_level>", "17"],
      ["<if_level>21474837</if_level>", "21474837"],
      ["<if_level>4294967297</if_level>", "4294967297"],
      ["<if_level>1</if_level><if_level>7</if_level>", "17"],
    ]) {
      const parse = () => parseRules(grp(`<rule id="100340" level="0">${inner}<description>t</description></rule>`), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: if_level ${shown} is over 16 in <rule id="100340" level="0">`);
    }
    expect(read("<if_level>16</if_level>").ifLevel).toBe(16);
    expect(read("<if_level>0016</if_level>").ifLevel).toBe(16);
    // A rule Wazuh skips sets no level parent, whatever the number.
    expect(read("<if_level>x</if_level><if_level>21474837</if_level>").ifLevel).toBeUndefined();
  });

  // rules_list.c 136-160 walks the joined text through its NUL, so a separator just before
  // the NUL, or a parent that reads 0, reaches atoi as sid 0, and _AddtoRule (45-107) then
  // hangs the rule under the first rule of its category, a stock template, beside the
  // parents it names. A separator before another separator or a digit calls nothing.
  test("refuses an if_sid ending in a separator, or naming a parent that reads 0, a join included", () => {
    const hangs = "which hangs the rule under a stock template rule";
    const refused: [string, string][] = [
      ["<if_sid>61605,</if_sid>", `if_sid "61605," ends in a separator, ${hangs} as parent 0`],
      ["<if_sid>61605 </if_sid>", `if_sid "61605 " ends in a separator, ${hangs} as parent 0`],
      ["<if_sid>61603, 61605, </if_sid>", `if_sid "61603, 61605, " ends in a separator, ${hangs} as parent 0`],
      ["<if_sid>,</if_sid>", `if_sid "," ends in a separator, ${hangs} as parent 0`],
      ["<if_sid> </if_sid>", `if_sid " " ends in a separator, ${hangs} as parent 0`],
      ["<if_sid>61605,</if_sid><if_sid></if_sid>", `if_sid "61605," ends in a separator, ${hangs} as parent 0`],
      ["<if_sid>0</if_sid>", `if_sid parent 0 reads as 0, ${hangs}`],
      ["<if_sid>61605, 000</if_sid>", `if_sid parent 000 reads as 0, ${hangs}`],
      ["<if_sid>6160</if_sid><if_sid>5, 0</if_sid>", `if_sid parent 0 reads as 0, ${hangs}`],
    ];
    for (const [inner, named] of refused) {
      const parse = () => parseRules(grp(`<rule id="100340" level="0">${inner}<description>t</description></rule>`), "pack.xml");
      expect(parse).toThrow(RulesError);
      expect(parse).toThrow(`pack.xml: ${named} in <rule id="100340" level="0">`);
    }
    expect(read("<if_sid>61605,,61603</if_sid>").ifSid).toEqual(["61605", "61603"]);
    expect(read("<if_sid>, 61605</if_sid>").ifSid).toEqual(["61605"]);
    expect(read("<if_sid>061605</if_sid>").ifSid).toEqual(["061605"]);
  });

  // sigma-lint reports each name in repeated, so the new links add none.
  test("adds nothing to repeated", () => {
    const r = read(
      "<if_group>a,</if_group><if_group>b</if_group><if_matched_group>c</if_matched_group><if_matched_group>d</if_matched_group><if_matched_sid>1</if_matched_sid><if_matched_sid>2</if_matched_sid><if_level>1</if_level><if_level>2</if_level>",
    );
    expect(r.repeated).toEqual([]);
  });
});

// os_xml reads each element name, attribute name, attribute value and run of text into a
// buffer of XML_MAXSIZE (20480) bytes, and fails the whole file on the byte after a full one
// (os_xml.c 296-303, 557-566). rules.c reads a rules file with OS_ReadXML, byte by byte, so
// the count is UTF-8 bytes. A run of text starts after a start tag or a child element, runs
// on through a comment without counting the comment's own bytes, and is not counted outside
// every element.
describe("parseRules sizes", () => {
  const MAX = 20480;
  const too = "runs to 20480 bytes or more, which os_xml refuses";
  // Four UTF-8 bytes in two UTF-16 units.
  const FOUR = "\u{1F600}";
  const parse = (inner: string) => () => parseRules(grp(`<rule id="100340" level="12">${body}${inner}</rule>`), "pack.xml");
  const ok = (inner: string) => expect(parse(inner)).not.toThrow();
  const refused = (inner: string, what: string) => {
    expect(parse(inner)).toThrow(RulesError);
    expect(parse(inner)).toThrow(`pack.xml: ${what}`);
    expect(parse(inner)).toThrow(too);
  };

  test("refuses an element name of 20480 bytes, the / of a closed element counted", () => {
    const pair = (name: string) => `<${name}>t</${name}>`;
    ok(pair("x".repeat(MAX - 1)));
    refused(pair("x".repeat(MAX)), "the element name at <xxx");
    refused(pair(`${"x".repeat(MAX - 2)}é`), "the element name at <xxx");
    ok(`<${"x".repeat(MAX - 2)}/>`);
    refused(`<${"x".repeat(MAX - 1)}/>`, "the element name at <xxx");
  });

  test("refuses an attribute name or value of 20480 bytes", () => {
    const field = (attr: string, value: string) => `<field ${attr}="${value}">t</field>`;
    ok(field("a".repeat(MAX - 1), "v"));
    refused(field("a".repeat(MAX), "v"), "the attribute name aaa");
    ok(field("name", "v".repeat(MAX - 1)));
    refused(field("name", "v".repeat(MAX)), "the value of attribute name");
    ok(field("name", `${"v".repeat(MAX - 5)}${FOUR}`));
    refused(field("name", `${"v".repeat(MAX - 4)}${FOUR}`), "the value of attribute name");
  });

  test("refuses a run of text of 20480 bytes, from the last start tag or child, through comments whose bytes are not counted", () => {
    const run = (text: string) => `<field name="x">${text}</field>`;
    ok(run("t".repeat(MAX - 1)));
    refused(run("t".repeat(MAX)), 'a run of text in <field name="x">');
    refused(run(`${"t".repeat(MAX - 2)}é`), 'a run of text in <field name="x">');
    ok(run(`${"t".repeat(MAX - 5)}${FOUR}`));
    // _oscomment reads a comment off the stream and the loop goes on (os_xml.c 225-252,
    // 307-315): its bytes never reach the content buffer or the count, and the count runs
    // on past it. So text one byte short of the limit passes around a comment longer than
    // the limit, and text that reaches it fails, comment or not.
    ok(run(`${"t".repeat(MAX / 2)}<!--${"c".repeat(MAX)}-->${"t".repeat(MAX / 2 - 1)}`));
    refused(run(`${"t".repeat(MAX / 2)}<!-- c -->${"t".repeat(MAX / 2)}`), 'a run of text in <field name="x">');
    ok(run(`${"t".repeat(MAX - 1)}<b/>${"t".repeat(MAX - 1)}<b>${"t".repeat(MAX - 1)}</b>${"t".repeat(MAX - 1)}`));
    // A backslash and an escaped "<" are text, and count.
    refused(run(`${"t".repeat(MAX - 2)}\\<`), 'a run of text in <field name="x">');
    // Outside every element os_xml skips text without counting it.
    expect(() => parseRules(`${"x".repeat(MAX * 2)}${grp(`<rule id="100340" level="12">${body}</rule>`)}${"x".repeat(MAX * 2)}`, "x.xml")).not.toThrow();
  });
});

describe("readRulesDir", () => {
  // ISA ISC-121: rule_dir does not recurse, so a file one folder down is never loaded.
  test("loads the top level only and reports deeper XML as skipped", () => {
    const dir = mkdtempSync(join(tmpdir(), "rules-t-"));
    try {
      writeFileSync(join(dir, "top.xml"), rule(100340));
      writeFileSync(join(dir, "notes.txt"), "not a rules file");
      mkdirSync(join(dir, "pack"));
      writeFileSync(join(dir, "pack/deep.xml"), rule(100341));
      const t = readRulesDir(dir);
      expect(t.rules.map((r) => [r.file, r.id])).toEqual([["top.xml", 100340]]);
      expect(t.skippedRules.map((r) => [r.file, r.id])).toEqual([["pack/deep.xml", 100341]]);
      expect(t.skippedFiles).toEqual(["pack/deep.xml"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("reads an upper-case .XML extension at either depth", () => {
    const dir = mkdtempSync(join(tmpdir(), "rules-t-"));
    try {
      writeFileSync(join(dir, "PACK.XML"), rule(100340));
      mkdirSync(join(dir, "sub"));
      writeFileSync(join(dir, "sub/Deep.Xml"), rule(100341));
      const t = readRulesDir(dir);
      expect(t.rules.map((r) => [r.file, r.id])).toEqual([["PACK.XML", 100340]]);
      expect(t.skippedFiles).toEqual(["sub/Deep.Xml"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // rules-config.c 26-46, 382: Wazuh sorts the files of every rule_dir together by strcmp
  // on the name, and every stock file is 0NNN-*.xml. A digit, "." or "-" first would load
  // a custom file before or among them, so later stock if_group rules could hang under it.
  test("refuses a top-level rules file whose name does not start with a letter", () => {
    for (const name of ["0599-x.xml", "9z.xml", "-x.xml", ".x.xml", "_x.xml"]) {
      const dir = mkdtempSync(join(tmpdir(), "rules-t-"));
      try {
        writeFileSync(join(dir, "local_a.xml"), rule(100340));
        writeFileSync(join(dir, name), rule(100341));
        expect(() => readRulesDir(dir)).toThrow(RulesError);
        expect(() => readRulesDir(dir)).toThrow(`${name}: a rules file name must start with a letter, so it loads after every stock 0NNN- file`);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
    // Either letter case loads after the digits, and a subfolder file never loads at all.
    const dir = mkdtempSync(join(tmpdir(), "rules-t-"));
    try {
      writeFileSync(join(dir, "Zeta.xml"), rule(100340));
      writeFileSync(join(dir, "alpha.xml"), rule(100341));
      writeFileSync(join(dir, "0599-notes.txt"), "not a rules file");
      mkdirSync(join(dir, "0599-sub"));
      writeFileSync(join(dir, "0599-sub/0599-x.xml"), rule(100342));
      const t = readRulesDir(dir);
      expect(t.rules.map((r) => [r.file, r.id])).toEqual([
        ["Zeta.xml", 100340],
        ["alpha.xml", 100341],
      ]);
      expect(t.skippedFiles).toEqual(["0599-sub/0599-x.xml"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
