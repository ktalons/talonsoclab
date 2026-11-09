// *****************************************************************************
// *Title: wazuh-rules*
// *Author: Kyle Versluis*
// *Description: Read rule ids, levels, parents and MITRE tags from Wazuh XML.*
// *****************************************************************************

// *--- Imports ---*

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

// *--- Configuration ---*

// Phase B detection pack ids (ISA Constraints). 100300-100331 belong to Phase A, so the
// EID-3 rules start at 100340. B.3 adds its ranges here.
export const PACK_RANGES: [number, number][] = [[100340, 100399]];
// The <rule> attributes rules.c getattributes knows (2250-2350); any other fails the file.
const RULE_ATTRS = new Set(["id", "level", "maxsize", "timeframe", "frequency", "accuracy", "noalert", "ignore", "overwrite"]);
// The rule elements whose text the reader keeps; the children of <mitre> are the others.
const TEXT_LEAVES = ["if_sid", "if_group", "if_matched_sid", "if_matched_group", "if_level", "group", "description"];
// rules.c 2258-2272: no rule id runs past six digits, and a level runs 0 to 16.
const MAX_ID = 999_999;
const MAX_LEVEL = 16;
// The children rules.c 1482-1518 reads in a <mitre> block; any other is an error.
const MITRE_KIDS = ["id", "tacticid", "techniqueid"];
// A space to JavaScript that C isspace does not take (NEL included), so os_xml reads it as
// part of a name or value.
const UNICODE_SPACE = /[^\S \t\n\v\f\r]|\u0085/;
// os_xml_internal.h: the buffer each element name, attribute name, attribute value and run of
// text is read into. os_xml fails the whole file on the byte after a full one.
const XML_MAXSIZE = 20480;

// *--- Types ---*

/** A rules file the reader cannot read whole, so the lint and logtest cannot run on it. */
export class RulesError extends Error {}

export interface WazuhRule {
  file: string;
  id: number;
  level: number;
  ifSid: string[];
  // The group text rules.c builds, which OS_WordMatch matches a parent pattern against.
  group: string;
  // Every <if_group>, and every <if_matched_group>, joined as rules.c joins them; "" for none.
  ifGroup: string;
  ifMatchedGroup: string;
  // The <if_matched_sid> parent; absent when there is none or Wazuh skips the rule over it.
  ifMatchedSid?: number;
  // The <if_level> a parent must reach; absent when there is none or Wazuh skips the rule.
  ifLevel?: number;
  // The <id> list Wazuh keeps from the <mitre> blocks (readMitre), each id as written.
  mitre: string[];
  // Each [tacticID, techniqueID] pair Wazuh keeps, which it holds apart from the <id> list.
  mitrePairs: [string, string][];
  description: string;
  // Elements that occur more than once in the rule. ifSid holds the parents of every <if_sid>
  // joined as Wazuh joins them, and mitre the ids of every <mitre> block Wazuh keeps.
  repeated: string[];
}

/** One element as os_xml reads it. */
interface XmlNode {
  name: string;
  attrs: [string, string][];
  children: XmlNode[];
  // All text directly inside the element; only leaf text (if_sid, id, description) is used.
  text: string;
  // The start tag as written, shortened, for error messages.
  tag: string;
}

// *--- Helper Functions ---*

/** A start tag on one line, cut short enough for an error message. */
const shortTag = (tag: string) => {
  const t = tag.replace(/\s+/g, " ");
  return t.length > 80 ? `${t.slice(0, 77)}...` : t;
};

// os_xml splits a tag with C isspace (os_xml.c 332, 605-607, 628, 645): six ASCII spaces.
const isSpace = (c: string | undefined) => c !== undefined && /^[ \t\n\v\f\r]$/.test(c);

// rules.c reads a rules file byte by byte (OS_ReadXML), so os_xml's sizes are UTF-8 bytes. A
// surrogate pair is one 4-byte character, 2 per half. A byte the file decode replaced with
// U+FFFD counts 3, never fewer than it stood for, so the count can only run high.
/** How many UTF-8 bytes one UTF-16 unit of the text stands for. */
const unitBytes = (unit: number) => (unit < 0x80 ? 1 : unit < 0x800 || (unit >= 0xd800 && unit <= 0xdfff) ? 2 : 3);

/** How many UTF-8 bytes a string is. */
const utf8Bytes = (s: string) => {
  let n = 0;
  for (let k = 0; k < s.length; k++) n += unitBytes(s.charCodeAt(k));
  return n;
};

/** True when an element has this name; Wazuh compares names with strcasecmp. */
const is = (node: XmlNode, name: string) => node.name.toLowerCase() === name;

/** The children of an element with this name, in order. */
const kids = (node: XmlNode, name: string) => node.children.filter((c) => is(c, name));

/** The text of each child with this name, in order. */
const texts = (node: XmlNode, name: string) => kids(node, name).map((c) => c.text);

// The grammar of os_xml.c 225-660, refusing what it refuses there: a comment runs from "<!"
// to the first "-->" or "!>", a backslash makes the next "<" text unless "!" follows, a tag
// splits on ASCII spaces, an attribute is name="value" or name='value' with no ">" in it,
// every element closes with its own name, and no name, value or run of text fills
// XML_MAXSIZE. Shapes os_xml reads but a rule never needs are refused rather than copied.
/** The top-level elements of an XML file, each with its attributes, children and text. */
function readXml(xml: string, file: string): XmlNode[] {
  const fail = (problem: string) => new RulesError(`${file}: ${problem}`);
  const tooLong = (what: string) => fail(`${what} runs to ${XML_MAXSIZE} bytes or more, which os_xml refuses`);
  let i = 0;

  // With i on "<", reads the start tag and returns the node and whether it self-closed.
  const readStart = (): [XmlNode, boolean] => {
    const from = i++;
    const seen = () => shortTag(xml.slice(from, i + 1));
    // A Unicode space where a tag needs a space would be a name or value byte to os_xml.
    const noUnicodeSpace = (s: string) => {
      const c = UNICODE_SPACE.exec(s)?.[0];
      if (c) throw fail(`${seen()} holds U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}, which os_xml does not read as a space`);
    };
    let name = "";
    while (i < xml.length && xml[i] !== ">" && !isSpace(xml[i])) name += xml[i++];
    noUnicodeSpace(name);
    // os_xml counts the name with the "/" of a closed element still on it (os_xml.c 332-341).
    if (utf8Bytes(name) >= XML_MAXSIZE) throw tooLong(`the element name at ${seen()}`);
    let selfClosed = name.endsWith("/");
    if (selfClosed) {
      name = name.slice(0, -1);
      // os_xml takes the element as closed at that "/" and then reads attributes up to ">"
      // (os_xml.c 346-370), so only spaces may follow it here.
      while (isSpace(xml[i])) i++;
      if (i >= xml.length) throw fail(`${seen()} has no closing >`);
      if (xml[i] !== ">") throw fail(`the / that closes ${seen()} is followed by more than spaces before >, which os_xml reads as attributes of a closed element`);
    }
    if (!name) throw fail(`an element with no name at ${seen()}`);
    const node: XmlNode = { name, attrs: [], children: [], text: "", tag: "" };
    while (!selfClosed && xml[i] !== ">") {
      while (isSpace(xml[i])) i++;
      if (i >= xml.length) throw fail(`${seen()} has no closing >`);
      if (xml[i] === ">") break;
      if (xml[i] === "/") {
        if (xml[i + 1] !== ">") throw fail(`a / not followed by > in ${seen()}`);
        selfClosed = true;
        i++;
        break;
      }
      let attr = "";
      while (i < xml.length && !"=>/".includes(xml[i]) && !isSpace(xml[i])) attr += xml[i++];
      noUnicodeSpace(attr);
      if (utf8Bytes(attr) >= XML_MAXSIZE) throw tooLong(`the attribute name ${shortTag(attr)} in ${seen()}`);
      if (!attr || xml[i] !== "=") throw fail(`attribute ${attr || "(no name)"} has no value in ${seen()}`);
      i++;
      while (isSpace(xml[i])) i++;
      noUnicodeSpace(xml[i] ?? "");
      const quote = xml[i];
      if (quote !== '"' && quote !== "'") throw fail(`attribute ${attr} is not followed by a quote in ${seen()}`);
      const end = xml.indexOf(quote, i + 1);
      if (end < 0) throw fail(`attribute ${attr} is not closed in ${seen()}`);
      const value = xml.slice(i + 1, end);
      i = end + 1;
      // os_xml.c 569-573: a ">" before the closing quote is "Attribute not closed".
      if (value.includes(">")) throw fail(`attribute ${attr} holds ">", which os_xml refuses in a value (${seen()})`);
      if (utf8Bytes(value) >= XML_MAXSIZE) throw tooLong(`the value of attribute ${shortTag(attr)} in ${seen()}`);
      noUnicodeSpace(xml[i] ?? "");
      if (!isSpace(xml[i]) && xml[i] !== ">" && xml[i] !== "/") throw fail(`attribute ${attr} runs into the next character in ${seen()}`);
      // os_xml refuses an exact repeat; rules.c reads names without case, so any repeat is ambiguous.
      if (node.attrs.some(([a]) => a.toLowerCase() === attr.toLowerCase())) throw fail(`attribute ${attr} is given twice in ${seen()}`);
      node.attrs.push([attr, value]);
    }
    i++;
    node.tag = shortTag(xml.slice(from, i));
    return [node, selfClosed];
  };

  // With i after a start tag (or at the top), reads children and text up to the matching end tag.
  const readContent = (parent: XmlNode | null): XmlNode[] => {
    const out: XmlNode[] = [];
    let escaped = false;
    // os_xml counts the text since the start tag or the last child (os_xml.c 371-411), on
    // through a comment whose own bytes it never counts (225-252, 307-315), and counts none
    // outside every element.
    let run = 0;
    while (i < xml.length) {
      if (xml[i] === "<" && xml[i + 1] === "!") {
        const close = /-->|!>/g;
        close.lastIndex = i + 2;
        const m = close.exec(xml);
        if (!m) throw fail(`the comment at ${shortTag(xml.slice(i, i + 40))} does not close`);
        // os_xml opens a comment even after a backslash (os_xml.c 307) and skips its escape
        // reset after one (313, 422-424), so the escape carries past the comment unchanged.
        i = m.index + m[0].length;
        continue;
      }
      if (xml[i] === "<" && !escaped) {
        if (xml[i + 1] === "/") {
          const end = xml.indexOf(">", i);
          const name = xml.slice(i + 2, end < 0 ? xml.length : end);
          if (!parent) throw fail(`</${name}> closes no open element`);
          if (end < 0 || name !== parent.name) throw fail(`${parent.tag} has no closing </${parent.name}> (found </${name}>)`);
          i = end + 1;
          return out;
        }
        const [node, selfClosed] = readStart();
        if (!selfClosed) node.children = readContent(node);
        out.push(node);
        run = 0;
        continue;
      }
      escaped = xml[i] === "\\" ? !escaped : false;
      if (parent) {
        parent.text += xml[i];
        run += unitBytes(xml.charCodeAt(i));
        if (run >= XML_MAXSIZE) throw tooLong(`a run of text in ${parent.tag}`);
      }
      i++;
    }
    if (parent) throw fail(`${parent.tag} has no closing </${parent.name}>`);
    return out;
  };

  return readContent(null);
}

// rules.c 1463-1613, block by block. An <id> block adds each id not yet held (strcmp). A
// block of one tacticID and one techniqueID adds that pair once and discards every <id>,
// earlier or later (1527-1532, 1547-1553). A block with an empty child, both forms, or a
// lone or repeated tacticID or techniqueID is warned about and dropped (1488-1565).
/** The <id> list and the tacticID/techniqueID pairs Wazuh keeps from a rule's <mitre> blocks. */
function readMitre(rule: XmlNode, fail: (problem: string) => RulesError): { ids: string[]; pairs: [string, string][] } {
  let ids: string[] = [];
  const pairs: [string, string][] = [];
  let newForm = false;
  for (const block of kids(rule, "mitre")) {
    // 1513-1517: smerror "Invalid option", so it is refused rather than dropped quietly.
    const other = block.children.find((c) => !MITRE_KIDS.some((n) => is(c, n)));
    if (other) throw fail(`${other.tag} inside <mitre> is not <id>, <tacticID> or <techniqueID>, and Wazuh errors on it`);
    const [id, tactic, technique] = MITRE_KIDS.map((n) => texts(block, n));
    if ([...id, ...tactic, ...technique].includes("")) continue;
    if (id.length) {
      if (tactic.length || technique.length || newForm) continue;
      for (const x of id) if (!ids.includes(x)) ids.push(x);
    } else if (tactic.length === 1 && technique.length === 1) {
      newForm = true;
      ids = [];
      if (!pairs.some(([a, b]) => a === tactic[0] && b === technique[0])) pairs.push([tactic[0], technique[0]]);
    }
  }
  return { ids, pairs };
}

/** One rule element as the lint and logtest see it, given its <group> name value. */
function readRule(node: XmlNode, file: string, groupName: string): WazuhRule {
  const fail = (problem: string) => new RulesError(`${file}: ${problem} in ${node.tag}`);
  for (const [a] of node.attrs) if (!RULE_ATTRS.has(a.toLowerCase())) throw fail(`attribute ${a} is not a <rule> attribute Wazuh knows`);
  const attr = (name: string) => node.attrs.find(([a]) => a.toLowerCase() === name)?.[1] ?? "";
  const whole = (v: string) => (/^\d+$/.test(v) ? Number(v) : Number.NaN);
  const id = whole(attr("id"));
  const level = whole(attr("level"));
  if (Number.isNaN(id)) throw fail("id is not a whole number");
  if (Number.isNaN(level)) throw fail("level is not a whole number");
  // rules.c 2258-2272 refuses an id over 6 characters, leading zeros included, and a level
  // outside 0 to 16, and either refusal fails the whole file.
  if (attr("id").length > 6) throw fail(`id ${attr("id")} is longer than 6 digits`);
  if (level > MAX_LEVEL) throw fail(`level ${attr("level")} is outside 0 to 16`);
  // os_xml starts an element's text over after each child element (os_xml.c 403-411), and
  // rules.c reads a rule's own children only, so Wazuh keeps just the text after the last
  // child, silently. The reader keeps all of it, so it refuses the child instead.
  const leaves = [...TEXT_LEAVES.flatMap((n) => kids(node, n)), ...kids(node, "mitre").flatMap((m) => MITRE_KIDS.flatMap((n) => kids(m, n)))];
  for (const leaf of leaves) {
    if (leaf.children.length) throw fail(`${leaf.tag} holds the element ${leaf.children[0].tag}, and Wazuh reads only the text after it`);
  }
  // loadmemory appends every <if_sid> with strcat and no separator (rules.c 968, 2026-2065),
  // so "61605" then "61603" is the one parent 6160561603. Wazuh skips the rule unless the
  // joined text is digits, commas and spaces (1625-1641).
  const ifSids = texts(node, "if_sid");
  const joined = ifSids.join("");
  if (ifSids.length && !/^[0-9, ]+$/.test(joined)) throw fail(`if_sid ${JSON.stringify(joined)} is not digits, commas and spaces, so Wazuh skips the rule`);
  // rules_list.c 136-160 walks the text through its NUL, so a separator just before the NUL,
  // or a parent that reads 0, reaches atoi as sid 0, and _AddtoRule (45-107) hangs the rule
  // under the first rule of its category, a stock template, beside the parents it names.
  const hangs = "which hangs the rule under a stock template rule";
  if (/[ ,]$/.test(joined)) throw fail(`if_sid ${JSON.stringify(joined)} ends in a separator, ${hangs} as parent 0`);
  const parentSids = joined.split(/[ ,]+/).filter(Boolean);
  const zero = parentSids.find((s) => Number(s) === 0);
  if (zero !== undefined) throw fail(`if_sid parent ${zero} reads as 0, ${hangs}`);
  // SECURITY: rules_list.c 148 reads each parent with atoi into an int, which wraps past
  // 2^31 (4295067646 reads as 100350) while the walk would use the number as written.
  const wraps = parentSids.find((s) => Number(s) > MAX_ID);
  if (wraps) throw fail(`if_sid parent ${wraps} is over six digits`);
  // The <group name> value, then each rule-level <group> appended with no separator; once
  // one is read, newlines go from the whole text (rules.c 418, 572-579).
  const own = texts(node, "group");
  const group = own.length ? (groupName + own.join("")).replaceAll("\n", "") : groupName;
  // OS_StrIsNum (digits, or empty), then atoi, each element replacing the last (1008-1017).
  // Text that is not digits makes Wazuh skip the rule, so it never fires and needs no
  // parent; empty text and 0 are none.
  const matchedSids = texts(node, "if_matched_sid");
  const matchedSid = matchedSids.every((t) => /^\d*$/.test(t)) ? Number(matchedSids[matchedSids.length - 1] ?? "") : 0;
  // SECURITY: atoi into an int again (rules.c 1017), so only the parent that stands is held.
  if (matchedSid > MAX_ID) throw fail(`if_matched_sid parent ${matchedSids[matchedSids.length - 1]} is over six digits`);
  // OS_StrIsNum on each <if_level>, joined with no separator (973-986), then atoi; a rule
  // whose level reads 0 is refused (rules_list.c 178-186).
  const levels = texts(node, "if_level");
  const ifLevel = levels.every((t) => /^\d*$/.test(t)) ? Number(levels.join("")) : 0;
  // SECURITY: rules_list.c 181-188 multiplies it by 100 in an int, so 21474837 turns
  // negative and every earlier rule becomes a parent. A rule's own level runs 0 to 16, so
  // anything above that is refused rather than read.
  if (ifLevel > MAX_LEVEL) throw fail(`if_level ${levels.join("")} is over 16`);
  const { ids, pairs } = readMitre(node, fail);
  return {
    file,
    id,
    level,
    ifSid: [...new Set(parentSids)],
    group,
    ifGroup: texts(node, "if_group").join(""),
    ifMatchedGroup: texts(node, "if_matched_group").join(""),
    ifMatchedSid: matchedSid || undefined,
    ifLevel: ifLevel || undefined,
    // As written, untrimmed: os_xml stores <id> text verbatim and sigma-lint judges it.
    mitre: ids,
    mitrePairs: pairs,
    description: kids(node, "description")[0]?.text.trim() ?? "",
    repeated: ["mitre", "if_sid"].filter((n) => kids(node, n).length > 1),
  };
}

// *--- Core Logic ---*

/** True when an id belongs to the detection pack. */
export const isPack = (id: number) => PACK_RANGES.some(([lo, hi]) => id >= lo && id <= hi);

// Wazuh keeps a repeated id where its first definition placed it and silently takes a
// later overwrite="yes" copy's group and level (rules.c 371-383, 1914-1916; rules_list.c
// 294-316), so no one copy is the rule that loads. sigma-lint and logtest refuse each one.
/** Each id defined more than once among the given rules, with its definitions in order. */
export function repeatedIds(rules: WazuhRule[]): [number, WazuhRule[]][] {
  const byId = new Map<number, WazuhRule[]>();
  for (const r of rules) byId.set(r.id, [...(byId.get(r.id) ?? []), r]);
  return [...byId].filter(([, defs]) => defs.length > 1);
}

// Every root element must be a <group> named and nothing else (rules.c 299-305), and every
// child of one a <rule> (339). Anything the reader refuses throws, because a rule it
// skipped would pass every check.
/** Every rule in one XML file, in file order. */
export function parseRules(xml: string, file: string): WazuhRule[] {
  const out: WazuhRule[] = [];
  for (const group of readXml(xml, file)) {
    if (!is(group, "group")) throw new RulesError(`${file}: ${group.tag} is outside any <group>`);
    for (const [a] of group.attrs) {
      if (a.toLowerCase() !== "name") throw new RulesError(`${file}: attribute ${a} is not allowed on ${group.tag}, which takes only name`);
    }
    if (!group.attrs.length) throw new RulesError(`${file}: ${group.tag} has no name attribute`);
    // rules.c 323-327: "Group without any rule" fails the whole file.
    if (!group.children.length) throw new RulesError(`${file}: ${group.tag} holds no <rule>, and Wazuh fails the whole file on it`);
    for (const child of group.children) {
      if (!is(child, "rule")) throw new RulesError(`${file}: ${child.tag} is inside a <group> but is not a <rule>`);
      out.push(readRule(child, file, group.attrs[0][1]));
    }
  }
  return out;
}

// rule_dir does not recurse, so only top-level files load. Deeper ones are returned
// separately: on the manager they are copied and then silently never read. Files are named
// relative to root as if dir sat at named, so a copy is read under its source's names.
/** Rules a manager would load from a rules folder, and the rules it would skip. */
export function readRulesDir(dir: string, root = dir, named = dir) {
  const rules: WazuhRule[] = [];
  const skippedRules: WazuhRule[] = [];
  const skippedFiles: string[] = [];
  const walk = (d: string, top: boolean) => {
    for (const name of readdirSync(d).sort()) {
      const path = join(d, name);
      if (statSync(path).isDirectory()) {
        walk(path, false);
        continue;
      }
      if (!/\.xml$/i.test(name)) continue;
      const file = relative(root, join(named, relative(dir, path)));
      // rules-config.c 26-46, 382: Wazuh sorts the files of every rule_dir together by strcmp
      // on the name, and each stock file is 0NNN-*.xml. A custom file loaded before a stock
      // one can take that file's if_group rules as children the walk never sees.
      if (top && !/^[A-Za-z]/.test(name)) {
        throw new RulesError(`${file}: a rules file name must start with a letter, so it loads after every stock 0NNN- file`);
      }
      const parsed = parseRules(readFileSync(path, "utf8"), file);
      if (top) rules.push(...parsed);
      else {
        skippedRules.push(...parsed);
        skippedFiles.push(file);
      }
    }
  };
  walk(dir, true);
  return { rules, skippedRules, skippedFiles };
}
