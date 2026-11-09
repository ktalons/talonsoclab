#!/usr/bin/env bun
// *****************************************************************************
// *Title: winevt*
// *Author: Kyle Versluis*
// *Description: Turn a captured Windows event into the JSON analysisd builds.*
// *****************************************************************************

// *--- TODO List ---*
// TODO-1: Port the audit-policy translation (winevtchannel.c 370-677) for Data named
//         categoryId, subcategoryId and auditPolicyChanges. Refused until then.
// TODO-2: Port the decoding of Event children other than System and EventData
//         (winevtchannel.c 294-321, 716-718). Refused until then.

// *--- Imports ---*

import { readFileSync } from "node:fs";

// *--- Configuration ---*

// Wazuh 4.14.9 src/analysisd/decoders/winevtchannel.c, DecodeWinevt(). Levels and the
// audit keyword bits come from the same file's headers.
const SEVERITY: Record<number, string> = { 1: "CRITICAL", 2: "ERROR", 3: "WARNING", 4: "INFORMATION", 5: "VERBOSE" };
const AUDIT_FAILURE = 0x10000000000000n;
const AUDIT_SUCCESS = 0x20000000000000n;
// strtol and strtoull saturate here on overflow.
const LONG_MAX = (1n << 63n) - 1n;
const ULLONG_MAX = (1n << 64n) - 1n;
// isspace() in the C locale.
const C_SPACE = " \t\n\v\f\r";
// XML_MAXSIZE (os_xml_internal.h 20). os_xml gives up on the whole event once one name, text run
// or attribute value reaches this many bytes of cJSON's print (os_xml.c 297-303, 558-567).
const XML_MAXSIZE = 20480;
// Markup as ToXml() writes it. Only a single-quoted value reaches os_xml intact, because cJSON
// has already turned each double quote into \". cJSON also prints every whitespace character
// but a space as an escape, so only a space separates inside a tag. A > ends a tag anywhere,
// and the port refuses a < in a value too, which ToXml always escapes.
const NAME = String.raw`[A-Za-z_][\w:.-]*`;
const VALUE = String.raw`[^'<>]*`;
const START_TAG = new RegExp(String.raw`<(${NAME})((?: +${NAME}='${VALUE}')*)( *)(/?)>`, "y");
const END_TAG = new RegExp(String.raw`</(${NAME})>`, "y");
const BAD_QUOTE = new RegExp(String.raw`<${NAME}(?: +${NAME}='${VALUE}')* +${NAME}=(?!')`, "y");
const OPEN_VALUE = new RegExp(String.raw`<${NAME}(?: +${NAME}='${VALUE}')* +${NAME}='${VALUE}>`, "y");
const ATTR = new RegExp(String.raw`(${NAME})='(${VALUE})'`, "g");
// XML_MAX_ATTR_DEPTH (os_xml_internal.h 21). Each attribute followed by a space reads the next
// one level deeper, and os_xml refuses any level past this (os_xml.c 549-552, 645-646).
const XML_MAX_ATTR_DEPTH = 48;
const MISTAKE = "analysisd would read only its leading digits and carry on, but a capture like this is a mistake";
// NOTE: the agent passes C strings and cJSON turns \u0000 back into a 0 byte (cJSON.c
// utf16_literal_to_utf8), so live the event ends at a NUL and no field after it reaches the rules.
export const NUL_REFUSAL = "a NUL character, where the agent's C string cuts the live event short";
// Data names DecodeWinevt saves aside and rewrites, compared after the first letter is lowered.
const AUDIT_POLICY_NAMES = new Set(["categoryId", "subcategoryId", "auditPolicyChanges"]);
// The only escapes wstr_unescape_json (string_op.c) undoes. Any other, \u00XX included, stays.
const JSON_UNESCAPE = new Map([
  ["b", "\b"],
  ["t", "\t"],
  ["n", "\n"],
  ["f", "\f"],
  ["r", "\r"],
  ['"', '"'],
  ["\\", "\\"],
]);

// *--- Types ---*

// One event as tools/winevt-capture.ts writes it: Get-WinEvent's Message and ToXml(). The
// record number only names the event in an error.
export interface Capture {
  id?: number;
  record?: number;
  message?: string | null;
  xml: string;
}

/** A capture refused whole rather than decoded in part. Its message never holds a value. */
export class CaptureError extends Error {
  override name = "CaptureError";
}

// One element as os_xml holds it: attribute values and text keep cJSON's escaping.
interface Node {
  name: string;
  attrs: [string, string][];
  content: string;
  children: Node[];
}

// *--- Helper Functions ---*

// tolower() in the C locale changes A to Z only.
const lcfirst = (s: string) => s.replace(/^[A-Z]/, (c) => c.toLowerCase());

// SECURITY: an error names the event by number only, so no field value reaches a terminal.
function recordOf(cap: Capture): string {
  if (Number.isSafeInteger(cap.record)) return `record ${cap.record}`;
  const id = /<EventRecordID>(\d{1,20})<\/EventRecordID>/.exec(cap.xml)?.[1];
  return id === undefined ? "capture" : `record ${id}`;
}

function refuseUnhandled(cap: unknown): asserts cap is Capture {
  if (typeof cap !== "object" || cap === null || Array.isArray(cap)) throw new CaptureError("capture: not an object");
  const c = cap as Capture;
  if (typeof c.xml !== "string" || c.xml.length === 0) throw new CaptureError("capture: no xml text");
  if (c.message != null && typeof c.message !== "string") throw new CaptureError(`${recordOf(c)}: a message that is not text`);
}

function fail(msg: string): never {
  console.error(`winevt: ${msg}`);
  process.exit(2);
}

// DecodeWinevt reads the XML only after cJSON has printed it as a JSON string, and os_xml
// decodes neither entities nor escapes. So every value keeps cJSON's escaping: one
// backslash becomes two, a quote becomes \", a newline becomes \n.
function cjsonEscaped(s: string): string {
  return JSON.stringify(s).slice(1, -1);
}

/** wstr_unescape_json: undo the escapes it knows, keep any other and a trailing lone backslash. */
function unescapeJson(s: string): string {
  return s.replace(/\\([\s\S]?)/g, (m, c: string) => JSON_UNESCAPE.get(c) ?? m);
}

/** replace_win_format(str, 0): trim trailing C-locale whitespace, never the first character. */
export function replaceWinFormat(s: string): string {
  let end = s.length - 1;
  while (end > 0 && C_SPACE.includes(s[end])) end--;
  return s.slice(0, end + 1);
}

/** Why the tag at `lt` is not one the port reads as os_xml does. Names the shape, never a value. */
function unreadTag(xml: string, lt: number): string {
  if (xml.startsWith("</", lt)) return "a closing tag with more than its name between </ and >, which os_xml reads as the name";
  OPEN_VALUE.lastIndex = BAD_QUOTE.lastIndex = lt;
  if (OPEN_VALUE.test(xml)) return "a > inside an attribute value, which os_xml reads as an attribute never closed";
  // Whitespace inside a quoted value is text, so the values are left out of this check.
  const tag = xml.slice(lt, xml.indexOf(">", lt) + 1 || xml.length);
  if (/^<[A-Za-z_]/.test(tag) && /[^\S ]/.test(tag.replace(/'[^']*'/g, ""))) {
    return "whitespace other than a space inside a tag; cJSON escapes it, and os_xml reads it as part of a name";
  }
  if (BAD_QUOTE.test(xml)) {
    return "an attribute value not in single quotes; cJSON escapes a double quote, and os_xml then cannot read the event";
  }
  return "a tag the port does not read";
}

// os_xml counts bytes, not characters, from 0 for each piece it reads (os_xml.c 297, 558).
const tooLong = (escaped: string, extra = 0) => Buffer.byteLength(escaped, "utf8") + extra >= XML_MAXSIZE;

// The element tree of one capture, or null where os_xml gives up on the event. Escaping is per
// character and leaves markup alone, so parsing the raw text and escaping each value gives what
// os_xml reads.
function parseXml(xml: string, refuse: (why: string) => never): Node | null {
  const stack: Node[] = [];
  let root: Node | undefined;
  // The > of a self-closing tag with attributes or a space opens its parent's next text run.
  let carry = 0;
  let i = 0;
  while (i < xml.length) {
    const lt = xml.indexOf("<", i);
    const text = xml.slice(i, lt === -1 ? xml.length : lt);
    if (stack.length) {
      const escaped = cjsonEscaped(text);
      if (tooLong(escaped, carry)) return null;
      stack[stack.length - 1].content += escaped;
    } else if (text.trim()) {
      // NOTE: os_xml skips text outside the root (os_xml.c 318-329), but ToXml writes none, so a
      // capture holding some is refused as a mistake rather than decoded around it.
      if (root) refuse("text after the closing </Event>");
      refuse(lt === -1 ? "no <Event> root with a <System> section" : "text before the root element");
    }
    carry = 0;
    if (lt === -1) break;
    if (xml.startsWith("<!", lt) || xml.startsWith("<?", lt)) refuse("a comment, declaration or CDATA section");
    END_TAG.lastIndex = START_TAG.lastIndex = lt;
    const end = END_TAG.exec(xml);
    if (end) {
      if (stack.pop()?.name !== end[1]) refuse("a closing tag that does not match its element");
      i = END_TAG.lastIndex;
      continue;
    }
    const start = START_TAG.exec(xml);
    if (!start) refuse(unreadTag(xml, lt));
    if (root && !stack.length) refuse("text after the closing </Event>");
    const [tag, name, attrText, spaces, slash] = start;
    const attrs = [...attrText.matchAll(ATTR)].map((m): [string, string] => [m[1], cjsonEscaped(m[2])]);
    const names = attrs.map(([k]) => k);
    if (new Set(names).size < names.length) refuse("an attribute repeated in one tag, which os_xml refuses");
    if ([name, ...names].some((n) => n.toLowerCase() === "var")) {
      refuse("an element or attribute named var, which os_xml stores as a variable");
    }
    if (attrs.length > XML_MAX_ATTR_DEPTH + 1 || (attrs.length === XML_MAX_ATTR_DEPTH + 1 && spaces)) {
      refuse("more attributes on one tag than os_xml reads");
    }
    // A / right after the name is read as part of it (os_xml.c 338-341). Anything between them
    // leaves the > to the parent instead (os_xml.c 649-650).
    const bare = slash !== "" && tag.length === name.length + 3;
    if (tooLong(name, bare ? 1 : 0) || attrs.some(([k, v]) => tooLong(k) || tooLong(v))) return null;
    carry = slash !== "" && !bare ? 1 : 0;
    const node: Node = { name, attrs, content: "", children: [] };
    if (stack.length) stack[stack.length - 1].children.push(node);
    else if (node.name === "Event") root = node;
    else refuse("no <Event> root with a <System> section");
    if (!slash) stack.push(node);
    i = START_TAG.lastIndex;
  }
  if (stack.length) refuse("an <Event> that never closes");
  return root ?? refuse("no <Event> root with a <System> section");
}

// Shapes the port does not decode. DecodeWinevt reads them, so a partial event here could
// pass a negative case that live would fail.
function sections(root: Node, refuse: (why: string) => never): { system: Node; eventdata?: Node } {
  const named = (n: string) => root.children.filter((c) => c.name === n);
  const [system, ...moreSystem] = named("System");
  const [eventdata, ...moreEventData] = named("EventData");
  if (!system) refuse("no <Event> root with a <System> section");
  if (moreSystem.length) refuse("a second <System>");
  if (moreEventData.length) refuse("a second <EventData>");
  if (eventdata?.attrs.length) refuse("<EventData> carries attributes");
  // TODO-2: Decode other Event children.
  const other = root.children.find((c) => c.name !== "System" && c.name !== "EventData");
  if (other) refuse(`a <${other.name}> section; the port decodes only <System> and <EventData>`);
  for (const field of [...system.children, ...(eventdata?.children ?? [])]) {
    if (field.children.length) refuse("markup inside a field, which os_xml reads as elements and the port does not");
  }
  return { system, eventdata };
}

// *--- Core Logic ---*

// The event analysisd hands to the rules: {"win":{"system":{...},"eventdata":{...}}}.
export function decodeWinevt(cap: Capture): { win: Record<string, Record<string, string>> } {
  refuseUnhandled(cap);
  const where = recordOf(cap);
  const refuse = (why: string): never => {
    throw new CaptureError(`${where}: ${why}`);
  };
  // A positive on a field after a NUL would pass here and never fire live.
  if (cap.xml.includes("\0") || cap.message?.includes("\0")) refuse(NUL_REFUSAL);
  // When os_xml gives up, DecodeWinevt reads no node and builds only the message (winevtchannel.c
  // 155-162, 683-689), so a rule on any XML field never fires.
  const root = parseXml(cap.xml, refuse);
  const parts = root ? sections(root, refuse) : undefined;
  // No prototype, so a Data named __proto__ lands as a field the way it does in cJSON.
  const system: Record<string, string> = Object.create(null);
  const eventdata: Record<string, string> = Object.create(null);
  let level: string | undefined;
  let keywords: string | undefined;

  // cJSON keeps both members and a lookup sees the first, so a repeated key is refused.
  const putSystem = (key: string, value: string) => {
    if (key in system) refuse(`two System values land on one key ${key}`);
    system[key] = value;
  };
  // The C walks attributes in order and adds each one it knows.
  const PROVIDER: Record<string, string> = { Name: "providerName", Guid: "providerGuid", EventSourceName: "eventSourceName" };
  const EXECUTION: Record<string, string> = { ProcessID: "processID", ThreadID: "threadID" };
  for (const c of parts?.system.children ?? []) {
    // These three take their own branch only when they carry attributes; with none they fall
    // through to the generic branch at the end (winevtchannel.c 176, 186, 190 and 223).
    if ((c.name === "Provider" || c.name === "Execution") && c.attrs.length > 0) {
      const known = c.name === "Provider" ? PROVIDER : EXECUTION;
      for (const [k, v] of c.attrs) if (Object.hasOwn(known, k)) putSystem(known[k], v);
    } else if (c.name === "TimeCreated" && c.attrs.length > 0) {
      if (c.attrs[0][0] === "SystemTime") putSystem("systemTime", c.attrs[0][1]);
    } else if (c.name === "Channel" || c.name === "Security") {
      // NOTE: Channel and Security add the literal "UserID" only when their first attribute's
      // value is "UserID", so a real Security, which carries a SID there, never lands.
      if (c.name === "Channel") putSystem("channel", c.content);
      if (c.attrs[0]?.[1] === "UserID") putSystem(c.name === "Channel" ? "userID" : "securityUserID", "UserID");
    } else if (c.name === "Correlation") {
      // The C gives Correlation an empty branch, so neither its attributes nor its text land.
    } else if (c.name === "Level") {
      level = c.content;
      putSystem("level", c.content);
    } else if (c.name === "Keywords") {
      keywords = c.content;
      putSystem("keywords", c.content);
    } else if (c.content.length > 0) {
      putSystem(lcfirst(c.name), c.content);
    }
  }

  // cJSON keeps both copies of a repeated key. What analysisd does with the pair is unverified.
  const put = (key: string, value: string) => {
    if (key in eventdata) refuse("two EventData values that land on one key");
    eventdata[key] = value;
  };
  const joined: string[] = [];
  for (const c of parts?.eventdata?.children ?? []) {
    const dropped = c.content === "(NULL)" || c.content === "-";
    if (c.name === "Data" && c.attrs.length > 0 && c.content.length > 0) {
      if (dropped) continue;
      // Each attribute's value is a key, not only Name's; Name ends the loop.
      for (const [attr, value] of c.attrs) {
        const key = lcfirst(value);
        // TODO-1: Translate audit-policy categories.
        if (attr === "Name" && AUDIT_POLICY_NAMES.has(key)) {
          refuse(`a Data named ${key}; the port does not translate audit-policy categories`);
        }
        put(key, replaceWinFormat(c.content));
        if (attr === "Name") break;
      }
    } else if (!dropped && c.content.length > 0) {
      const value = replaceWinFormat(c.content);
      if (c.name === "Data") joined.push(value);
      else put(lcfirst(c.name), value);
    }
  }
  if (joined.length) put("data", joined.join(", "));

  // Windows writes Level in decimal and Keywords in hex, so anything else is a bad fixture.
  if (level !== undefined && !/^\d+$/.test(level)) refuse(`a Level that is not a decimal number on its own; ${MISTAKE}`);
  if (keywords !== undefined && !/^(?:0x)?[0-9a-f]+$/i.test(keywords)) refuse(`a Keywords that is not hex on its own; ${MISTAKE}`);
  if (level !== undefined && keywords !== undefined) {
    // strtol(level, NULL, 10) into an int, and strtoull(keywords, NULL, 16).
    const l = BigInt(level);
    const n = Number(BigInt.asIntN(32, l > LONG_MAX ? LONG_MAX : l));
    const k = BigInt(`0x${keywords.replace(/^0x/i, "")}`);
    const bits = k > ULLONG_MAX ? ULLONG_MAX : k;
    let sev = SEVERITY[n] ?? "UNKNOWN";
    if (n === 0) sev = bits & AUDIT_FAILURE ? "AUDIT_FAILURE" : bits & AUDIT_SUCCESS ? "AUDIT_SUCCESS" : "UNKNOWN";
    putSystem("severityValue", sev);
  }
  // replace_win_format(cJSON_PrintUnformatted(Message), 1): printed with its quotes, then the
  // known escapes undone, so a control character cJSON writes as \u00XX stays six characters.
  // The agent sends no Message when the provider has no template, and then none is set.
  if (cap.message != null) putSystem("message", replaceWinFormat(unescapeJson(`"${cjsonEscaped(cap.message)}"`)));

  const win: Record<string, Record<string, string>> = { system };
  if (Object.keys(eventdata).length) win.eventdata = eventdata;
  return { win };
}

// *--- Entry Point ---*

// usage: bun tools/winevt.ts <captures.json>   one decoded event per line
if (import.meta.main) {
  if (Bun.argv.length !== 3) {
    console.error("usage: bun tools/winevt.ts <captures.json>");
    process.exit(2);
  }
  let text = "";
  try {
    text = readFileSync(Bun.argv[2], "utf8");
  } catch {
    fail("cannot read the captures file");
  }
  let caps: unknown;
  try {
    caps = JSON.parse(text);
  } catch {
    fail("the captures file is not JSON");
  }
  if (!Array.isArray(caps)) fail("the captures file does not hold an array");
  // Decode every capture before printing any, so a refusal leaves no partial output.
  const lines: string[] = [];
  for (const [i, c] of caps.entries()) {
    try {
      lines.push(JSON.stringify(decodeWinevt(c)));
    } catch (e) {
      if (e instanceof CaptureError) fail(`entry ${i}: ${e.message}`);
      throw e;
    }
  }
  for (const line of lines) console.log(line);
}
