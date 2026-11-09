// *****************************************************************************
// *Title: winevt.test*
// *Author: Kyle Versluis*
// *Description: Hold the decoder port to a live alert, and test redaction.*
// *****************************************************************************

// *--- Imports ---*

import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { captureScript, decodeAnswer, redact, replaceGuidPrefixes, sshArgv, sysmonGuidPrefixes } from "./winevt-capture.ts";
import { type Capture, CaptureError, decodeWinevt, replaceWinFormat } from "./winevt.ts";

// *--- Configuration ---*

const FIX = resolve(import.meta.dir, "fixtures/winevt");
const load = (name: string) => JSON.parse(readFileSync(resolve(FIX, name), "utf8"));
const event = (system: string, eventdata: string) =>
  `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>${system}</System><EventData>${eventdata}</EventData></Event>`;

// Built from parts, because leakcheck reads this file too and refuses a private address.
const v4 = (...o: number[]) => o.join(".");
const v6 = (...g: string[]) => g.join(":");
const arpa6 = (hex32: string) => `${[...hex32].reverse().join(".")}.ip6.arpa`;
const b64 = (s: string, enc: BufferEncoding) => Buffer.from(s, enc).toString("base64");

// *--- Tests ---*

describe("decodeWinevt", () => {
  // ISA ISC-120: the 2026-10-26 lsass plant, as the live manager alerted on it (29 fields).
  test("matches the live alert's data.win field for field", () => {
    const want = load("plant-alert-win.json");
    expect(Object.keys(want.system).length + Object.keys(want.eventdata).length).toBe(29);
    expect(decodeWinevt(load("plant-capture.json")[0]).win).toEqual(want);
  });

  test("keeps cJSON's escaping in values, as analysisd does", () => {
    const xml = event("<Channel>Security</Channel>", `<Data Name='Image'>C:\\a "b"</Data>`);
    expect(decodeWinevt({ xml }).win.eventdata).toEqual({ image: 'C:\\\\a \\"b\\"' });
  });

  test("drops (NULL), dash and empty values, and joins unnamed Data", () => {
    const xml = event(
      "<Channel>Application</Channel>",
      "<Data Name='A'>(NULL)</Data><Data Name='B'>-</Data><Data Name='C'></Data><Data>one</Data><Data>two  </Data>",
    );
    expect(decodeWinevt({ xml }).win.eventdata).toEqual({ data: "one, two" });
  });

  test("names level 0 from the audit keyword bits", () => {
    const sys = (k: string) => `<Level>0</Level><Keywords>${k}</Keywords>`;
    expect(decodeWinevt({ xml: event(sys("0x8010000000000000"), "") }).win.system.severityValue).toBe("AUDIT_FAILURE");
    expect(decodeWinevt({ xml: event(sys("0x8020000000000000"), "") }).win.system.severityValue).toBe("AUDIT_SUCCESS");
    expect(decodeWinevt({ xml: event("<Level>4</Level><Keywords>0x0</Keywords>", "") }).win.system.severityValue).toBe("INFORMATION");
  });

  // The closing quote stays on, so the trailing-whitespace trim never reaches a CRLF.
  test("quotes the message, and sets none when the capture has none", () => {
    expect(decodeWinevt({ message: null, xml: event("", "") }).win.system.message).toBeUndefined();
    expect(decodeWinevt({ message: "hi\r\n", xml: event("", "") }).win.system.message).toBe('"hi\r\n"');
  });

  test("keeps Data named __proto__, constructor and toString as fields", () => {
    const xml = event(
      "<Channel>Security</Channel>",
      "<Data Name='__proto__'>a</Data><Data Name='constructor'>b</Data><Data Name='toString'>c</Data>",
    );
    expect(JSON.stringify(decodeWinevt({ xml }).win.eventdata)).toBe('{"__proto__":"a","constructor":"b","toString":"c"}');
  });

  // These pin what the port does today. No live alert has checked them yet.
  test("pins the port: the message keeps its quotes, and inner quotes and tabs as they are", () => {
    expect(decodeWinevt({ message: 'say "hi"\tnow', xml: event("", "") }).win.system.message).toBe('"say "hi"\tnow"');
  });

  test("pins the port: a control character in a value comes out escaped as cJSON prints it", () => {
    expect(decodeWinevt({ xml: event("", "<Data Name='A'>x\u0001y</Data>") }).win.eventdata.a).toBe("x\\u0001y");
  });

  test("pins the port: level 1 is CRITICAL, 2 is ERROR, 0 with no audit bit is UNKNOWN", () => {
    const sev = (l: string, k: string) =>
      decodeWinevt({ xml: event(`<Level>${l}</Level><Keywords>${k}</Keywords>`, "") }).win.system.severityValue;
    expect(sev("1", "0x0")).toBe("CRITICAL");
    expect(sev("2", "0x0")).toBe("ERROR");
    expect(sev("0", "0x8000000000000000")).toBe("UNKNOWN");
  });

  test("the CLI prints the plant capture as the live alert's data.win", () => {
    const p = Bun.spawnSync([process.execPath, resolve(import.meta.dir, "winevt.ts"), resolve(FIX, "plant-capture.json")], {
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(p.exitCode).toBe(0);
    expect(p.stderr.toString()).toBe("");
    const lines = p.stdout.toString().trimEnd().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toEqual({ win: load("plant-alert-win.json") });
  });
});

// Checked against the 4.14.9 source (winevtchannel.c), not yet against a live alert.
describe("decodeWinevt follows the C", () => {
  const data = (body: string) => decodeWinevt({ xml: event("", body) }).win.eventdata;
  const sev = (l: string, k: string) =>
    decodeWinevt({ xml: event(`<Level>${l}</Level><Keywords>${k}</Keywords>`, "") }).win.system.severityValue;

  test("replace_win_format trims space, tab, CR, LF, VT and FF, and never the first character", () => {
    expect(replaceWinFormat("x \t\r\n\v\f")).toBe("x");
    for (const s of ["x\u00a0", "x\u2028", "x\ufeff", "x\u3000"]) expect(replaceWinFormat(s)).toBe(s);
    expect(replaceWinFormat("   ")).toBe(" ");
    expect(replaceWinFormat("\n")).toBe("\n");
    expect(replaceWinFormat("")).toBe("");
  });

  test("keeps a trailing non-ASCII space, and one space of an all-blank value", () => {
    expect(data("<Data Name='A'>x\u00a0</Data><Data Name='B'>y\u3000</Data><Data Name='C'>z  </Data>")).toEqual({
      a: "x\u00a0",
      b: "y\u3000",
      c: "z",
    });
    expect(data("<Data Name='A'>   </Data>")).toEqual({ a: " " });
    expect(data("<Data>   </Data>")).toEqual({ data: " " });
  });

  // cJSON prints the XML before os_xml reads it, so the trim sees "\t", not a tab.
  test("trims after cJSON escaping, so a trailing tab or newline stays as its escape", () => {
    expect(data("<Data Name='A'>x\t</Data><Data Name='B'>y\r\n</Data>")).toEqual({ a: "x\\t", b: "y\\r\\n" });
  });

  test("keys a Data by each attribute's value, stopping at Name", () => {
    expect(data("<Data Foo='bar'>x</Data>")).toEqual({ bar: "x" });
    expect(data("<Data Foo='Bar' Name='Baz'>x</Data>")).toEqual({ bar: "x", baz: "x" });
    expect(data("<Data Name='Baz' Foo='Bar'>x</Data>")).toEqual({ baz: "x" });
    expect(data("<Data Foo='bar'>(NULL)</Data><Data Foo='baz'>-</Data>")).toBeUndefined();
  });

  test("lowers only an ASCII first letter, as tolower does in the C locale", () => {
    expect(data("<Data Name='\u00c4rger'>x</Data><Data Name='ABC'>y</Data>")).toEqual({ "\u00c4rger": "x", aBC: "y" });
  });

  test("reads Keywords as hex with or without 0x", () => {
    expect(sev("0", "8020000000000000")).toBe("AUDIT_SUCCESS");
    expect(sev("0", "10000000000000")).toBe("AUDIT_FAILURE");
    expect(sev("0", "0X8010000000000000")).toBe("AUDIT_FAILURE");
    expect(sev("0", "8000000000000000")).toBe("UNKNOWN");
  });

  // strtoull saturates at all ones; strtol saturates at LONG_MAX, then the long lands in an int.
  test("saturates Level and Keywords the way strtol and strtoull do", () => {
    expect(sev("0", "F8000000000000000")).toBe("AUDIT_FAILURE");
    expect(sev("4294967300", "0")).toBe("INFORMATION");
    expect(sev("99999999999999999999", "0")).toBe("UNKNOWN");
  });

  test("sets severityValue only when Level and Keywords are both present", () => {
    expect(decodeWinevt({ xml: event("<Level>4</Level>", "") }).win.system).toEqual({ level: "4" });
    expect(decodeWinevt({ xml: event("<Keywords>0x8020000000000000</Keywords>", "") }).win.system).toEqual({
      keywords: "0x8020000000000000",
    });
  });

  // winevtchannel.c 199-207 tests the first attribute's value, not its name, and adds that
  // value. A real Security carries a SID there, so it adds nothing.
  test("adds the literal UserID for a Channel or Security whose first attribute value is UserID", () => {
    const system = (s: string) => decodeWinevt({ xml: event(s, "") }).win.system;
    expect(system("<Channel X='UserID'>Security</Channel>")).toEqual({ channel: "Security", userID: "UserID" });
    expect(Object.keys(system("<Channel X='UserID'>Security</Channel><EventID>1</EventID>"))).toEqual(["channel", "userID", "eventID"]);
    expect(system("<Channel>Security</Channel>")).toEqual({ channel: "Security" });
    expect(system("<Channel X='a' Y='UserID'>Security</Channel>")).toEqual({ channel: "Security" });
    expect(system("<Security X='UserID'/>")).toEqual({ securityUserID: "UserID" });
    expect(system("<Security UserID='S-1-5-18'/>")).toEqual({});
    expect(system("<Security X='S-1-5-18' Y='UserID'/>")).toEqual({});
    expect(() => system("<Security X='UserID'/><Security Y='UserID'/>")).toThrow(/^capture: two System values land on one key securityUserID$/);
    expect(() => system("<Channel X='UserID'>a</Channel><UserID>b</UserID>")).toThrow(/^capture: two System values land on one key userID$/);
  });

  // winevtchannel.c 222 gives Correlation an empty branch, so neither its attributes nor its
  // text reach the generic lowercase-and-add branch below it.
  test("drops Correlation whatever its attributes or text", () => {
    const system = (s: string) => decodeWinevt({ xml: event(s, "") }).win.system;
    expect(system("<Correlation ActivityID='UserID'/>")).toEqual({});
    expect(system("<Correlation ActivityID='UserID'>x</Correlation>")).toEqual({});
    expect(system("<Correlation>x</Correlation>")).toEqual({});
    expect(Object.keys(system("<Channel>a</Channel><Correlation A='UserID'/><EventID>1</EventID>"))).toEqual(["channel", "eventID"]);
  });

  // winevtchannel.c 176, 186 and 190 read these three only when they carry attributes. With none
  // they fall through to the generic branch at 223, like any other element.
  test("adds a Provider, TimeCreated or Execution with no attributes as its lower-cased name holding its text", () => {
    const system = (s: string) => decodeWinevt({ xml: event(s, "") }).win.system;
    expect(system("<Provider>p</Provider><TimeCreated>t</TimeCreated><Execution>e</Execution>")).toEqual({
      provider: "p",
      timeCreated: "t",
      execution: "e",
    });
    expect(system("<Provider/><TimeCreated></TimeCreated><Execution />")).toEqual({});
    expect(system("<Provider Foo='x'>p</Provider><TimeCreated Foo='x'>t</TimeCreated><Execution Foo='x'>e</Execution>")).toEqual({});
    expect(() => system("<Provider>p</Provider><provider>q</provider>")).toThrow(/^capture: two System values land on one key provider$/);
  });

  // winevtchannel.c 200 adds Channel whatever its content, and os_xml gives an empty or
  // self-closing element "". Only the generic branch at 223 needs a length over 0.
  test("adds an empty Channel as an empty value, where an empty generic element lands nowhere", () => {
    const system = (s: string) => decodeWinevt({ xml: event(s, "") }).win.system;
    for (const s of ["<Channel></Channel>", "<Channel/>", "<Channel />"]) expect(system(s)).toEqual({ channel: "" });
    expect(system("<Channel X='UserID'></Channel>")).toEqual({ channel: "", userID: "UserID" });
    expect(system("<Computer></Computer><Task/>")).toEqual({});
  });

  // cJSON_PrintUnformatted writes a control character it has no short escape for as \u00XX, and
  // wstr_unescape_json (string_op.c 952-1006) undoes only \b \t \n \f \r \" \\, keeping the rest.
  test("leaves a control character in the message as cJSON's \\u escape, and undoes the short ones", () => {
    const msg = (m: string) => decodeWinevt({ message: m, xml: event("", "") }).win.system.message;
    expect(msg("a\u001bb\u0007c\u0001d\u001f")).toBe('"a\\u001bb\\u0007c\\u0001d\\u001f"');
    expect(msg("t\tl\nc\rb\bf\f")).toBe('"t\tl\nc\rb\bf\f"');
    // A backslash and quote come back as written, so a typed \u001b reads the same as an ESC.
    expect(msg('C:\\users "q" \\u001b')).toBe('"C:\\users "q" \\u001b"');
    expect(msg("end\u001b")).toBe('"end\\u001b"');
  });
});

// os_xml_internal.h 20 and os_xml.c 297-303, 558-567: OS_ReadXMLString counts each element name,
// text run and attribute name or value in bytes of cJSON's print, each from 0, and gives up on
// the whole event at 20480. DecodeWinevt then builds only the message (winevtchannel.c 155-162, 683-689).
describe("decodeWinevt gives up on the event where os_xml does", () => {
  const LIMIT = 20480;
  const win = (system: string, eventdata: string, message: string | null = "m") => decodeWinevt({ message, xml: event(system, eventdata) }).win;
  const gaveUp = { system: { message: '"m"' } };
  const data = (value: string) => `<Data Name='A'>${value}</Data>`;

  test("decodes a Data value one byte under the limit, and keeps only the message at it", () => {
    expect(win("<Channel>c</Channel>", data("x".repeat(LIMIT - 1)))).toEqual({
      system: { channel: "c", message: '"m"' },
      eventdata: { a: "x".repeat(LIMIT - 1) },
    });
    expect(win("<Channel>c</Channel>", data("x".repeat(LIMIT)))).toEqual(gaveUp);
    // With no message the C sets none, so system is left empty.
    expect(win("<Channel>c</Channel>", data("x".repeat(LIMIT)), null)).toEqual({ system: {} });
  });

  test("counts cJSON's print in UTF-8 bytes, so a backslash or quote counts twice", () => {
    const units: [string, number][] = [["\\", 2], ['"', 2], ["\t", 2], ["\u0001", 6], ["é", 2], ["中", 3], ["\u{1f600}", 4]];
    for (const [unit, bytes] of units) {
      // Exactly n bytes once printed, ending in a plain x so no trim reaches the count.
      const fill = (n: number) => unit.repeat(Math.floor(n / bytes)) + "x".repeat(n % bytes);
      expect([...fill(LIMIT)].length).toBeLessThan(LIMIT);
      expect(Object.keys(win("", data(fill(LIMIT - 1))).eventdata)).toEqual(["a"]);
      expect(win("", data(fill(LIMIT)))).toEqual(gaveUp);
    }
  });

  test("measures attribute names and values and element names the same way", () => {
    expect(Object.keys(win("", `<Data Name='${"n".repeat(LIMIT - 1)}'>v</Data>`).eventdata)).toEqual([`n`.repeat(LIMIT - 1)]);
    expect(win("", `<Data Name='${"n".repeat(LIMIT)}'>v</Data>`)).toEqual(gaveUp);
    expect(win("", `<Data Name='${"\\".repeat(LIMIT / 2)}'>v</Data>`)).toEqual(gaveUp);
    expect(win("", `<Data ${"N".repeat(LIMIT - 1)}='k'>v</Data>`).eventdata).toEqual({ k: "v" });
    expect(win("", `<Data ${"N".repeat(LIMIT)}='k'>v</Data>`)).toEqual(gaveUp);
    expect(win(`<Provider Name='p' Guid='${"g".repeat(LIMIT)}'/>`, "")).toEqual(gaveUp);
    const name = (n: number) => `T${"t".repeat(n - 1)}`;
    expect(win(`<${name(LIMIT - 1)}>v</${name(LIMIT - 1)}>`, "").system[`t${"t".repeat(LIMIT - 2)}`]).toBe("v");
    expect(win(`<${name(LIMIT)}>v</${name(LIMIT)}>`, "")).toEqual(gaveUp);
  });

  // os_xml.c 338-341: a self-closing tag with nothing after its name keeps the / in the name's count.
  // 649-650: one with attributes or a space returns at the /, and its parent reads the > as text.
  test("counts the / of a bare self-closing tag in its name, and the > after any other in the parent's text", () => {
    const name = (n: number) => `T${"t".repeat(n - 1)}`;
    const decoded = { system: { channel: "c", message: '"m"' } };
    expect(win(`<${name(LIMIT - 2)}/><Channel>c</Channel>`, "")).toEqual(decoded);
    expect(win(`<${name(LIMIT - 1)} /><Channel>c</Channel>`, "")).toEqual(decoded);
    expect(win(`<${name(LIMIT - 1)}/><Channel>c</Channel>`, "")).toEqual(gaveUp);
    const run = "x".repeat(LIMIT - 1);
    expect(win(`<Channel/>${run}<EventID>1</EventID>`, "").system).toEqual({ channel: "", eventID: "1", message: '"m"' });
    for (const tag of ["<Channel />", "<Provider Name='p'/>", "<Provider Name='p' />"]) {
      expect(win(`${tag}${run}<EventID>1</EventID>`, "")).toEqual(gaveUp);
    }
  });

  test("counts each text run on its own, a container's included", () => {
    const run = "x".repeat(LIMIT - 1);
    expect(win(`${run}<Channel>c</Channel>${run}`, "").system).toEqual({ channel: "c", message: '"m"' });
    // The > a self-closing tag leaves counts in the next run only.
    const after = decodeWinevt({ message: "m", xml: event("<Channel />", "").replace("</System>", `</System>${run}`) }).win;
    expect(after.system).toEqual({ channel: "", message: '"m"' });
    expect(win(`${run}x<Channel>c</Channel>`, "")).toEqual(gaveUp);
    expect(win("", `${run}x${data("v")}`)).toEqual(gaveUp);
  });

  // os_xml reads in order and stops at the first failure, so nothing after it counts.
  test("stops at the first oversize piece, but still refuses a shape before it", () => {
    const big = data("x".repeat(LIMIT));
    expect(win("<Level>x</Level><Keywords>0x0</Keywords>", big)).toEqual(gaveUp);
    expect(win("", `${big}<Data Name='CategoryId'>%%8272</Data>`)).toEqual(gaveUp);
    expect(decodeWinevt({ message: "m", xml: event("", big).replace("</Event>", "<UserData><X>y</X></UserData></Event>") }).win).toEqual(gaveUp);
    expect(win("", `${big}<!-- c -->`)).toEqual(gaveUp);
    expect(() => win("", `<!-- c -->${big}`)).toThrow(/a comment, declaration or CDATA/);
  });
});

describe("decodeWinevt refuses what the port does not handle", () => {
  const refuses = (cap: unknown) => expect(() => decodeWinevt(cap as Capture)).toThrow(CaptureError);

  test("a capture that is not an object, or holds no xml text", () => {
    for (const cap of [null, undefined, "x", 3, [], {}, { xml: "" }, { xml: 5 }]) refuses(cap);
  });

  test("text with no Event root or no System section", () => {
    refuses({ xml: "not xml at all" });
    refuses({ xml: "<Event><EventData></EventData></Event>" });
    refuses({ xml: "<Events><System></System></Events>" });
  });

  test("EventData that carries attributes, and UserData", () => {
    refuses({ xml: event("", "<Data>x</Data>").replace("<EventData>", "<EventData Name='Task'>") });
    refuses({ xml: event("", "").replace("<EventData></EventData>", "<EventData Name='Task'/>") });
    refuses({ xml: event("", "").replace("<EventData></EventData>", "<UserData><Log><Name>x</Name></Log></UserData>") });
  });

  test("accepts EventData that is missing, empty or self-closing", () => {
    const head = "<Event xmlns='x'><System><Channel>Security</Channel></System>";
    for (const tail of ["</Event>", "<EventData></EventData></Event>", "<EventData/></Event>", "<EventData /></Event>"]) {
      expect(decodeWinevt({ xml: head + tail }).win.eventdata).toBeUndefined();
    }
  });

  test("a Level or Keywords that is not a number", () => {
    refuses({ xml: event("<Level>4</Level><Keywords>high</Keywords>", "") });
    refuses({ xml: event("<Level>4</Level><Keywords></Keywords>", "") });
    refuses({ xml: event("<Level>x</Level><Keywords>0x0</Keywords>", "") });
  });

  test("says why: the C would read such a Level or Keywords, but the capture is a mistake", () => {
    const bad = (system: string, why: RegExp) => expect(() => decodeWinevt({ xml: event(system, "") })).toThrow(why);
    bad("<Level>4</Level><Keywords>high</Keywords>", /a Keywords that is not hex on its own.*a mistake/);
    bad("<Level>4</Level><Keywords>0x</Keywords>", /a Keywords that is not hex/);
    bad("<Level>4x</Level><Keywords>0x0</Keywords>", /a Level that is not a decimal number on its own.*a mistake/);
    bad("<Level> 4</Level><Keywords>0x0</Keywords>", /a Level that is not/);
    bad("<Level>x</Level>", /a Level that is not/);
    bad("<Keywords>0xZZ</Keywords>", /a Keywords that is not hex/);
  });

  test("an attribute value not in single quotes, which os_xml cannot read once cJSON escapes it", () => {
    for (const xml of [
      event("", `<Data Name="A">x</Data>`),
      event(`<Provider Name="P"/>`, ""),
      event("", "<Data Name=A>x</Data>"),
      event("", "").replace(/xmlns='([^']*)'/, 'xmlns="$1"'),
      // Whitespace inside a single-quoted value is text, so the quote is what is named.
      event("", `<Data Name='a\tb' Foo="c">x</Data>`),
    ]) {
      expect(() => decodeWinevt({ xml })).toThrow(/an attribute value not in single quotes/);
    }
    // A < that opens no name is not a tag at all, whatever whitespace follows it.
    expect(() => decodeWinevt({ xml: event("", "<Data Name='A'>a <\nb</Data>") })).toThrow(/a tag the port does not read/);
  });

  // os_xml.c 377-381 reads a closing name up to the >, so anything after the name is part of it.
  test("a closing tag with more than its name before the >", () => {
    for (const close of ["</Data >", "</Data\t>", "</Data\n>"]) {
      expect(() => decodeWinevt({ xml: event("", `<Data Name='A'>x${close}`) })).toThrow(/a closing tag with more than its name between <\/ and >/);
    }
    expect(() => decodeWinevt({ xml: event("<Channel>c</Channel >", "") })).toThrow(/a closing tag with more than its name/);
  });

  // cJSON prints a tab, CR or LF as two characters and any other control one as six, so os_xml
  // sees no whitespace in a tag but a space and reads the rest into a name (os_xml.c 332, 628).
  test("whitespace but a space inside a tag, which os_xml reads as part of a name", () => {
    const tags = [
      "<Data\tName='A'>x</Data>",
      "<Data\nName='A'>x</Data>",
      "<Data\r\nName='A'>x</Data>",
      "<Data Name='A'\t>x</Data>",
      "<Data Name='A'\fFoo='B'>x</Data>",
      // os_xml takes these two, as an attribute named \tName and an element named Channel\t.
      "<Data \tName='A'>x</Data>",
      "<Data Name='A'>x</Data>",
    ];
    for (const tag of tags) expect(() => decodeWinevt({ xml: event("", tag) })).toThrow(/whitespace other than a space inside a tag/);
    expect(() => decodeWinevt({ xml: event("<Channel\t/>", "") })).toThrow(/whitespace other than a space inside a tag/);
    // Inside a quoted value it is text, and more than one space is still a separator.
    expect(decodeWinevt({ xml: event("<Provider Name='a\tb'/>", "") }).win.system).toEqual({ providerName: "a\\tb" });
    expect(decodeWinevt({ xml: event("", "<Data  Name='A'  Foo='B' >x</Data>") }).win.eventdata).toEqual({ a: "x" });
  });

  // os_xml.c 569-573: a > ends the tag wherever it falls, inside a value included.
  test("a > inside an attribute value, which os_xml reads as an attribute never closed", () => {
    for (const xml of [event("", "<Data Name='a>b'>x</Data>"), event("<Provider Name='>'/>", "")]) {
      expect(() => decodeWinevt({ xml })).toThrow(/a > inside an attribute value/);
    }
    expect(decodeWinevt({ xml: event("", "<Data Name='a&gt;b'>x</Data>") }).win.eventdata).toEqual({ "a&gt;b": "x" });
  });

  // os_xml.c 586-593 compares the names with strcmp, so another case is another attribute.
  test("an attribute repeated in one tag", () => {
    for (const xml of [
      event("<Provider Name='a' Name='b'/>", ""),
      event("", "<Data Name='A' Name='B'>x</Data>"),
      event("", "<Data Foo='a' Name='b' Foo='c'>x</Data>"),
    ]) {
      expect(() => decodeWinevt({ xml })).toThrow(/an attribute repeated in one tag/);
    }
    expect(decodeWinevt({ xml: event("", "<Data Name='A' name='B'>x</Data>") }).win.eventdata).toEqual({ a: "x" });
  });

  // os_xml.c 513-516 stores a name equal to var, in any case, as a variable and not as an
  // element or attribute.
  test("an element or attribute named var, in any case", () => {
    for (const xml of [
      event("<Var>x</Var>", ""),
      event("<VAR/>", ""),
      event("", "<Data var='k'>x</Data>"),
      event("", "<Data Name='A' vAr='k'>x</Data>"),
    ]) {
      expect(() => decodeWinevt({ xml })).toThrow(/named var, which os_xml stores as a variable/);
    }
    expect(decodeWinevt({ xml: event("", "<Data Name='Var'>x</Data><Data Name='vars'>y</Data>") }).win.eventdata).toEqual({ var: "x", vars: "y" });
  });

  // os_xml.c 549-552 and 645-646: each attribute followed by a space reads the next one level
  // deeper, and level 49 is refused, so a 49th followed by a space or any 50th fails.
  test("more attributes on one tag than os_xml reads", () => {
    const attrs = (n: number) => Array.from({ length: n }, (_, k) => ` A${k}='v${k}'`).join("");
    expect(Object.keys(decodeWinevt({ xml: event("", `<Data${attrs(49)}>x</Data>`) }).win.eventdata)).toHaveLength(49);
    for (const tag of [`<Data${attrs(49)} >x</Data>`, `<Data${attrs(49)} />`, `<Data${attrs(50)}>x</Data>`]) {
      expect(() => decodeWinevt({ xml: event("", tag) })).toThrow(/more attributes on one tag than os_xml reads/);
    }
  });

  test("an <Event> that never closes, a closing tag that does not match, and text after the event", () => {
    const open = "<Event xmlns='x'><System><Channel>Security</Channel></System>";
    expect(() => decodeWinevt({ xml: open })).toThrow(/an <Event> that never closes/);
    expect(() => decodeWinevt({ xml: `${open}<EventData>` })).toThrow(/an <Event> that never closes/);
    expect(() => decodeWinevt({ xml: `${open}</EventData></Event>` })).toThrow(/a closing tag that does not match/);
    expect(() => decodeWinevt({ xml: `${open}</Event><Event/>` })).toThrow(/text after the closing <\/Event>/);
  });

  // os_xml skips text outside the root, as it skips the quotes cJSON prints around the event, but
  // ToXml writes none, so a capture holding some is refused as a mistake.
  test("plain text before the root or after the closing </Event>, though whitespace passes", () => {
    const xml = event("<Channel>Security</Channel>", "");
    expect(() => decodeWinevt({ xml: `${xml} trailing` })).toThrow(/: text after the closing <\/Event>$/);
    expect(() => decodeWinevt({ xml: `leading ${xml}` })).toThrow(/: text before the root element$/);
    expect(() => decodeWinevt({ xml: "not xml at all" })).toThrow(/: no <Event> root with a <System> section$/);
    expect(decodeWinevt({ xml: ` \r\n${xml}\r\n ` }).win.system.channel).toBe("Security");
  });

  test("a < inside an attribute value, which ToXml always escapes", () => {
    for (const xml of [event("", "<Data Name='a<b'>x</Data>"), event("<Provider Name='a<b'/>", "")]) {
      expect(() => decodeWinevt({ xml })).toThrow(/: a tag the port does not read$/);
    }
  });

  test("a comment, declaration or CDATA section", () => {
    for (const extra of ["<!-- c -->", "<![CDATA[x]]>", "<?pi x?>"]) {
      expect(() => decodeWinevt({ xml: event("", `<Data Name='A'>x</Data>${extra}`) })).toThrow(/a comment, declaration or CDATA/);
    }
  });

  test("a second <EventData> or <System>", () => {
    const twoData = event("", "<Data Name='A'>x</Data>").replace("</Event>", "<EventData><Data Name='B'>y</Data></EventData></Event>");
    const twoSystem = event("", "").replace("</Event>", "<System><Channel>x</Channel></System></Event>");
    expect(() => decodeWinevt({ xml: twoData })).toThrow(/a second <EventData>/);
    expect(() => decodeWinevt({ xml: twoSystem })).toThrow(/a second <System>/);
  });

  test("markup inside a Data or System field", () => {
    for (const xml of [
      event("", "<Data Name='A'>a<b>c</b></Data>"),
      event("", "<Data Name='A'><Data Name='B'>x</Data></Data>"),
      event("", "<Data>a<br/>b</Data>"),
      event("<Channel>a<b/></Channel>", ""),
    ]) {
      expect(() => decodeWinevt({ xml })).toThrow(/markup inside a field/);
    }
  });

  test("two EventData values that land on one key", () => {
    for (const body of [
      "<Data Name='A'>x</Data><Data Name='A'>y</Data>",
      "<Data Name='Foo'>x</Data><Data Name='foo'>y</Data>",
      "<Data Name='data'>x</Data><Data>y</Data>",
      "<Data Foo='a' Name='a'>x</Data>",
      "<Data Name='binary'>x</Data><Binary>00</Binary>",
    ]) {
      expect(() => decodeWinevt({ xml: event("", body) })).toThrow(/two EventData values that land on one key/);
    }
    // A dropped value lands nowhere, so it collides with nothing.
    expect(decodeWinevt({ xml: event("", "<Data Name='A'>(NULL)</Data><Data Name='A'>y</Data>") }).win.eventdata).toEqual({ a: "y" });
  });

  test("two System values that land on one key", () => {
    const shapes: [string, string][] = [
      ["<EventID>1</EventID><EventID>2</EventID>", "eventID"],
      ["<EventID>1</EventID><eventID>2</eventID>", "eventID"],
      ["<Level>4</Level><level>4</level><Keywords>0x0</Keywords>", "level"],
      ["<Channel>a</Channel><Channel>b</Channel>", "channel"],
      ["<ProviderName>x</ProviderName><Provider Name='a'/>", "providerName"],
      ["<SeverityValue>x</SeverityValue><Level>4</Level><Keywords>0x0</Keywords>", "severityValue"],
    ];
    for (const [system, key] of shapes) {
      expect(() => decodeWinevt({ xml: event(system, "") })).toThrow(new RegExp(`^capture: two System values land on one key ${key}$`));
    }
    expect(() => decodeWinevt({ message: "m", xml: event("<Message>x</Message>", "") })).toThrow(/^capture: two System values land on one key message$/);
    // An empty generic value never lands, so it collides with nothing.
    expect(decodeWinevt({ xml: event("<EventID></EventID><EventID>2</EventID>", "") }).win.system).toEqual({ eventID: "2" });
  });

  test("a Data named for an audit-policy category, which the port does not translate", () => {
    for (const [name, key] of [
      ["CategoryId", "categoryId"],
      ["subcategoryId", "subcategoryId"],
      ["AuditPolicyChanges", "auditPolicyChanges"],
    ]) {
      const xml = event("", `<Data Name='${name}'>%%8272</Data>`);
      expect(() => decodeWinevt({ xml })).toThrow(new RegExp(`a Data named ${key}; the port does not translate audit-policy categories`));
      expect(() => decodeWinevt({ xml })).not.toThrow(/8272/);
    }
    // A dropped value takes no special path in the C either.
    expect(decodeWinevt({ xml: event("", "<Data Name='CategoryId'>-</Data>") }).win.eventdata).toBeUndefined();
  });

  test("any Event child but System and EventData, named in the error", () => {
    for (const name of ["UserData", "RenderingInfo", "DebugData", "ProcessingErrorData", "BinaryEventData", "Foo"]) {
      const xml = event("", "").replace("</Event>", `<${name}><Message>x</Message></${name}></Event>`);
      expect(() => decodeWinevt({ xml })).toThrow(new RegExp(`a <${name}> section; the port decodes only <System> and <EventData>`));
    }
  });

  // Live, the agent passes C strings and cJSON turns \u0000 back into a 0 byte, so the event
  // ends at a NUL: a positive on a later field passes here and never fires. Sysmon logs NULs in
  // registry key names, a known hiding technique.
  test("a NUL anywhere in the XML or the message, where the live event is cut short", () => {
    const run = "HKU\\S-1-5-21-0-0-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\";
    const fields = (target: string) => `<Data Name='TargetObject'>${target}</Data><Data Name='Details'>C:\\x.exe</Data>`;
    const clean = event("<EventRecordID>9</EventRecordID>", fields(`${run}hidden`));
    const why = /^record 9: a NUL character, where the agent's C string cuts the live event short$/;
    expect(() => decodeWinevt({ xml: event("<EventRecordID>9</EventRecordID>", fields(`${run}\u0000hidden`)) })).toThrow(why);
    for (const xml of [clean.replace("<System>", "<System><Provider Name='Sys\u0000mon'/>"), clean.replace("</EventData>", "</EventData>\u0000")]) {
      expect(() => decodeWinevt({ xml })).toThrow(why);
    }
    expect(() => decodeWinevt({ xml: clean, message: `Registry value set:\r\nTargetObject: ${run}\u0000hidden` })).toThrow(why);
    // The same event without the NUL decodes in full, its later field included.
    expect(decodeWinevt({ xml: clean, message: "Registry value set" }).win.eventdata).toEqual({
      targetObject: `${run.replaceAll("\\", "\\\\")}hidden`,
      details: "C:\\\\x.exe",
    });
  });

  test("names the record, never the value, in a refusal", () => {
    const xml = event("<EventRecordID>42</EventRecordID><Computer>secret-host</Computer>", "").replace(
      "<EventData>",
      "<EventData Name='secret-name'>",
    );
    expect(() => decodeWinevt({ xml })).toThrow(/^record 42: /);
    expect(() => decodeWinevt({ xml, record: 7 })).toThrow(/^record 7: /);
    expect(() => decodeWinevt({ xml })).not.toThrow(/secret/);
    for (const body of [`<Data Name="secret">x</Data>`, "<Data Name='secret'>x</Data><Data Name='secret'>y</Data>"]) {
      expect(() => decodeWinevt({ xml: event("<Level>secret</Level>", body) })).not.toThrow(/secret/);
      expect(() => decodeWinevt({ xml: event("", body) })).not.toThrow(/secret/);
    }
  });

  test("the CLI prints one winevt line and exits 2 on bad JSON or a refused capture", () => {
    const dir = mkdtempSync(join(tmpdir(), "winevt-test-"));
    try {
      const good = JSON.stringify({ xml: event("<Channel>Security</Channel>", "") });
      for (const body of ["{not json", JSON.stringify({ xml: "x" }), `[${good}, {"xml": "no event here"}]`]) {
        writeFileSync(join(dir, "c.json"), body);
        const p = Bun.spawnSync([process.execPath, resolve(import.meta.dir, "winevt.ts"), join(dir, "c.json")], {
          stdout: "pipe",
          stderr: "pipe",
        });
        expect(p.exitCode).toBe(2);
        expect(p.stderr.toString()).toMatch(/^winevt: [^\n]*\n$/);
        expect(p.stdout.toString()).toBe("");
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("redact", () => {
  const a = v4(10, 1, 2, 3);
  const b = v4(192, 168, 0, 9);
  const ll = v6("fe80", "", "1%12");
  const one = (text: string, literals: [string, string][] = [], raw = false) =>
    redact([{ message: text, xml: "" }], literals, raw)[0].message;

  test("replaces literals on whole tokens only, keeping upper case", () => {
    const [c] = redact([{ message: "LABBOX\\alice on labbox, labboxes", xml: "<Computer>labbox</Computer>" }], [
      ["labbox", "host"],
      ["alice", "user"],
    ]);
    expect(c.message).toBe("HOST\\user on host, labboxes");
    expect(c.xml).toBe("<Computer>host</Computer>");
  });

  // A dot is a token boundary, so a domain run first would leave the host label in front of it.
  test("replaces a longer source before its suffix, in every order given", () => {
    const xml = event("<Computer>wkstn.lab.internal</Computer>", "<Data Name='Domain'>lab.internal</Data><Data Name='Zone'>internal</Data>");
    const caps = [{ message: "wkstn.lab.internal joined lab.internal under internal", xml }];
    const maps: [string, string][] = [
      ["internal", "top"],
      ["lab.internal", "realm"],
      ["wkstn.lab.internal", "host"],
    ];
    const orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    const outs = orders.map((o) => redact(caps, o.map((k) => maps[k])));
    expect(outs[0][0].message).toBe("host joined realm under top");
    expect(outs[0][0].xml).toBe(event("<Computer>host</Computer>", "<Data Name='Domain'>realm</Data><Data Name='Zone'>top</Data>"));
    for (const out of outs) expect(out).toEqual(outs[0]);
    // The order that leaked the host label before: suffix first.
    expect(redact(caps.slice(0, 1), [["lab.internal", "realm"], ["wkstn.lab.internal", "host"]])[0].message).toBe("host joined realm under internal");
  });

  test("names a mapping by its command-line position, though a longer source runs first", () => {
    const xml = event("<Computer>labbox</Computer>", "<Data Name='User'>bob</Data>");
    expect(() => redact([{ record: 9, message: "", xml }], [["Data", "x"], ["labbox", "labhost"]])).toThrow(
      /^record 9: --redact #1 \(to x\) matches a tag, attribute or field name in the XML$/,
    );
  });

  test("replaces the XML-escaped form of a literal too", () => {
    const [c] = redact(
      [{ message: "CORP\\O'Brien&Co", xml: "<Data>corp\\o&apos;brien&amp;co</Data><Data>o&#39;BRIEN&amp;CO</Data>" }],
      [["o'brien&co", "user.x"]],
    );
    expect(c.message).toBe("CORP\\user.x");
    expect(c.xml).toBe("<Data>corp\\user.x</Data><Data>user.x</Data>");
  });

  test("refuses an alias that could carry XML, naming the mapping", () => {
    for (const to of ["a&b", "a<b>c</b>", "a b", 'a"b', "a'b", ""]) {
      expect(() => redact([{ message: "alice", xml: "" }], [["alice", to]])).toThrow(
        /^--redact #1: the alias may hold only letters, digits, dot, dash and underscore$/,
      );
    }
  });

  test("refuses a source that would rewrite a tag, an attribute name or a Data name", () => {
    const xml = event(
      "<Provider Name='alice'/><Computer>labbox</Computer>",
      "<Data Name='User'>bob</Data><Data Name='Note'>Data, System and Event</Data>",
    );
    const refused = (from: string) =>
      expect(() => redact([{ record: 9, message: from, xml }], [["labbox", "labhost"], [from, "x"]])).toThrow(
        /^record 9: --redact #2 \(to x\) matches a tag, attribute or field name in the XML$/,
      );
    for (const from of ["Data", "data", "Name", "System", "Event", "xmlns", "User", "/"]) refused(from);
    expect(() => redact([{ record: 9, message: "", xml }], [["System", "x"]])).not.toThrow(/System/);
  });

  test("replaces a source that appears only in values, even one spelled like a tag", () => {
    const xml = event("<Provider Name='alice'/><Computer>labbox</Computer>", "<Data Name='Note'>alice wrote Data</Data>");
    const [c] = redact([{ message: "alice", xml }], [["alice", "user"]]);
    expect(c.xml).toContain("<Provider Name='user'/>");
    expect(c.xml).toContain("<Data Name='Note'>user wrote Data</Data>");
    // Whole tokens only, so neither <EventData> nor these words hold "data".
    const plain = "<Event><System><Channel>datapoint data-x</Channel></System><EventData/></Event>";
    expect(redact([{ message: "", xml: plain }], [["data", "v"]])[0].xml).toBe(plain);
  });

  test("refuses mappings that would recreate or merge a source, in either order", () => {
    const outcome = (literals: [string, string][]) => {
      try {
        redact([{ message: "P Q", xml: "" }], literals);
        return "passed";
      } catch (e) {
        return e instanceof CaptureError ? e.message : `other: ${e}`;
      }
    };
    expect(outcome([["Q", "R"], ["P", "Q"]])).toBe("--redact #2's alias is --redact #1's source");
    expect(outcome([["P", "Q"], ["Q", "R"]])).toBe("--redact #1's alias is --redact #2's source");
    expect(outcome([["q", "R"], ["P", "Q"]])).toBe("--redact #2's alias is --redact #1's source");
    expect(outcome([["alice", "xy"], ["ALICE", "xz"]])).toBe("--redact #2's source is --redact #1's source");
    expect(outcome([["labbox", "LABBOX"]])).toBe("--redact #1's alias is --redact #1's source");
    expect(outcome([["labbox", "lab.host"], ["host", "x"]])).toBe("--redact #1's alias holds --redact #2's source");
    expect(outcome([["alice", "xalicex"]])).toBe("--redact #1's alias holds --redact #1's source");
    expect(outcome([["host", "x"], ["labbox", "LABHOSTX"]])).toBe("--redact #2's alias holds --redact #1's source");
    expect(outcome([["labbox", "labhost"], ["alice", "labuser"]])).toBe("passed");
  });

  // Two sources under one alias would print as one identity.
  test("refuses two mappings that share an alias, in any case", () => {
    const run = (literals: [string, string][]) => () => redact([{ message: "alpha and beta", xml: "" }], literals);
    expect(run([["alpha", "sam"], ["beta", "sam"]])).toThrow(/^--redact #2's alias is --redact #1's alias$/);
    expect(run([["alpha", "sam"], ["beta", "SAM"]])).toThrow(/^--redact #2's alias is --redact #1's alias$/);
    expect(run([["alpha", "xy"], ["gamma", "xz"], ["beta", "xy"]])).toThrow(/^--redact #3's alias is --redact #1's alias$/);
    expect(run([["alpha", "uno"], ["beta", "two"]])()[0].message).toBe("uno and two");
  });

  test("refuses an alias the capture already holds as a whole token, in any case", () => {
    const literals: [string, string][] = [
      ["labbox", "xz"],
      ["alice", "labhost"],
    ];
    for (const c of [
      { record: 3, message: "labhost was here", xml: "" },
      { record: 3, message: null, xml: "<Computer>LabHost</Computer>" },
    ]) {
      expect(() => redact([{ message: "", xml: "" }, c], literals)).toThrow(/^record 3: --redact #2's alias labhost already occurs in the capture$/);
    }
    // Part of a longer token is not the alias, and an alias nowhere in the capture passes.
    for (const text of ["labhosts", "my-labhost", "labhost_2"]) expect(one(text, [["alice", "labhost"]])).toBe(text);
    expect(one("alice", [["alice", "labhost"]])).toBe("labhost");
  });

  test("refuses a source that would cut into an entity reference", () => {
    const xml = event("<Provider Name='a &amp; b'/>", "<Data Name='Note'>a &amp; b &#39;c&#x27; &lt;d&gt;</Data>");
    for (const from of ["amp", "39", "x27", "lt", "gt"]) {
      expect(() => redact([{ record: 9, message: "", xml }], [[from, "user"]])).toThrow(
        /^record 9: --redact #1 \(to user\) matches a tag, attribute or field name in the XML$/,
      );
    }
  });

  test("still replaces a source beside an entity, and an escaped form that holds a whole one", () => {
    const xml = event("<Provider Name='alice &amp; co'/>", "<Data Name='Note'>alice &amp; bob</Data>");
    const [c] = redact([{ message: "", xml }], [["alice", "user"]]);
    expect(c.xml).toContain("<Provider Name='user &amp; co'/>");
    expect(c.xml).toContain("<Data Name='Note'>user &amp; bob</Data>");
    const escaped = event("", "<Data Name='U'>o&apos;brien</Data>");
    expect(redact([{ message: "", xml: escaped }], [["o'brien", "user"]])[0].xml).toContain("<Data Name='U'>user</Data>");
  });

  // An earlier alias can make a later source match where none did before. Longest runs first.
  test("checks each source against the XML as the earlier ones left it", () => {
    const xml = event("<Computer>labbox</Computer>", "");
    const run = (literals: [string, string][]) => () => redact([{ record: 4, message: "", xml }], literals);
    const shape = (n: number) => new RegExp(`^record 4: --redact #${n} \\(to x\\) matches a tag, attribute or field name in the XML$`);
    expect(run([["labbox", "goo"], ["goo<", "x"]])).toThrow(shape(2));
    expect(run([["goo<", "x"], ["labbox", "goo"]])).toThrow(shape(1));
    // The longer source runs first and finds nothing; the alias then spells it, which is refused.
    expect(run([["labbox", "goo"], ["goo</Computer", "x"]])).toThrow(/^record 4: --redact #2 \(to x\) still matches after redaction$/);
  });

  // An alias and the text beside it can spell a source that has already run.
  test("refuses a source an alias spells in the output, in either order", () => {
    const xml = event("<Computer>wkstn.lab.internal</Computer>", "");
    const run = (literals: [string, string][]) => () => redact([{ record: 5, message: "wkstn.lab.internal", xml }], literals);
    expect(run([["wkstn", "host"], ["host.lab.internal", "zz"]])).toThrow(/^record 5: --redact #2 \(to zz\) still matches after redaction$/);
    expect(run([["host.lab.internal", "zz"], ["wkstn", "host"]])).toThrow(/^record 5: --redact #1 \(to zz\) still matches after redaction$/);
    expect(() => redact([{ message: null, xml }], [["wkstn", "host"], ["host.lab.internal", "zz"]])).toThrow(/^capture 0: --redact #2 /);
    // A host and its domain both redacted is the clean case: the host name runs first.
    for (const literals of [[["lab.internal", "realm"], ["wkstn.lab.internal", "host"]], [["wkstn.lab.internal", "host"], ["lab.internal", "realm"]]] as [string, string][][]) {
      expect(run(literals)()[0].message).toBe("host");
    }
  });

  // An alias and the text beside it can make an address name, which the address passes then rewrite
  // and merge with a real one elsewhere in the batch: here the plain form of the same address.
  test("refuses an alias a later pass rewrites, as an address it makes with the text beside it", () => {
    const rewritten = (n: number) => new RegExp(`^record ${n}: --redact #1 \\(to in-addr\\) was taken into text a later pass rewrote$`);
    const name = `${v4(3, 2, 1, 10)}.wkstn.arpa`;
    const batch = [
      { record: 9, message: `copied from ${name}`, xml: "" },
      { record: 10, message: `then ${a}`, xml: "" },
    ];
    expect(() => redact(batch, [["wkstn", "in-addr"]])).toThrow(rewritten(9));
    expect(() => redact([{ record: 11, message: name, xml: "" }], [["wkstn", "in-addr"]])).toThrow(rewritten(11));
    const xml = event(`<Computer>${name}</Computer>`, "");
    expect(() => redact([{ record: 12, message: null, xml }], [["wkstn", "in-addr"]])).toThrow(rewritten(12));
    // The same alias with no address beside it comes through.
    expect(one("wkstn then wkstn", [["wkstn", "in-addr"]])).toBe("in-addr then in-addr");
  });

  // A shorter source runs later and can take an alias and the text beside it.
  test("refuses an alias a later --redact source rewrites", () => {
    expect(() => redact([{ record: 13, message: "wkstnx.c", xml: "" }], [["wkstnx", "log"], ["log.c", "y"]])).toThrow(
      /^record 13: --redact #1 \(to log\) was taken into text a later pass rewrote$/,
    );
  });

  // A check only at the end would pass this: the mapped pass drops the 0 and leaves log a whole
  // token, and the last pass then reads log as a zone and cuts it to lo.
  test("checks after every pass, so a later pass that rewrites a copy of the alias cannot hide it", () => {
    const message = `${v6("fe80", "", "1")}%log${v6("0", "", "ffff", "a01", "203")}`;
    expect(() => redact([{ record: 14, message, xml: "" }], [["wkstn", "log"]])).toThrow(
      /^record 14: --redact #1 \(to log\) appears in text a later pass wrote$/,
    );
    expect(one(message)).toBe("2001:db8::1g::ffff:c000:201");
  });

  // An address pass can also make a copy of an alias, which would then stand for two things. Here
  // the mapped pass drops a leading 0 group, and log0 comes out as log, a whole token.
  test("refuses an alias that a later pass makes whole beside an address", () => {
    const batch = [
      { record: 15, message: "wkstn", xml: "" },
      { record: 16, message: `log${v6("0", "", "ffff", "a01", "203")}`, xml: "" },
    ];
    expect(() => redact(batch, [["wkstn", "log"]])).toThrow(/^record 16: --redact #1 \(to log\) appears in text a later pass wrote$/);
  });

  // An alias of hex digits alone can join an address beside it while its count still balances:
  // wkstn=192 before .168.1.1 printed 192.0.2.1, so the hostname read as an address alias.
  test("refuses an alias made only of hex digits, by its edges, naming the mapping", () => {
    const cases = [
      ["ping wkstn.168.1.1", "192"],
      [`route ${v6("fd00", "wkstn", "", "1")}`, "db8"],
      [`${ll} wkstn`, "2001"],
      ["wkstn", "DB8"],
      ["wkstn", "0"],
    ];
    for (const [text, to] of cases) {
      expect(() => redact([{ message: text, xml: "" }], [["labbox", "labhost"], ["wkstn", to]])).toThrow(
        /^--redact #2 alias must begin and end with a letter g to z, so an address beside it cannot read it as part of the address$/,
      );
    }
    for (const to of ["labhost", "lab.host", "lab-01-host"]) expect(one("ping wkstn.lab", [["wkstn", to]])).toBe(`ping ${to}.lab`);
  });

  // A zone holds letters, so a pass can still take a legal alias in. Each alias here came through
  // as a whole token, so its count balanced. Only where the alias sits tells them apart.
  test("refuses an alias a later pass's match overlaps, though its count balances", () => {
    const taken = (n: number) => new RegExp(`^record ${n}: --redact #1 \\(to labhost\\) was taken into text a later pass rewrote$`);
    const zoned = [`${v6("fe80", "", "1")}%wkstn`, `${v6("fe80", "", "")}${a}%wkstn`, `${v6("", "", "ffff", "a01", "203")}%wkstn`];
    for (const message of zoned) {
      expect(() => redact([{ record: 18, message, xml: "" }], [["wkstn", "labhost"]])).toThrow(taken(18));
      expect(() => redact([{ record: 19, message: null, xml: event(`<Computer>${message}</Computer>`, "") }], [["wkstn", "labhost"]])).toThrow(taken(19));
    }
    // A pass that only touches an alias glues it on: 2001:db8::1 then runs into labhost, which is
    // no longer a whole token.
    expect(() => redact([{ record: 20, message: `${v6("fe80", "", "")}wkstn`, xml: "" }], [["wkstn", "labhost"]])).toThrow(taken(20));
    // Beside an address but apart from it, or meeting it at a colon, each alias comes through.
    expect(one(`wkstn reached ${v4(10, 1, 2, 3)}`, [["wkstn", "lab.host"]])).toBe("lab.host reached 192.0.2.1");
    expect(one(`wkstn${v6("", "", "ffff", "a01", "203")}`, [["wkstn", "lax"]])).toBe("lax::ffff:c000:201");
    expect(one(`${v6("fe80", "", "1")} wkstn`, [["wkstn", "gus"]])).toBe("2001:db8::1 gus");
  });

  // A copy inside another alias is that alias's own; one that runs out of it into the text beside
  // it, at either end, makes a second spelling of the longer alias.
  test("refuses an alias that another alias spells with the text beside it", () => {
    const literals: [string, string][] = [
      ["wkstn", "host"],
      ["labbox", "lab.host"],
      ["alice", "host.lax"],
    ];
    expect(() => redact([{ record: 21, message: "lab.wkstn", xml: "" }], literals)).toThrow(
      /^record 21: --redact #2 \(to lab\.host\) appears in text a later pass wrote$/,
    );
    expect(() => redact([{ record: 22, message: "wkstn.lax", xml: "" }], literals)).toThrow(
      /^record 22: --redact #3 \(to host\.lax\) appears in text a later pass wrote$/,
    );
    expect(one("wkstn labbox alice", literals)).toBe("host lab.host host.lax");
  });

  test("passes an alias that is also a dot-separated part of another alias", () => {
    const literals: [string, string][] = [
      ["wkstn", "host"],
      ["wkstn.lab.internal", "host.lax"],
    ];
    expect(one("wkstn and wkstn.lab.internal", literals)).toBe("host and host.lax");
    expect(one("WKSTN.LAB.INTERNAL", literals)).toBe("HOST.LAX");
  });

  test("maps private addresses and SIDs the same way across captures", () => {
    const out = redact(
      [
        { message: `${a} ${ll} S-1-5-21-11-22-33-1001`, xml: `<Data>${a}</Data>` },
        { message: `${b} then ${a}, public 198.51.100.7`, xml: `<Data>${ll.toUpperCase()}</Data>` },
      ],
      [],
    );
    expect(out[0].message).toBe("192.0.2.1 2001:db8::1 S-1-5-21-0-0-1-1001");
    expect(out[0].xml).toBe("<Data>192.0.2.1</Data>");
    expect(out[1].message).toBe("192.0.2.2 then 192.0.2.1, public 198.51.100.7");
    expect(out[1].xml).toBe("<Data>2001:db8::1</Data>");
  });

  test("--raw keeps private addresses only", () => {
    const guid = "{abcdef01-0001-0002-0003-000000000004}";
    const [c] = redact(
      [{ message: `${a} ${ll} S-1-5-21-111-222-333-1001 ProcessGuid: ${guid} on labbox`, xml: `<Data Name='ProcessGuid'>${guid}</Data>` }],
      [["labbox", "host"]],
      true,
    );
    expect(c.message).toBe(`${a} ${ll} S-1-5-21-0-0-1-1001 ProcessGuid: {00000000-0001-0002-0003-000000000004} on host`);
  });

  test("redacts a SID with no RID, before _Classes, in lower case, and before a period", () => {
    expect(one("S-1-5-21-111-222-333 HKU\\S-1-5-21-111-222-333_Classes\\x s-1-5-21-444-555-666-1001 S-1-5-21-111-222-333-500.")).toBe(
      "S-1-5-21-0-0-1 HKU\\S-1-5-21-0-0-1_Classes\\x s-1-5-21-0-0-2-1001 S-1-5-21-0-0-1-500.",
    );
  });

  test("gives two machine parts two aliases, and one part seen twice one alias", () => {
    expect(one("S-1-5-21-1-2-3-500 S-1-5-21-4-5-6-500 S-1-5-21-1-2-3-501")).toBe(
      "S-1-5-21-0-0-1-500 S-1-5-21-0-0-2-500 S-1-5-21-0-0-1-501",
    );
  });

  test("leaves a SID already in 0-0-N form alone and never reuses its N", () => {
    const out = redact(
      [
        { message: "S-1-5-21-111-222-333-1001", xml: "" },
        { message: "S-1-5-21-0-0-1-1006", xml: "" },
      ],
      [],
    );
    expect(out.map((c) => c.message)).toEqual(["S-1-5-21-0-0-2-1001", "S-1-5-21-0-0-1-1006"]);
  });

  test("reserves an existing 0-0-N of more than one digit", () => {
    const fresh = Array.from({ length: 12 }, (_, i) => `S-1-5-21-${i + 1}-${i + 1}-${i + 1}-500`);
    expect(one(`S-1-5-21-0-0-12-500 ${fresh.join(" ")}`)!.split(" ")).toEqual([
      "S-1-5-21-0-0-12-500",
      ...Array.from({ length: 11 }, (_, i) => `S-1-5-21-0-0-${i + 1}-500`),
      "S-1-5-21-0-0-13-500",
    ]);
  });

  // Leading zeros leave a sub-authority's value alone, so they must not give it a second alias.
  test("keys a SID's machine part by value, so a zero-padded spelling shares its alias", () => {
    expect(one("S-1-5-21-0123-456-789-500 S-1-5-21-123-456-789-501 s-1-5-21-123-0456-000789")).toBe(
      "S-1-5-21-0-0-1-500 S-1-5-21-0-0-1-501 s-1-5-21-0-0-1",
    );
    // A run of zeros is the value 0, a padded 00-0 is still not exempt, and a value past 2^53
    // keeps every digit.
    expect(one("S-1-5-21-00-0-5-500 S-1-5-21-000-00-05-501")).toBe("S-1-5-21-0-0-1-500 S-1-5-21-0-0-1-501");
    expect(one("S-1-5-21-9007199254740993-1-1 S-1-5-21-9007199254740992-1-1")).toBe("S-1-5-21-0-0-1 S-1-5-21-0-0-2");
  });

  test("redacts a private IPv4 before a sentence period and after a letter-dot prefix", () => {
    expect(one(`to ${a}. Then addr.${a}`)).toBe("to 192.0.2.1. Then addr.192.0.2.1");
  });

  test("leaves a longer dotted run or number alone", () => {
    // A private quad that does not start its run is not read, with a port after it or not.
    for (const s of [`1.${a}`, `1${a}`, `1.${a}.80`]) expect(one(s)).toBe(s);
  });

  // README: an IPv6 address.port form is not redacted, and leakcheck catches it. A dot and a digit
  // after the address end the match, so the port is never read as part of the address.
  test("leaves an IPv6 address.port form whole, as the README states", () => {
    for (const s of [`${v6("fe80", "", "1")}.80`, `${v6("fd12", "3456", "", "5")}.443`]) expect(one(s)).toBe(s);
  });

  // leakcheck catches neither of these, so the leftover check must: the private IPv4 address sits
  // in hex, where no plain-IPv4 rule reads it.
  test("refuses a private IPv4 address in a hex mapped or NAT64 form before a port", () => {
    const why = /^record 6: a private IPv4 address in an IPv4-mapped or NAT64 form redaction did not reach$/;
    const ports = [
      `${v6("", "", "ffff", "a01", "203")}.80`,
      `${v6("", "", "FFFF", "0", "C0A8", "9")}.8080`,
      `${v6("64", "ff9b", "", "a01", "203")}.443`,
      `${v6("64", "ff9b", "1", "", "ac10", "1")}.53`,
    ];
    for (const text of ports) {
      expect(() => redact([{ record: 6, message: text, xml: "" }], [])).toThrow(why);
      expect(() => redact([{ record: 6, message: null, xml: `<Data>${text}</Data>` }], [])).toThrow(why);
    }
    // A documentation or public address passes, and so does a dotted tail read as a hex pair.
    for (const s of ["::ffff:c000:201.80", "64:ff9b::c000:201.443", v6("", "", "ffff", "808", "808.53"), "64:ff9b::a01:192.0.2.1"]) {
      expect(one(s)).toBe(s);
    }
    // A dotted private tail after a hex group is still read as dotted, as before.
    expect(() => redact([{ record: 6, message: v6("64", "ff9b", "", "a", ["010", 1, 2, 3].join(".")), xml: "" }], [])).toThrow(why);
  });

  // Neither the address passes nor leakcheck reads a private IPv4 address with a port after it,
  // dotted in a mapped or NAT64 form or on its own, so the leftover check refuses it.
  test("refuses a private IPv4 address before a port, dotted in a mapped or NAT64 form or plain", () => {
    const mapped = /^record 6: a private IPv4 address in an IPv4-mapped or NAT64 form redaction did not reach$/;
    const plain = /^record 6: a private IPv4 address with a port after it, which no pass redacts$/;
    const refused = (text: string, why: RegExp) => {
      expect(() => redact([{ record: 6, message: text, xml: "" }], [])).toThrow(why);
      expect(() => redact([{ record: 6, message: null, xml: `<Data>${text}</Data>` }], [])).toThrow(why);
    };
    for (const text of [`::ffff:${a}.80`, `::FFFF:0:${b}.8080`, `64:ff9b::${a}.443`, `64:ff9b:1::${v4(172, 16, 0, 1)}.53`]) refused(text, mapped);
    // A five-part run such as 10.1.2.3.4 reads as an address and port too, so it refuses.
    const plains = [`${a}.80`, `${a}.4`, `${b}.443`, `to ${v4(100, 64, 0, 1)}.53.`, `addr.${a}.80`, `${a}.80.5`, `::${a}.80`, `${v6("fe80", "", "")}${a}.80`];
    for (const text of plains) refused(text, plain);
    // Documentation addresses pass, and so does a global IPv6 address whose dotted tail looks private.
    for (const s of ["192.0.2.1.80", "::ffff:192.0.2.1.80", "64:ff9b::192.0.2.1.443", `2001:db8::${a}.80`]) expect(one(s)).toBe(s);
  });

  test("maps every private range, and leaves the public ones beside them", () => {
    const priv = [
      [v4(10, 9, 8, 7), "192.0.2.1"],
      [v4(172, 16, 0, 1), "192.0.2.1"],
      [v4(172, 31, 255, 1), "192.0.2.1"],
      [v4(192, 168, 5, 5), "192.0.2.1"],
      [v4(100, 64, 0, 1), "192.0.2.1"],
      [v4(100, 127, 255, 1), "192.0.2.1"],
      [v4(169, 254, 3, 3), "192.0.2.1"],
      [v6("fc00", "", "1"), "2001:db8::1"],
      [v6("fd00", "", "2"), "2001:db8::1"],
      [v6("fe80", "", "3"), "2001:db8::1"],
      [v6("febf", "", "4"), "2001:db8::1"],
    ];
    for (const [text, want] of priv) expect(one(text)).toBe(want);
    for (const s of ["172.15.0.1", "172.32.0.1", "100.63.255.1", "100.128.0.1", "169.253.0.1", "11.0.0.1", "fec0::1", "fbff::1"]) {
      expect(one(s)).toBe(s);
    }
  });

  test("rewrites the in-addr.arpa name of a private address to its alias's name", () => {
    const ptr = `${v4(3, 2, 1, 10)}.in-addr.arpa`;
    expect(one(`${ptr} is ${a}; 7.100.51.198.in-addr.arpa stays`)).toBe(
      "1.2.0.192.in-addr.arpa is 192.0.2.1; 7.100.51.198.in-addr.arpa stays",
    );
  });

  test("leaves an alias's own in-addr.arpa name alone", () => {
    const ten = Array.from({ length: 10 }, (_, i) => v4(10, 0, 0, i + 1));
    const ptr = `${v4(10, 0, 0, 10).split(".").reverse().join(".")}.in-addr.arpa`;
    // Built from parts: the reversed alias reads as a private address to leakcheck.
    expect(one(`${ten.join(" ")} ${ptr}`)).toEndWith(`192.0.2.10 ${v4(10, 2, 0, 192)}.in-addr.arpa`);
  });

  // An in-addr.arpa name is rewritten only when its octets read back as an address. With one
  // above 255 it names none and stays whole, though a plain quad in a private range is replaced.
  test("leaves an in-addr.arpa name with an octet above 255 whole", () => {
    for (const s of [`${v4(999, 1, 0, 10)}.in-addr.arpa`, `${v4(3, 2, 256, 10)}.in-addr.arpa`]) expect(one(s)).toBe(s);
    expect(one(`${v4(3, 2, 1, 10)}.in-addr.arpa`)).toBe("1.2.0.192.in-addr.arpa");
    expect(one(v4(10, 1, 2, 999))).toBe("192.0.2.1");
  });

  test("maps IPv4-mapped IPv6, in hex or dotted, to the plain address's alias", () => {
    const hex = v6("", "", "ffff", "a01", "203");
    const upper = v6("", "", "FFFF", "C0A8", "9");
    expect(one(`${a} ${hex} ::ffff:${a} ${upper}`)).toBe("192.0.2.1 ::ffff:c000:201 ::ffff:192.0.2.1 ::ffff:c000:202");
  });

  // The mapped pass caps each open stretch of a run, and the longest spellings must still fit.
  test("maps the longest spellings of a mapped and a NAT64 address, every zero written out", () => {
    expect(one(v6("0000", "0000", "0000", "0000", "0000", "ffff", "0a01", "0203"))).toBe("::ffff:c000:201");
    expect(one(v6("0064", "ff9b", "0000", "0000", "0000", "0000", "0a01", "0203"))).toBe("64:ff9b::c000:201");
  });

  test("redacts private IPv6 ending in ::, with a prefix length, and one alias with or without a zone", () => {
    const ula = v6("fd12", "3456", "789a", "", "");
    const bare = v6("fe80", "", "1");
    const zoned = v6("FE80", "", "1%eth0");
    expect(one(`${ula} ${ula}/48 ${ll} ${bare} ${zoned}.`)).toBe("2001:db8::1 2001:db8::1/48 2001:db8::2 2001:db8::2 2001:db8::2.");
  });

  test("leaves a bare fd00: word alone", () => {
    expect(one("fd00: then fc12:")).toBe("fd00: then fc12:");
  });

  test("rewrites the ip6.arpa name of a private IPv6 address to its alias's name", () => {
    const name = arpa6(`fe80${"0".repeat(27)}1`);
    expect(one(`${name} ${v6("fe80", "", "1")}`)).toBe(`${arpa6(`20010db8${"0".repeat(23)}1`)} 2001:db8::1`);
  });

  test("skips an alias that is already in the batch", () => {
    const out = redact(
      [
        { message: `${a} ${ll}`, xml: "" },
        { message: "192.0.2.1 and 2001:db8::1", xml: "" },
      ],
      [],
    );
    expect(out.map((c) => c.message)).toEqual(["192.0.2.2 2001:db8::2", "192.0.2.1 and 2001:db8::1"]);
  });

  test("skips an alias the batch holds only as an ip6.arpa name, a mapped one included", () => {
    const name = arpa6(`20010db8${"0".repeat(23)}1`);
    expect(one(`${name} ${ll}`)).toBe(`${name} 2001:db8::2`);
    const mapped = arpa6(`${"0".repeat(20)}ffffc0000201`);
    expect(one(`${mapped} ${a}`)).toBe(`${mapped} 192.0.2.2`);
  });

  test("refuses rather than write past 192.0.2.254", () => {
    const many = Array.from({ length: 255 }, (_, i) => v4(10, 0, 0, i));
    expect(one(many.slice(0, 254).join(" "))).toEndWith("192.0.2.254");
    expect(() => one(many.join(" "))).toThrow(CaptureError);
  });

  test("refuses a private IPv6 address run together with a colon or hex digit before it", () => {
    const fe = v6("fe80", "", "1");
    const glued = [`addr:${fe}`, `0${fe}`, `a${v6("fd12", "", "5")}`, `Dec:${fe}`, `:${fe}%12`, `x::${fe}`];
    for (const text of glued) {
      expect(() => redact([{ record: 5, message: text, xml: "" }], [])).toThrow(/^record 5: a private IPv6 address run together/);
      expect(() => redact([{ message: null, xml: `<Data>${text}</Data>` }], [])).toThrow(/^capture 0: a private IPv6 address/);
      expect(() => redact([{ message: text, xml: "" }], [])).not.toThrow(/fe80|fd12/);
    }
  });

  test("reads an IPv6 address with a dotted tail by value: one alias per address, a global one kept", () => {
    const quad = v4(10, 1, 2, 3);
    const hexForm = v6("fe80", "", "a01", "203");
    expect(one(`${hexForm} fe80::${quad}`)).toBe("2001:db8::1 2001:db8::1");
    expect(one(`FE80::${quad}%eth0 ${hexForm}`)).toBe("2001:db8::1 2001:db8::1");
    const global = `2001:db8::${quad}`;
    expect(one(`${global} ${quad}`)).toBe(`${global} 192.0.2.1`);
  });

  test("takes a zone with any RFC 6874 character, tilde and percent-encoding included", () => {
    expect(one(`${v6("fe80", "", "1")}%eth0~1 then`)).toBe("2001:db8::1 then");
    expect(one(`${v6("fe80", "", "1")}%eth%2D0.`)).toBe("2001:db8::1.");
    expect(one(`::ffff:${v4(10, 1, 2, 3)}%a~b`)).toBe("::ffff:192.0.2.1");
    expect(one(`${v6("", "", "ffff", "a01", "203")}%x~1`)).toBe("::ffff:c000:201");
  });

  test("drops a zone index from every redacted IPv6 form, dotted tails included", () => {
    const a4 = v4(10, 1, 2, 3);
    expect(one(`::ffff:${a4}%12`)).toBe("::ffff:192.0.2.1");
    expect(one(`::FFFF:0:${a4}%eth0.5 then`)).toBe("::FFFF:0:192.0.2.1 then");
    expect(one(`::${a4}%3.`)).toBe("::192.0.2.1.");
    // A bare IPv4 address takes no zone, so text after its % is not one and stays.
    expect(one(`${a4}%12`)).toBe("192.0.2.1%12");
  });

  test("refuses an alias a later pass would rewrite: an address, SID or GUID shape", () => {
    const shapes = [
      v4(10, 1, 2, 3),
      `${v4(3, 2, 1, 10)}.in-addr.arpa`,
      arpa6(`fe80${"0".repeat(27)}1`),
      "S-1-5-21-1-2-3",
      "s-1-5-21-0-0-1",
      "abcdef01-host",
      "ABCDEF01-0001-0002-0003-000000000004",
    ];
    for (const to of shapes) {
      expect(() => redact([{ message: "alice", xml: "" }], [["labbox", "labhost"], ["alice", to]])).toThrow(
        /^--redact #2 alias looks like an address, SID or GUID$/,
      );
    }
    for (const to of ["labhost", "lab.deadbeefhost", "lab.host-x"]) expect(one("alice", [["alice", to]])).toBe(to);
  });

  test("refuses a private IPv4 address left in an IPv4-mapped form", () => {
    const leaks = [
      `e${v6("", "", "ffff", "a01", "203")}`,
      `1f${v6("", "", "FFFF", "C0A8", "9")}`,
      v6("", "", "ffff", "0", "a01", "203"),
      `x${v6("", "", "ffff", "0000", "ac10", "1")}`,
      `::ffff:${["010", 1, 2, 3].join(".")}`,
    ];
    for (const text of leaks) {
      expect(() => redact([{ record: 6, message: text, xml: "" }], [])).toThrow(
        /^record 6: a private IPv4 address in an IPv4-mapped or NAT64 form redaction did not reach$/,
      );
      expect(() => redact([{ message: null, xml: `<Data>${text}</Data>` }], [])).toThrow(/^capture 0: a private IPv4 address/);
    }
  });

  test("redacts a private IPv4 address in a 64:ff9b:: (NAT64) form, hex or dotted, to its alias", () => {
    const a4 = v4(10, 1, 2, 3);
    const hex = v6("64", "ff9b", "", "a01", "203");
    const full = v6("64", "FF9B", "0", "0", "0", "0", "C0A8", "9");
    expect(one(`${a4} ${hex} 64:ff9b::${a4} ${full}`)).toBe("192.0.2.1 64:ff9b::c000:201 64:ff9b::192.0.2.1 64:ff9b::c000:202");
    expect(one(arpa6(`0064ff9b${"0".repeat(16)}0a010203`))).toBe(arpa6(`0064ff9b${"0".repeat(16)}c0000201`));
    // An alias already in the batch in NAT64 form is not handed out again.
    expect(one(`64:ff9b::c000:201 ${a4}`)).toBe("64:ff9b::c000:201 192.0.2.2");
  });

  test("refuses a glued NAT64 form holding a private IPv4 address, and passes a public one", () => {
    // Any form under 64:ff9b: is checked, the local-use 64:ff9b:1::/48 included, though only the
    // well-known 64:ff9b::/96 is redacted.
    const local = [v6("64", "ff9b", "1", "", "a01", "203"), v6("64", "ff9b", "", "1", "a01", "203")];
    for (const text of [`e${v6("64", "ff9b", "", "a01", "203")}`, `x:${v6("64", "ff9b", "", "a01", "203")}`, ...local]) {
      expect(() => redact([{ record: 6, message: text, xml: "" }], [])).toThrow(
        /^record 6: a private IPv4 address in an IPv4-mapped or NAT64 form redaction did not reach$/,
      );
    }
    for (const s of [v6("64", "ff9b", "", "808", "808"), `e${v6("64", "ff9b", "", "808", "808")}`]) expect(one(s)).toBe(s);
  });

  // 32 KB of either once took 5 to 7 seconds, and 128 KB a minute and a half or more. Past about
  // 2.5 seconds JavaScriptCore also gave up on the NAT64 check without a match, so a private
  // address after the long run passed.
  test("reads 128 KB of ff9b: or 64:ff9b: groups in linear time, and still refuses a leftover after or in it", () => {
    for (const unit of ["ff9b:", "64:ff9b:"]) {
      const run = unit.repeat(Math.ceil(131072 / unit.length));
      const t0 = performance.now();
      expect(one(run)).toBe(run);
      expect(performance.now() - t0).toBeLessThan(2000);
    }
    const long = "64:ff9b:".repeat(16384);
    for (const message of [`${long}:a01:203`, `${long} then ${v6("64", "ff9b", "1", "", "a01", "203")}`]) {
      expect(() => redact([{ record: 6, message, xml: "" }], [])).toThrow(
        /^record 6: a private IPv4 address in an IPv4-mapped or NAT64 form redaction did not reach$/,
      );
    }
  });

  test("still redacts a plain mapped address, and passes public mapped and global ones", () => {
    expect(one(v6("", "", "ffff", "a01", "203"))).toBe("::ffff:c000:201");
    expect(one(`e::ffff:${v4(10, 1, 2, 3)}`)).toBe("e::ffff:192.0.2.1");
    for (const s of [v6("", "", "ffff", "808", "808"), `e${v6("", "", "ffff", "808", "808")}`, v6("2001", "db8", "", "ffff", "a01", "203")]) {
      expect(one(s)).toBe(s);
    }
  });

  test("passes a global address with a private-looking group inside, and a glued one under --raw", () => {
    const global = v6("2001", "db8", "fd12", "", "1");
    expect(one(`${global} and ${v6("2001", "db8", "", "fe80", "1")}`)).toBe(`${global} and ${v6("2001", "db8", "", "fe80", "1")}`);
    expect(one(`addr:${v6("fe80", "", "1")}`, [], true)).toBe(`addr:${v6("fe80", "", "1")}`);
  });

  // A NUL would reach a fixture that decodes in full here and is cut short live (see winevt.ts).
  test("refuses a record holding a NUL in its message or XML, naming the record", () => {
    const run = "HKU\\S-1-5-21-0-0-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\";
    const xml = (target: string) => event("", `<Data Name='TargetObject'>${target}</Data><Data Name='Details'>C:\\x.exe</Data>`);
    const why = (where: string) => new RegExp(`^${where}: a NUL character, where the agent's C string cuts the live event short$`);
    const clean = { record: 9, message: `TargetObject: ${run}hidden`, xml: xml(`${run}hidden`) };
    expect(() => redact([clean, { record: 10, message: null, xml: xml(`${run}\u0000hidden`) }], [])).toThrow(why("record 10"));
    expect(() => redact([{ message: `TargetObject: ${run}\u0000hidden`, xml: clean.xml }], [], true)).toThrow(why("capture 0"));
    // Ordinary captures come through unchanged.
    expect(redact([clean], [])).toEqual([clean]);
  });
});

describe("Sysmon GUID first fields", () => {
  const xml =
    "<Provider Name='Microsoft-Windows-Sysmon' Guid='{11111111-2222-3333-4444-555555555555}'/>" +
    "<Data Name='ProcessGuid'>{abcdef01-0001-0002-0003-000000000004}</Data>" +
    "<Data Name='SourceProcessGUID'>{ABCDEF02-0001-0002-0003-000000000004}</Data>";
  const message = "ParentProcessGuid: {abcdef03-0001-0002-0003-000000000004}\r\nLogonGuid: {00000000-0000-0000-0000-000000000000}";
  const json = '{"providerGuid":"{11111111-2222-3333-4444-555555555555}","targetProcessGuid":"{abcdef04-0001-0002-0003-000000000004}"}';

  test("learns only from an XML Data field with a Sysmon GUID name, in any case", () => {
    expect(sysmonGuidPrefixes(xml)).toEqual(["abcdef01", "abcdef02"]);
    for (const name of ["ParentProcessGuid", "processguid", "TargetProcessGUID", "SourceProcessGuid", "LogonGuid"]) {
      expect(sysmonGuidPrefixes(`<Data Name='${name}'>{abcdef05-0001-0002-0003-000000000004}</Data>`)).toEqual(["abcdef05"]);
    }
    expect(sysmonGuidPrefixes(message)).toEqual([]);
    expect(sysmonGuidPrefixes(json)).toEqual([]);
    for (const name of ["NotProcessGuid", "ProcessGuidX", "TaskGuid"]) {
      expect(sysmonGuidPrefixes(`<Data Name='${name}'>{abcdef06-0001-0002-0003-000000000004}</Data>`)).toEqual([]);
    }
  });

  test("a GUID label in message text teaches nothing, so an unrelated GUID stays", () => {
    const unrelated = "<Correlation ActivityID='{abcdef09-1111-2222-3333-444444444444}'/>";
    const out = redact(
      [
        { message: "NotProcessGuid {abcdef09-0001-0002-0003-000000000004}", xml: "" },
        { message: null, xml: unrelated },
      ],
      [],
    );
    expect(out[0].message).toBe("NotProcessGuid {abcdef09-0001-0002-0003-000000000004}");
    expect(out[1].xml).toBe(unrelated);
  });

  test("the plant capture learns its prefix from its XML fields and comes back as committed", () => {
    const [cap] = load("plant-capture.json");
    const raw = { ...cap, message: cap.message.replaceAll("{00000000-", "{1a2b3c4d-"), xml: cap.xml.replaceAll("{00000000-", "{1A2B3C4D-") };
    expect(sysmonGuidPrefixes(raw.xml)).toEqual(["1a2b3c4d"]);
    expect(redact([raw], [])).toEqual([cap]);
  });

  test("learns a GUID with ASCII whitespace around it inside the field, the GUID itself exact", () => {
    const g = "{abcdef07-0001-0002-0003-000000000004}";
    for (const [before, after] of [[" ", ""], ["\r\n  ", "\r\n"], ["\t\v\f", " "], ["", "\n"]]) {
      expect(sysmonGuidPrefixes(`<Data Name='ProcessGuid'>${before}${g}${after}</Data>`)).toEqual(["abcdef07"]);
    }
    const xml = event("", `<Data Name='LogonGuid'>\n ${g}</Data><Data Name='Note'>{ABCDEF07-9}</Data>`);
    expect(redact([{ message: null, xml }], [])[0].xml).toBe(xml.replace("abcdef07", "00000000").replace("ABCDEF07", "00000000"));
    // Whitespace inside the braces, or other text before the GUID, teaches nothing.
    for (const text of ["{ abcdef07-0001-0002-0003-000000000004}", "{abcdef07 -0001-0002-0003-000000000004}", `x ${g}`]) {
      expect(sysmonGuidPrefixes(`<Data Name='ProcessGuid'>${text}</Data>`)).toEqual([]);
    }
  });

  test("replaces every prefix followed by a dash, in any case", () => {
    expect(replaceGuidPrefixes("{ABCDEF01-x} {abcdef01-y} {abcdef01z} 9abcdef01-", ["abcdef01"])).toBe(
      "{00000000-x} {00000000-y} {abcdef01z} 9abcdef01-",
    );
  });

  test("redact zeroes a prefix seen anywhere in the batch, in every capture", () => {
    const out = redact(
      [
        { message: null, xml },
        { message: "Correlation {ABCDEF01-9999-9999-9999-999999999999}", xml: "" },
      ],
      [],
    );
    expect(out[0].xml).toContain("Guid='{11111111-2222-3333-4444-555555555555}'");
    expect(out[0].xml).toContain("<Data Name='ProcessGuid'>{00000000-0001-");
    expect(out[0].xml).toContain("<Data Name='SourceProcessGUID'>{00000000-0001-");
    expect(out[1].message).toBe("Correlation {00000000-9999-9999-9999-999999999999}");
  });
});

describe("encoded blobs", () => {
  const a = v4(10, 1, 2, 3);
  const cmd = (inner: string): Capture => ({ record: 77, message: `powershell -EncodedCommand ${b64(inner, "utf16le")}`, xml: "" });

  test("refuses a UTF-16LE EncodedCommand blob that holds a private address", () => {
    expect(() => redact([cmd(`ping ${a}`)], [])).toThrow(/^record 77: an encoded blob/);
  });

  test("passes the same blob holding only a documentation address", () => {
    const c = cmd("ping 192.0.2.10");
    expect(redact([c], [])[0].message).toBe(c.message);
  });

  test("refuses a redacted literal inside a UTF-8 blob, naming the index when there is no record", () => {
    const caps = [
      { message: null, xml: "" },
      { message: b64("user labbox here", "utf8"), xml: "" },
    ];
    expect(() => redact(caps, [["labbox", "host"]])).toThrow(/^capture 1: an encoded blob/);
  });

  test("under --raw a private address in a blob passes but a SID does not", () => {
    expect(redact([cmd(`ping ${a}`)], [], true)[0].message).toStartWith("powershell -EncodedCommand ");
    expect(() => redact([cmd("whoami S-1-5-21-111-222-333-1001")], [], true)).toThrow(CaptureError);
  });

  test("lets hex hashes and long words through", () => {
    const text = `SHA256=${"0123456789ABCDEF".repeat(4)} DestinationHostname WindowsPowerShell`;
    expect(redact([{ message: text, xml: text }], [["labbox", "host"]])[0].message).toBe(text);
  });

  test("keeps the blob and its text out of the error", () => {
    expect(() => redact([cmd(`ping ${a}`)], [])).not.toThrow(new RegExp(`${a.replaceAll(".", "\\.")}|${b64(`ping ${a}`, "utf16le").slice(0, 16)}`));
  });

  test("refuses a blob inside the XML, naming the record", () => {
    const xml = event("", `<Data Name='CommandLine'>powershell -enc ${b64(`ping ${a}`, "utf16le")}</Data>`);
    expect(() => redact([{ record: 78, message: null, xml }], [])).toThrow(/^record 78: an encoded blob/);
  });

  test("refuses a blob holding a private IPv6 address run together with a colon", () => {
    expect(() => redact([cmd(`ping addr:${v6("fe80", "", "1")}`)], [])).toThrow(/^record 77: an encoded blob/);
  });

  test("refuses a blob holding a private IPv4 address in a glued mapped form", () => {
    expect(() => redact([cmd(`ping e${v6("", "", "ffff", "a01", "203")}`)], [])).toThrow(/^record 77: an encoded blob/);
  });

  test("refuses a blob holding a private IPv4 address in a NAT64 form", () => {
    expect(() => redact([cmd(`ping ${v6("64", "ff9b", "", "a01", "203")}`)], [])).toThrow(/^record 77: an encoded blob/);
  });

  // .NET's Convert.ToBase64String(..., InsertLineBreaks) form: 76 columns, CRLF.
  const wrap = (blob: string, eol = "\r\n") => blob.match(/.{1,76}/g)!.join(eol);
  const job = (host: string, addr: string) =>
    `Write-Output 'stage one of the job runs here first'; Invoke-Thing -ComputerName ${host} -Address ${addr} -Verbose`;
  const refused = (message: string, literals: [string, string][]) => () => redact([{ record: 79, message, xml: "" }], literals);

  test("reads a blob wrapped at 76 columns as one run, in UTF-16LE and UTF-8, CRLF or LF", () => {
    const cases: [string, [string, string][]][] = [
      [job("labbox", a), [["labbox", "host"]]],
      [job("labbox", "192.0.2.10"), [["labbox", "host"]]],
      [job("web01", a), []],
    ];
    for (const enc of ["utf16le", "utf8"] as const) {
      for (const eol of ["\r\n", "\n"]) {
        for (const [text, literals] of cases) expect(refused(wrap(b64(text, enc), eol), literals)).toThrow(/^record 79: an encoded blob/);
      }
    }
  });

  test("refuses a source split across a wrap boundary in the decoded text", () => {
    const text = "Write-Output 'stage one of the job runs here first'; labbox -Verbose";
    for (const enc of ["utf16le", "utf8"] as const) {
      const lines = wrap(b64(text, enc)).split("\r\n");
      // No line alone holds the source, so only the joined run can find it.
      for (const line of lines) expect(Buffer.from(line, "base64").toString(enc)).not.toContain("labbox");
      expect(refused(lines.join("\r\n"), [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
    }
  });

  test("finds a wrapped blob when words before it join the run at any length", () => {
    const text = "Write-Output 'stage one of the job runs here first'; labbox -Verbose";
    for (const enc of ["utf16le", "utf8"] as const) {
      const blob = wrap(b64(text, enc));
      const lead = [..."12345678"].map((_, n) => `${"x".repeat(n + 1)} `);
      for (const before of [...lead, "powershell -EncodedCommand ", "run this\r\n"]) {
        expect(refused(before + blob, [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
      }
    }
  });

  test("counts short pieces once they join to 16 characters", () => {
    const blob = b64("at labbox ok", "utf8");
    expect(blob).toHaveLength(16);
    expect(refused(blob.match(/.{4}/g)!.join(" "), [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
  });

  test("passes a wrapped blob of harmless text, and words that join into noise", () => {
    const harmless = job("web01", "192.0.2.10");
    const texts = [
      ...(["utf16le", "utf8"] as const).flatMap((enc) => ["\r\n", "\n"].map((eol) => `powershell -EncodedCommand ${wrap(b64(harmless, enc), eol)}`)),
      `${"0123456789ABCDEF".repeat(2)} ${"FEDCBA9876543210".repeat(2)}`,
      "An account was successfully logged on to this computer by DestinationHostname WindowsPowerShell",
    ];
    for (const text of texts) expect(redact([{ record: 79, message: text, xml: text }], [["labbox", "host"]])[0].message).toBe(text);
  });

  // An XML writer may spell a wrapped blob's breaks as character references, in any hex case and
  // with leading zeros. Whether Windows does is unverified, so each is read as whitespace.
  const REFS = ["&#xD;&#xA;", "&#13;&#10;", "&#xA;", "&#10;", "&#xd;&#xa;", "&#x0D;&#x000A;", "&#013;&#0010;", "&#xD;\n", "&#x9;", "&#9;", "&#x20;", "&#32;"];
  const inXml = (body: string): Capture => ({ record: 79, message: null, xml: event("", `<Data Name='CommandLine'>${body}</Data>`) });

  test("reads a blob wrapped at character-reference breaks as one run, in the message and the XML", () => {
    const text = "Write-Output 'stage one of the job runs here first'; labbox -Verbose";
    for (const enc of ["utf16le", "utf8"] as const) {
      for (const ref of REFS) {
        const body = wrap(b64(text, enc), ref);
        for (const line of body.split(ref)) expect(Buffer.from(line, "base64").toString(enc)).not.toContain("labbox");
        expect(refused(body, [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
        expect(() => redact([inXml(body)], [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
      }
    }
  });

  test("finds a private address that straddles a character-reference break after the first line", () => {
    for (const [enc, pad] of [["utf8", 102], ["utf16le", 45]] as const) {
      const text = `${"#".repeat(pad)}ping ${a} -n 1`;
      const from = Buffer.from(text.slice(0, text.indexOf(a)), enc).length;
      const to = from + Buffer.from(a, enc).length - 1;
      // It starts in the second 57-byte line and ends in the third, so no line holds it.
      expect([Math.floor(from / 57), Math.floor(to / 57)]).toEqual([1, 2]);
      for (const ref of REFS) {
        const body = wrap(b64(text, enc), ref);
        expect(refused(body, [])).toThrow(/^record 79: an encoded blob/);
        expect(() => redact([inXml(body)], [])).toThrow(/^record 79: an encoded blob/);
      }
    }
  });

  test("passes harmless text wrapped at character-reference breaks", () => {
    for (const enc of ["utf16le", "utf8"] as const) {
      for (const ref of REFS) {
        const body = `powershell -EncodedCommand ${wrap(b64(job("web01", "192.0.2.10"), enc), ref)}`;
        expect(redact([{ record: 79, message: body, xml: "" }], [["labbox", "host"]])[0].message).toBe(body);
        expect(redact([inXml(body)], [["labbox", "host"]])[0].xml).toBe(inXml(body).xml);
      }
    }
  });

  // Words after a reference break join the run too and decode to bytes glued to the blob's last
  // token. A read of the blob's own pieces must still find a source that ends it.
  test("still finds a source ending a blob when a reference break and more words follow it", () => {
    // 117 bytes, so the run needs no padding and goes on; labbox spans bytes 111-116, across 114.
    const text = `${"#".repeat(111)}labbox`;
    expect(Buffer.byteLength(text)).toBe(117);
    const body = `${wrap(b64(text, "utf8"))}&#xD;&#xA;Next line here`;
    expect(refused(body, [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
    expect(() => redact([inXml(body)], [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
  });

  // Words joined to a wrapped blob by raw whitespace decode to bytes glued onto its first or last
  // token, which can hide a source that ends the blob across its last wrap.
  describe("a source ending a wrapped blob that words join", () => {
    // The plaintext's byte count is a multiple of 3, so the blob has no padding and the run goes
    // on into the words after it. The source fills the end of the given byte count.
    const ending = (src: string, enc: "utf8" | "utf16le", bytes: number) => {
      const text = `${"#".repeat(bytes / (enc === "utf8" ? 1 : 2) - src.length)}${src}`;
      const from = Buffer.byteLength(text.slice(0, -src.length), enc);
      expect([bytes % 3, Math.floor(from / 57) < Math.floor((bytes - 1) / 57)]).toEqual([0, true]);
      return { blob: wrap(b64(text, enc)), pieces: Math.floor((bytes - 1) / 57) - Math.floor(from / 57) + 1 };
    };
    // A second UTF-16LE blob decodes to ASCII code units, the glue UTF-16 text needs to hide a token.
    const next = b64("Write-Output done", "utf16le");
    const long = "workstation-0001.subdomain.department.corp.example.internal";
    const shapes: [string, string, "utf8" | "utf16le", number, (b: string) => string][] = [
      ["UTF-8, CRLF and words after", "labbox", "utf8", 117, (b) => `${b}\r\nNext line here`],
      ["UTF-8, a space and a word after", "labbox", "utf8", 117, (b) => `${b} Next`],
      ["UTF-8, words before and after", "labbox", "utf8", 117, (b) => `run this\r\n${b}\r\nNext line here`],
      ["UTF-16LE, CRLF and words after", "labbox", "utf16le", 120, (b) => `${b}\r\nNext line here`],
      ["UTF-16LE, a UTF-16LE blob after", "labbox", "utf16le", 120, (b) => `${b}\r\n${next}`],
      ["UTF-16LE, a word before and a blob after", "labbox", "utf16le", 120, (b) => `run this\r\n${b}\r\n${next}`],
      ["UTF-8, a long source", long, "utf8", 174, (b) => `${b}\r\nNext line here`],
      ["UTF-16LE, a long source over four pieces", long, "utf16le", 174, (b) => `${b}\r\n${next}`],
    ];

    for (const [name, src, enc, bytes, shape] of shapes) {
      test(`${name}: refused in the message and the XML`, () => {
        const { blob } = ending(src, enc, bytes);
        expect(refused(shape(blob), [[src, "host"]])).toThrow(/^record 79: an encoded blob/);
        expect(() => redact([inXml(shape(blob))], [[src, "host"]])).toThrow(/^record 79: an encoded blob/);
      });
    }

    test("the long UTF-16LE source spans four pieces, past a run of three", () => {
      expect(ending(long, "utf16le", 174).pieces).toBe(4);
    });

    // Two lines make no run of equal ones, so only the pair of pieces reads the blob alone.
    test("a blob of one full line and a short one", () => {
      const { blob } = ending("labbox", "utf8", 60);
      expect(blob.split("\r\n").map((l) => l.length)).toEqual([76, 4]);
      expect(refused(`${blob}\r\nNext line here`, [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
    });

    // Lines of three lengths make no run either, so only three adjacent pieces read it alone.
    test("a blob wrapped at uneven widths, its source across three pieces", () => {
      const flat = b64(`${"#".repeat(28)}${long}`, "utf16le");
      const pieces = [flat.slice(0, 100), flat.slice(100, 180), flat.slice(180)];
      // No padding, so the run goes on into the blob after it. The source starts at byte 56,
      // before byte 75 where the second piece starts, so the last two pieces lack its head.
      expect([flat.endsWith("="), Buffer.byteLength("#".repeat(28), "utf16le")]).toEqual([false, 56]);
      expect(refused(`${pieces.join("\r\n")}\r\n${next}`, [[long, "host"]])).toThrow(/^record 79: an encoded blob/);
    });

    // Short pieces of uneven length make no window and no run, so only the whole join reads them.
    test("a blob split anywhere into short pieces", () => {
      const blob = b64("at labbox ok", "utf8");
      const split = `${blob.slice(0, 5)} ${blob.slice(5, 8)} ${blob.slice(8)}`;
      expect(split.split(" ").map((p) => p.length)).toEqual([5, 3, 8]);
      expect(refused(split, [["labbox", "host"]])).toThrow(/^record 79: an encoded blob/);
    });

    // With no short last line the piece after the run is a word, so the run is read without it.
    test("a blob of full lines only, its long source across four of them", () => {
      const src = `${long}.${"x".repeat(100 - long.length - 1)}`;
      const { blob, pieces } = ending(src, "utf16le", 342);
      expect([blob.split("\r\n").every((l) => l.length === 76), pieces]).toEqual([true, 4]);
      expect(refused(`${blob}\r\n${next}`, [[src, "host"]])).toThrow(/^record 79: an encoded blob/);
    });

    test("the same shapes pass when the source is not one redaction knows", () => {
      for (const [, src, enc, bytes, shape] of shapes) {
        const message = shape(ending(src, enc, bytes).blob);
        expect(redact([{ record: 79, message, xml: "" }], [["alice", "host"]])[0].message).toBe(message);
      }
    });
  });

  // A word joined before or after a blob hides a source at that end from every longer read, so
  // the blob's own head and tail are read alone however short its pieces are.
  describe("a source at either end of a blob split into short pieces", () => {
    const wkstn = (message: string) => refused(message, [["wkstn", "labhost"]]);
    const wrapAt = (blob: string, w: number) => blob.match(new RegExp(`.{1,${w}}`, "g"))!.join("\r\n");
    const head = b64("wkstn NoProfile go copy path", "utf8");
    // 24 bytes, so the blob has no padding and a word after it joins its run.
    const tail = b64("go copy path xyz \\\\wkstn", "utf8");
    // Each passed before: a random search over piece widths 4 to 43 found them.
    const found = [
      "cmd -enc dXNlIHB\r\nhdGggZ28geCBhb\r\nHBoYSBcXHdrc3Ru NoProfile",
      "cmd -enc eCB4IHBhdGggaXRlbSBzaGFyZSBnbyBwY\r\nXRoIGNv\r\ncHkgeCBcXH\r\ndrc3Ru NoProfile",
      "cmd -enc alpha d2tzdG4\r\ngQnJhdm8gdXN\r\nlIGdvIGNvc\r\nHkgcGF0aCBzaGFyZSBuZXQgc2hhcmUg\r\neA==",
      "cmd -enc x d2tzd\r\nG4gaXRlbSBza\r\nGFyZSBw\r\nYXRoIG5ldCBjb3B5IGdvIHggTm9\r\nQcm9maWxlIH\r\nNoYXJl go",
    ];
    // Lines of 4 or 5 make windows of three under 16 characters, and a word as long as a line
    // joins the run of equal lines.
    const narrow = [`cmd -enc path ${wrapAt(head, 4)}`, `cmd -enc alpha ${wrapAt(head, 5)}`, `cmd -enc ${wrapAt(tail, 4)} copy`];

    test("three pieces each under 16 characters, the source last and a word after", () => {
      const [repro] = found;
      expect(repro.split(/\s+/).every((p) => p.length < 16)).toBe(true);
      expect(Buffer.from(repro.slice(9, -10).replaceAll("\r\n", ""), "base64").toString()).toBe("use path go x alpha \\\\wkstn");
      expect(wkstn(repro)).toThrow(/^record 79: an encoded blob/);
      expect(() => redact([inXml(repro)], [["wkstn", "labhost"]])).toThrow(/^record 79: an encoded blob/);
    });

    test("the source first, a word before it, every piece under 16 characters", () => {
      const message = `cmd -enc alpha ${head.slice(0, 7)}\r\n${head.slice(7, 19)}\r\n${head.slice(19, 29)}\r\n${head.slice(29)}`;
      expect(message.split(/\s+/).every((p) => p.length < 16)).toBe(true);
      expect(wkstn(message)).toThrow(/^record 79: an encoded blob/);
      expect(() => redact([inXml(message)], [["wkstn", "labhost"]])).toThrow(/^record 79: an encoded blob/);
    });

    test("the cases the random search found", () => {
      for (const message of found.slice(1)) {
        expect(wkstn(message)).toThrow(/^record 79: an encoded blob/);
        expect(() => redact([inXml(message)], [["wkstn", "labhost"]])).toThrow(/^record 79: an encoded blob/);
      }
    });

    test("a blob wrapped at 4 or 5 columns, a word as long as a line before or after it", () => {
      for (const message of narrow) {
        expect(wkstn(message)).toThrow(/^record 79: an encoded blob/);
        expect(() => redact([inXml(message)], [["wkstn", "labhost"]])).toThrow(/^record 79: an encoded blob/);
      }
    });

    test("the same shapes pass when the source is not one redaction knows", () => {
      for (const message of [...found, ...narrow]) {
        expect(redact([{ record: 79, message, xml: "" }], [["alice", "labhost"]])[0].message).toBe(message);
        expect(redact([inXml(message)], [["alice", "labhost"]])[0].xml).toBe(inXml(message).xml);
      }
    });
  });

  // The read before redaction skips a run under 16 characters. An alias longer than its source
  // can carry one past that, and only the read after redaction then sees what it decodes to.
  test("reads the blobs again after redaction, so an alias that lengthens a short run cannot hide it", () => {
    const short = Buffer.from(a).toString("base64").replace(/=+$/, "");
    const message = `X: "${short}+abc"`;
    expect(message.match(/[A-Za-z0-9+/]+/g)!.every((run) => run.length < 16)).toBe(true);
    expect(refused(message, [["abc", "labhost"]])).toThrow(/^record 79: an encoded blob/);
    // The same alias beside a run that decodes to nothing is let through.
    const harmless = `X: "${Buffer.from("192.0.2.10").toString("base64").replace(/=+$/, "")}+abc"`;
    expect(redact([{ record: 79, message: harmless, xml: "" }], [["abc", "labhost"]])[0].message).toBe(harmless.replace("abc", "labhost"));
  });

  // redactable() learns GUID first fields from decoded text by the batch's own rule: only from an
  // XML Data field with a Sysmon GUID name, never from a label in free text.
  test("refuses a blob holding a Sysmon GUID Data field whose first field the batch never saw", () => {
    const field = (name: string, first: string) => `<Data Name='${name}'>{${first}-0001-0002-0003-000000000004}</Data>`;
    for (const name of ["ProcessGuid", "logonguid"]) {
      expect(refused(b64(field(name, "abcdef01"), "utf8"), [])).toThrow(/^record 79: an encoded blob/);
    }
    for (const text of [field("ProcessGuid", "00000000"), field("TaskGuid", "abcdef01"), "ProcessGuid: {abcdef01-0001-0002-0003-000000000004}"]) {
      const message = b64(text, "utf8");
      expect(redact([{ record: 79, message, xml: "" }], [])[0].message).toBe(message);
    }
  });

  // An alias is never reused, so a 255th distinct private IPv4 address makes redaction throw.
  // That must refuse the blob, not let it pass.
  test("refuses a blob holding more distinct private IPv4 addresses than there are aliases", () => {
    const many = Array.from({ length: 255 }, (_, i) => v4(10, 0, 0, i)).join(" ");
    expect(() => redact([{ message: many, xml: "" }], [])).toThrow(/^more than 254 distinct private IPv4 addresses/);
    expect(refused(b64(many, "utf8"), [])).toThrow(/^record 79: an encoded blob holds text that redaction would change$/);
  });

  // A source between + and / sits inside a base64 run. An alias of another length shifts the
  // rest of the run, and one holding . - or _ splits it, so the blob is read before redaction too.
  test("reads a blob before redaction, so an alias inside the run cannot hide it", () => {
    const blob = b64(`ping ${a}`, "utf16le");
    for (const before of ["", "-enc "]) {
      for (const to of ["gus", "lab-u"]) {
        expect(refused(`X: "${before}A+alice/${blob}"`, [["alice", to]])).toThrow(/^record 79: an encoded blob/);
        const xml = event("", `<Data Name='CommandLine'>${before}A+alice/${blob}</Data>`);
        expect(() => redact([{ record: 79, message: null, xml }], [["alice", to]])).toThrow(/^record 79: an encoded blob/);
        const harmless = `X: "${before}A+alice/${b64("ping 192.0.2.10", "utf16le")}"`;
        expect(redact([{ record: 79, message: harmless, xml: "" }], [["alice", to]])[0].message).toBe(harmless.replace("alice", to));
      }
    }
    // Split by the dash, neither piece reaches 16 characters, so only the read before redaction sees it.
    const literals: [string, string][] = [
      ["alice", "lab-u"],
      ["labbox", "host"],
    ];
    for (const inner of [a, "labbox"]) {
      const short = `A+alice/${b64(inner, "utf8")}`;
      expect(short.replace("alice", "lab-u").split("-").every((p) => p.length < 16)).toBe(true);
      expect(refused(`X: "${short}"`, literals)).toThrow(/^record 79: an encoded blob/);
      const xml = event("", `<Data Name='CommandLine'>${short}</Data>`);
      expect(() => redact([{ record: 79, message: null, xml }], literals)).toThrow(/^record 79: an encoded blob/);
    }
  });

  // The wrapped path already reads from each offset and from an odd byte; one line now does too.
  test("reads a single-line run from every offset, and as UTF-16LE from an odd byte", () => {
    const shifted = (s: string) => Buffer.concat([Buffer.from([0x41]), Buffer.from(s, "utf16le")]).toString("base64");
    const junk = shifted(`ping ${a}`);
    // Each UTF-16 read also covers another but for one end character, so these open on the address.
    const first = [shifted(`${a} ping`), b64(`${a} ping`, "utf16le")];
    for (const text of [junk, `X: "${junk}"`, ...first, `x/${b64(`ping ${a}`, "utf16le")}`, `ab/${b64(`ping ${a}`, "utf8")}`]) {
      expect(refused(text, [])).toThrow(/^record 79: an encoded blob/);
    }
    const xml = event("", `<Data Name='CommandLine'>${junk}</Data>`);
    expect(() => redact([{ record: 79, message: null, xml }], [])).toThrow(/^record 79: an encoded blob/);
  });

  // UTF-16LE from an odd byte reads UTF-16BE text but its last character, so an address that ends
  // the blob needs the UTF-16BE read itself.
  test("reads a run as UTF-16BE too, so an address at the very end is not cut off", () => {
    const be = (s: string) => Buffer.from(s, "utf16le").swap16();
    for (const bytes of [be(`ping ${a}`), Buffer.concat([Buffer.from([0x41]), be(`ping ${a}`)])]) {
      expect(refused(`X: "${bytes.toString("base64")}"`, [])).toThrow(/^record 79: an encoded blob/);
      expect(refused(`run this\r\n${wrap(bytes.toString("base64"))}`, [])).toThrow(/^record 79: an encoded blob/);
    }
    const harmless = `X: "${be("ping 192.0.2.10").toString("base64")}"`;
    expect(redact([{ record: 79, message: harmless, xml: "" }], [])[0].message).toBe(harmless);
  });

  // UTF-16LE of non-ASCII text is not valid UTF-8. That decode must not stop the others running.
  test("reads the other decodings when the UTF-8 one is malformed", () => {
    const cafe = `caf${String.fromCharCode(0xe9)}`;
    const bytes = Buffer.from(`${cafe} ping ${a}`, "utf16le");
    expect(() => new TextDecoder("utf-8", { fatal: true }).decode(bytes)).toThrow();
    expect(refused(`powershell -EncodedCommand ${bytes.toString("base64")}`, [])).toThrow(/^record 79: an encoded blob/);
    expect(refused(bytes.toString("base64"), [])).toThrow(/^record 79: an encoded blob/);
    const harmless = `powershell -EncodedCommand ${b64(`${cafe} ping 192.0.2.10`, "utf16le")}`;
    expect(redact([{ record: 79, message: harmless, xml: "" }], [])[0].message).toBe(harmless);
  });
});

describe("capture entry point", () => {
  test("builds the XPath from the filters", () => {
    const s = captureScript({ log: "Security", id: 4624, record: 9, since: 10, max: 3 });
    expect(s).toContain(
      "Get-WinEvent -LogName 'Security' -FilterXPath '*[System[(EventID=4624) and (EventRecordID=9) and TimeCreated[timediff(@SystemTime) <= 600000]]]' -MaxEvents 3",
    );
    expect(captureScript({ log: "Security", max: 1 })).toContain("-FilterXPath '*' -MaxEvents 1");
  });

  test("bounds the ssh connection and puts the host after --", () => {
    expect(sshArgv("labbox", "cmd")).toEqual([
      "ssh",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=15",
      "-o",
      "ServerAliveInterval=15",
      "-o",
      "ServerAliveCountMax=4",
      "--",
      "labbox",
      "cmd",
    ]);
  });

  test("refuses an ssh host that starts with a dash", () => {
    expect(() => sshArgv("-oProxyCommand=x", "cmd")).toThrow();
  });

  const answer = (v: unknown) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64");

  test("reads the last line of the answer and keeps only the capture fields", () => {
    const body = answer([{ id: 3, record: 9, message: null, xml: "<Event/>", extra: "x" }]);
    expect(decodeAnswer(`banner\r\n${body}\r\n`)).toEqual([{ id: 3, record: 9, message: null, xml: "<Event/>" }]);
    expect(decodeAnswer(answer([]))).toEqual([]);
  });

  test("refuses an answer that is not base64 of a JSON array of captures", () => {
    const bad = [
      "",
      "not base64!",
      "QUJD$",
      "QUJ",
      answer("{nope"),
      answer({ xml: "x", message: null }),
      answer([1]),
      answer([null]),
      answer([{ xml: 1, message: null }]),
      answer([{ xml: "x" }]),
      answer([{ xml: "x", message: 5 }]),
      Buffer.from([0x5b, 0xff, 0x5d]).toString("base64"),
    ];
    for (const s of bad) expect(() => decodeAnswer(s)).toThrow(CaptureError);
  });

  // Buffer reads base64 leniently, skipping what is not base64 and a missing or extra pad, so
  // each of these would decode to [] without the shape check.
  test("refuses an answer only a lenient base64 read would take", () => {
    for (const s of ["W10", "W1 0=", "W1\t0=", "!W10=", "W10=!", "W10=="]) {
      expect(Buffer.from(s, "base64").toString()).toBe("[]");
      expect(() => decodeAnswer(`banner\r\n${s}\r\n`)).toThrow(/^the host did not answer with base64$/);
    }
    expect(decodeAnswer("banner\r\nW10=\r\n")).toEqual([]);
  });

  // With the byte replaced by U+FFFD this is valid JSON, so only a fatal decode refuses it.
  test("refuses an answer that is JSON only once a byte that is not UTF-8 is replaced", () => {
    const bytes = Buffer.concat([Buffer.from('[{"message":null,"xml":"<Event/>'), Buffer.from([0xff]), Buffer.from('"}]')]);
    expect(JSON.parse(new TextDecoder().decode(bytes))).toHaveLength(1);
    expect(() => decodeAnswer(bytes.toString("base64"))).toThrow(/^the host's answer is not UTF-8 JSON$/);
  });

  // The stub is the only ssh on PATH, so no test can reach a real host. It records its argv
  // and answers with a banner line, then the given base64. Given a failure, it also writes
  // that stderr, byte for byte from a file, and exits with that code.
  const capture = (args: string[], reply: string, failure?: { code: number; stderr: string }) => {
    const dir = mkdtempSync(join(tmpdir(), "winevt-capture-test-"));
    try {
      let stub = `#!/bin/sh\nprintf '%s\\n' "$@" > '${join(dir, "argv")}'\nprintf 'banner\\r\\n%s\\r\\n' '${reply}'\n`;
      if (failure) {
        writeFileSync(join(dir, "stderr"), failure.stderr);
        stub += `/bin/cat '${join(dir, "stderr")}' >&2\nexit ${failure.code}\n`;
      }
      writeFileSync(join(dir, "ssh"), stub, { mode: 0o755 });
      const p = Bun.spawnSync([process.execPath, resolve(import.meta.dir, "winevt-capture.ts"), ...args], {
        env: { PATH: dir },
        stdout: "pipe",
        stderr: "pipe",
      });
      let argv: string[] = [];
      try {
        argv = readFileSync(join(dir, "argv"), "utf8").trimEnd().split("\n");
      } catch {}
      return { code: p.exitCode, out: p.stdout.toString(), err: p.stderr.toString(), argv };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  test("redacts on the way to stdout, so what the host sent never prints", () => {
    const a = v4(10, 1, 2, 3);
    const ll = v6("fe80", "", "1");
    const xml = event("<Computer>labbox</Computer>", `<Data Name='DestinationIp'>${ll}</Data><Data Name='User'>S-1-5-21-111-222-333-1001</Data>`);
    const r = capture(["labbox", "--redact", "labbox=labhost"], answer([{ id: 3, record: 9, message: `labbox reached ${a}`, xml }]));
    expect(r.err).toBe("winevt-capture: 1 event(s)\n");
    expect(r.code).toBe(0);
    for (const literal of ["labbox", a, ll, "111-222-333"]) expect(r.out).not.toContain(literal);
    const [c] = JSON.parse(r.out);
    expect(c.message).toBe("labhost reached 192.0.2.1");
    expect(c.xml).toContain("<Computer>labhost</Computer>");
    expect(c.xml).toContain("<Data Name='DestinationIp'>2001:db8::1</Data><Data Name='User'>S-1-5-21-0-0-1-1001</Data>");
    const opts = ["BatchMode=yes", "ConnectTimeout=15", "ServerAliveInterval=15", "ServerAliveCountMax=4"];
    expect(r.argv.slice(0, -1)).toEqual([...opts.flatMap((o) => ["-o", o]), "--", "labbox"]);
    expect(r.argv.at(-1)).toStartWith("powershell -NoProfile -NonInteractive -EncodedCommand ");
  });

  test("refuses a --redact source that names markup, and takes a plain alias", () => {
    const xml = event("<Computer>labbox</Computer>", "<Data Name='User'>Data</Data>");
    const r = capture(["labbox", "--redact", "labbox=lab-host_1.x", "--redact", "Data=somebody"], answer([{ record: 9, message: "Data", xml }]));
    expect([r.code, r.out]).toEqual([2, ""]);
    expect(r.err).toBe("winevt-capture: record 9: --redact #2 (to somebody) matches a tag, attribute or field name in the XML\n");
    const ok = capture(["labbox", "--redact", "labbox=lab-host_1.x"], answer([{ record: 9, message: "Data", xml }]));
    expect(ok.code).toBe(0);
    expect(JSON.parse(ok.out)[0].xml).toContain("<Computer>lab-host_1.x</Computer>");
  });

  // A failing remote PowerShell writes its error, event text and the endpoint's name
  // included, to the stderr ssh relays. Redaction never sees it, so none of it may print.
  test("a failed ssh exits 2 and prints none of the remote stderr", () => {
    const a = v4(10, 1, 2, 3);
    const ll = v6("fe80", "", "1");
    const stderr = `Get-WinEvent : labbox reached ${a} via ${ll}\r\n\u001b]0;retitled\u0007\u001b[2K\u001b[1APASS\r\n`;
    for (const code of [1, 255]) {
      const r = capture(["labbox"], answer([]), { code, stderr });
      expect([r.code, r.out]).toEqual([2, ""]);
      expect(r.err).toBe(`winevt-capture: ssh exited ${code}; its output is not shown, since a failed capture's errors can hold event text: run ssh labbox by hand to see why\n`);
      for (const leak of [a, ll, "Get-WinEvent", "retitled", "PASS", "\u001b", "\u0007", "\r"]) expect(r.err).not.toContain(leak);
      // ssh really ran, so the refusal is the stderr rule and not an argument check.
      expect(r.argv.at(-2)).toBe("labbox");
    }
  });

  test("an ssh that cannot start exits 2 with one line and no stack", () => {
    const dir = mkdtempSync(join(tmpdir(), "winevt-capture-test-"));
    try {
      const p = Bun.spawnSync([process.execPath, resolve(import.meta.dir, "winevt-capture.ts"), "labbox"], {
        env: { PATH: dir },
        stdout: "pipe",
        stderr: "pipe",
      });
      const err = p.stderr.toString();
      expect([p.exitCode, p.stdout.toString()]).toEqual([2, ""]);
      expect(err).toBe("winevt-capture: ssh could not start (ENOENT)\n");
      expect(err).not.toMatch(/^\s*at /m);
      expect(err).not.toContain(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("prints nothing when redaction refuses the capture", () => {
    const blob = b64(`ping ${v4(10, 1, 2, 3)}`, "utf16le");
    const r = capture(["labbox"], answer([{ record: 12, message: `powershell -EncodedCommand ${blob}`, xml: event("", "") }]));
    expect(r.code).toBe(2);
    expect(r.out).toBe("");
    expect(r.err).toBe("winevt-capture: record 12: an encoded blob holds text that redaction would change\n");
  });

  test("prints nothing when a record holds a NUL", () => {
    const xml = event("", "<Data Name='TargetObject'>Run\\\u0000hidden</Data><Data Name='Details'>C:\\x.exe</Data>");
    const r = capture(["labbox"], answer([{ record: 12, message: null, xml }]));
    expect([r.code, r.out]).toEqual([2, ""]);
    expect(r.err).toBe("winevt-capture: record 12: a NUL character, where the agent's C string cuts the live event short\n");
  });

  test("parseArgs: help, an unknown flag, a missing value and no host never reach ssh", () => {
    const help = capture(["--help"], answer([]));
    expect([help.code, help.argv]).toEqual([0, []]);
    expect(help.out).toStartWith("usage: bun tools/winevt-capture.ts <ssh-host>");
    expect(help.out).toContain("and begins and ends with a letter g to z");
    expect(help.out).not.toContain("hex digits");
    const bad: [string[], RegExp][] = [
      [["labbox", "--bogus"], /^winevt-capture: unknown argument: --bogus\n/],
      [["labbox", "--id"], /^winevt-capture: --id needs a value\n$/],
      [["labbox", "--max", "x"], /^winevt-capture: --max needs a whole number\n$/],
      [["labbox", "--log"], /^winevt-capture: --log needs a value\n$/],
      [["--log", "--raw", "labbox"], /^winevt-capture: --log needs a value\n$/],
      [["labbox", "--redact"], /^winevt-capture: --redact needs a value\n$/],
      [["labbox", "--redact", "a=b=c"], /^winevt-capture: --redact needs a=b\n$/],
      [["labbox", "--redact", "a="], /^winevt-capture: --redact needs a=b\n$/],
      [["labbox", "--redact", `alice=${v4(10, 1, 2, 3)}`], /^winevt-capture: --redact #1 alias looks like an address, SID or GUID\n$/],
      [["labbox", "--redact", "x=y", "--redact", "alice=S-1-5-21-1-2-3"], /^winevt-capture: --redact #2 alias looks like an address, SID or GUID\n$/],
      [["labbox", "--redact", "Q=R", "--redact", "P=Q"], /^winevt-capture: --redact #2's alias is --redact #1's source\n$/],
      [["labbox", "--redact", "P=Q", "--redact", "Q=R"], /^winevt-capture: --redact #1's alias is --redact #2's source\n$/],
      [["labbox", "--redact", "alpha=sam", "--redact", "beta=sam"], /^winevt-capture: --redact #2's alias is --redact #1's alias\n$/],
      [["labbox", "--redact", "x=y", "--redact", "wkstn=192"], /^winevt-capture: --redact #2 alias must begin and end with a letter g to z, so an address beside it cannot read it as part of the address\n$/],
      [["labbox", "--redact", "wkstn=Db8"], /^winevt-capture: --redact #1 alias must begin and end with a letter g to z, so an address beside it cannot read it as part of the address\n$/],
      [["--raw"], /^winevt-capture: need an ssh host alias\n/],
      ...["a&b", "a<b", "a b", 'a"b', "a'b", "a>b"].map((to): [string[], RegExp] => [
        ["labbox", "--redact", `alice=${to}`],
        /^winevt-capture: --redact alias may hold only letters, digits, dot, dash and underscore\n$/,
      ]),
    ];
    for (const [args, why] of bad) {
      const r = capture(args, answer([]));
      expect([args, r.code, r.out, r.argv]).toEqual([args, 2, "", []]);
      expect(r.err).toMatch(why);
    }
    // An alias that begins and ends with a letter past f, whatever is between, reaches ssh.
    const ok = capture(["labbox", "--redact", "wkstn=hostx", "--redact", "labbox=gc-01x"], answer([]));
    expect([ok.code, ok.out.trim(), ok.argv.at(-2)]).toEqual([0, "[]", "labbox"]);
  });

  // An alias edge that is a digit or a letter a to f changes how a later pass reads the address
  // beside it, without overlapping it, so nothing refuses and the private address stays.
  describe("alias edges", () => {
    const why = (n: number) => `--redact #${n} alias must begin and end with a letter g to z, so an address beside it cannot read it as part of the address`;
    const a = v4(10, 1, 2, 3);
    const ula = v6("fd12", "3456", "", "5");
    const mapped = v6("", "", "ffff", "a01", "203");
    const nat64 = v6("64", "ff9b", "", "a01", "203");
    // The text, the alias that left its private address behind, and labhost's output (null: refused).
    const shapes: [string, string, string | null][] = [
      [`wkstn.${a}`, "labhost1", "labhost.192.0.2.1"],
      [`wkstn::${a}`, "host2024", "labhost::192.0.2.1"],
      [`wkstn${mapped}`, "host2024", "labhost::ffff:c000:201"],
      [`wkstn:${ula}`, "host2024", null],
      [`wkstn:${nat64}`, "host2024", null],
      [`${ula}.wkstn`, "1host", "2001:db8::1.labhost"],
      [`${v4(3, 2, 1, 10)}.in-addr.arpa.wkstn`, "1host", `${v4(1, 2, 0, 192)}.in-addr.arpa.labhost`],
    ];
    const inXml = (text: string) => event(`<Computer>${text}</Computer>`, "");
    const refusedByRedact = (text: string, to: string) => {
      const literals: [string, string][] = [["labbox", "labhost"], ["wkstn", to]];
      const exact = new RegExp(`^${why(2)}$`);
      expect(() => redact([{ record: 9, message: text, xml: "" }], literals)).toThrow(exact);
      expect(() => redact([{ record: 9, message: null, xml: inXml(text) }], literals)).toThrow(exact);
    };
    const refusedByCli = (text: string, to: string) => {
      const r = capture(["labbox", "--redact", `wkstn=${to}`], answer([{ record: 9, message: text, xml: inXml(text) }]));
      expect([to, r.code, r.out, r.argv]).toEqual([to, 2, "", []]);
      expect(r.err).toBe(`winevt-capture: ${why(1)}\n`);
    };

    test("refuses each alias that left a private address, in the message and the XML", () => {
      for (const [text, to] of shapes) refusedByRedact(text, to);
    });

    test("refuses each of them at parse, with no ssh call", () => {
      for (const [text, to] of shapes) refusedByCli(text, to);
    });

    test("the same text under a legal alias is redacted, or refused for the address", () => {
      for (const [text, , want] of shapes) {
        const run = () => redact([{ record: 9, message: text, xml: "" }], [["wkstn", "labhost"]])[0].message;
        if (want === null) expect(run).toThrow(/^record 9: a private IPv[46] address/);
        else expect(run()).toBe(want);
      }
    });

    const refusedEdges = [..."0123456789abcdefABCDEF", ".", "-", "_"];
    const edgeCases: [string, (c: string) => string][] = [
      ["first", (c) => `${c}host`],
      ["last", (c) => `host${c}`],
    ];
    for (const [where, alias] of edgeCases) {
      test(`refuses a digit, a letter a to f in either case, a dot, a dash or an underscore as the ${where} character`, () => {
        for (const c of refusedEdges) {
          refusedByRedact("ping wkstn", alias(c));
          refusedByCli("ping wkstn", alias(c));
        }
      });
    }

    // Each of these once passed the alias checks and reached the span checks or the hex rule.
    test("refuses the aliases an address pass could read", () => {
      for (const to of ["lab.10", "1.10", "lab.fe80", "2.3", "192.0", "a.192", "host192", "1.x", "bob", "..lab", "host1", "dc-01"]) refusedByRedact("ping wkstn", to);
    });

    test("accepts an alias whose edges are letters g to z, whatever is between them", () => {
      const bounds = ["g", "z", "G", "Z"].flatMap((c) => [`${c}ost`, `hos${c}`]);
      for (const to of ["labhost", "labuser", "zz", "x", "lab.host", "lab-01-host", "Host", "g0.1-a_fz", ...bounds]) {
        expect(redact([{ message: "ping wkstn", xml: "" }], [["wkstn", to]])[0].message).toBe(`ping ${to}`);
        const ok = capture(["labbox", "--redact", `wkstn=${to}`], answer([]));
        expect([to, ok.code, ok.out.trim(), ok.argv.at(-2)]).toEqual([to, 0, "[]", "labbox"]);
      }
    });
  });
});
