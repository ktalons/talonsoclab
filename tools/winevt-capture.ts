#!/usr/bin/env bun
// *****************************************************************************
// *Title: winevt-capture*
// *Author: Kyle Versluis*
// *Description: Capture Windows events over ssh as winevt.ts input.*
// *****************************************************************************

// *--- Imports ---*

import { type Capture, CaptureError, NUL_REFUSAL } from "./winevt.ts";

// *--- Configuration ---*

const USAGE = `usage: bun tools/winevt-capture.ts <ssh-host> [options] > captures.json
  --log <channel>     event log (default Microsoft-Windows-Sysmon/Operational)
  --id <n>            event ID
  --record <n>        EventRecordID
  --since <minutes>   only events newer than this
  --max <n>           at most this many, newest first (default 5)
  --redact <a>=<b>    replace the literal a with b, case-insensitive, whole tokens, plain or
                      XML-escaped (repeatable); b holds only letters, digits, . - and _,
                      and begins and ends with a letter g to z
  --raw              keep private IPv4 and IPv6 addresses (never for a committed fixture)

Account SIDs, Sysmon GUID first fields and --redact literals are replaced even under --raw,
and a capture is refused when a base64 run in it decodes to text redaction would change, when
an a would rewrite a tag, attribute or field name in the XML, or when an a still matches once
redaction is done.`;
const DEFAULT_LOG = "Microsoft-Windows-Sysmon/Operational";
// SECURITY: these values are spliced into a PowerShell script or the ssh argv, so each one is
// held to a pattern that cannot close a quote, start a new statement or read as an option.
const SAFE_LOG = /^[A-Za-z0-9 /_.-]{1,128}$/;
const SAFE_HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_TOKEN = /^[^\s=]{1,128}$/;
// An alias holds no XML metacharacter, so it reads the same raw or entity-escaped and never
// needs escaping where it lands.
const SAFE_ALIAS = /^[A-Za-z0-9._-]{1,128}$/;
const ALIAS_RULE = "alias may hold only letters, digits, dot, dash and underscore";
const ALIAS_SHAPE = "alias looks like an address, SID or GUID";
// SECURITY: an edge that is a digit or a letter a to f changes how a later pass reads the address
// beside it, without overlapping it, so nothing refuses and the private address stays.
const ALIAS_EDGES = /^[g-z](?:.*[g-z])?$/i;
const ALIAS_EDGE = "alias must begin and end with a letter g to z, so an address beside it cannot read it as part of the address";
// An entity reference in the XML, named or numeric.
const ENTITY = /&(?:[A-Za-z_][\w.-]*|#\d+|#x[0-9a-f]+);/gi;
// ssh drops a dead link on its own; this caps a remote command that stays up but never ends.
const SSH_TIMEOUT_MS = 300_000;

// Addresses leakcheck refuses, one source for every form they take. IPv4: RFC 1918, CGNAT
// and link-local. IPv6, by first group: link-local fe80::/10 and ULA fc00::/7.
const V4_PRIVATE = String.raw`(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}`;
const V6_PRIVATE = String.raw`(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2})`;
const IS_V4_PRIVATE = new RegExp(`^${V4_PRIVATE}$`);
const IS_V6_PRIVATE = new RegExp(`^${V6_PRIVATE}$`, "i");

// An IPv6 zone index (RFC 6874): letters, digits, - . _ ~ and %XX escapes, as in %eth0 or %12.
// A dot ends it unless more zone follows, so a sentence period stays.
const ZONE_CHAR = String.raw`(?:[A-Za-z0-9_~-]|%[0-9a-f]{2})`;
const ZONE = String.raw`(?:%${ZONE_CHAR}+(?:\.${ZONE_CHAR}+)*)?`;
// A full in-addr.arpa name is taken whole, so its reversed octets never reach the plain
// branch. Around a match: no digit or digit-dot before, no digit or dot-digit after.
const V4_ANY = new RegExp(
  String.raw`(?<!\d)(?<!\d\.)(?:(\d{1,3}(?:\.\d{1,3}){3})(\.in-addr\.arpa)|(${V4_PRIVATE}))(?!\d)(?!\.\d)`,
  "gi",
);
// A dotted quad that ends a hex-and-colon run, with its zone. The whole run is read as IPv6.
const V6_DOTTED = new RegExp(String.raw`(?<![0-9a-f:])([0-9a-f:]*:)(\d{1,3}(?:\.\d{1,3}){3})${ZONE}(?!\d)(?!\.\d)`, "gi");
const DOTTED = /(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)/g;
const ARPA6 = /((?:[0-9a-f]\.){32})(ip6\.arpa)/gi;
const V6_END = String.raw`(?![0-9a-f:]|\.\d)`;
// A ::ffff: (mapped) or 64:ff9b:: (NAT64) address ending in hex; the value decides which. Each
// open stretch is capped at 39 characters, the longest IPv6 text, so a long run fails fast
// rather than being tried at every pair of colons; v6Value refuses anything longer anyway.
const V6_MAPPED = new RegExp(
  String.raw`(?<![0-9a-f:])([0-9a-f:]{0,39}:(?:ffff|ff9b:[0-9a-f:]{0,39}):[0-9a-f]{1,4}:[0-9a-f]{1,4})${ZONE}${V6_END}`,
  "gi",
);
// One more hex digit or colon after the first colon, so the word "fd00:" is not taken.
const V6_PRIVATE_ANY = new RegExp(
  String.raw`(?<![0-9a-f:])(${V6_PRIVATE}:(?=[0-9a-f:])[0-9a-f:]*(?:\d{1,3}(?:\.\d{1,3}){3})?)${ZONE}${V6_END}`,
  "gi",
);
// A private first group the pass above skips, because a colon or hex digit stands before it.
const V6_GLUED = new RegExp(String.raw`(?<=[0-9a-f:])${V6_PRIVATE}:(?=[0-9a-f:])`, "gi");
const HEX_OR_COLON = /[0-9a-f:]/i;
// The last 32 bits of a ::ffff: (mapped) or ::ffff:0: (translated) form, in hex or dotted.
const V4_IN_MAPPED = /:ffff:(?:0{1,4}:)?(?:([0-9a-f]{1,4}):([0-9a-f]{1,4})|(\d{1,3}(?:\.\d{1,3}){3}))(?![0-9a-f:]|\.\d)/gi;
// The last 32 bits of any form under 64:ff9b: (NAT64), the local-use 64:ff9b:1::/48 included.
// Read once per run, from its start through its first 64:ff9b:, since every later one ends at the
// same last 32 bits; tried at each 64:ff9b:, a long run was read again from each.
const V4_IN_NAT64 =
  /(?<![0-9a-f:])(?:(?!64:ff9b:)[0-9a-f:])*64:ff9b:[0-9a-f:]*?:(?:([0-9a-f]{1,4}):([0-9a-f]{1,4})|(\d{1,3}(?:\.\d{1,3}){3}))(?![0-9a-f:]|\.\d)/gi;
// Both forms followed by a port, which neither the passes nor leakcheck read: a hex pair before
// .digits (not the rest of a dotted quad), or a dotted quad before a dot and a digit. Apart from
// the two above, so a hex pair never shadows a dotted tail.
const PORT = String.raw`(?:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?=\.\d+(?!\d|\.\d))|(\d{1,3}(?:\.\d{1,3}){3})(?=\.\d))`;
const V4_IN_MAPPED_PORT = new RegExp(String.raw`:ffff:(?:0{1,4}:)?${PORT}`, "gi");
const V4_IN_NAT64_PORT = new RegExp(String.raw`(?<![0-9a-f:])(?:(?!64:ff9b:)[0-9a-f:])*64:ff9b:[0-9a-f:]*?:${PORT}`, "gi");
// A private IPv4 address with a dot and a digit after it, bounded on the left as the IPv4 pass is.
// Every private range starts with a 1, and the lookahead for it lets the engine skip to one.
const V4_PORT = new RegExp(String.raw`(?=1)(?<!\d)(?<!\d\.)(${V4_PRIVATE})(?=\.\d)`, "g");
// Starts only where a hex run starts, so a long one is scanned once, not from every offset.
const V6_CANDIDATE = /(?<![0-9a-f:])[0-9a-f]*(?::[0-9a-f]*){2,}/gi;
// The machine or domain part of an account SID is unique to the host; the RID after it is not.
const SID = /(S-1-5-21-)(\d+)-(\d+)-(\d+)(?!\d)/gi;
const SID_DONE = /S-1-5-21-0-0-(\d+)(?!\d)/gi;
// Sysmon derives the first field of its process and logon GUIDs from the machine's GUID. It is
// learned only from an XML Data field of one of these exact names, in any case, so no label in
// free text can teach a prefix that is then zeroed across the batch. ASCII whitespace may stand
// before the GUID inside the field; the GUID itself is matched exactly.
const GUID_NAMES = new Set(["processguid", "parentprocessguid", "sourceprocessguid", "targetprocessguid", "logonguid"]);
const GUID_DATA = /<Data\s+Name='([^']*)'\s*>[ \t\n\v\f\r]*\{([0-9a-f]{8})-/gi;
// What replaceGuidPrefixes can zero: eight hex digits at a token start, before a dash.
const GUID_HEAD = /(?<![0-9a-z])[0-9a-f]{8}(?=-)/i;
// The shortest base64 run read; most shorter runs are plain words.
const BLOB_MIN = 16;
const BLOB = new RegExp(`[A-Za-z0-9+/]{${BLOB_MIN},}={0,2}`, "g");
// Whitespace between base64 pieces: a tab, line break or space, raw or as a character reference
// in any hex case and with leading zeros, as an XML writer may spell a wrapped blob's breaks.
const SPACE_REF = String.raw`&#(?:x0*(?:9|a|d|20)|0*(?:9|10|13|32));`;
const BLOB_SPACE = new RegExp(String.raw`(?:[ \t\r\n]|${SPACE_REF})+`, "gi");
// Base64 pieces split only by that whitespace, padding on the last. It matches from any piece
// character and never fails, so a long run is scanned once.
const SPLIT_BLOB = new RegExp(String.raw`[A-Za-z0-9+/]+(?:${BLOB_SPACE.source}[A-Za-z0-9+/]+)*={0,2}`, "gi");
// RFC 5737 and RFC 3849 documentation ranges, numbered in order of first sight.
const DOC4 = 0xc0000200;
const DOC6 = 0x20010db8n << 96n;
const XML_ENTITY = new Map([
  ["&", "&amp;"],
  ["<", "&lt;"],
  [">", "&gt;"],
  ['"', "&quot;"],
  ["'", "&apos;"],
]);

// *--- Types ---*

interface Options {
  host: string;
  log: string;
  id?: number;
  record?: number;
  since?: number;
  max: number;
  redact: [string, string][];
  raw: boolean;
}

// Alias numbers already in the batch, so a rewrite never lands on one.
interface Taken {
  v4: Set<number>;
  v6: Set<bigint>;
  sid: Set<number>;
}

// A source's pattern, its alias, and its --redact position, which messages name.
type Literal = [RegExp, string, number];

// What a match becomes, called as String.replace calls it.
type Replacer = (match: string, ...rest: any[]) => string;

// One match a pass changed, in the text before that pass: start, end and what replaced it.
type Edit = [number, number, string];

// Where the literal stage wrote an alias, and which literal wrote it (its index in run order).
interface Span {
  from: number;
  to: number;
  k: number;
}

// *--- Helper Functions ---*

function fail(msg: string): never {
  console.error(`winevt-capture: ${msg}`);
  process.exit(2);
}

function int(flag: string, v: string | undefined): number {
  if (!v || !/^\d{1,12}$/.test(v)) fail(`${flag} needs a whole number`);
  return Number(v);
}

function parseArgs(argv: string[]): Options {
  const o: Options = { host: "", log: DEFAULT_LOG, max: 5, redact: [], raw: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    // A flag never stands in for a value, so "--log --raw" cannot drop the --raw.
    const next = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) fail(`${a} needs a value`);
      return v;
    };
    if (a === "--log") o.log = next();
    else if (a === "--id") o.id = int(a, next());
    else if (a === "--record") o.record = int(a, next());
    else if (a === "--since") o.since = int(a, next());
    else if (a === "--max") o.max = int(a, next());
    else if (a === "--redact") {
      const [from, to, extra] = next().split("=");
      if (extra !== undefined || !SAFE_TOKEN.test(from ?? "") || !to) fail("--redact needs a=b");
      if (!SAFE_ALIAS.test(to)) fail(`--redact ${ALIAS_RULE}`);
      o.redact.push([from, to]);
    } else if (a === "--raw") o.raw = true;
    else if (a === "--help" || a === "-h") {
      console.log(USAGE);
      process.exit(0);
    } else if (!a.startsWith("-") && !o.host) o.host = a;
    else fail(`unknown argument: ${a}\n${USAGE}`);
  }
  if (!SAFE_HOST.test(o.host)) fail(`need an ssh host alias\n${USAGE}`);
  if (!SAFE_LOG.test(o.log)) fail("--log holds characters a channel name never has");
  if (o.max < 1 || o.max > 500) fail("--max must be 1 to 500");
  const shaped = o.redact.findIndex(([, to]) => aliasLooksRedactable(to));
  if (shaped !== -1) fail(`--redact #${shaped + 1} ${ALIAS_SHAPE}`);
  const edge = o.redact.findIndex(([, to]) => !ALIAS_EDGES.test(to));
  if (edge !== -1) fail(`--redact #${edge + 1} ${ALIAS_EDGE}`);
  const clash = mappingClash(o.redact);
  if (clash) fail(clash);
  return o;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const xmlUnescape = (s: string) =>
  s.replace(/&(?:#x([0-9a-f]+)|#(\d+)|([a-z]+));/gi, (m, hex, dec, name) => {
    if (hex || dec) return String.fromCodePoint(Number.parseInt(hex ?? dec, hex ? 16 : 10));
    return [...XML_ENTITY].find(([, e]) => e === `&${name.toLowerCase()};`)?.[0] ?? m;
  });

// Message holds a literal as typed and ToXml() holds it entity-escaped, so each of & < > " '
// matches raw or as any entity for it.
function literalPattern(from: string): RegExp {
  const body = [...from].map((c) => {
    const entity = XML_ENTITY.get(c);
    if (entity === undefined) return escapeRe(c);
    const code = c.charCodeAt(0);
    return `(?:${escapeRe(c)}|${entity}|&#0*${code};|&#x0*${code.toString(16)};)`;
  });
  return new RegExp(`(?<![A-Za-z0-9_-])${body.join("")}(?![A-Za-z0-9_-])`, "gi");
}

// An alias a later pass would rewrite, renumber or zero: a private address in any form the
// passes take, any S-1-5-21 SID (0-0-n included), or a GUID first field.
function aliasLooksRedactable(to: string): boolean {
  return redactor([], false, [], takenIn([]))(to) !== to || to.search(SID) !== -1 || GUID_HEAD.test(to);
}

/** Why two --redact mappings would recreate a source or merge two, or null when none would. */
function mappingClash(literals: [string, string][]): string | null {
  for (const [j, [from, alias]] of literals.entries()) {
    for (const [i, [other, to]] of literals.entries()) {
      if (i < j && other.toLowerCase() === from.toLowerCase()) return `--redact #${j + 1}'s source is --redact #${i + 1}'s source`;
      if (i < j && to.toLowerCase() === alias.toLowerCase()) return `--redact #${j + 1}'s alias is --redact #${i + 1}'s alias`;
      if (to.toLowerCase() === from.toLowerCase()) return `--redact #${i + 1}'s alias is --redact #${j + 1}'s source`;
      // A source anywhere inside an alias would print in the output, whole token or not.
      if (to.toLowerCase().includes(from.toLowerCase())) return `--redact #${i + 1}'s alias holds --redact #${j + 1}'s source`;
    }
  }
  return null;
}

// The alias goes in as is over a raw or an entity-escaped match alike (see SAFE_ALIAS); only
// its case follows the match.
function literalOut(match: string, to: string): string {
  const plain = xmlUnescape(match);
  return plain === plain.toUpperCase() && plain !== plain.toLowerCase() ? to.toUpperCase() : to;
}

// Spans that make up the event's shape: all of a tag but its quoted values, and the whole of a
// <Data> tag, whose attribute values become field names.
function shapeRanges(xml: string): [number, number][] {
  const out: [number, number][] = [];
  let lt = xml.indexOf("<");
  while (lt !== -1) {
    const keys = /^<Data[\s/>]/.test(xml.slice(lt, lt + 6));
    let from = lt;
    let i = lt + 1;
    while (i < xml.length && xml[i] !== ">") {
      if (xml[i] === "'" || xml[i] === '"') {
        const close = xml.indexOf(xml[i], i + 1);
        if (close === -1) break;
        if (!keys) {
          out.push([from, i + 1]);
          from = close;
        }
        i = close;
      }
      i++;
    }
    out.push([from, Math.min(i + 1, xml.length)]);
    lt = xml.indexOf("<", i + 1);
  }
  return out;
}

// A source that matches the event's shape would hand winevt.ts an event it no longer decodes,
// or decodes under other names. Each source meets the XML as the earlier ones left it.
function refuseShapeHits(xml: string, literals: Literal[], where: string): void {
  let t = xml;
  literals.forEach(([re, to, n]) => {
    const ranges = shapeRanges(t);
    const entities = [...t.matchAll(ENTITY)].map((e): [number, number] => [e.index, e.index + e[0].length]);
    for (const m of t.matchAll(re)) {
      const end = m.index + m[0].length;
      // A match may hold a whole entity (the escaped form of a source), never cut into one.
      const cuts = entities.some(([a, b]) => m.index < b && a < end && (a < m.index || end < b));
      if (cuts || ranges.some(([a, b]) => m.index < b && a < end)) {
        throw new CaptureError(`${where}: --redact #${n} (to ${to}) matches a tag, attribute or field name in the XML`);
      }
    }
    t = t.replace(re, (m) => literalOut(m, to));
  });
}

function v4Value(dotted: string): number | null {
  const o = dotted.split(".").map(Number);
  if (o.length !== 4 || !o.every((x) => x <= 255)) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

const v4Text = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
const reversed = (dotted: string) => dotted.split(".").reverse().join(".");

// The 128-bit value of an IPv6 address written without a zone, or null when it is not one.
function v6Value(text: string): bigint | null {
  let s = text.toLowerCase();
  let low: number | null = null;
  const tail = /:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (tail) {
    low = v4Value(tail[1]);
    if (low === null) return null;
    s = `${s.slice(0, tail.index + 1)}0:0`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parts = halves.map((h) => (h === "" ? [] : h.split(":")));
  const given = parts.flat();
  if (!given.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  const gap = 8 - given.length;
  if (halves.length === 1 ? gap !== 0 : gap < 1) return null;
  const groups = halves.length === 1 ? given : [...parts[0], ...Array(gap).fill("0"), ...parts[1]];
  const v = groups.reduce((acc, g) => (acc << 16n) | BigInt(Number.parseInt(g, 16)), 0n);
  return low === null ? v : (v & ~0xffffffffn) | BigInt(low);
}

const isMapped = (v: bigint) => v >> 32n === 0xffffn;
// The NAT64 well-known prefix 64:ff9b::/96 carries an IPv4 address in its last 32 bits.
const isNat64 = (v: bigint) => v >> 32n === 0x64ff9bn << 64n;

// True when the dotted address at `at` ends a hex-and-colon run that reads as IPv6.
function v6Tail(text: string, at: number, dotted: string): boolean {
  let start = at;
  while (start > 0 && HEX_OR_COLON.test(text[start - 1])) start--;
  return start < at && v6Value(text.slice(start, at) + dotted) !== null;
}
const nibbles = (v: bigint) => [...v.toString(16).padStart(32, "0")].reverse().join(".");
const fromNibbles = (name: string) => BigInt(`0x${[...name.replaceAll(".", "")].reverse().join("")}`);

function allocate<K>(taken: Set<K>, key: (n: number) => K, max: number, what: string): number {
  for (let n = 1; n <= max; n++) {
    if (!taken.has(key(n))) {
      taken.add(key(n));
      return n;
    }
  }
  throw new CaptureError(`more than ${max} distinct ${what} in the batch, and an alias is never reused`);
}

// Aliases already written in the batch, in any form. Over-counting only skips an alias.
function takenIn(texts: string[]): Taken {
  const t: Taken = { v4: new Set(), v6: new Set(), sid: new Set() };
  const addV4 = (n: number | null) => n !== null && n >>> 8 === DOC4 >>> 8 && t.v4.add(n & 255);
  const addV6 = (v: bigint | null) => {
    if (v === null) return;
    t.v6.add(v);
    if (isMapped(v) || isNat64(v)) addV4(Number(v & 0xffffffffn));
  };
  for (const s of texts) {
    for (const m of s.matchAll(SID_DONE)) t.sid.add(Number(m[1]));
    for (const [d] of s.matchAll(DOTTED)) [d, reversed(d)].forEach((x) => addV4(v4Value(x)));
    for (const [c] of s.matchAll(V6_CANDIDATE)) addV6(v6Value(c));
    for (const m of s.matchAll(ARPA6)) addV6(fromNibbles(m[1]));
  }
  return t;
}

/** One pass of re over t, noting in edits each match it changed. */
function runPass(t: string, re: RegExp, fn: Replacer, edits: Edit[]): string {
  return t.replace(re, (...args) => {
    const out = fn(...(args as [string]));
    // The offset is the first number replace passes, since no pattern here has named groups.
    const at: number = args.find((a, i) => i > 0 && typeof a === "number");
    if (out !== args[0]) edits.push([at, at + args[0].length, out]);
    return out;
  });
}

/** The alias spans after one pass's edits, plus each edit when it wrote alias `added`. */
function carrySpans(spans: Span[], edits: Edit[], added: number | null, taken: (k: number) => never): Span[] {
  const out: Span[] = [];
  let shift = 0;
  let i = 0;
  const keep = (s: Span) => out.push({ from: s.from + shift, to: s.to + shift, k: s.k });
  // Both lists are sorted and neither overlaps itself, so one walk places every span.
  for (const [from, to, text] of edits) {
    for (; i < spans.length && spans[i].to <= from; i++) keep(spans[i]);
    if (i < spans.length && spans[i].from < to) taken(spans[i].k);
    if (added !== null) out.push({ from: from + shift, to: from + shift + text.length, k: added });
    shift += text.length - (to - from);
  }
  for (; i < spans.length; i++) keep(spans[i]);
  return out;
}

// SECURITY: an alias must come through every later pass where the literal stage put it, still
// a whole token, and be the only copy of itself. A match that took part of it in (wkstn=a.192
// before .168.1.1 printed a.192.0.2.1) or glued text onto it, and a token a pass wrote that
// spells it (192.0.2.1 holds 192.0), would each make it stand for something else.
function holdAliases(t: string, spans: Span[], aliases: RegExp[], refuse: (k: number, why: string) => never): void {
  aliases.forEach((re, k) => {
    const found = new Set<number>();
    let j = 0;
    for (const m of t.matchAll(re)) {
      found.add(m.index);
      while (j < spans.length && spans[j].to <= m.index) j++;
      // One alias may be a dot-separated part of another, so a copy inside any span is its own.
      if (!spans[j] || spans[j].from > m.index || m.index + m[0].length > spans[j].to) refuse(k, "appears in text a later pass wrote");
    }
    for (const s of spans) if (s.k === k && !found.has(s.from)) refuse(k, "was taken into text a later pass rewrote");
  });
}

// The redaction pipeline: literals, account SIDs, Sysmon GUID fields, then private addresses
// unless raw. Each call to this builds fresh alias maps. Given a record's name, the returned
// function also holds each alias in place through every pass and refuses under that name.
function redactor(literals: Literal[], raw: boolean, prefixes: string[], taken: Taken): (s: string, where?: string) => string {
  const sids = new Map<string, number>();
  const v4 = new Map<string, number>();
  const v6 = new Map<string, number>();
  const alias4 = (dotted: string) => {
    const n = v4Value(dotted);
    const key = n === null ? dotted : v4Text(n);
    if (!v4.has(key)) v4.set(key, allocate(taken.v4, (i) => i, 254, "private IPv4 addresses"));
    return (DOC4 | v4.get(key)!) >>> 0;
  };
  const alias6 = (key: string) => {
    if (!v6.has(key)) v6.set(key, allocate(taken.v6, (i) => DOC6 + BigInt(i), 0xffff, "private IPv6 addresses"));
    return DOC6 + BigInt(v6.get(key)!);
  };
  // The alias value for a private address given as a number, or null when it is not private.
  const aliasOf = (v: bigint): bigint | null => {
    // The prefix stays and the embedded IPv4 address takes its plain alias.
    if (isMapped(v) || isNat64(v)) {
      const d = v4Text(Number(v & 0xffffffffn));
      return IS_V4_PRIVATE.test(d) ? (v & ~0xffffffffn) | BigInt(alias4(d)) : null;
    }
    return IS_V6_PRIVATE.test((v >> 112n).toString(16).padStart(4, "0")) ? alias6(`${v}`) : null;
  };

  // A sub-authority's value, not its spelling: 0123 and 123 are one. Text, so no digit is lost.
  const value = (part: string) => part.replace(/^0+(?=\d)/, "");
  const passes: [RegExp, Replacer][] = [
    [
      SID,
      (m, head: string, a: string, b: string, c: string) => {
        if (a === "0" && b === "0") return m;
        const key = [a, b, c].map(value).join("-");
        if (!sids.has(key)) sids.set(key, allocate(taken.sid, (i) => i, Number.MAX_SAFE_INTEGER, "SIDs"));
        return `${head}0-0-${sids.get(key)}`;
      },
    ],
  ];
  const guid = guidPrefixPattern(prefixes);
  if (guid) passes.push([guid, () => "00000000"]);
  if (!raw) {
    passes.push(
      // A dotted quad that ends an IPv6 address is read with it: a private address takes the
      // alias of its hex spelling, a global one stays whole, and any other keeps its prefix while
      // a private quad takes its plain alias. A rewrite drops the zone.
      [
        V6_DOTTED,
        (m, head: string, quad: string) => {
          const v = v6Value(head + quad);
          if (v === null || v >> 125n === 1n) return m;
          if (IS_V6_PRIVATE.test((v >> 112n).toString(16).padStart(4, "0"))) return `2001:db8::${(alias6(`${v}`) - DOC6).toString(16)}`;
          return IS_V4_PRIVATE.test(quad) ? `${head}${v4Text(alias4(quad))}` : m;
        },
      ],
      // A quad still ending an IPv6 address was left on purpose by the pass above.
      [
        V4_ANY,
        (m, ptr?: string, suffix?: string, plain?: string, at?: number, all?: string) => {
          if (plain !== undefined) return v6Tail(all!, at!, plain) ? m : v4Text(alias4(plain));
          const fwd = reversed(ptr!);
          return v4Value(fwd) !== null && IS_V4_PRIVATE.test(fwd) ? `${reversed(v4Text(alias4(fwd)))}${suffix}` : m;
        },
      ],
      [
        ARPA6,
        (m, name: string, suffix: string) => {
          const out = aliasOf(fromNibbles(name));
          return out === null ? m : `${nibbles(out)}.${suffix}`;
        },
      ],
      [
        V6_MAPPED,
        (m, addr: string) => {
          const v = v6Value(addr);
          const out = v !== null && (isMapped(v) || isNat64(v)) ? aliasOf(v) : null;
          if (out === null) return m;
          return `${isNat64(out) ? "64:ff9b::" : "::ffff:"}${((out >> 16n) & 0xffffn).toString(16)}:${(out & 0xffffn).toString(16)}`;
        },
      ],
      // A zone index is not part of the address, so it is neither a key nor written back.
      [
        V6_PRIVATE_ANY,
        (_m, addr: string) => {
          const v = v6Value(addr);
          const n = alias6(v === null ? `text:${addr.toLowerCase()}` : `${v}`) - DOC6;
          return `2001:db8::${n.toString(16)}`;
        },
      ],
    );
  }
  const aliases = literals.map(([, to]) => literalPattern(to));

  return (s, where) => {
    let t = s;
    if (where === undefined) {
      for (const [re, to] of literals) t = t.replace(re, (m) => literalOut(m, to));
      for (const [re, fn] of passes) t = t.replace(re, fn);
      return t;
    }
    const refuse = (k: number, why: string): never => {
      throw new CaptureError(`${where}: --redact #${literals[k][2]} (to ${literals[k][1]}) ${why}`);
    };
    const overlapped = (k: number) => refuse(k, "was taken into text a later pass rewrote");
    // A later source can take an earlier alias too, so each literal is a pass of its own.
    let spans: Span[] = [];
    literals.forEach(([re, to], k) => {
      const edits: Edit[] = [];
      t = runPass(t, re, (m) => literalOut(m, to), edits);
      spans = carrySpans(spans, edits, k, overlapped);
    });
    holdAliases(t, spans, aliases, refuse);
    for (const [re, fn] of passes) {
      const edits: Edit[] = [];
      t = runPass(t, re, fn, edits);
      spans = carrySpans(spans, edits, null, overlapped);
      holdAliases(t, spans, aliases, refuse);
    }
    return t;
  };
}

// SECURITY: a private address run into the text before it has no start the pass can trust.
// Inside a global (2000::/3) address the group is only a group; anywhere else, refuse.
function gluedPrivateV6(text: string): boolean {
  let scanned = 0;
  for (const m of text.matchAll(V6_GLUED)) {
    if (m.index < scanned) continue;
    let start = m.index;
    let end = m.index;
    while (start > 0 && HEX_OR_COLON.test(text[start - 1])) start--;
    while (end < text.length && HEX_OR_COLON.test(text[end])) end++;
    scanned = end;
    const v = v6Value(text.slice(start, end));
    if (v === null || v >> 125n !== 1n) return true;
  }
  return false;
}

// SECURITY: the mapped pass takes only a well-formed ::ffff: or 64:ff9b::/96 address that starts
// its run and has no port after it, so a glued, ::ffff:0:, other 64:ff9b: or hex-and-port form
// keeps its private IPv4 address. Inside a global address it may stay.
function mappedPrivateV4(text: string): boolean {
  // The NAT64 pattern opens on no literal the engine can scan for, so it runs only where one is.
  const nat64 = /64:ff9b:/i.test(text) ? [...text.matchAll(V4_IN_NAT64), ...text.matchAll(V4_IN_NAT64_PORT)] : [];
  for (const m of [...text.matchAll(V4_IN_MAPPED), ...text.matchAll(V4_IN_MAPPED_PORT), ...nat64]) {
    const n = m[3] === undefined ? Number.parseInt(m[1], 16) * 65536 + Number.parseInt(m[2], 16) : v4Value(m[3]);
    if (n === null || !IS_V4_PRIVATE.test(v4Text(n))) continue;
    let start = m.index;
    while (start > 0 && HEX_OR_COLON.test(text[start - 1])) start--;
    const v = v6Value(text.slice(start, m.index + m[0].length));
    if (v === null || v >> 125n !== 1n) return true;
  }
  return false;
}

// SECURITY: no pass reads a private IPv4 address with a port after it, and leakcheck stops at the
// same .digit, so it errs toward refusing a version string that starts like one. Only the dotted
// tail of a valid global (2000::/3) address may stay, as the IPv4 pass leaves it.
function portedPrivateV4(text: string): boolean {
  for (const m of text.matchAll(V4_PORT)) {
    let start = m.index;
    while (start > 0 && HEX_OR_COLON.test(text[start - 1])) start--;
    const v = start < m.index ? v6Value(text.slice(start, m.index) + m[1]) : null;
    if (v === null || v >> 125n !== 1n) return true;
  }
  return false;
}

/** Why a private address is left in redacted text the passes could not place, or null. */
function leftoverPrivate(text: string): string | null {
  if (gluedPrivateV6(text)) return "a private IPv6 address run together with a colon or hex digit before it";
  if (mappedPrivateV4(text)) return "a private IPv4 address in an IPv4-mapped or NAT64 form redaction did not reach";
  if (portedPrivateV4(text)) return "a private IPv4 address with a port after it, which no pass redacts";
  return null;
}

/** True when redaction would change decoded text, or leave a private address in it. */
function redactable(decoded: string, literals: Literal[], raw: boolean, prefixes: string[]): boolean {
  const all = [...prefixes, ...sysmonGuidPrefixes(decoded)];
  try {
    return redactor(literals, raw, all, takenIn([]))(decoded) !== decoded || (!raw && leftoverPrivate(decoded) !== null);
  } catch {
    return true;
  }
}

// Characters before a blob in its run shift its 4-character groups, and a junk byte shifts its
// UTF-16 pairs, so a run is read from each offset, and as UTF-16 from an odd byte as well.
// NOTE: Buffer's UTF-8 decode is not fatal, so a malformed sequence never stops the others.
function decodings(run: string): string[] {
  const out: string[] = [];
  for (let offset = 0; offset < 4; offset++) {
    const bytes = Buffer.from(run.slice(offset), "base64");
    out.push(bytes.toString("utf8"));
    for (const pairs of [bytes, bytes.subarray(1)]) {
      // swap16 needs an even length and works in place, so it gets a trimmed copy.
      const even = pairs.subarray(0, pairs.length & ~1);
      out.push(pairs.toString("utf16le"), Buffer.from(even).swap16().toString("utf16le"));
    }
  }
  return out;
}

// SECURITY: base64 hides text from every pattern above, so a run that decodes to text the
// pipeline would change refuses the capture. Hex hashes share the alphabet but decode to noise.
function refuseBlobs(text: string, where: string, literals: Literal[], raw: boolean, prefixes: string[]): void {
  const refuse = (decoded: string) => {
    if (redactable(decoded, literals, raw, prefixes)) throw new CaptureError(`${where}: an encoded blob holds text that redaction would change`);
  };
  for (const [run] of text.matchAll(BLOB)) decodings(run).forEach(refuse);
  // A wrapped blob (.NET InsertLineBreaks: 76 columns, CRLF) decodes line by line to slices cut
  // mid-token, so it is read joined.
  const read = new Set<string>();
  const once = (joined: string) => {
    if (joined.length < BLOB_MIN || read.has(joined)) return;
    read.add(joined);
    decodings(joined).forEach(refuse);
  };
  for (const [split] of text.matchAll(SPLIT_BLOB)) {
    const pieces = split.split(BLOB_SPACE);
    if (pieces.length < 2) continue;
    once(pieces.join(""));
    // Words joined before or after a blob decode to bytes glued onto its first or last token,
    // so shorter runs are read alone too: every two and three adjacent pieces, however short,
    // and each run of equal-length pieces, as a wrapped blob is laid out, with and without the
    // piece after it, and without its first or last piece, which may be a word as long as a
    // line. Each piece is in one run, so this stays linear.
    for (let k = 0; k + 1 < pieces.length; k++) {
      for (const run of [pieces.slice(k, k + 2), pieces.slice(k, k + 3)]) once(run.join(""));
    }
    for (let i = 0; i < pieces.length; ) {
      let j = i + 1;
      while (j < pieces.length && pieces[j].length === pieces[i].length) j++;
      if (j - i > 1) {
        once(pieces.slice(i, j).join(""));
        if (j < pieces.length) once(pieces.slice(i, j + 1).join(""));
        if (j - i > 2) [pieces.slice(i + 1, j), pieces.slice(i, j - 1)].forEach((run) => once(run.join("")));
      }
      i = j;
    }
  }
}

// *--- Core Logic ---*

/** The PowerShell that prints the matching events as base64 of UTF-8 JSON. */
export function captureScript(o: Pick<Options, "log" | "id" | "record" | "since" | "max">): string {
  const terms: string[] = [];
  if (o.id !== undefined) terms.push(`(EventID=${o.id})`);
  if (o.record !== undefined) terms.push(`(EventRecordID=${o.record})`);
  if (o.since !== undefined) terms.push(`TimeCreated[timediff(@SystemTime) <= ${o.since * 60000}]`);
  const xpath = terms.length ? `*[System[${terms.join(" and ")}]]` : "*";
  // NOTE: base64 over the wire, because the console's OEM code page turns non-ASCII
  // (the "(R)" in Microsoft's product strings) into other characters before ssh sees it.
  return [
    "$ErrorActionPreference = 'Stop'",
    "try {",
    `  $ev = Get-WinEvent -LogName '${o.log}' -FilterXPath '${xpath}' -MaxEvents ${o.max}`,
    "} catch {",
    "  if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }",
    "  $ev = @()",
    "}",
    "$out = @($ev | ForEach-Object { [ordered]@{ id = $_.Id; record = $_.RecordId; message = $_.Message; xml = $_.ToXml() } })",
    "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $out -Depth 3 -Compress)))",
  ].join("\n");
}

/** First fields of the Sysmon GUIDs in an event's XML Data fields, lower case, all-zero dropped. */
export function sysmonGuidPrefixes(xml: string): string[] {
  const out = new Set<string>();
  for (const [, name, first] of xml.matchAll(GUID_DATA)) {
    if (GUID_NAMES.has(name.toLowerCase())) out.add(first.toLowerCase());
  }
  out.delete("00000000");
  return [...out];
}

/** These GUID first fields standing before a dash, in any case, or null when there are none. */
function guidPrefixPattern(prefixes: Iterable<string>): RegExp | null {
  const list = [...prefixes].filter((p) => /^[0-9a-f]{8}$/i.test(p));
  return list.length === 0 ? null : new RegExp(`(?<![0-9a-z])(?:${list.join("|")})(?=-)`, "gi");
}

/** Zero every one of these GUID first fields that stands before a dash, in any case. */
export function replaceGuidPrefixes(text: string, prefixes: Iterable<string>): string {
  const re = guidPrefixPattern(prefixes);
  return re ? text.replace(re, "00000000") : text;
}

/** Replace lab identifiers the same way in every capture, so decoded fields stay comparable. */
export function redact(caps: Capture[], literals: [string, string][], raw = false): Capture[] {
  literals.forEach(([, to], k) => {
    if (!SAFE_ALIAS.test(to)) throw new CaptureError(`--redact #${k + 1}: the ${ALIAS_RULE}`);
    if (aliasLooksRedactable(to)) throw new CaptureError(`--redact #${k + 1} ${ALIAS_SHAPE}`);
    if (!ALIAS_EDGES.test(to)) throw new CaptureError(`--redact #${k + 1} ${ALIAS_EDGE}`);
  });
  const clash = mappingClash(literals);
  if (clash) throw new CaptureError(clash);
  // Longest source first, so a name is replaced before any dot-separated suffix of it and the
  // order given changes nothing. The sort is stable; equal lengths cannot hold one another.
  const order = [...literals.keys()].sort((x, y) => literals[y][0].length - literals[x][0].length);
  const pats = order.map((k): Literal => [literalPattern(literals[k][0]), literals[k][1], k + 1]);
  const held = literals.map(([, to]) => literalPattern(to));
  const texts = caps.flatMap((c) => (c.message == null ? [c.xml] : [c.message, c.xml]));
  const prefixes = [...new Set(caps.flatMap((c) => sysmonGuidPrefixes(c.xml)))];
  const one = redactor(pats, raw, prefixes, takenIn([...texts, ...literals.map(([, to]) => to)]));
  return caps.map((c, i) => {
    const where = Number.isSafeInteger(c.record) ? `record ${c.record}` : `capture ${i}`;
    // A record cut short live must never become a fixture that decodes in full (see winevt.ts).
    if ([c.message ?? "", c.xml].some((t) => t.includes("\0"))) throw new CaptureError(`${where}: ${NUL_REFUSAL}`);
    // An alias already in the capture would merge a real token with the one it replaces.
    held.forEach((re, k) => {
      if ([c.message ?? "", c.xml].some((t) => t.search(re) !== -1)) {
        throw new CaptureError(`${where}: --redact #${k + 1}'s alias ${literals[k][1]} already occurs in the capture`);
      }
    });
    refuseShapeHits(c.xml, pats, where);
    // SECURITY: a source inside a base64 run takes an alias of another length, or one holding
    // . - or _, which shifts or splits the rest of the run, so each blob is read before redaction.
    for (const t of [c.message, c.xml]) if (t != null) refuseBlobs(t, where, pats, raw, prefixes);
    const out = { ...c, message: c.message == null ? c.message : one(c.message, where), xml: one(c.xml, where) };
    // SECURITY: an alias and the text beside it can spell a source that has already run, so
    // every source is sought again once all the passes are done.
    for (const [re, to, n] of pats) {
      if ([out.message ?? "", out.xml].some((t) => t.search(re) !== -1)) {
        throw new CaptureError(`${where}: --redact #${n} (to ${to}) still matches after redaction`);
      }
    }
    for (const t of [out.message, out.xml]) {
      if (t == null) continue;
      const leftover = raw ? null : leftoverPrivate(t);
      if (leftover) throw new CaptureError(`${where}: ${leftover}`);
      refuseBlobs(t, where, pats, raw, prefixes);
    }
    return out;
  });
}

/** The ssh argv for one capture: no prompts, bounded connect and liveness, host after "--". */
export function sshArgv(host: string, command: string): string[] {
  if (!SAFE_HOST.test(host)) throw new CaptureError("the ssh host alias holds characters an alias never has");
  const opts = ["BatchMode=yes", "ConnectTimeout=15", "ServerAliveInterval=15", "ServerAliveCountMax=4"];
  return ["ssh", ...opts.flatMap((o) => ["-o", o]), "--", host, command];
}

/** The captures in the remote answer, whose last line is base64 of UTF-8 JSON. */
export function decodeAnswer(stdout: string): Capture[] {
  const last = stdout.trim().split(/\r?\n/).pop() ?? "";
  if (!last || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(last)) {
    throw new CaptureError("the host did not answer with base64");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(last, "base64")));
  } catch {
    throw new CaptureError("the host's answer is not UTF-8 JSON");
  }
  if (!Array.isArray(parsed)) throw new CaptureError("the host's answer is not an array");
  // SECURITY: only the known fields go on, so nothing unredacted rides along in an extra one.
  return parsed.map((e: unknown, i) => {
    if (typeof e !== "object" || e === null || Array.isArray(e)) throw new CaptureError(`entry ${i} is not an object`);
    const { id, record, message, xml } = e as Record<string, unknown>;
    if (typeof xml !== "string") throw new CaptureError(`entry ${i} has no xml text`);
    if (message !== null && typeof message !== "string") throw new CaptureError(`entry ${i} has a message that is neither text nor null`);
    return {
      ...(Number.isSafeInteger(id) ? { id: id as number } : {}),
      ...(Number.isSafeInteger(record) ? { record: record as number } : {}),
      message,
      xml,
    };
  });
}

// *--- Entry Point ---*

if (import.meta.main) {
  const o = parseArgs(Bun.argv.slice(2));
  const encoded = Buffer.from(captureScript(o), "utf16le").toString("base64");
  const ssh = (() => {
    try {
      return Bun.spawnSync(sshArgv(o.host, `powershell -NoProfile -NonInteractive -EncodedCommand ${encoded}`), {
        stdout: "pipe",
        stderr: "pipe",
        timeout: SSH_TIMEOUT_MS,
      });
    } catch (e) {
      // An errno code such as ENOENT says why without the message's path or the stack.
      const code = (e as { code?: unknown } | null)?.code;
      fail(`ssh could not start (${typeof code === "string" && /^E[A-Z]{1,15}$/.test(code) ? code : e instanceof Error ? e.name : "unknown error"})`);
    }
  })();
  if (ssh.exitedDueToTimeout) fail(`ssh did not finish in ${SSH_TIMEOUT_MS / 1000} s`);
  // SECURITY: a failing remote PowerShell writes its error, event text, the endpoint's name
  // and addresses included, to the stderr ssh relays, with any escape sequences in it. None
  // of that passes redaction, so none is printed; the alias is the operator's own, SAFE_HOST.
  if (ssh.exitCode !== 0)
    fail(`ssh exited ${ssh.exitCode}; its output is not shown, since a failed capture's errors can hold event text: run ssh ${o.host} by hand to see why`);
  let out: Capture[] = [];
  try {
    out = redact(decodeAnswer(ssh.stdout.toString()), o.redact, o.raw);
  } catch (e) {
    // SECURITY: only a CaptureError's text is known to hold no captured value.
    fail(e instanceof CaptureError ? e.message : `redaction failed (${e instanceof Error ? e.name : "unknown error"})`);
  }
  console.log(JSON.stringify(out, null, 1));
  console.error(`winevt-capture: ${out.length} event(s)`);
}
