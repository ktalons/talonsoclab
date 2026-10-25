#!/usr/bin/env bun
// *****************************************************************************
// *Title: noise-lint*
// *Author: Kyle Versluis*
// *Description: Hold every Wazuh suppression rule to the B.0 keying rules.*
// *****************************************************************************

// *--- Imports ---*

import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const RULES_DIR = "deploy/soc-recon/wazuh/custom-rules";
const NOISE_MIN = 100100;
const NOISE_MAX = 100199;
// log_alert_level in config/wazuh_cluster/wazuh_manager.conf. Any rule below it is never
// indexed, so it silences as surely as level 0.
const LOG_ALERT_LEVEL = 3;
// Parents a suppression may hang off. A new parent is added here on purpose, never by accident.
const PARENTS = new Set(["80792"]);
// Fields that name the process image. A suppression must pin one, anchored.
const IMAGE_FIELDS = new Set(["audit.exe", "win.eventdata.image"]);
// An auditd suppression pins all of these (NOISE-BASELINE.md "How the suppressions are keyed").
const AUDIT_FIELDS = ["audit.auid", "audit.tty", "audit.exe", "audit.cwd", "audit.uid", "audit.euid", "audit.gid"];
// Probes for a pattern that matches anything: the empty string and a value no rule names.
const PROBES = ["", "zq9 not-a-real-value /tmp/x;id"];
// NOTE: silencing rules outside the noise range, each kept on purpose. 100200 is the
// Phase A Suricata ethertype rule; narrowing it is out of Phase B scope (ISA).
const GRANDFATHERED = new Set([100200]);

// *--- Types ---*

export interface Finding {
  file: string;
  rule: number;
  problem: string;
}

// *--- Helper Functions ---*

// JS RegExp stands in for PCRE2 here; every construct the rules use means the same in both.
// A pattern JS cannot compile fails closed.
function compiles(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

// One rule's matchers (<field>, <regex>, <match>) with their attributes and pattern.
function matchers(inner: string) {
  return [...inner.matchAll(/<(field|regex|match)\b([^>]*)>([\s\S]*?)<\/\1>/g)].map((m) => ({
    tag: m[1],
    name: /\bname="([^"]+)"/.exec(m[2])?.[1] ?? "",
    attrs: m[2],
    pattern: m[3].trim(),
  }));
}

// *--- Core Logic ---*

// Lint one rules file. Comments are dropped first so a commented-out rule is ignored.
export function lint(xml: string, file: string): Finding[] {
  const out: Finding[] = [];
  const body = xml.replace(/<!--[\s\S]*?-->/g, "");
  if (body.includes("<![CDATA[")) out.push({ file, rule: 0, problem: "CDATA in a rules file" });
  for (const m of body.matchAll(/<rule\b([^>]*)>([\s\S]*?)<\/rule>/g)) {
    const attrs = m[1];
    const inner = m[2];
    const id = Number(/\bid="(\d+)"/.exec(attrs)?.[1] ?? NaN);
    const level = Number(/\blevel="(\d+)"/.exec(attrs)?.[1] ?? NaN);
    const bad = (problem: string) => out.push({ file, rule: id, problem });
    const inRange = id >= NOISE_MIN && id <= NOISE_MAX;
    if (Number.isNaN(id) || Number.isNaN(level)) {
      bad("rule without a numeric id and level");
      continue;
    }
    const silences =
      level < LOG_ALERT_LEVEL || /\bnoalert\s*=/.test(attrs) || /<options>[^<]*\bno_log\b/.test(inner);
    if (silences && !inRange && !GRANDFATHERED.has(id)) {
      bad(`silencing rule outside ${NOISE_MIN}-${NOISE_MAX}`);
      continue;
    }
    if (!inRange) continue;

    // Shape: level 0 under one listed parent, nothing else deciding whether it fires.
    if (level !== 0) bad("noise-range rule is not level 0");
    const parents = [...inner.matchAll(/<if_sid>([^<]*)<\/if_sid>/g)];
    if (parents.length === 0) bad("no if_sid parent");
    for (const p of parents) {
      for (const sid of p[1].split(/[\s,]+/).filter(Boolean)) {
        if (!PARENTS.has(sid)) bad(`if_sid ${sid} is not a listed parent`);
      }
    }
    for (const t of ["if_group", "if_level", "if_matched_sid", "if_matched_group"]) {
      if (inner.includes(`<${t}>`)) bad(`<${t}> parent`);
    }

    // Matchers: pcre2 only, never negated, never able to match anything.
    const all = matchers(inner);
    for (const x of all) {
      const label = x.name || `<${x.tag}>`;
      if (!/\btype="pcre2"/.test(x.attrs)) bad(`${label} is not type="pcre2"`);
      if (/\bnegate\s*=/.test(x.attrs)) bad(`${label} is negated`);
      const re = compiles(x.pattern);
      if (!re) bad(`${label} does not compile`);
      else if (PROBES.some((p) => re.test(p))) bad(`${label} matches anything`);
    }
    const fields = all.filter((x) => x.tag === "field");
    if (fields.length < 2) bad(`${fields.length} field constraint(s), need at least 2`);
    for (const f of fields) {
      if (!/^\^[\s\S]*\$$/.test(f.pattern)) bad(`${f.name} is not anchored ^...$`);
    }
    const image = fields.find((f) => IMAGE_FIELDS.has(f.name));
    if (!image) bad("no image field (audit.exe or win.eventdata.image)");

    // auditd shapes: every keying field, and the argv (or the failed path) pinned in full_log.
    if (image?.name === "audit.exe") {
      const names = new Set(fields.map((f) => f.name));
      for (const need of AUDIT_FIELDS) if (!names.has(need)) bad(`no ${need} field`);
      const failed = fields.some((f) => f.name === "audit.success" && f.pattern === "^no$");
      const regex = all.find((x) => x.tag === "regex");
      if (!regex) bad("no full_log regex");
      else {
        if (!/subj=\S+ key=/.test(regex.pattern)) bad("regex does not pin the AppArmor label");
        if (!failed && !/argc=\d+ /.test(regex.pattern)) bad("regex does not pin argc");
        if (failed && !/type=PATH /.test(regex.pattern)) bad("failed-exec regex does not pin the PATH record");
      }
    }
  }
  return out;
}

// Lint every file in the rules folder, and flag an id used twice anywhere in it.
export function lintDir(dir: string): Finding[] {
  const out: Finding[] = [];
  const seen = new Map<number, string>();
  for (const name of readdirSync(dir).filter((n) => n.endsWith(".xml")).sort()) {
    const path = join(dir, name);
    const file = relative(ROOT, path);
    const xml = readFileSync(path, "utf8");
    out.push(...lint(xml, file));
    const body = xml.replace(/<!--[\s\S]*?-->/g, "");
    for (const m of body.matchAll(/<rule\b[^>]*\bid="(\d+)"/g)) {
      const id = Number(m[1]);
      const prev = seen.get(id);
      if (prev) out.push({ file, rule: id, problem: `id also used in ${prev}` });
      else seen.set(id, file);
    }
  }
  return out;
}

// *--- Entry Point ---*

if (import.meta.main) {
  const dir = resolve(ROOT, Bun.argv[2] ?? RULES_DIR);
  const findings = lintDir(dir);
  for (const f of findings) console.log(`${f.file}: rule ${f.rule}: ${f.problem}`);
  console.error(`noise-lint: ${findings.length} finding(s)`);
  process.exit(findings.length ? 1 : 0);
}
