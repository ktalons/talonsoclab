#!/usr/bin/env bun
// *****************************************************************************
// *Title: apparmor-profiles*
// *Author: Kyle Versluis*
// *Description: Hold each compose service to its own copy of docker-default.*
// *****************************************************************************

// *--- Imports ---*

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const DEPLOY = "deploy/soc-recon";
export const PROFILE_DIR = `${DEPLOY}/apparmor`;
export const COMPOSE = `${DEPLOY}/docker-compose.yml`;
// Docker's own profile as the box renders it. See PROFILE_DIR/README.md for where it comes from.
export const REFERENCE = "docker-default.reference";
// SECURITY: the reference is the root every profile is checked against, so it is pinned.
// A new Docker template means a new digest here, changed on purpose beside the new text.
export const REFERENCE_SHA256 = "93651c1f3c0f17c84bf7a2f2af85daf18eb0d031ca540a594f632f2862e7685d";
// Files compose merges over the one checked, without being asked.
const OVERRIDES = ["compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml"];
// Other names compose looks for in the same folder. With one of them present, which file a
// bare "docker compose up" reads is no longer certain to be the one checked.
const SHADOWS = ["compose.yaml", "compose.yml", "docker-compose.yaml"];
const DEFAULT_NAME = "docker-default";
// The template names itself three times: the profile line, the signal peer, the ptrace peer.
const NAME_COUNT = 3;
// Compose service to profile, one to one. A new service is added here on purpose.
export const SERVICES: Record<string, string> = {
  "wazuh.indexer": "soc-recon-indexer",
  "wazuh.manager": "soc-recon-manager",
  "wazuh.dashboard": "soc-recon-dashboard",
  suricata: "soc-recon-suricata",
};
export const PROFILES = Object.values(SERVICES);
// Files the profile folder may hold besides one file per profile.
const EXTRA_FILES = new Set([REFERENCE, "README.md"]);

// *--- Types ---*

export interface Finding {
  file: string;
  problem: string;
}

interface ComposeService {
  security_opt?: unknown;
  privileged?: unknown;
  extends?: unknown;
  runtime?: unknown;
}

// *--- Helper Functions ---*

const header = (name: string, service: string) =>
  [
    `# ${name}: AppArmor profile for the ${service} service (ISA ISC-115).`,
    `# Docker's docker-default under this service's own name, so the label in an audit`,
    `# record names the service. Nothing else differs from ${REFERENCE}.`,
    `# Written by tools/apparmor-profiles.ts --write. Do not edit by hand.`,
    "",
  ].join("\n");

// *--- Core Logic ---*

/** One service's profile: the reference with its three names swapped, under a header. */
export function render(reference: string, name: string, service: string): string {
  const parts = reference.split(`"${DEFAULT_NAME}"`);
  if (parts.length !== NAME_COUNT + 1) {
    throw new Error(`${REFERENCE} names "${DEFAULT_NAME}" ${parts.length - 1} times, expected ${NAME_COUNT}`);
  }
  // NOTE: the name is quoted in the profile, but a quote or space would still split a subj= pin.
  if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new Error(`profile name ${name} is not lowercase kebab-case`);
  return header(name, service) + parts.join(`"${name}"`);
}

/** The apparmor entries of one compose service's security_opt. */
function apparmorOpts(svc: ComposeService): string[] | null {
  if (svc.security_opt === undefined) return [];
  if (!Array.isArray(svc.security_opt)) return null;
  return svc.security_opt
    .map(String)
    .filter((o) => /^apparmor[=:]/.test(o))
    .map((o) => o.replace(/^apparmor[=:]/, ""));
}

/**
 * Check the profile folder against the reference, then the compose file against SERVICES.
 * composeDir, when given, is searched for override files compose would merge in.
 */
export function check(dir: string, composeText: string, composeDir?: string): Finding[] {
  const out: Finding[] = [];
  const refPath = join(dir, REFERENCE);
  if (!existsSync(refPath)) return [{ file: REFERENCE, problem: "reference profile is missing" }];
  const reference = readFileSync(refPath, "utf8");
  if (new Bun.CryptoHasher("sha256").update(reference).digest("hex") !== REFERENCE_SHA256) {
    out.push({ file: REFERENCE, problem: "does not match the pinned digest" });
  }

  for (const [service, name] of Object.entries(SERVICES)) {
    const path = join(dir, name);
    let want: string;
    try {
      want = render(reference, name, service);
    } catch (e) {
      out.push({ file: REFERENCE, problem: (e as Error).message });
      break;
    }
    if (!existsSync(path)) out.push({ file: name, problem: "profile file is missing" });
    else if (readFileSync(path, "utf8") !== want) out.push({ file: name, problem: `differs from ${REFERENCE} by more than its name` });
  }
  if (new Set(PROFILES).size !== PROFILES.length) out.push({ file: "SERVICES", problem: "two services share a profile" });
  if (PROFILES.includes(DEFAULT_NAME)) out.push({ file: "SERVICES", problem: `a service is mapped to ${DEFAULT_NAME}` });
  for (const f of readdirSync(dir).sort()) {
    if (!EXTRA_FILES.has(f) && !PROFILES.includes(f)) out.push({ file: f, problem: "file in the profile folder that no service uses" });
  }

  let doc: { services?: Record<string, ComposeService> };
  try {
    doc = Bun.YAML.parse(composeText) as typeof doc;
  } catch {
    return [...out, { file: COMPOSE, problem: "compose file does not parse" }];
  }
  // WARN: this reads one file as written. Anything compose resolves from elsewhere is
  // refused here instead of followed: include, extends, a variable, an override file.
  if ((doc as Record<string, unknown>)?.include !== undefined) out.push({ file: COMPOSE, problem: "include pulls in files this check cannot read" });
  // SECURITY: a YAML tag (!reset, !override) changes what compose builds, and the parser
  // here drops tags without a trace. A tag can sit almost anywhere, on its own line too, so
  // no "!" at all outside a line that is only a comment.
  if (composeText.split("\n").some((line) => !/^\s*#/.test(line) && line.includes("!"))) {
    out.push({ file: COMPOSE, problem: 'holds "!", which may be a YAML tag that changes how compose merges this file' });
  }
  for (const name of composeDir ? OVERRIDES : []) {
    if (existsSync(join(composeDir as string, name))) out.push({ file: name, problem: "compose merges this file over the one checked" });
  }
  for (const name of composeDir ? SHADOWS : []) {
    if (existsSync(join(composeDir as string, name))) out.push({ file: name, problem: "a second compose file; compose may read it in place of the one checked" });
  }
  const services = doc?.services ?? {};
  for (const service of Object.keys(SERVICES)) {
    if (!(service in services)) out.push({ file: COMPOSE, problem: `service ${service} is not in the compose file` });
  }
  for (const [service, svc] of Object.entries(services)) {
    const bad = (problem: string) => out.push({ file: COMPOSE, problem: `${service}: ${problem}` });
    const want = SERVICES[service];
    if (!want) {
      bad("no profile is mapped to this service");
      continue;
    }
    // WARN: a privileged container runs unconfined whatever security_opt says.
    if (svc?.privileged) bad("privileged, so no profile applies");
    if (svc?.extends !== undefined) bad("extends another service, which this check cannot follow");
    // A sandboxed runtime runs the container in its own kernel, where a host profile is moot.
    if (svc?.runtime !== undefined) bad("sets a runtime, so the profile may not apply");
    const opts = apparmorOpts(svc ?? {});
    if (Array.isArray(svc?.security_opt) && svc.security_opt.some((o) => String(o).includes("$"))) bad("security_opt is set from a variable");
    else if (opts === null) bad("security_opt is not a list");
    else if (opts.length !== 1) bad(`${opts.length} apparmor entries in security_opt, need 1`);
    else if (opts[0] !== want) bad(`runs under ${opts[0]}, want ${want}`);
  }
  return out;
}

/** Write every service profile from the reference. */
export function write(dir: string): string[] {
  const reference = readFileSync(join(dir, REFERENCE), "utf8");
  return Object.entries(SERVICES).map(([service, name]) => {
    writeFileSync(join(dir, name), render(reference, name, service));
    return name;
  });
}

// *--- Entry Point ---*

if (import.meta.main) {
  const dir = resolve(ROOT, PROFILE_DIR);
  if (Bun.argv[2] === "--write") {
    for (const name of write(dir)) console.log(`wrote ${PROFILE_DIR}/${name}`);
  } else if (Bun.argv.length > 2) {
    console.error("usage: bun tools/apparmor-profiles.ts [--write]");
    process.exit(2);
  }
  const findings = check(dir, readFileSync(resolve(ROOT, COMPOSE), "utf8"), resolve(ROOT, DEPLOY));
  for (const f of findings) console.log(`${f.file}: ${f.problem}`);
  console.error(`apparmor-profiles: ${findings.length} finding(s)`);
  process.exit(findings.length ? 1 : 0);
}
