// *****************************************************************************
// *Title: apparmor-profiles.test*
// *Author: Kyle Versluis*
// *Description: Planted profile and compose faults the check must refuse.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, describe, expect, test } from "bun:test";
import { cpSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { check, COMPOSE, PROFILE_DIR, PROFILES, REFERENCE, render, SERVICES, write } from "./apparmor-profiles.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const LIVE_DIR = resolve(ROOT, PROFILE_DIR);
const LIVE_COMPOSE = readFileSync(resolve(ROOT, COMPOSE), "utf8");
const reference = readFileSync(join(LIVE_DIR, REFERENCE), "utf8");
const made: string[] = [];
// A throwaway copy of the profile folder for one planted fault.
const copy = () => {
  const dir = mkdtempSync(join(tmpdir(), "apparmor-profiles-"));
  made.push(dir);
  cpSync(LIVE_DIR, dir, { recursive: true });
  return dir;
};
const compose = (services: Record<string, string[] | null>, extra = "") =>
  "services:\n" +
  Object.entries(services)
    .map(([s, opts]) => `  ${s}:\n    image: x\n${opts === null ? "" : `    security_opt: [${opts.map((o) => `"${o}"`).join(", ")}]\n`}${extra}`)
    .join("");
const GOOD = Object.fromEntries(Object.entries(SERVICES).map(([s, p]) => [s, [`apparmor=${p}`]]));
const problems = (dir: string, text: string, composeDir?: string) => check(dir, text, composeDir).map((x) => `${x.file}: ${x.problem}`);

afterAll(() => {
  for (const d of made) rmSync(d, { recursive: true, force: true });
});

// *--- Tests ---*

describe("render", () => {
  test("a service profile is the reference with only its three names changed", () => {
    const text = render(reference, "soc-recon-manager", "wazuh.manager");
    const body = text.slice(text.indexOf("# profile generated"));
    expect(body.split('"soc-recon-manager"').length).toBe(4);
    expect(body.split('"soc-recon-manager"').join('"docker-default"')).toBe(reference);
    expect(body).not.toContain("docker-default");
  });

  test("every line above the reference text is a comment", () => {
    const text = render(reference, "soc-recon-indexer", "wazuh.indexer");
    const head = text.slice(0, text.indexOf("# profile generated")).split("\n").filter(Boolean);
    expect(head.length).toBeGreaterThan(0);
    for (const line of head) expect(line.startsWith("#")).toBe(true);
  });

  test("refuses a reference that does not name itself three times", () => {
    expect(() => render(reference.replace('peer="docker-default"', "peer=x"), "soc-recon-manager", "m")).toThrow(/2 times/);
  });

  for (const name of ["soc recon", 'a"b', "Soc-Recon", "a=b", ""]) {
    test(`refuses the profile name ${JSON.stringify(name)}`, () => {
      expect(() => render(reference, name, "m")).toThrow(/kebab-case/);
    });
  }
});

describe("check: profile folder", () => {
  test("the committed folder and compose file are clean", () => {
    expect(problems(LIVE_DIR, LIVE_COMPOSE)).toEqual([]);
  });

  test("the reference still carries the denies the copies must keep", () => {
    for (const line of ["deny mount,", "deny network alg,", "deny network vsock,", "deny /sys/kernel/security/** rwklx,"]) {
      expect(reference).toContain(`  ${line}\n`);
    }
    expect(reference).toContain("abi <abi/3.0>,\n");
  });

  // ISA ISC-115, R1: a copy under its own name and nothing tighter or looser.
  test("refuses a profile with one rule removed", () => {
    const dir = copy();
    const p = join(dir, "soc-recon-suricata");
    writeFileSync(p, readFileSync(p, "utf8").replace("  deny mount,\n", ""));
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["soc-recon-suricata: differs from docker-default.reference by more than its name"]);
  });

  test("refuses a profile with one rule added", () => {
    const dir = copy();
    const p = join(dir, "soc-recon-manager");
    writeFileSync(p, readFileSync(p, "utf8").replace("  capability,\n", "  capability,\n  change_profile,\n"));
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["soc-recon-manager: differs from docker-default.reference by more than its name"]);
  });

  test("refuses a profile whose peer still names another profile", () => {
    const dir = copy();
    const p = join(dir, "soc-recon-indexer");
    writeFileSync(p, readFileSync(p, "utf8").replace('signal (send,receive) peer="soc-recon-indexer"', 'signal (send,receive) peer="soc-recon-manager"'));
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["soc-recon-indexer: differs from docker-default.reference by more than its name"]);
  });

  test("refuses a missing profile file", () => {
    const dir = copy();
    unlinkSync(join(dir, "soc-recon-dashboard"));
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["soc-recon-dashboard: profile file is missing"]);
  });

  test("refuses a missing reference", () => {
    const dir = copy();
    unlinkSync(join(dir, REFERENCE));
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["docker-default.reference: reference profile is missing"]);
  });

  test("refuses a file no service uses", () => {
    const dir = copy();
    writeFileSync(join(dir, "soc-recon-extra"), "profile x {}\n");
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["soc-recon-extra: file in the profile folder that no service uses"]);
  });

  test("a changed reference fails its digest and every copy made from the old one", () => {
    const dir = copy();
    writeFileSync(join(dir, REFERENCE), reference.replace("  umount,\n", ""));
    const got = problems(dir, LIVE_COMPOSE);
    expect(got).toContain("docker-default.reference: does not match the pinned digest");
    expect(got.length).toBe(PROFILES.length + 1);
  });

  // Audit 2026-11-14: the reference was trusted as it stood, so a weakened reference with
  // four copies rebuilt from it passed.
  test("refuses a weakened reference even when all four copies are rebuilt from it", () => {
    const dir = copy();
    writeFileSync(join(dir, REFERENCE), reference.replace("  deny mount,\n", ""));
    write(dir);
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["docker-default.reference: does not match the pinned digest"]);
  });

  test("refuses a reference with one rule added, copies rebuilt", () => {
    const dir = copy();
    writeFileSync(join(dir, REFERENCE), reference.replace("  capability,\n", "  capability,\n  ptrace (trace,read) peer=unconfined,\n"));
    write(dir);
    expect(problems(dir, LIVE_COMPOSE)).toEqual(["docker-default.reference: does not match the pinned digest"]);
  });
});

describe("check: compose file", () => {
  const C = `${COMPOSE}: `;

  test("a compose file with one profile per service passes", () => {
    expect(problems(LIVE_DIR, compose(GOOD))).toEqual([]);
  });

  test("accepts the colon form of the option", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, suricata: ["apparmor:soc-recon-suricata"] }))).toEqual([]);
  });

  test("refuses a service with no security_opt", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, "wazuh.dashboard": null }))).toEqual([
      `${C}wazuh.dashboard: 0 apparmor entries in security_opt, need 1`,
    ]);
  });

  test("refuses a service left on docker-default", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, "wazuh.indexer": ["apparmor=docker-default"] }))).toEqual([
      `${C}wazuh.indexer: runs under docker-default, want soc-recon-indexer`,
    ]);
  });

  test("refuses an unconfined service", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, suricata: ["apparmor=unconfined"] }))).toEqual([
      `${C}suricata: runs under unconfined, want soc-recon-suricata`,
    ]);
  });

  // ISA ISC-116: the label must name one service, so no two services may share a profile.
  test("refuses a service under another service's profile", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, "wazuh.dashboard": ["apparmor=soc-recon-manager"] }))).toEqual([
      `${C}wazuh.dashboard: runs under soc-recon-manager, want soc-recon-dashboard`,
    ]);
  });

  test("refuses two apparmor entries on one service", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, suricata: ["apparmor=soc-recon-suricata", "apparmor=unconfined"] }))).toEqual([
      `${C}suricata: 2 apparmor entries in security_opt, need 1`,
    ]);
  });

  test("ignores other security options beside the profile", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, suricata: ["no-new-privileges:true", "apparmor=soc-recon-suricata"] }))).toEqual([]);
  });

  test("refuses a new service with no mapped profile", () => {
    expect(problems(LIVE_DIR, compose({ ...GOOD, recon: ["apparmor=soc-recon-manager"] }))).toEqual([
      `${C}recon: no profile is mapped to this service`,
    ]);
  });

  test("refuses a mapped service that left the compose file", () => {
    const { suricata: _, ...rest } = GOOD;
    expect(problems(LIVE_DIR, compose(rest))).toEqual([`${C}service suricata is not in the compose file`]);
  });

  test("refuses a privileged service", () => {
    const text = compose({ suricata: ["apparmor=soc-recon-suricata"] }, "    privileged: true\n") + compose(GOOD).replace("services:\n", "").replace(/  suricata:\n(    .*\n)+/, "");
    expect(problems(LIVE_DIR, text)).toEqual([`${C}suricata: privileged, so no profile applies`]);
  });

  // Audit 2026-11-14: the check reads one file, and compose builds a service from more than
  // that. Each of these passed while compose would have run the service privileged or
  // under another profile.
  test("refuses a service that extends another", () => {
    const text = compose(GOOD).replace("  suricata:\n", "  suricata:\n    extends: { file: base.yml, service: priv }\n");
    expect(problems(LIVE_DIR, text)).toEqual([`${C}suricata: extends another service, which this check cannot follow`]);
  });

  test("refuses a compose file that includes another", () => {
    expect(problems(LIVE_DIR, "include:\n  - extra.yml\n" + compose(GOOD))).toEqual([`${C}include pulls in files this check cannot read`]);
  });

  for (const opt of ["apparmor=${SURICATA_PROFILE}", "apparmor=${P:-soc-recon-suricata}", "apparmor=$P"]) {
    test(`refuses an interpolated profile name: ${opt}`, () => {
      const got = problems(LIVE_DIR, compose({ ...GOOD, suricata: [opt] }));
      expect(got).toContain(`${C}suricata: security_opt is set from a variable`);
    });
  }

  test("refuses privileged set through a merge key", () => {
    const text = "x-base: &base\n  privileged: true\n" + compose(GOOD).replace("  suricata:\n", "  suricata:\n    <<: *base\n");
    expect(problems(LIVE_DIR, text)).toEqual([`${C}suricata: privileged, so no profile applies`]);
  });

  test("refuses privileged written as a string or a variable", () => {
    for (const v of ['"true"', '"${PRIV}"']) {
      const text = compose({ suricata: ["apparmor=soc-recon-suricata"] }, `    privileged: ${v}\n`) + compose(GOOD).replace("services:\n", "").replace(/  suricata:\n(    .*\n)+/, "");
      expect(problems(LIVE_DIR, text)).toEqual([`${C}suricata: privileged, so no profile applies`]);
    }
  });

  test("refuses a runtime other than the default", () => {
    const text = compose(GOOD).replace("  suricata:\n", "  suricata:\n    runtime: io.containerd.kata.v2\n");
    expect(problems(LIVE_DIR, text)).toEqual([`${C}suricata: sets a runtime, so the profile may not apply`]);
  });

  // Audit round 2, 2026-11-14: a tag may sit on the line after its key, where a scan for
  // ": !tag" missed it. The parser drops tags, so any "!" outside a comment line is refused.
  const TAGGED = `${C}holds "!", which may be a YAML tag that changes how compose merges this file`;
  for (const tag of ["!reset", "!override", "!!seq", "!custom"]) {
    test(`refuses the tag ${tag} on the key's line`, () => {
      const text = compose(GOOD).replace('security_opt: ["apparmor=soc-recon-suricata"]', `security_opt: ${tag} ["apparmor=soc-recon-suricata"]`);
      expect(problems(LIVE_DIR, text)).toEqual([TAGGED]);
    });

    test(`refuses the tag ${tag} on the next line`, () => {
      const text = compose(GOOD).replace('security_opt: ["apparmor=soc-recon-suricata"]', `security_opt:\n      ${tag} ["apparmor=soc-recon-suricata"]`);
      expect(problems(LIVE_DIR, text)).toEqual([TAGGED]);
    });
  }

  test("refuses a tag after a quoted key that holds a #", () => {
    const text = compose(GOOD).replace("  suricata:\n", '  suricata:\n    labels: { "a #b": !reset x }\n');
    expect(problems(LIVE_DIR, text)).toEqual([TAGGED]);
  });

  test("a line that is only a comment may hold a !", () => {
    expect(problems(LIVE_DIR, "# CHANGE THEM! and see !reset in the compose docs\n" + compose(GOOD))).toEqual([]);
  });

  test("refuses an override file beside the compose file", () => {
    for (const name of ["docker-compose.override.yml", "compose.override.yaml"]) {
      const dir = mkdtempSync(join(tmpdir(), "apparmor-compose-"));
      made.push(dir);
      writeFileSync(join(dir, name), "services: {}\n");
      expect(problems(LIVE_DIR, compose(GOOD), dir)).toEqual([`${name}: compose merges this file over the one checked`]);
    }
  });

  // Audit round 2, 2026-11-14: compose looks for these names too.
  test("refuses a compose file that would be read in place of the one checked", () => {
    for (const name of ["compose.yaml", "compose.yml", "docker-compose.yaml"]) {
      const dir = mkdtempSync(join(tmpdir(), "apparmor-compose-"));
      made.push(dir);
      writeFileSync(join(dir, name), "services: {}\n");
      expect(problems(LIVE_DIR, compose(GOOD), dir)).toEqual([`${name}: a second compose file; compose may read it in place of the one checked`]);
    }
  });

  test("the folder that holds the live compose file has no override file", () => {
    expect(problems(LIVE_DIR, LIVE_COMPOSE, resolve(ROOT, "deploy/soc-recon"))).toEqual([]);
  });

  test("refuses a compose file that does not parse", () => {
    expect(problems(LIVE_DIR, "services:\n  a: [")).toEqual([`${C}compose file does not parse`]);
  });
});
