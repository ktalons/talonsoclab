// *****************************************************************************
// *Title: wazuh-init.test*
// *Author: Kyle Versluis*
// *Description: Owned 0-wazuh-init: stock bytes, trap fix and hold.*
// *****************************************************************************

// *--- Imports ---*

import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { OWNED, rebuildStock, STOCK_SHA256 } from "./wazuh-init.ts";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
const OWNED_TEXT = readFileSync(resolve(ROOT, OWNED), "utf8");
// The stock text, rebuilt from the owned copy; its first test proves the bytes by digest.
const STOCK_TEXT = rebuildStock(OWNED_TEXT).stock;
const COMPOSE = resolve(ROOT, "deploy/soc-recon/docker-compose.yml");
// The sandbox moves /srv/tier2 under its root, the path in this line included.
const HOLD_LINE = "Backup hold <root>/srv/tier2/HOLD is in place: no Wazuh configuration files mounted, see runbook 09";
const FIX_LINE = "empty: no restore source, an earlier init of this container removed data_tmp";
const TRAP_ERROR = "Error executing command: 'cp -ar ";
const made: string[] = [];

afterAll(() => {
  for (const d of made) rmSync(d, { recursive: true, force: true });
});

// *--- Helper Functions ---*

// The container runs bash 5. macOS ships 3.2 at /bin/bash, so a newer one is required.
function findBash(): string {
  for (const b of ["/opt/homebrew/bin/bash", "/usr/local/bin/bash", Bun.which("bash") ?? ""]) {
    if (!b || !existsSync(b)) continue;
    const v = Bun.spawnSync([b, "-c", "echo ${BASH_VERSINFO[0]}"]).stdout.toString().trim();
    if (Number(v) >= 4) return b;
  }
  throw new Error("no bash 4 or newer on this machine; the sandbox runs need one");
}
const BASH = findBash();

const plant = (text: string, from: string, to: string) => {
  if (!text.includes(from)) throw new Error(`plant target not found: ${from}`);
  return text.replace(from, to);
};
const problems = (text: string) => rebuildStock(text).problems;

// Paths the stock script names in code. Each is moved under the sandbox root; any other
// absolute path in a code line would escape the sandbox, so it fails the harness test.
const SWAP = /\/permanent_data\.env|\/wazuh-config-mount|\/var\/ossec|\/srv\/tier2|find \/ /g;
const NOT_PATHS = /\/dev\/null|\/CN=|<\\\/[a-z_]+>|\/g'/g;

/** The script text with every absolute path it uses moved under root, in one pass. */
function sandboxed(text: string, root: string): string {
  return text.replace(SWAP, (m) => (m === "find / " ? `find ${root}/ ` : `${root}${m}`));
}

// GNU behaviour the stock script relies on, from BSD tools, plus no-op ownership changes:
// the sandbox is not root, and in the container these chowns succeed.
const SHIMS: Record<string, string> = {
  cp: `#!/bin/bash
args=()
for a in "$@"; do
  case $a in --verbose) a=-v ;; -ar) a=-a ;; esac
  args+=("$a")
done
exec /bin/cp "\${args[@]}"
`,
  sed: `#!/bin/bash
if [ "$1" = -i ]; then shift; exec /usr/bin/sed -i '' "$@"; fi
exec /usr/bin/sed "$@"
`,
  chown: `#!/bin/bash
printf '%s\\n' "$*" >>"$CHOWN_LOG"
`,
  openssl: `#!/bin/bash
while [ $# -gt 0 ]; do [ "$1" = -out ] && : >"$2"; shift; done
`,
};

/** A fresh container: data_tmp holds the image payload, the volumes are empty. */
function sandbox(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "wazuh-init-")));
  made.push(root);
  if (/[\s*?[\]'"\\$]/.test(root)) throw new Error(`sandbox path unsafe for the unquoted stock script: ${root}`);
  const w = (rel: string, body: string) => {
    const p = join(root, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, body);
  };
  const perm = `var/ossec/data_tmp/permanent${root}/var/ossec`;
  w(`${perm}/etc/ossec.conf`, "<ossec_config>image</ossec_config>\n");
  w(`${perm}/etc/internal_options.conf`, "image\n");
  w(`${perm}/etc/sslmanager.key`, "key\n");
  w(`${perm}/etc/lists/audit-keys`, "list\n");
  w(`${perm}/queue/rids/sender`, "0\n");
  mkdirSync(join(root, perm, "var/multigroups"), { recursive: true });
  w(`var/ossec/data_tmp/exclusion${root}/var/ossec/etc/internal_options.conf`, "image\n");
  for (const v of ["etc", "var/multigroups", "queue"]) mkdirSync(join(root, "var/ossec", v), { recursive: true });
  w(
    "permanent_data.env",
    `PERMANENT_DATA=( "${root}/var/ossec/etc" "${root}/var/ossec/var/multigroups" "${root}/var/ossec/queue" )\n` +
      `PERMANENT_DATA_EXCP=( "${root}/var/ossec/etc/internal_options.conf" )\n` +
      "PERMANENT_DATA_MOVE=()\nPERMANENT_DATA_DEL=()\n",
  );
  w("wazuh-config-mount/etc/ossec.conf", "<node_name>to_be_replaced_by_hostname</node_name><key>to_be_replaced_by_cluster_key</key>\n");
  rule(root, "v1");
  mkdirSync(join(root, "srv/tier2"), { recursive: true });
  for (const [name, body] of Object.entries(SHIMS)) {
    w(`shims/${name}`, body);
    Bun.spawnSync(["chmod", "755", join(root, "shims", name)]);
  }
  return root;
}

/** The checkout's copy of one custom rule file, as the config mount shows it. */
function rule(root: string, body: string) {
  const p = join(root, "wazuh-config-mount/etc/rules/custom");
  mkdirSync(p, { recursive: true });
  writeFileSync(join(p, "local_test.xml"), `<!-- ${body} -->\n`);
}

/** The manager's installed copy of that rule file, or null. */
const installed = (root: string) => {
  const p = join(root, "var/ossec/etc/rules/custom/local_test.xml");
  return existsSync(p) ? readFileSync(p, "utf8") : null;
};

interface Run {
  code: number;
  out: string;
}

/** Run one init text in the sandbox, as s6 would at a container start. */
function init(text: string, root: string): Run {
  const script = join(root, "init.sh");
  writeFileSync(script, sandboxed(text, root));
  const r = Bun.spawnSync([BASH, "-c", 'exec "$0" "$1" 2>&1', BASH, script], {
    cwd: root,
    env: { PATH: `${root}/shims:/usr/bin:/bin`, HOME: root, HOSTNAME: "sandbox", LC_ALL: "C", WAZUH_CLUSTER_KEY: "sandbox-key", CHOWN_LOG: join(root, "chown.log") },
  });
  return { code: r.exitCode ?? -1, out: r.stdout.toString().split(root).join("<root>") };
}

/** Every file under var/ossec with its content digest, root-relative. */
function tree(root: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = join(d, e.name);
      const rel = p.slice(root.length).split(root).join("<root>");
      if (e.isDirectory()) {
        out.push(`dir  ${rel}`);
        walk(p);
      } else out.push(`file ${rel} ${createHash("sha256").update(readFileSync(p)).digest("hex").slice(0, 16)}`);
    }
  };
  walk(join(root, "var/ossec"));
  return out;
}

/** A sandbox past its first start: data_tmp gone, the installed ossec.conf planted back. */
function started(text: string): string {
  const root = sandbox();
  const first = init(text, root);
  if (first.code !== 0) throw new Error(`first start failed: ${first.out}`);
  writeFileSync(join(root, "var/ossec/etc/ossec.conf"), "<node_name>to_be_replaced_by_hostname</node_name>\n");
  rule(root, "v2");
  return root;
}

const hold = (root: string) => join(root, "srv/tier2/HOLD");

// *--- Tests: the stock bytes (ISC-174) ---*

describe("ISC-174: the owned script against the stock bytes", () => {
  test("the owned script rebuilds to the stock sha256 with exactly two blocks", () => {
    const r = rebuildStock(OWNED_TEXT);
    expect(r.problems).toEqual([]);
    expect(r.sha256).toBe(STOCK_SHA256);
    expect(r.stock.split("\n").length).toBe(239);
  });

  test("planted: one changed byte outside a block fails", () => {
    const p = problems(plant(OWNED_TEXT, "files to mount...", "files to mount.."));
    expect(p.join("\n")).toContain("the rebuilt stock text hashes");
  });

  test("planted: a changed byte in a recorded stock line fails", () => {
    const p = problems(plant(OWNED_TEXT, "#|main", "#|main "));
    expect(p.join("\n")).toContain("the rebuilt stock text hashes");
  });

  test("planted: a removed stock line fails", () => {
    const p = problems(plant(OWNED_TEXT, "  # Allow setting custom cluster key\n  set_custom_cluster_key\n", "  # Allow setting custom cluster key\n"));
    expect(p.join("\n")).toContain("the rebuilt stock text hashes");
  });

  test("planted: a third block fails even though it replaces nothing", () => {
    const third = "# F7-BLOCK-3 begin: more\necho extra\n# F7-BLOCK-3 stock\n# F7-BLOCK-3 end\n";
    const p = problems(plant(OWNED_TEXT, "# F7-BLOCK-2 end\n", `# F7-BLOCK-2 end\n${third}`));
    expect(p).toEqual(["3 blocks, want 2"]);
  });

  test("planted: a code line in the header fails", () => {
    const p = problems(plant(OWNED_TEXT, "(License GPLv2)\n#\n", "(License GPLv2)\ntouch /tmp/x\n#\n"));
    expect(p.join("\n")).toContain("the rebuilt stock text hashes");
  });

  test("planted: a stock section line that is not a record fails", () => {
    const p = problems(plant(OWNED_TEXT, "#|main", "main"));
    expect(p.join("\n")).toContain('does not start with "#|"');
  });

  test("planted: block markers out of order, unterminated, or without a reason fail", () => {
    expect(problems(OWNED_TEXT.replaceAll("F7-BLOCK-2", "F7-BLOCK-3")).join("\n")).toContain("block 3 where block 2 was due");
    expect(problems(plant(OWNED_TEXT, "# F7-BLOCK-2 end\n", "")).join("\n")).toContain("block 2 never ends");
    expect(problems(plant(OWNED_TEXT, "# F7-BLOCK-1 begin: the restart trap fix (ISA F7, compose GOTCHA 2)", "# F7-BLOCK-1 begin")).join("\n")).toContain(
      "begins with no reason",
    );
    expect(problems(plant(OWNED_TEXT, "# F7-BLOCK-1 stock", "# F7-BLOCK-1 stok")).join("\n")).toContain("malformed block marker");
  });

  test("control: a change inside a block's new lines or a header comment passes", () => {
    expect(problems(plant(OWNED_TEXT, "exit 75", "exit 76"))).toEqual([]);
    expect(problems(plant(OWNED_TEXT, "(License GPLv2)\n#\n", "(License GPLv2)\n# one more note\n#\n"))).toEqual([]);
  });

  test("the owned script is executable, as s6 runs it directly", () => {
    expect(statSync(resolve(ROOT, OWNED)).mode & 0o111).toBe(0o111);
  });

  test("compose binds it read-only over the image's copy, failing the start when missing", () => {
    const doc = Bun.YAML.parse(readFileSync(COMPOSE, "utf8")) as { services: Record<string, { volumes: unknown[] }> };
    const binds = doc.services["wazuh.manager"].volumes.filter(
      (v): v is Record<string, unknown> => typeof v === "object" && v !== null && (v as Record<string, unknown>).target === "/etc/cont-init.d/0-wazuh-init",
    );
    expect(binds).toEqual([
      { type: "bind", source: "./wazuh/cont-init/0-wazuh-init", target: "/etc/cont-init.d/0-wazuh-init", read_only: true, bind: { create_host_path: false } },
    ]);
  });
});

// *--- Tests: behaviour in a sandbox ---*

describe("the sandbox harness", () => {
  test("every absolute path in a stock code line is moved under the root", () => {
    const code = STOCK_TEXT.split("\n").filter((l) => !l.trimStart().startsWith("#"));
    const left = code.map((l) => l.replace(SWAP, "@root").replace(NOT_PATHS, "")).filter((l) => /(^|[\s"'=(])\//.test(l));
    expect(left).toEqual([]);
  });

  test("a first start installs the config mount and removes data_tmp, owned and stock alike", () => {
    for (const text of [STOCK_TEXT, OWNED_TEXT]) {
      const root = sandbox();
      const r = init(text, root);
      expect(r.code).toBe(0);
      expect(r.out).toContain("Identified Wazuh configuration files to mount...");
      expect(installed(root)).toBe("<!-- v1 -->\n");
      expect(existsSync(join(root, "var/ossec/data_tmp"))).toBe(false);
      expect(readFileSync(join(root, "var/ossec/etc/ossec.conf"), "utf8")).toContain("<key>sandbox-key</key>");
    }
  });
});

describe("the restart trap and its fix", () => {
  test("control: the stock script exits 1 before mount_files on a second start", () => {
    const root = started(STOCK_TEXT);
    const r = init(STOCK_TEXT, root);
    expect(r.code).toBe(1);
    expect(r.out).toContain(`${TRAP_ERROR}<root>/var/ossec/data_tmp/permanent<root>/var/ossec/var/multigroups/. <root>/var/ossec/var/multigroups'.`);
    expect(r.out).not.toContain("Identified Wazuh configuration files to mount...");
    expect(installed(root)).toBe("<!-- v1 -->\n");
    // It stopped before every later step too: the hostname placeholder is still there.
    expect(readFileSync(join(root, "var/ossec/etc/ossec.conf"), "utf8")).toContain("to_be_replaced_by_hostname");
  });

  test("the owned script installs the change on the same second start and exits 0", () => {
    const root = started(OWNED_TEXT);
    const r = init(OWNED_TEXT, root);
    expect(r.code).toBe(0);
    expect(r.out).toContain(`Left <root>/var/ossec/var/multigroups ${FIX_LINE}`);
    expect(r.out.split(FIX_LINE).length).toBe(2);
    expect(r.out).not.toContain(TRAP_ERROR);
    expect(r.out).toContain("Identified Wazuh configuration files to mount...");
    expect(installed(root)).toBe("<!-- v2 -->\n");
    expect(readdirSync(join(root, "var/ossec/var/multigroups"))).toEqual([]);
  });

  test("a missing source on a first start fails exactly as stock does", () => {
    const runs = [STOCK_TEXT, OWNED_TEXT].map((text) => {
      const root = sandbox();
      rmSync(join(root, `var/ossec/data_tmp/permanent${root}/var/ossec/var/multigroups`), { recursive: true });
      return { ...init(text, root), tree: tree(root) };
    });
    expect(runs[0].code).toBe(1);
    expect(runs[0].out).toContain(TRAP_ERROR);
    expect(runs[1]).toEqual(runs[0]);
  });

  test("with no hold and no trap, the owned script matches stock byte for byte", () => {
    for (const setup of ["first start", "second start, multigroups not empty"]) {
      const runs = [STOCK_TEXT, OWNED_TEXT].map((text) => {
        const root = setup === "first start" ? sandbox() : started(text);
        if (setup !== "first start") writeFileSync(join(root, "var/ossec/var/multigroups/group"), "x\n");
        return { ...init(text, root), tree: tree(root) };
      });
      expect(runs[0].code).toBe(0);
      expect(runs[1]).toEqual(runs[0]);
    }
  });
});

describe("the backup hold", () => {
  const kinds: Record<string, (p: string) => void> = {
    "a well-formed marker": (p) => writeFileSync(p, "hold 1764000000\n"),
    "an empty file": (p) => writeFileSync(p, ""),
    "a link to a file": (p) => {
      writeFileSync(`${p}.real`, "hold 1764000000\n");
      symlinkSync(`${p}.real`, p);
    },
    "a dangling link": (p) => symlinkSync(`${p}.nowhere`, p),
    "a folder": (p) => mkdirSync(p),
    "a FIFO": (p) => {
      if (Bun.spawnSync(["mkfifo", p]).exitCode !== 0) throw new Error("mkfifo failed");
    },
  };

  for (const [kind, make] of Object.entries(kinds)) {
    test(`${kind} holds: nothing copied, the log names the hold, exit 75`, () => {
      const root = started(OWNED_TEXT);
      make(hold(root));
      const r = init(OWNED_TEXT, root);
      expect(r.code).toBe(75);
      expect(r.out.split(HOLD_LINE).length).toBe(2);
      expect(r.out).not.toContain("Identified Wazuh configuration files to mount...");
      expect(installed(root)).toBe("<!-- v1 -->\n");
    });
  }

  test("under a hold every other step of main still runs", () => {
    const root = started(OWNED_TEXT);
    writeFileSync(hold(root), "hold 1764000000\n");
    const r = init(OWNED_TEXT, root);
    expect(r.code).toBe(75);
    expect(r.out).toContain(`Left <root>/var/ossec/var/multigroups ${FIX_LINE}`);
    expect(readFileSync(join(root, "var/ossec/etc/ossec.conf"), "utf8")).not.toContain("to_be_replaced_by_hostname");
    expect(readFileSync(join(root, "chown.log"), "utf8")).toContain(`-R wazuh:wazuh ${root}/var/ossec/etc/lists`);
  });

  test("a new container under a hold restores permanent data, installs nothing, removes data_tmp", () => {
    const root = sandbox();
    writeFileSync(hold(root), "hold 1764000000\n");
    const r = init(OWNED_TEXT, root);
    expect(r.code).toBe(75);
    expect(r.out).toContain("Updating <root>/var/ossec/etc/internal_options.conf");
    expect(installed(root)).toBeNull();
    expect(readFileSync(join(root, "var/ossec/etc/ossec.conf"), "utf8")).toBe("<ossec_config>image</ossec_config>\n");
    expect(existsSync(join(root, "var/ossec/data_tmp"))).toBe(false);
  });

  test("an error under a hold still exits 1, not 75", () => {
    const root = sandbox();
    rmSync(join(root, `var/ossec/data_tmp/permanent${root}/var/ossec/var/multigroups`), { recursive: true });
    writeFileSync(hold(root), "hold 1764000000\n");
    const r = init(OWNED_TEXT, root);
    expect(r.code).toBe(1);
    expect(r.out).toContain(TRAP_ERROR);
  });

  // NOTE: no lowercase "hold" here: macOS volumes are case-insensitive, so it is the same
  // entry. The box's ext4 is case-sensitive and test -e matches the exact name.
  for (const name of [".HOLD.tmp", "HOLD.bak", "HOLDX", "HOLD~"]) {
    test(`a neighbour named ${name} is not a hold: the copy runs, exit 0`, () => {
      const root = started(OWNED_TEXT);
      writeFileSync(join(root, "srv/tier2", name), "hold 1764000000\n");
      const r = init(OWNED_TEXT, root);
      expect(r.code).toBe(0);
      expect(r.out).not.toContain(HOLD_LINE);
      expect(installed(root)).toBe("<!-- v2 -->\n");
    });
  }

  test("the hold released, the next start installs and exits 0", () => {
    const root = started(OWNED_TEXT);
    writeFileSync(hold(root), "hold 1764000000\n");
    expect(init(OWNED_TEXT, root).code).toBe(75);
    rmSync(hold(root));
    const r = init(OWNED_TEXT, root);
    expect(r.code).toBe(0);
    expect(installed(root)).toBe("<!-- v2 -->\n");
  });
});
