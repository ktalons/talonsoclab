#!/usr/bin/env bun
// *****************************************************************************
// *Title: wazuh-init*
// *Author: Kyle Versluis*
// *Description: Hold the owned 0-wazuh-init to stock outside its two blocks.*
// *****************************************************************************

// *--- Imports ---*

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// *--- Configuration ---*

const ROOT = resolve(import.meta.dir, "..");
export const OWNED = "deploy/soc-recon/wazuh/cont-init/0-wazuh-init";
// SECURITY: the stock text this copy shadows, wazuh/wazuh-manager 4.14.9. A new image means
// a new digest here, changed on purpose after a re-diff (ISA ISC-174, drill D0).
export const STOCK_SHA256 = "b22d6e7c06b51d11f7cb254bf0ca0e151f750170295d60f1a54d57edf3b4832b";
// One block fixes the restart trap, one is the backup hold. A third is a design change.
export const BLOCK_NAMES = ["fix", "hold"] as const;
const BANNER = /^# \*{78}$/;
const HEADER_FIELD = /^# \*(Title|Author|Description): .+\*$/;
const MARKER = /^# F7-BLOCK-(\d+) (begin|stock|end)(: .+)?$/;
// A recorded stock line: "#|" then the stock line exactly as it was.
const RECORD = "#|";

// *--- Types ---*

export interface Rebuild {
  /** The stock text rebuilt from the owned copy. */
  stock: string;
  /** SHA-256 of the rebuilt stock text. */
  sha256: string;
  /** Every way the owned copy breaks the contract; empty when it holds. */
  problems: string[];
}

// *--- Core Logic ---*

/** Strip the added header and put each block's recorded stock lines back. */
export function rebuildStock(owned: string): Rebuild {
  const problems: string[] = [];
  const lines = owned.split("\n");
  const out: string[] = [];

  // Line 1 is the stock shebang. The header follows it in two parts: the five-line banner
  // block, then comment lines after the stock copyright line, up to the first other line.
  if (lines.length < 8) problems.push("too short to hold the header");
  out.push(lines[0] ?? "");
  let i = 1;
  const banner = lines.slice(1, 6);
  if (banner.length !== 5 || !BANNER.test(banner[0]) || !BANNER.test(banner[4]) || !banner.slice(1, 4).every((l) => HEADER_FIELD.test(l))) {
    problems.push("lines 2 to 6 are not the Title, Author and Description banner");
  } else {
    i = 6;
  }
  out.push(lines[i] ?? "");
  i++;
  while (i < lines.length && lines[i].startsWith("#") && !MARKER.test(lines[i])) i++;

  let expected = 1;
  let state: "outside" | "new" | "stock" = "outside";
  let open = 0;
  for (; i < lines.length; i++) {
    const line = lines[i];
    const m = MARKER.exec(line);
    if (!m) {
      if (line.includes("F7-BLOCK")) problems.push(`line ${i + 1}: a malformed block marker`);
      if (state === "outside") out.push(line);
      else if (state === "stock") {
        if (line.startsWith(RECORD)) out.push(line.slice(RECORD.length));
        else problems.push(`line ${i + 1}: block ${open} holds a stock line that does not start with "${RECORD}"`);
      }
      continue;
    }
    const n = Number(m[1]);
    const kind = m[2];
    if (kind === "begin") {
      if (state !== "outside") problems.push(`line ${i + 1}: block ${n} begins inside block ${open}`);
      if (n !== expected) problems.push(`line ${i + 1}: block ${n} where block ${expected} was due`);
      if (!m[3]) problems.push(`line ${i + 1}: block ${n} begins with no reason`);
      state = "new";
      open = n;
      expected = n + 1;
    } else if (kind === "stock") {
      if (state !== "new" || n !== open) problems.push(`line ${i + 1}: a stock marker for block ${n} outside its new lines`);
      state = "stock";
    } else {
      if (state !== "stock" || n !== open) problems.push(`line ${i + 1}: block ${n} ends without its stock marker`);
      state = "outside";
    }
  }
  if (state !== "outside") problems.push(`block ${open} never ends`);
  const blocks = expected - 1;
  if (blocks !== BLOCK_NAMES.length) problems.push(`${blocks} blocks, want ${BLOCK_NAMES.length}`);

  const stock = out.join("\n");
  const sha256 = createHash("sha256").update(stock).digest("hex");
  if (sha256 !== STOCK_SHA256) problems.push(`the rebuilt stock text hashes ${sha256}, want ${STOCK_SHA256}`);
  return { stock, sha256, problems };
}

// *--- Entry Point ---*

if (import.meta.main) {
  const [cmd, file] = Bun.argv.slice(2);
  if ((cmd !== "check" && cmd !== "stock") || Bun.argv.length > 4) {
    console.error("usage: bun tools/wazuh-init.ts check|stock [owned file]");
    process.exit(2);
  }
  const path = resolve(ROOT, file ?? OWNED);
  const { stock, problems } = rebuildStock(readFileSync(path, "utf8"));
  if (cmd === "stock") {
    // NOTE: the rebuilt bytes go out even when they are wrong, so a re-diff shows where.
    process.stdout.write(stock);
    for (const p of problems) console.error(`wazuh-init: ${p}`);
  } else {
    for (const p of problems) console.log(`${file ?? OWNED}: ${p}`);
    console.error(`wazuh-init: ${problems.length} finding(s)`);
  }
  process.exit(problems.length ? 1 : 0);
}
