#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { analyze } from "./timeline.js";
import { boardMarkdown, brief } from "./board.js";
import type { Assumptions } from "./impact.js";

const USAGE = `breach-to-boardroom [--year YYYY] [--aware ISO-TIME] [--set key=value ...] [--json] FILE...

Reads Windows event exports, syslog auth.log and web access logs and prints a board-ready incident brief.
--set keys: downtimeCostPerHour recordsAtRisk costPerRecord annualRevenue responderRate iterations seed`;

function main(argv: string[]): number {
  const args = argv.slice(2);
  const files: string[] = [];
  const set: Partial<Assumptions> = {};
  let year: number | undefined;
  let aware: number | undefined;
  let json = false;
  const keys = ["downtimeCostPerHour", "recordsAtRisk", "costPerRecord", "annualRevenue", "responderRate", "iterations", "seed"] as const;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--help") { console.log(USAGE); return 0; }
    else if (a === "--json") json = true;
    else if (a === "--year") year = Number(args[++i]);
    else if (a === "--aware") { aware = Date.parse(args[++i] ?? ""); if (Number.isNaN(aware)) { console.error("--aware needs an ISO time"); return 2; } }
    else if (a === "--set") {
      const [k, v] = (args[++i] ?? "").split("=");
      const n = Number(v);
      if (!k || !(keys as readonly string[]).includes(k) || !Number.isFinite(n) || n < 0) { console.error(`bad --set ${k}=${v}`); return 2; }
      (set as Record<string, number>)[k] = n;
    } else if (a.startsWith("--")) { console.error(`unknown flag ${a}`); return 2; }
    else files.push(a);
  }
  if (!files.length || (year !== undefined && !Number.isInteger(year))) { console.log(USAGE); return 2; }
  const an = analyze(files.map((f) => ({ name: basename(f), text: readFileSync(f, "utf8") })), year !== undefined ? { year } : {});
  const b = brief(an, { assumptions: set, ...(aware !== undefined ? { awareAt: aware } : {}) });
  if (json) {
    console.log(JSON.stringify({ categories: b.categories, loss: { mean: b.loss.mean, p50: b.loss.p50, p90: b.loss.p90, p95: b.loss.p95, scenarios: b.loss.scenarios }, deadlines: b.clock.deadlines.map((d) => ({ ...d, due: new Date(d.due).toISOString() })), significant: b.clock.significant }, null, 2));
  } else process.stdout.write(boardMarkdown(b));
  return b.clock.significant ? 1 : 0;
}

process.exitCode = main(process.argv);
