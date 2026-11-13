import type { Analysis } from "./timeline.js";
import { classify, PROFILES, simulate, type Assumptions, type LossResult } from "./impact.js";
import { clock, remaining, type Clock } from "./nis2.js";
import { iso } from "./report.js";
import { SEVERITY_RANK } from "./types.js";

export interface Brief {
  analysis: Analysis;
  categories: ReturnType<typeof classify>;
  loss: LossResult;
  clock: Clock;
  now: number;
}

export function brief(a: Analysis, opts: { assumptions?: Partial<Assumptions>; awareAt?: number; now?: number } = {}): Brief {
  const categories = classify(a);
  const loss = simulate(categories, opts.assumptions ?? {});
  const c = clock(a, opts.awareAt !== undefined ? { awareAt: opts.awareAt } : {});
  const last = a.events.length ? a.events[a.events.length - 1]!.ts : 0;
  return { analysis: a, categories, loss, clock: c, now: opts.now ?? last };
}

export const eur = (n: number): string => {
  const v = Math.round(n);
  if (Math.abs(v) >= 1_000_000) return `EUR ${(v / 1_000_000).toFixed(1)}M`;
  if (Math.abs(v) >= 1000) return `EUR ${Math.round(v / 1000)}k`;
  return `EUR ${v}`;
};

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");

export function headline(b: Brief): string {
  if (!b.analysis.findings.length) return "No malicious activity detected in the supplied logs.";
  const hosts = new Set(b.analysis.chains.map((c) => c.host));
  const order = ["ransomware", "web-compromise", "account-compromise", "credential-theft"] as const;
  const lead = order.find((c) => b.categories.includes(c));
  const what = lead ? PROFILES[lead].label.toLowerCase() : "suspicious activity";
  const extra = b.categories.length > 1 ? `, with ${b.categories.length - 1} related activity type(s)` : "";
  return `Evidence of ${what}${extra}, across ${hosts.size || 1} system(s). Most likely cost ${eur(b.loss.p50)}, with a 1-in-10 chance of exceeding ${eur(b.loss.p90)}.`;
}

export function decisions(b: Brief): string[] {
  const d: string[] = [];
  if (b.clock.significant) d.push(`Authorise the NIS2 early warning now. The first deadline is ${iso(b.clock.deadlines[0]!.due)}.`);
  if (b.categories.includes("ransomware")) d.push("Decide whether to isolate affected servers from the network. This stops spread but takes services offline.");
  if (b.categories.includes("account-compromise") || b.categories.includes("credential-theft")) d.push("Approve a forced credential reset for exposed accounts, including service accounts and the domain.");
  if (b.categories.includes("web-compromise")) d.push("Approve taking the affected web application offline or behind a maintenance page until it is rebuilt.");
  if (b.clock.personalData) d.push("Instruct the DPO to assess whether individuals must be notified under GDPR.");
  d.push("Approve external incident response support and a communications holding statement.");
  return d;
}

export function actions72(b: Brief): string[] {
  const a = ["Preserve evidence: snapshot affected hosts and export the logs before anything is rebuilt.", "Block the attacker addresses seen in the findings at the perimeter."];
  const ips = new Set<string>();
  for (const f of b.analysis.findings) for (const id of f.evidence) { const ip = b.analysis.events[id]?.ip; if (ip && !/^(10\.|192\.168\.|127\.)/.test(ip)) ips.add(ip); }
  if (ips.size) a.push(`Addresses to block first: ${[...ips].slice(0, 6).join(", ")}.`);
  if (b.categories.includes("ransomware")) a.push("Verify that offline backups exist and are untouched before restoring anything.");
  a.push("Reset credentials for accounts seen in the findings and remove the persistence items listed in the appendix.");
  a.push("Start a decision log with timestamps. Regulators ask for it.");
  return a;
}

export function boardMarkdown(b: Brief): string {
  const a = b.analysis;
  const L: string[] = ["# Incident brief for the board", "", `**${headline(b)}**`, ""];
  L.push("## What happened", "");
  if (!a.chains.length && !a.findings.length) L.push("The logs show no attack activity.");
  for (const c of a.chains) L.push(`- ${iso(c.start)} to ${iso(c.end)} on ${c.host}: ${c.tactics[0]!.toLowerCase()} through ${c.tactics[c.tactics.length - 1]!.toLowerCase()}, ${c.tactics.length} ATT&CK tactics (${c.findings} findings, ${c.severity}).`);
  if (!a.chains.length) for (const f of a.findings.slice(0, 5)) L.push(`- ${iso(f.start)} on ${f.host}: ${f.title}.`);
  L.push("", "## What it could cost", "", `Monte Carlo over ${b.loss.iterations.toLocaleString("en-US")} runs (seed ${b.loss.seed}). The range comes from three-point estimates that you can change. The scenarios overlap (one attacker, one incident), so the total takes the largest matching cost line per run instead of adding scenarios together.`, "");
  L.push("| Scenario (stand-alone) | Average | Median | 1 in 10 | 1 in 20 |", "|---|---:|---:|---:|---:|");
  for (const s of b.loss.scenarios) L.push(`| ${s.label} | ${eur(s.mean)} | ${eur(s.p50)} | ${eur(s.p90)} | ${eur(s.p95)} |`);
  L.push(`| **Combined incident** | **${eur(b.loss.mean)}** | **${eur(b.loss.p50)}** | **${eur(b.loss.p90)}** | **${eur(b.loss.p95)}** |`, "");
  for (const s of b.loss.scenarios) L.push(`- ${s.label}, average split: ${s.components.map((c) => `${c.name} ${eur(c.mean)}`).join(", ")}.`);
  L.push("", "## Regulatory clocks", "");
  if (!b.clock.deadlines.length) L.push("No notification duty is triggered by what the logs show. Re-check if scope grows.");
  else {
    L.push(`Awareness is taken as ${iso(b.clock.awareAt)}. ${b.clock.reasons.length ? "Why this looks significant: " + b.clock.reasons.join("; ") + "." : ""}`, "", "| Duty | Due (UTC) | Status at last log entry | Basis |", "|---|---|---|---|");
    for (const d of b.clock.deadlines) L.push(`| ${d.label} | ${iso(d.due)} | ${remaining(d.due, b.now)} | ${d.basis} |`);
  }
  L.push("", "## Decisions needed from leadership", "", ...decisions(b).map((x, i) => `${i + 1}. ${x}`));
  L.push("", "## Next 72 hours", "", ...actions72(b).map((x) => `- ${x}`));
  L.push("", "## Appendix: findings", "", "| When (UTC) | Severity | Finding | Host | ATT&CK |", "|---|---|---|---|---|");
  for (const f of [...a.findings].sort((x, y) => SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity] || x.start - y.start).slice(0, 40)) L.push(`| ${iso(f.start)} | ${f.severity} | ${esc(f.title)} | ${esc(f.host)} | ${f.technique} |`);
  L.push("", "## Assumptions", "", `Downtime ${eur(b.loss.assumptions.downtimeCostPerHour)} per hour, ${b.loss.assumptions.recordsAtRisk.toLocaleString("en-US")} records at risk at ${eur(b.loss.assumptions.costPerRecord)} each, annual revenue ${eur(b.loss.assumptions.annualRevenue)}, responder rate ${eur(b.loss.assumptions.responderRate)} per hour. Three-point ranges per scenario are in \`src/impact.ts\`.`, "", "_This brief is decision support built from log heuristics and stated assumptions. It is not legal advice: confirm notification duties with counsel and the competent authority._", "");
  return L.join("\n");
}
