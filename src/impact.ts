import type { Analysis } from "./timeline.js";
import { Rng } from "./rng.js";

export type Category = "ransomware" | "account-compromise" | "web-compromise" | "credential-theft";

export interface Assumptions {
  /** Euros of lost output or revenue per hour the affected systems are down. */
  downtimeCostPerHour: number;
  /** Personal records reachable from the compromised systems. */
  recordsAtRisk: number;
  /** All-in cost per exposed record (notification, monitoring, claims). */
  costPerRecord: number;
  /** Annual turnover, the base for administrative fines. */
  annualRevenue: number;
  /** Loaded hourly rate of responders and forensic consultants. */
  responderRate: number;
  iterations: number;
  seed: number;
}

export const DEFAULTS: Assumptions = { downtimeCostPerHour: 8000, recordsAtRisk: 20000, costPerRecord: 150, annualRevenue: 50_000_000, responderRate: 150, iterations: 20000, seed: 2026 };

type Tri = [number, number, number];

interface Profile {
  label: string;
  responseHours: Tri;
  downtimeHours: Tri;
  exposedShare: Tri;
  fineProbability: number;
  /** fine as a share of annual revenue, when one is imposed */
  fineShare: Tri;
  legalPr: Tri;
}

/** Three-point estimates (min, most likely, max). Judgement values: every one is exposed in the report and overridable. */
export const PROFILES: Record<Category, Profile> = {
  ransomware: { label: "Ransomware or destructive attack", responseHours: [200, 500, 1200], downtimeHours: [24, 96, 336], exposedShare: [0, 0.1, 0.6], fineProbability: 0.15, fineShare: [0, 0.002, 0.02], legalPr: [20000, 60000, 300000] },
  "account-compromise": { label: "Account takeover and lateral movement", responseHours: [40, 100, 250], downtimeHours: [0, 4, 24], exposedShare: [0, 0.05, 0.3], fineProbability: 0.05, fineShare: [0, 0.001, 0.01], legalPr: [5000, 20000, 100000] },
  "web-compromise": { label: "Web application compromise", responseHours: [60, 160, 400], downtimeHours: [2, 12, 72], exposedShare: [0.05, 0.3, 1], fineProbability: 0.25, fineShare: [0, 0.003, 0.02], legalPr: [10000, 40000, 200000] },
  "credential-theft": { label: "Credential theft", responseHours: [30, 80, 200], downtimeHours: [0, 2, 12], exposedShare: [0, 0.05, 0.25], fineProbability: 0.05, fineShare: [0, 0.001, 0.01], legalPr: [5000, 15000, 80000] },
};

export function classify(a: Analysis): Category[] {
  const out = new Set<Category>();
  const hit = (f: { technique: string; title: string; severity: string }) => f;
  const fs = a.findings.map(hit);
  const has = (p: (f: (typeof fs)[number]) => boolean) => fs.some(p);
  const persistence = has((f) => /^T1543|^T1053/.test(f.technique));
  if (has((f) => f.technique === "T1490") || (has((f) => f.technique === "T1070.001") && persistence)) out.add("ransomware");
  if (has((f) => /Brute force followed|RDP logon|SSH password logon/.test(f.title)) || has((f) => f.technique === "T1098" || f.technique === "T1136.001")) out.add("account-compromise");
  if (has((f) => f.technique === "T1505.003" || /server answered 2xx/.test(f.title))) out.add("web-compromise");
  if (has((f) => /^T1003|^T1558/.test(f.technique))) out.add("credential-theft");
  return [...out];
}

export interface Percentiles {
  mean: number;
  p50: number;
  p90: number;
  p95: number;
}

export interface Component {
  name: string;
  mean: number;
}

export interface ScenarioResult extends Percentiles {
  category: Category;
  label: string;
  components: Component[];
}

export interface LossResult extends Percentiles {
  scenarios: ScenarioResult[];
  iterations: number;
  seed: number;
  assumptions: Assumptions;
}

function pct(sorted: number[], q: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] ?? 0;
}

function summarise(xs: number[]): Percentiles {
  const s = [...xs].sort((a, b) => a - b);
  return { mean: xs.reduce((t, v) => t + v, 0) / (xs.length || 1), p50: pct(s, 0.5), p90: pct(s, 0.9), p95: pct(s, 0.95) };
}

export function simulate(cats: Category[], assumptions: Partial<Assumptions> = {}): LossResult {
  const A: Assumptions = { ...DEFAULTS, ...assumptions };
  const n = Math.max(1000, Math.min(200_000, Math.floor(A.iterations)));
  // Overlapping categories are one incident (the account takeover is how the ransomware got in), so each cost
  // line takes the largest matching scenario in a run instead of adding them up. Summing would double count.
  const lines = ["response", "downtime", "breach", "fine", "legal"] as const;
  const peak = lines.map(() => new Array<number>(n).fill(0));
  const scenarios: ScenarioResult[] = [];
  cats.forEach((cat, k) => {
    const p = PROFILES[cat];
    const rng = new Rng(A.seed * 7919 + k * 104729);
    const sums = { response: 0, downtime: 0, breach: 0, fine: 0, legal: 0 };
    const losses: number[] = [];
    for (let i = 0; i < n; i++) {
      const response = rng.pert(...p.responseHours) * A.responderRate * 3; // three responders on average
      const downtime = rng.pert(...p.downtimeHours) * A.downtimeCostPerHour;
      const breach = rng.pert(...p.exposedShare) * A.recordsAtRisk * A.costPerRecord;
      const fine = rng.next() < p.fineProbability ? rng.pert(...p.fineShare) * A.annualRevenue : 0;
      const legal = rng.pert(...p.legalPr);
      sums.response += response; sums.downtime += downtime; sums.breach += breach; sums.fine += fine; sums.legal += legal;
      const t = response + downtime + breach + fine + legal;
      losses.push(t);
      [response, downtime, breach, fine, legal].forEach((v, li) => { const row = peak[li]!; if (v > (row[i] ?? 0)) row[i] = v; });
    }
    scenarios.push({ category: cat, label: p.label, ...summarise(losses), components: [
      { name: "Response and forensics", mean: sums.response / n }, { name: "Downtime", mean: sums.downtime / n },
      { name: "Data breach handling", mean: sums.breach / n }, { name: "Regulatory fines", mean: sums.fine / n }, { name: "Legal and communications", mean: sums.legal / n },
    ] });
  });
  const total = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i++) for (const row of peak) total[i] = (total[i] ?? 0) + (row[i] ?? 0);
  return { ...summarise(cats.length ? total : [0]), scenarios, iterations: n, seed: A.seed, assumptions: A };
}
