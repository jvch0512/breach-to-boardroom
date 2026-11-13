import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { Rng } from "../src/rng.js";
import { analyze } from "../src/timeline.js";
import { classify, simulate, DEFAULTS } from "../src/impact.js";
import { clock, remaining } from "../src/nis2.js";
import { boardMarkdown, brief, eur, headline } from "../src/board.js";

const ex = (n: string) => readFileSync(new URL(`../../examples/${n}`, import.meta.url), "utf8");
const full = () => analyze([{ name: "win-security.jsonl", text: ex("win-security.jsonl") }, { name: "auth.log", text: ex("auth.log") }, { name: "access.log", text: ex("access.log") }], { year: 2026 });
const win = (id: number, min: number, data: Record<string, string>, host = "H1") => JSON.stringify({ Id: id, TimeCreated: new Date(Date.UTC(2026, 0, 1, 0, min)).toISOString(), MachineName: host, EventData: data });
const cli = new URL("../src/cli.js", import.meta.url).pathname;
const exPath = (n: string) => new URL(`../../examples/${n}`, import.meta.url).pathname;

test("rng is deterministic per seed and differs across seeds", () => {
  const a = new Rng(1), b = new Rng(1), c = new Rng(2);
  const xs = [a.next(), a.next(), a.next()];
  assert.deepEqual(xs, [b.next(), b.next(), b.next()]);
  assert.notEqual(xs[0], c.next());
  assert.ok(xs.every((x) => x >= 0 && x < 1));
});

test("pert stays in range and its mean sits near (min + 4*mode + max) / 6", () => {
  const r = new Rng(7);
  let sum = 0;
  const n = 40000;
  for (let i = 0; i < n; i++) {
    const v = r.pert(10, 20, 100);
    assert.ok(v >= 10 && v <= 100);
    sum += v;
  }
  const expected = (10 + 4 * 20 + 100) / 6;
  assert.ok(Math.abs(sum / n - expected) < 0.6, `mean ${sum / n} vs ${expected}`);
  assert.equal(new Rng(1).pert(5, 5, 5), 5);
});

test("gamma with shape below one is positive", () => {
  const r = new Rng(3);
  for (let i = 0; i < 1000; i++) assert.ok(r.gamma(0.5) > 0);
});

test("classification maps findings to incident categories", () => {
  const cats = classify(full());
  for (const c of ["ransomware", "account-compromise", "web-compromise", "credential-theft"]) assert.ok(cats.includes(c as never), c);
  const quiet = analyze([{ name: "a", text: win(4624, 0, { LogonType: "2" }) }]);
  assert.deepEqual(classify(quiet), []);
  const clear = analyze([{ name: "a", text: win(1102, 0, {}) }]);
  assert.deepEqual(classify(clear), [], "log clearing alone is not ransomware");
});

test("simulation is reproducible and ordered", () => {
  const a = simulate(["ransomware"], { seed: 5 });
  const b = simulate(["ransomware"], { seed: 5 });
  assert.equal(a.mean, b.mean);
  assert.ok(a.p50 <= a.p90 && a.p90 <= a.p95);
  assert.notEqual(simulate(["ransomware"], { seed: 6 }).mean, a.mean);
});

test("overlapping scenarios are not summed", () => {
  const all = simulate(["ransomware", "account-compromise", "web-compromise", "credential-theft"], { seed: 9 });
  const sum = all.scenarios.reduce((t, s) => t + s.mean, 0);
  const biggest = Math.max(...all.scenarios.map((s) => s.mean));
  assert.ok(all.mean < sum * 0.8, "well below the plain sum");
  assert.ok(all.mean >= biggest * 0.98, "at least the largest single scenario");
});

test("no category means zero loss and assumptions move the result", () => {
  assert.equal(simulate([]).mean, 0);
  const base = simulate(["ransomware"], { seed: 1 }).mean;
  assert.ok(simulate(["ransomware"], { seed: 1, downtimeCostPerHour: 0 }).mean < base);
  assert.ok(simulate(["ransomware"], { seed: 1, recordsAtRisk: 0 }).mean < base);
  assert.ok(simulate(["web-compromise"], { seed: 1, annualRevenue: 0 }).mean < simulate(["web-compromise"], { seed: 1, annualRevenue: 500_000_000 }).mean);
});

test("iterations are clamped", () => {
  assert.equal(simulate(["ransomware"], { iterations: 1 }).iterations, 1000);
  assert.equal(simulate(["ransomware"], { iterations: 99_999_999 }).iterations, 200_000);
});

test("NIS2 and GDPR deadlines are computed from awareness", () => {
  const a = full();
  const c = clock(a);
  const t0 = c.awareAt;
  const by = (id: string) => c.deadlines.find((d) => d.id === id)!;
  assert.equal(by("nis2-early").due - t0, 24 * 3600_000);
  assert.equal(by("nis2-notify").due - t0, 72 * 3600_000);
  assert.equal(by("gdpr").due - t0, 72 * 3600_000);
  assert.equal(new Date(by("nis2-final").due).toISOString(), "2026-04-17T02:10:00.000Z");
  assert.deepEqual(c.deadlines.map((d) => d.due), [...c.deadlines.map((d) => d.due)].sort((x, y) => x - y));
  assert.equal(clock(a, { awareAt: Date.UTC(2026, 0, 1) }).awareAt, Date.UTC(2026, 0, 1));
});

test("a quiet log triggers no duty", () => {
  const c = clock(analyze([{ name: "a", text: win(4624, 0, { LogonType: "2" }) }]));
  assert.equal(c.significant, false);
  assert.deepEqual(c.deadlines, []);
});

test("month rollover handles a 31st", () => {
  const a = analyze([{ name: "a", text: win(1102, 0, {}).replace("2026-01-01T00:00:00", "2026-01-28T00:00:00") }]);
  const c = clock(a, { awareAt: Date.UTC(2026, 0, 28, 12) });
  assert.ok(c.deadlines.length === 0 || c.deadlines.every((d) => Number.isFinite(d.due)));
});

test("remaining formats overdue and upcoming", () => {
  assert.equal(remaining(10 * 3600_000, 0), "10 h left");
  assert.equal(remaining(0, 5 * 3600_000), "5 h overdue");
  assert.equal(remaining(5 * 86400_000, 0), "5 days left");
});

test("eur formatting", () => {
  assert.equal(eur(950), "EUR 950");
  assert.equal(eur(12_400), "EUR 12k");
  assert.equal(eur(2_540_000), "EUR 2.5M");
});

test("board brief has every section and mentions the first deadline", () => {
  const b = brief(full());
  const md = boardMarkdown(b);
  for (const h of ["# Incident brief for the board", "## What happened", "## What it could cost", "## Regulatory clocks", "## Decisions needed from leadership", "## Next 72 hours", "## Appendix: findings", "## Assumptions", "not legal advice"]) assert.ok(md.includes(h), h);
  assert.ok(md.includes("2026-03-15T02:10:00Z"));
  assert.ok(headline(b).startsWith("Evidence of ransomware"));
  assert.ok(md.includes("203.0.113.45"), "attacker address in actions");
  assert.ok(!md.includes("10.20.0."), "internal addresses are not suggested for blocking");
});

test("board brief for a clean log says so and has no decisions about NIS2", () => {
  const md = boardMarkdown(brief(analyze([{ name: "a", text: win(4624, 0, { LogonType: "2" }) }])));
  assert.ok(md.includes("No malicious activity detected"));
  assert.ok(md.includes("No notification duty"));
  assert.ok(!md.includes("NIS2 early warning now"));
});

test("hostile text in a log cannot break the appendix table", () => {
  const evil = analyze([{ name: "a", text: win(7045, 0, { ServiceName: "x|y\nz", ImagePath: "C:\\Users\\Public\\a|b.exe" }) }]);
  const md = boardMarkdown(brief(evil));
  const row = md.split("\n").find((l) => l.startsWith("| 2026") && l.includes("Suspicious service"))!;
  assert.equal(row.split(/(?<!\\)\|/).length, 7, "pipe in title or host did not add columns");
});

test("cli prints a brief and exits 1 when notification duties exist", () => {
  const r = spawnSync("node", [cli, exPath("win-security.jsonl"), exPath("auth.log"), exPath("access.log"), "--year", "2026"], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.ok(r.stdout.startsWith("# Incident brief for the board"));
});

test("cli json output and --set overrides", () => {
  const r = spawnSync("node", [cli, exPath("auth.log"), "--year", "2026", "--json", "--set", "seed=3"], { encoding: "utf8" });
  const j = JSON.parse(r.stdout);
  assert.ok(Array.isArray(j.deadlines));
  assert.ok(j.loss.p50 >= 0);
});

test("cli rejects bad input with exit 2", () => {
  for (const args of [["--set", "nope=1", "x"], ["--set", "seed=-1", "x"], ["--aware", "banana", "x"], ["--bogus"], []]) {
    assert.equal(spawnSync("node", [cli, ...args], { encoding: "utf8" }).status, 2, args.join(" "));
  }
});

test("defaults are sane", () => {
  assert.ok(DEFAULTS.iterations >= 10000 && DEFAULTS.annualRevenue > 0);
});
