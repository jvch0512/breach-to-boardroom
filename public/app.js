import { analyze } from "/lib/timeline.js";
import { boardMarkdown, brief, decisions, actions72, headline, eur } from "/lib/board.js";
import { iso } from "/lib/report.js";
import { remaining } from "/lib/nis2.js";

const $ = (id) => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";
let inputs = [];
let current = null;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text; // log-derived text only ever goes through textContent
  return e;
}

function assumptions() {
  const n = (id, d) => { const v = Number($(id).value); return Number.isFinite(v) && v >= 0 ? v : d; };
  return { downtimeCostPerHour: n("a-down", 8000), recordsAtRisk: n("a-rec", 20000), costPerRecord: n("a-cpr", 150), annualRevenue: n("a-rev", 50000000) };
}

function run() {
  if (!inputs.length) return;
  const an = analyze(inputs, { year: Number($("year").value) || 2026 });
  $("warn").textContent = an.warnings.join(" | ");
  current = brief(an, { assumptions: assumptions() });
  render(current);
}

function card(big, small) {
  const d = el("div", "card");
  d.append(el("b", "", big), el("span", "", small));
  return d;
}

function render(b) {
  $("out").hidden = false;
  $("head").textContent = headline(b);
  const cards = $("cards");
  cards.replaceChildren(card(eur(b.loss.p50), "most likely total cost"), card(eur(b.loss.p90), "1-in-10 worst case"), card(String(b.analysis.findings.length), "findings in " + b.analysis.events.length + " events"), card(b.clock.deadlines[0] ? remaining(b.clock.deadlines[0].due, b.now) : "none", "until the first legal deadline"));
  chart(b);
  const t = $("clocks");
  t.replaceChildren();
  const hr = el("tr");
  for (const h of ["Duty", "Due (UTC)", "Status"]) hr.append(el("th", "", h));
  t.append(hr);
  if (!b.clock.deadlines.length) { const r = el("tr"); const c = el("td", "", "No notification duty triggered by these logs."); c.colSpan = 3; r.append(c); t.append(r); }
  for (const d of b.clock.deadlines) {
    const r = el("tr");
    const s = remaining(d.due, b.now);
    r.append(el("td", "", d.label), el("td", "", iso(d.due)), el("td", s.includes("overdue") ? "t-over" : "t-left", s));
    t.append(r);
  }
  $("decisions").replaceChildren(...decisions(b).map((x) => el("li", "", x)));
  $("actions").replaceChildren(...actions72(b).map((x) => el("li", "", x)));
  $("md").textContent = boardMarkdown(b);
}

function chart(b) {
  const svg = $("chart");
  svg.replaceChildren();
  const rows = [...b.loss.scenarios.map((s) => ({ label: s.label, p50: s.p50, p90: s.p90 })), { label: "Combined incident", p50: b.loss.p50, p90: b.loss.p90 }];
  const max = Math.max(1, ...rows.map((r) => r.p90));
  const x0 = 190, w = 250;
  rows.forEach((r, i) => {
    const y = 12 + i * 34;
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", "0"); t.setAttribute("y", String(y + 15)); t.textContent = r.label.length > 30 ? r.label.slice(0, 29) + "…" : r.label;
    const bar = document.createElementNS(NS, "rect");
    bar.setAttribute("class", "bar"); bar.setAttribute("x", String(x0)); bar.setAttribute("y", String(y)); bar.setAttribute("height", "20"); bar.setAttribute("width", String(Math.max(1, (r.p50 / max) * w)));
    const l = document.createElementNS(NS, "line");
    const lx = x0 + (r.p90 / max) * w;
    l.setAttribute("class", "p90"); l.setAttribute("x1", String(lx)); l.setAttribute("x2", String(lx)); l.setAttribute("y1", String(y - 2)); l.setAttribute("y2", String(y + 22));
    const v = document.createElementNS(NS, "text");
    v.setAttribute("x", "518"); v.setAttribute("text-anchor", "end"); v.setAttribute("y", String(y + 15)); v.textContent = eur(r.p50);
    svg.append(t, bar, l, v);
  });
}

async function readFiles(files) {
  inputs = [];
  for (const f of files) inputs.push({ name: f.name, text: await f.text() });
  run();
}

const drop = $("drop");
for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); });
drop.addEventListener("drop", (e) => readFiles(e.dataTransfer.files));
$("file").addEventListener("change", (e) => readFiles(e.target.files));
$("sample").addEventListener("click", async () => {
  inputs = [];
  for (const n of ["win-security.jsonl", "auth.log", "access.log"]) inputs.push({ name: n, text: await (await fetch("/examples/" + n)).text() });
  run();
});
for (const id of ["a-down", "a-rec", "a-cpr", "a-rev", "year"]) $(id).addEventListener("change", run);
$("dl").addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([boardMarkdown(current)], { type: "text/markdown" }));
  const a = document.createElement("a"); a.href = url; a.download = "incident-brief.md"; a.click(); URL.revokeObjectURL(url);
});
$("print").addEventListener("click", () => window.print());
