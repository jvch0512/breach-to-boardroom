import type { Analysis } from "./timeline.js";
import { classify } from "./impact.js";

export interface Deadline {
  id: string;
  label: string;
  basis: string;
  due: number; // epoch ms
}

export interface Clock {
  awareAt: number;
  significant: boolean;
  personalData: boolean;
  reasons: string[];
  deadlines: Deadline[];
}

const H = 3_600_000;

/**
 * Deadlines from NIS2 Article 23(4) (early warning 24h, notification 72h, final report one month after the
 * notification) and GDPR Article 33 (72h to the supervisory authority). All run from the moment of awareness.
 * `awareAt` defaults to the first finding, which is the earliest moment the logs prove someone could have known.
 */
export function clock(a: Analysis, opts: { awareAt?: number } = {}): Clock {
  const first = a.findings.length ? Math.min(...a.findings.map((f) => f.start)) : (a.events[0]?.ts ?? 0);
  const awareAt = opts.awareAt ?? first;
  const cats = classify(a);
  const reasons: string[] = [];
  const crit = a.findings.filter((f) => f.severity === "critical");
  if (crit.length) reasons.push(`${crit.length} critical finding(s), e.g. ${crit[0]!.title}`);
  if (cats.includes("ransomware")) reasons.push("destructive or recovery-inhibiting activity: severe operational disruption is likely");
  if (cats.includes("web-compromise")) reasons.push("public-facing service answered attacker requests successfully");
  const significant = reasons.length > 0;
  const personalData = cats.includes("web-compromise") || cats.includes("account-compromise") || cats.includes("credential-theft");
  const deadlines: Deadline[] = [];
  if (significant) {
    deadlines.push({ id: "nis2-early", label: "NIS2 early warning to the CSIRT or authority", basis: "Art. 23(4)(a): within 24 hours of becoming aware", due: awareAt + 24 * H });
    deadlines.push({ id: "nis2-notify", label: "NIS2 incident notification with initial assessment", basis: "Art. 23(4)(b): within 72 hours", due: awareAt + 72 * H });
    deadlines.push({ id: "nis2-final", label: "NIS2 final report", basis: "Art. 23(4)(d): within one month of the notification", due: addMonth(awareAt + 72 * H) });
  }
  if (personalData) deadlines.push({ id: "gdpr", label: "GDPR notification to the supervisory authority", basis: "Art. 33(1): within 72 hours, unless the breach is unlikely to risk individuals", due: awareAt + 72 * H });
  deadlines.sort((x, y) => x.due - y.due);
  return { awareAt, significant, personalData, reasons, deadlines };
}

function addMonth(ts: number): number {
  const d = new Date(ts);
  d.setUTCMonth(d.getUTCMonth() + 1);
  return d.getTime();
}

export function remaining(due: number, now: number): string {
  const ms = due - now;
  const h = Math.abs(ms) / H;
  const txt = h >= 48 ? `${Math.round(h / 24)} days` : `${Math.round(h * 10) / 10} h`;
  return ms >= 0 ? `${txt} left` : `${txt} overdue`;
}
