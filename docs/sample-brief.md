# Incident brief for the board

**Evidence of ransomware or destructive attack, with 3 related activity type(s), across 3 system(s). Most likely cost EUR 2.6M, with a 1-in-10 chance of exceeding EUR 3.5M.**

## What happened

- 2026-03-14T02:10:00Z to 2026-03-14T02:24:05Z on ws-fin-07: initial access through impact, 9 ATT&CK tactics (11 findings, critical).
- 2026-03-14T02:50:00Z to 2026-03-14T02:53:20Z on web01: initial access through command and control, 5 ATT&CK tactics (5 findings, critical).
- 2026-03-14T03:00:00Z to 2026-03-14T03:03:10Z on web: initial access through discovery, 3 ATT&CK tactics (4 findings, critical).

## What it could cost

Monte Carlo over 20,000 runs (seed 2026). The range comes from three-point estimates that you can change. The scenarios overlap (one attacker, one incident), so the total takes the largest matching cost line per run instead of adding scenarios together.

| Scenario (stand-alone) | Average | Median | 1 in 10 | 1 in 20 |
|---|---:|---:|---:|---:|
| Ransomware or destructive attack | EUR 1.9M | EUR 1.8M | EUR 2.6M | EUR 2.9M |
| Account takeover and lateral movement | EUR 392k | EUR 368k | EUR 622k | EUR 697k |
| Web application compromise | EUR 1.5M | EUR 1.4M | EUR 2.2M | EUR 2.5M |
| Credential theft | EUR 324k | EUR 306k | EUR 514k | EUR 572k |
| **Combined incident** | **EUR 2.6M** | **EUR 2.6M** | **EUR 3.5M** | **EUR 3.8M** |

- Ransomware or destructive attack, average split: Response and forensics EUR 256k, Downtime EUR 993k, Data breach handling EUR 500k, Regulatory fines EUR 35k, Legal and communications EUR 93k.
- Account takeover and lateral movement, average split: Response and forensics EUR 52k, Downtime EUR 53k, Data breach handling EUR 251k, Regulatory fines EUR 6k, Legal and communications EUR 31k.
- Web application compromise, average split: Response and forensics EUR 82k, Downtime EUR 162k, Data breach handling EUR 1.1M, Regulatory fines EUR 66k, Legal and communications EUR 62k.
- Credential theft, average split: Response and forensics EUR 41k, Downtime EUR 27k, Data breach handling EUR 226k, Regulatory fines EUR 6k, Legal and communications EUR 24k.

## Regulatory clocks

Awareness is taken as 2026-03-14T02:10:00Z. Why this looks significant: 6 critical finding(s), e.g. Brute force followed by successful logon; destructive or recovery-inhibiting activity: severe operational disruption is likely; public-facing service answered attacker requests successfully.

| Duty | Due (UTC) | Status at last log entry | Basis |
|---|---|---|---|
| NIS2 early warning to the CSIRT or authority | 2026-03-15T02:10:00Z | 22.1 h left | Art. 23(4)(a): within 24 hours of becoming aware |
| NIS2 incident notification with initial assessment | 2026-03-17T02:10:00Z | 3 days left | Art. 23(4)(b): within 72 hours |
| GDPR notification to the supervisory authority | 2026-03-17T02:10:00Z | 3 days left | Art. 33(1): within 72 hours, unless the breach is unlikely to risk individuals |
| NIS2 final report | 2026-04-17T02:10:00Z | 34 days left | Art. 23(4)(d): within one month of the notification |

## Decisions needed from leadership

1. Authorise the NIS2 early warning now. The first deadline is 2026-03-15T02:10:00Z.
2. Decide whether to isolate affected servers from the network. This stops spread but takes services offline.
3. Approve a forced credential reset for exposed accounts, including service accounts and the domain.
4. Approve taking the affected web application offline or behind a maintenance page until it is rebuilt.
5. Instruct the DPO to assess whether individuals must be notified under GDPR.
6. Approve external incident response support and a communications holding statement.

## Next 72 hours

- Preserve evidence: snapshot affected hosts and export the logs before anything is rebuilt.
- Block the attacker addresses seen in the findings at the perimeter.
- Addresses to block first: 203.0.113.45, 198.51.100.77, 192.0.2.88.
- Verify that offline backups exist and are untouched before restoring anything.
- Reset credentials for accounts seen in the findings and remove the persistence items listed in the appendix.
- Start a decision log with timestamps. Regulators ask for it.

## Appendix: findings

| When (UTC) | Severity | Finding | Host | ATT&CK |
|---|---|---|---|---|
| 2026-03-14T02:10:00Z | critical | Brute force followed by successful logon | ws-fin-07 | T1110.001 |
| 2026-03-14T02:23:00Z | critical | Backup and recovery inhibited | ws-fin-07 | T1490 |
| 2026-03-14T02:52:10Z | critical | Reverse shell | web01 | T1059.004 |
| 2026-03-14T03:02:00Z | critical | SQL injection attempt (server answered 2xx) | web | T1190 |
| 2026-03-14T03:02:30Z | critical | Path traversal attempt (server answered 2xx) | web | T1190 |
| 2026-03-14T03:03:10Z | critical | Web shell access (server answered 2xx) | web | T1505.003 |
| 2026-03-14T02:12:20Z | high | RDP logon from a public address | ws-fin-07 | T1133 |
| 2026-03-14T02:17:00Z | high | Ingress tool transfer | ws-fin-07 | T1105 |
| 2026-03-14T02:18:10Z | high | Encoded PowerShell | ws-fin-07 | T1059.001 |
| 2026-03-14T02:19:40Z | high | Suspicious service installed | ws-fin-07 | T1543.003 |
| 2026-03-14T02:21:50Z | high | Added to privileged group | ws-fin-07 | T1098 |
| 2026-03-14T02:24:05Z | high | Event log cleared | ws-fin-07 | T1070.001 |
| 2026-03-14T02:40:00Z | high | Kerberoasting pattern | srv-dc-01 | T1558.003 |
| 2026-03-14T02:50:00Z | high | Password spraying | web01 | T1110.003 |
| 2026-03-14T02:53:20Z | high | Added to privileged group | web01 | T1098 |
| 2026-03-14T02:14:05Z | medium | Discovery commands in quick succession | ws-fin-07 | T1087 |
| 2026-03-14T02:20:15Z | medium | Scheduled task created | ws-fin-07 | T1053.005 |
| 2026-03-14T02:21:30Z | medium | Local account created | ws-fin-07 | T1136.001 |
| 2026-03-14T02:51:05Z | medium | SSH password logon from a public address | web01 | T1078 |
| 2026-03-14T02:53:00Z | medium | Local account created | web01 | T1136.001 |
| 2026-03-14T03:00:00Z | low | Web scanning | web | T1595.002 |

## Assumptions

Downtime EUR 8k per hour, 20,000 records at risk at EUR 150 each, annual revenue EUR 50.0M, responder rate EUR 150 per hour. Three-point ranges per scenario are in `src/impact.ts`.

_This brief is decision support built from log heuristics and stated assumptions. It is not legal advice: confirm notification duties with counsel and the competent authority._
