# ADR 0003 — Analyst console on top of Wazuh

- **Status:** Accepted
- **Date:** 2026-10-25

## Decision

SentinelForge is a custom analyst console. It reads Wazuh. It does not collect logs, decode them, or replace the Wazuh dashboard. The first story the console must tell is: failed logons, a successful logon, suspicious PowerShell, a privilege change, and a remote connection (`docs/ROADMAP.md`).

## Context / why

Wazuh already answers "what rule fired?" The gap is the analyst loop: group those alerts into a case, show the evidence, record notes, explain a risk score, and promote a hunt to an incident. Building that loop is the portfolio piece. Rebuilding a SIEM is not. Demo mode exists so the UI can be built on the Mac before WAZUH01 exists, and it has to be obvious when the numbers are fixtures.

## Alternatives considered

| Option | Why it lost |
|---|---|
| Use only the Wazuh dashboard | Nothing in the repo would show an investigation workflow. |
| Fork the Wazuh UI | Upgrades become a merge problem, and the boundary between SIEM and console disappears. |
| Replace Wazuh's rules with app-side detections only | The lab would lose agent collection and `wazuh-logtest`. Correlation can still live in the backend when a Wazuh frequency rule is the wrong tool. |
| A paid SOAR on top | Out of scope. Response actions in this project are lab-only and off by default. |

## Tradeoffs

- Two UIs will exist: Wazuh for administration, SentinelForge for the case. That is intentional.
- Demo mode can look finished before a single lab alert exists. The banner and the validation statuses are how that stays honest.
- Risk scores are rule-based points, shown as a breakdown. They are not a model, and they are not a measured detection rate.
- Indexes, field names, and API paths that are not confirmed on 4.14.9 stay marked **VERIFY** instead of being drawn into the UI as facts.

## What I must understand

- Source of truth for events and alerts: Wazuh. Source of truth for cases, notes, scores, and saved hunts: SentinelForge.
- A hunt result is not an incident until someone promotes it or correlation creates the case.
- Severity in the UI is a text label plus a color. Color alone is not the status.
- `LAB VALIDATED` requires a simulation in this lab and the evidence. A screenshot of demo mode does not count.
- Windows event mapping is **REQUIRES WINDOWS VALIDATION** even after the screen looks right.

## Likely interview questions + short answers

**Why build a console on top of Wazuh instead of using theirs?**
Their dashboard shows alerts. I still needed cases, notes, a risk breakdown I can explain, and a way to turn a hunt into an incident. Wazuh keeps doing collection and detection.

**How do you keep demo data from turning into fake results?**
Fixtures live in fixture folders, the API marks them `"demo": true`, and the UI shows a DEMO DATA banner. Live mode does not fall back to those fixtures. The README does not get metrics until the lab produces them.

**What is the source of truth?**
Wazuh for logs and alerts. My database for the incident, the notes, and the score. If those disagree, the alert evidence wins and the case gets corrected.
