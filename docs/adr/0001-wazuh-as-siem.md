# ADR 0001 — Wazuh as the SIEM

- **Status:** Accepted
- **Date:** 2026-10-25
- **Versions:** Wazuh 4.14.9 for manager, indexer, dashboard, and agents (`docs/VERSIONS.md`)

## Decision

Wazuh 4.14.9, installed all-in-one on WAZUH01, is the SIEM. SentinelForge sits on top of it. Wazuh 5.x pre-releases are out of scope.

## Context / why

The lab needs a free collector, a rule engine, and an indexer for Windows and Linux. Wazuh provides agents, decoders, rules, an OpenSearch indexer, and a dashboard under one open-source project. Pinning 4.14.9 keeps every agent on the same release as the manager. The 4.x line is the one this project will install; 5.0 was still beta or release-candidate when versions were checked on 2026-10-25.

## Alternatives considered

| Option | Why it lost |
|---|---|
| Splunk, Microsoft Sentinel, or another paid SIEM | The project is free and open-source only. |
| Elastic Stack assembled by hand | License limits get easy to violate, and the agent story is a second project. |
| Security Onion | Heavier than this host's RAM budget, and it hides the "console on top" boundary this portfolio is about. |
| Wazuh 5.x | Pre-release. Agents, indexes, and APIs can still move. |

## Tradeoffs

- Rules are XML, with parent rule IDs that must be checked against 4.14.9. Uncertain parents get `<!-- VERIFY: -->`.
- The indexer wants RAM. WAZUH01 has 8 GB for the whole stack, so the heap has to be capped. The setting name is **VERIFY**.
- The stock dashboard is enough to administer Wazuh and the wrong place to pretend we built an investigation product.
- All-in-one is simpler on one VM and noisier to upgrade than a split cluster. A split cluster does not fit the RAM budget.

## What I must understand

- Manager, indexer, dashboard, and agent are four roles, even when three of them share WAZUH01.
- Alerts (`wazuh-alerts-*`) and archives (`wazuh-archives-*`) are different indexes. **VERIFY** both names on 4.14.9.
- A Wazuh alert is the input to SentinelForge. It is not yet an incident.
- Custom rule IDs in this repo stay inside `100000`–`109999`.
- "It fired in logtest" and "it fired from a lab simulation" are different validation statuses.

## Likely interview questions + short answers

**Why Wazuh instead of Splunk?**
Wazuh is free, it has Windows and Linux agents, and I can put my own console on top without a license. I pinned 4.14.9 so the manager and the agents match. I can show the rules and the lab, which is the point of the project.

**What does Wazuh do, and what does your app do?**
Wazuh collects logs, decodes them, runs the rules, and stores the alerts. SentinelForge reads those alerts with a read-only user and adds incidents, notes, correlation, risk scores, and the hunt UI.

**Why not the newest major version?**
Wazuh 5 was still a pre-release when I pinned versions. I stayed on 4.14.9 so I would not chase API and index changes in the middle of the lab. I re-check the release notes on install day.
