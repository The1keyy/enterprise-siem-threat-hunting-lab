# ADR 0005 — Correlation lives in the backend

- **Status:** Accepted
- **Date:** 2026-10-27

## Decision

SentinelForge correlates alerts in `backend/app/services/correlation.py`. SF-020 is that behavior. It is not a Wazuh rule, and there is no `detections/metadata/SF-020.yml`.

A new alert joins an incident when it shares a normalized user, or a source IP, with an alert already in the group, and the two timestamps are inside the configured window (60 minutes). Union-find closes the chain: A linked to B by user, and B linked to C by source IP, are one incident. Alerts are keyed by the indexer `_id`. Processing the same id again does not add a second copy.

An incident opens when the group's final score is at least medium, or any alert's `rule.level` is at least 12. A later alert is appended only while the incident status is New, Investigating, or Contained. Resolved and False Positive stay closed. A later alert that would have matched opens a new incident instead.

## Context / why

The attack story is not one event on one host. Failed logons are recorded on DC01 with `ipAddress` 10.10.10.20. The script block and the local Administrators change are on WS01. The admin-share event is on DC01 again, from 10.10.10.20. Wazuh frequency rules can count repeats of one field inside one rule. They do not do all of the following at once:

- Join a user on WS01 to a source IP on DC01, then to a third alert that shares only one of those.
- Count a category once. Six more 4625s must not add the auth-burst points again.
- Show which link was used, and which alert was not counted, and why.
- Refuse to append after an analyst has marked the incident Resolved or False Positive.
- Ignore a link key that shows up across too many users, and ignore the gateway `10.10.10.1`, loopback, and machine accounts.

Those are analyst-workflow decisions. They belong next to incident status, which already lives in this backend (ADR 0002).

## Alternatives considered

| Option | Why it lost |
|---|---|
| One Wazuh rule, `if_matched_group` across SF-001 through SF-011 | The rule engine matches one event stream. It does not union a user key with a different IP key, and it does not know that an incident was Resolved. |
| A composite alert only, still inside analysisd | The composite alert would be another Wazuh document. The console would still need status, notes, and a breakdown. The hard part would just move. |
| Group in the React app | The browser would re-implement the window, the hub guard, and the score. Two analysts would not share a case. |
| OpenSearch transforms | Another moving piece on WAZUH01, and still no incident status. |

## Tradeoffs

- The incident exists only after the backend has read the alerts. A rule that fires on the manager is visible in the Wazuh dashboard immediately. SF-020 will not be.
- The window, the size cap, and the hub limit are code plus config. A frequency rule would have been a shorter XML block and a weaker model.
- Latency is the poll interval plus this function. The function itself is pure and does not call the network. Step 14A does not wire it to a route. That wait is not measured here.
- Cross-host correlation depends on the fields the agent actually sends. The synthetic tests set `targetUserName`, `subjectUserName`, `ipAddress`, and `srcip`. A lab 4104 that omits the user will not join unless some other key matches. That is a lab check, not a result of this step.

## What I must understand

- Linking is by normalized user or source IP. It is not by host. Every DC01 alert must not become one incident.
- `10.10.10.1`, `127.0.0.1`, `::1`, empty users, `-`, and accounts that end in `$` are not link keys.
- A key seen with more distinct users than `hub_user_limit` is not a link key. The story's `10.10.10.20` is shared by three lab accounts, so the default limit is 8.
- A component stops accepting alerts at `max_incident_alerts` (200).
- Open means New, Investigating, or Contained. The other two statuses never grow.
- Reprocessing is safe because the key is `_id`.
- This ADR does not change ADR 0004. Rule level is still the display label. The points are ADR 0006.

## Likely interview questions + short answers

**Why not a Wazuh correlation rule?**
The story crosses hosts and crosses fields. The case also has a status. Wazuh can count repeats. It should not own "do not append to a closed case" or "explain which category was skipped."

**What fails if the backend is down?**
Wazuh still alerts. The console does not open or extend the SF-020 incident until the backend runs. Detection does not move into the browser.

**How do you stop one busy IP from gluing the whole lab together?**
The gateway and loopback are excluded. Any other key that appears with more than the configured number of users is not used as a link. The cap on incident size is a second guard.

**Is this live?**
No. Step 14A is pytest against synthetic alerts. No route calls it yet. Nothing here is `LAB VALIDATED`.
