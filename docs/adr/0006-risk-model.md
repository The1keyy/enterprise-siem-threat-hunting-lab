# ADR 0006 — Explainable risk model

- **Status:** Accepted
- **Date:** 2026-10-27

## Decision

Incident risk is a sum of categories, then one asset multiplier, then a band. Every number is in `backend/app/core/risk_config.yml`. The scorer is `backend/app/services/correlation.py`. It is not a model trained on data.

Each category counts once per incident, at the points below. A later alert in the same category is kept on the timeline with `counted: false` and the reason `category already counted`. An alert that is not an SF detection scores 0 and stays on the incident when a link key put it there.

| Category | SF IDs | Points |
|---|---|---|
| auth_burst | SF-001, SF-002, SF-013 | 15 |
| success_after_failures | SF-003, SF-014 | 25 |
| suspicious_powershell | SF-004, SF-005, SF-006 | 30 |
| privileged_group_change | SF-007, SF-008 | 35 |
| new_account | SF-009 | 10 |
| remote_access | SF-010 | 20 |
| lateral_movement | SF-011, SF-012 | 30 |

The asset class comes from the host map in the same file. The multiplier is the highest class among the hosts on the incident:

| Class | Hosts | Multiplier |
|---|---|---|
| workstation | WS01 | 1.0 |
| server | UBU01, WAZUH01 | 1.3 |
| domain_controller | DC01 | 1.7 |

`final = round(subtotal × multiplier)` with half-up rounding, the same rule as `final_score` in `backend/app/services/risk.py`. The host that set the multiplier is stored on the incident.

Bands for this score, which are not the ADR 0004 rule-level labels:

| Final score | Band |
|---|---|
| 1–39 | low |
| 40–79 | medium |
| 80–149 | high |
| 150 and above | critical |

A single alert at `rule.level` 15 or above forces the band to critical. The points do not change.

Entity pages sum the counted subtotal of each incident the user or host appears on. The weight is `points × 0.5 ^ (age_hours / half_life_hours)`. The half-life is 24 hours, measured from the incident's last alert. At 24 hours the subtotal is worth half. At 48 hours it is worth a quarter. The multiplier is not applied a second time on the entity page.

## Context / why

Repeated alerts are the normal shape of this lab. SF-001 is already "many failures." If each extra 4625 added 15 points, the score would measure volume, not what happened. Counting the category once keeps a password spray and a later success distinct, and it stops the spray from outscoring a privileged group change.

The host multiplier is there because the same PowerShell alert on DC01 is worse than on WS01. Using the max class means one domain controller on the incident sets the multiplier. A workstation in the same incident does not dilute it.

The decay is there so a user page does not show last week's incident at full weight forever. It is a half-life, not a learned threshold. An analyst can recompute it from the breakdown and the timestamps.

This is not machine learning. There is no training set, no feature matrix, and no probability. Rule 8 of the project rules forbids a fake model. A reviewer can add the rows and get the number.

## Worked example

Synthetic story used by `backend/tests/test_correlation.py`. Not a lab result.

| Alert | Category | Counted | Points |
|---|---|---|---|
| SF-001 | auth_burst | yes | 15 |
| SF-002 | auth_burst | no, category already counted | 15 shown, not added |
| SF-003 | success_after_failures | yes | 25 |
| SF-004 | suspicious_powershell | yes | 30 |
| SF-007 | privileged_group_change | yes | 35 |
| SF-011 | lateral_movement | yes | 30 |

Subtotal `15 + 25 + 30 + 35 + 30 = 135`. Hosts are DC01 and WS01. DC01 is a domain controller, so the multiplier is 1.7. `round(135 × 1.7) = round(229.5) = 230`, which is critical.

The same alerts with every agent name set to WS01 stay at multiplier 1.0, final 135, high.

An unrelated SSH pair, SF-013 and SF-014, for a different user from `10.10.10.200` on UBU01 is a second incident: `15 + 25 = 40`, server multiplier 1.3, `40 × 1.3 = 52`, medium.

## Alternatives considered

| Option | Why it lost |
|---|---|
| Add points for every alert | A noisy auth rule would outrank a group-membership change. |
| A learned score | There is no labeled incident history. A weight that cannot be shown on the breakdown is not usable in an interview or a write-up. |
| Reuse the demo Settings bands (30 / 60 / 100) | Those bands belong to the fixture incidents. This model uses 40 / 80 / 150. Changing Settings would change INC-0001's displayed band. Step 14A does not do that. |
| Multiply every entity by the asset factor again | The host page would double-count the domain-controller factor that the incident score already applied. |

## Tradeoffs

- Two auth detections in one incident still look like one 15-point row plus a skipped row. The timeline keeps both alerts. The score does not.
- A level-15 alert on a low point total is critical by rule, not because the points crossed 150. The breakdown has to say so (`forced_critical`). SF-008 on DC01 is 35 × 1.7 = 60, which is medium on points and critical because the rule level is 15.
- The demo incident fixtures still use the older Settings weights. This file does not rescore INC-0001. Wiring that is a later step.
- Half-life math is floating point. The tests use the exact halves (40 → 20 → 10).

## What I must understand

- Sum only rows with `counted: true`. The points column on a skipped row is the category value that was not added.
- Unknown alerts add context, not points.
- The multiplier is the max class on the incident, and the incident records which host set it.
- ADR 0004 still maps `rule.level` to a display word. That word is not this score.
- Entity risk decays the incident subtotal. It does not decay the multiplied final.
- None of these numbers were measured in the lab.

## Likely interview questions + short answers

**Why not machine learning?**
There is nothing to train on. The score has to be re-added from the breakdown during a review. A probability would hide the category that actually fired.

**Why count a category once?**
SF-001 already means "many failures." Counting every child alert would make the noisiest stage the highest risk.

**Walk the story.**
Auth burst 15, success 25, PowerShell 30, local admin 35, admin share 30. SF-002 is the same burst category and is not added. Subtotal 135. DC01 sets 1.7. Round half up: 230, critical.

**What does the 24 hour half-life mean?**
An entity's counted points from an incident are worth half one day after that incident's last alert, and a quarter after two days. It is a clock, not a confidence interval.
