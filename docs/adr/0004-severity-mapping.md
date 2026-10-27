# ADR 0004 — Wazuh rule level to console severity

- **Status:** Accepted
- **Date:** 2026-10-26

## Decision

The console severity label comes from the Wazuh rule level:

| Wazuh `rule.level` | Console severity |
|---|---|
| 0–6 | low |
| 7–11 | medium |
| 12–14 | high |
| 15 and above | critical |

The cutoffs live in `backend/app/core/config.py` (`WAZUH_LEVEL_LOW_MAX`, `WAZUH_LEVEL_MEDIUM_MAX`, `WAZUH_LEVEL_HIGH_MAX`). A missing level stays `None`. The mapper does not invent a label.

## Context / why

Wazuh alerts carry a numeric level. The console charts and incident queue use the words low, medium, high, and critical. One mapping has to be shared by the overview aggregations and by `alert_to_timeline`, or the same alert would show two severities. The bands are coarse on purpose: this is a display label, not a second risk score. The correlation engine owns the point-based risk score.

## Alternatives considered

| Option | Why it lost |
|---|---|
| Use the Wazuh level number in the UI | The rest of the console already speaks in five severity words. |
| Copy the incident risk bands (30 / 60 / 100) | Those are point totals, not rule levels. Mixing them would make a level-12 alert look "high" for two different reasons. |
| Let each page pick its own cutoffs | The overview histogram and the timeline would disagree. |

## Tradeoffs

- A level-15 alert and a level-12 alert are not the same thing, and this mapping flattens 12–14 into one word. The raw level stays in the alert document.
- **VERIFY (4.14.9):** built-in rules top out at 15. Levels above 15, if a custom rule uses them, are critical.
- The indexer aggregation uses the same edges (`to` is exclusive): 0–7, 7–12, 12–15, 15+.

## What I must understand

- Severity here is a label for a Wazuh rule level. It is not the incident risk score.
- A missing `rule.level` is `None`, not low.
- Changing a cutoff is a config change plus this ADR, not a silent edit in a chart.

## Likely interview questions + short answers

**Why not show the raw Wazuh level?**
The console's filters, colors, and incident severity already use words. The level is still stored on the alert. The word is only the display band.

**Is this the risk score?**
No. Risk points are a separate, explainable sum. This table only translates `rule.level`.
