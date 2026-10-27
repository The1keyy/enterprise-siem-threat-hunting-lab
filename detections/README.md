# detections/

Detection-as-code. Every detection `SF-XXX` is made of:

| Path | Contents |
|---|---|
| `metadata/SF-XXX.yml` | Source of truth: severity, MITRE, telemetry, validation status, test procedure |
| `wazuh/rules/` | Wazuh custom rule(s), IDs 100000–109999 |
| `sigma/SF-XXX.yml` | Portable Sigma version |
| `../tests/logs/SF-XXX.yml` | Synthetic logtest cases (positive and negative) for `wazuh-logtest` |
| `../docs/detections/SF-XXX.md` | Full writeup |

CI checks syntax, metadata, MITRE IDs, naming, and duplicate rule IDs.

**Status:** SF-001 through SF-014 are written. SF-001 through SF-012 are `SYNTAX VALID`. SF-013 and SF-014 are `LOGTEST VALID`. Nothing is `LAB VALIDATED`.
