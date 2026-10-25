# tests/

| Folder | Contents |
|---|---|
| `logs/` | Synthetic sample log lines per detection, labeled as test input. Used with `wazuh-logtest`. |
| `detections/` | Python tests: metadata fields, MITRE ID format, naming, duplicate rule IDs. |
| `results/` | Local logtest output (gitignored, regenerated). |

Backend unit tests live in `backend/tests/`.
