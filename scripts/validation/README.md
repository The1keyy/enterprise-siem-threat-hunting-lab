# scripts/validation/

Tooling that runs on the Mac and in CI.

| Script | Purpose | Status |
|---|---|---|
| `check_scaffold.sh` | Verifies repo structure and that `.env` isn't tracked | Ready to run |
| `run_logtest.sh` | Feeds `tests/logs/` into `wazuh-logtest` (Docker) | Step 9 |
| `validate_detections.py` | XML, metadata, MITRE IDs, status honesty, Sigma shape, hunt syntax | Step 11A, Step 13A |
| `build_hunt_fixtures.py` | Rebuilds `fixtures/hunts.json` from `hunting/*.yml` | Step 13A |
| `indexed_fields.txt` | Field names a hunt query or aggregation may use | Step 13A |
| `lint_powershell.ps1` | PSScriptAnalyzer and a parse check. `make lint-scripts` runs it | Step 12.1 |
| `sigma_check.py` | `sigma check` plus OpenSearch Lucene convert | Step 11A |
| `update_attack_ids.py` | Rebuilds `attack_techniques.json` from ATT&CK v20.0 | Step 11A |
