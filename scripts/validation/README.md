# scripts/validation/

Tooling that runs on the Mac and in CI.

| Script | Purpose | Status |
|---|---|---|
| `check_scaffold.sh` | Verifies repo structure and that `.env` isn't tracked | Ready to run |
| `run_logtest.sh` | Feeds `tests/logs/` into `wazuh-logtest` (Docker) | Ready when Docker is up |
| `validate_detections.py` | XML, metadata, MITRE IDs, status honesty, Sigma shape, hunt syntax | Used by `make validate` |
| `build_hunt_fixtures.py` | Rebuilds `fixtures/hunts.json` from `hunting/*.yml` | Rebuilds the fixture |
| `indexed_fields.txt` | Field names a hunt query or aggregation may use | Allow-list |
| `lint_powershell.ps1` | PSScriptAnalyzer and a parse check. `make lint-scripts` runs it | Used by `make lint-scripts` |
| `sigma_check.py` | `sigma check` plus OpenSearch Lucene convert | Used by `make validate` |
| `update_attack_ids.py` | Rebuilds `attack_techniques.json` from ATT&CK v20.0 | Manual refresh |
