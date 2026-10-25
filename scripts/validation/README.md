# scripts/validation/

Tooling that runs on the Mac and in CI.

| Script | Purpose | Status |
|---|---|---|
| `check_scaffold.sh` | Verifies repo structure and that `.env` isn't tracked | Ready to run |
| `run_logtest.sh` | Feeds `tests/logs/` into `wazuh-logtest` (Docker) | Step 9 |
| `validate_detections.py` | Metadata, MITRE IDs, naming, duplicate rule IDs | Step 11 |
