# tests/detections/

pytest checks for detection-as-code:
- required metadata
- MITRE ID format
- `SF-XXX` naming
- unique Wazuh rule IDs in 100000–109999

**Status:** `test_validator.py` checks metadata, MITRE IDs, names, and rule IDs.
