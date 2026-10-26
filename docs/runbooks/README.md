# docs/runbooks/

Step-by-step procedures for building and operating the lab:
- VM build
- AD setup
- telemetry
- agent enrollment
- read-only Wazuh users
- detection deployment

Each step ends with a verification check.

| Runbook | Status |
|---|---|
| `wazuh-readonly-users.md` | Written in Step 8. REQUIRES LAB VALIDATION |
| `wazuh-archives.md` | Written in Step 8. The 12B procedure is `03-wazuh-config.md` |
| `03-wazuh-config.md` | NOT TESTED. Manager snippet, archives, ISM, rule deploy, read-only users |
| `01-lab-build.md` | NOT TESTED. Script order and snapshot points for DC01, WS01, UBU01, and the WAZUH01 checks |

The scripts those runbooks call are SYNTAX VALID on the Mac. They have not run on a VM.
