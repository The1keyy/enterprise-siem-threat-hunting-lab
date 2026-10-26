# Mac vs Windows lab

All implementation through Step 14 happens on the Mac. The Windows PC is the hypervisor for the lab, later.

"Test on Mac" means a check that can fail the change before any VM exists: lint, unit tests, a production build, or `wazuh-logtest` against a labeled synthetic log. It does not mean the lab already proved the detection.

The Wazuh manager API client and indexer client are built and mock-tested on the Mac (Step 8). Live behavior against WAZUH01 **REQUIRES LAB VALIDATION**. The mocks are labeled synthetic and are not lab alerts.

Step 9 runs `wazuh/wazuh-manager:4.14.9` as `linux/arm64` (container `uname` `aarch64`) with no Rosetta platform flag. `make logtest` passed CANARY-001 on built-in sshd rule 5710. CANARY-002, a synthetic Windows 4625 event, did not reach decoder `windows_eventchannel` (observed decoder `json`, rule 1002). That case is `REQUIRES WINDOWS VALIDATION / logtest-limited`. Logtest does not replace the WAZUH01 install.

The `logtest` GitHub Actions job uses that same image and `scripts/validation/logtest/docker-compose.yml` on `ubuntu-latest` (amd64). It sets no `platform` flag. The API password is generated in the job and is not committed. Windows cases stay `LIMITED` there too.

| Component | Build on Mac? | Test on Mac? | How it is tested on Mac | Needs Windows/lab validation? |
|---|---|---|---|---|
| Architecture, roadmap, ADRs | Yes | Yes | Read-through against `docs/VERSIONS.md` and the core rules | No, except the network and VM plan when the lab is built |
| React console | Yes | Yes | `npm run lint`, `npm run build`, click-through in demo mode | Live data: yes, after WAZUH01 exists |
| FastAPI backend | Yes | Yes | `ruff check`, `pytest`, demo mode | Live mode against WAZUH01: yes |
| SQLite (incidents, notes, hunts, audit log) | Yes | Yes | `pytest` against a local file | No |
| Single-admin auth and CORS | Yes | Yes | `pytest` | No |
| `DATA_MODE=demo` fixtures | Yes | Yes | UI banner plus `"demo": true` | No. Fixtures are not lab evidence. |
| Wazuh manager API client | Yes | Yes | Unit tests with mocked HTTP | Yes. Real JWT login and payloads. **VERIFY** endpoints. |
| Wazuh indexer client | Yes | Yes | Unit tests with mocked HTTP | Yes. Real `wazuh-alerts-*` / `wazuh-archives-*`. **VERIFY** names. |
| Correlation and risk scoring | Yes | Yes | `pytest` with synthetic events | Yes, once real alerts exist. The math can be proven earlier. |
| Wazuh rules and decoders | Yes | Yes | `wazuh-logtest` in Docker (Step 9) on sample lines | **REQUIRES WINDOWS VALIDATION** for Windows events and `win.eventdata.*` |
| Sigma rules | Yes | Yes | `sigma convert` in CI | Field accuracy on real logs: yes for Windows sources |
| Detection metadata | Yes | Yes | `pytest` for IDs, MITRE format, required fields | `observed_result` stays `NOT YET VALIDATED` until the lab |
| GitHub Actions CI | Written on Mac | Yes, on push | `detections`, `app`, `logtest` (`wazuh-manager:4.14.9`), and `secrets` (gitleaks 8.30.1) | CI cannot mark a rule `LAB VALIDATED` |
| Sysmon config | Written on Mac | No | XML review and credit to the upstream config only | **REQUIRES WINDOWS VALIDATION** on WS01 and DC01 |
| Windows audit policy and PowerShell logging | Written on Mac | No | Review of the documented `auditpol` / GPO steps | **REQUIRES WINDOWS VALIDATION** |
| PowerShell setup and simulation scripts | Written on Mac | Lint only | PSScriptAnalyzer via `pwsh` | **REQUIRES WINDOWS VALIDATION**. Run only on `sentinelforge.lab`. |
| Bash lab scripts | Written on Mac | Lint only | `shellcheck` | Runtime on UBU01 or WAZUH01, not on the Mac host |
| auditd rules | Written on Mac | No | Review only | UBU01 in the lab |
| Wazuh `ossec.conf` snippets | Written on Mac | No | Review only. Placeholders such as `<WAZUH_MANAGER_IP>`. | Yes, when applied on agents and the manager |
| Suricata config | Written on Mac | No | Review only. Stretch. | SURI01, and only when that VM is powered on |
| Saved hunts | Written on Mac | Schema only | YAML lint. Queries are not executed. | Yes, against the indexer |
| Attack simulations | Written on Mac | No | Must refuse to run outside the domain | **REQUIRES WINDOWS VALIDATION**. Snapshot first. |
| VMware networks, static IPs, NAT update window | No | No | Documented in `architecture/ARCHITECTURE.md` | **REQUIRES WINDOWS VALIDATION** |
| WS01 vTPM and VM encryption | No | No | Documented only | **REQUIRES WINDOWS VALIDATION** on Workstation Pro 26.0.1 |
| DC01 AD DS and DNS | No | No | — | **REQUIRES WINDOWS VALIDATION** |
| WS01 domain join | No | No | — | **REQUIRES WINDOWS VALIDATION** |
| Wazuh 4.14.9 all-in-one install | No | No | Docker logtest is not this install | **REQUIRES WINDOWS VALIDATION** on WAZUH01 |
| Wazuh Windows agent | No | No | — | **REQUIRES WINDOWS VALIDATION** on DC01 and WS01 |
| Wazuh Linux agent | No | No | — | UBU01 (and SURI01 if used) |
| SSH tunnel from the Mac to WAZUH01 | Config on the Mac later | Port check only after the tunnel exists | `curl` to `127.0.0.1` forwards | **REQUIRES WINDOWS VALIDATION** of the host SSH listener and firewall |
| Screenshots | No | No | Do not capture fixtures and label them as the lab | Yes. Real UI and Wazuh screens only. |
| Incident report `INC-0001` | Written after the run | No | — | Yes. Step 19, from real alerts. |

Ubuntu guests are lab validation, not Windows validation. The table says which one applies.
