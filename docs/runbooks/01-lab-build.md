# 01 — Lab build order

> Status: NOT TESTED. The scripts are SYNTAX VALID on the Mac. They have not run on a VM.
> Snapshot every VM before the first script. Steps 15–16 install WAZUH01 and follow this order.

A VERIFY line prints `PASS` or `FAIL`. Stop on `FAIL`. Do not mark a step done from this Mac.

## DC01

1. Snapshot: clean Windows install, before any script.
2. `scripts/powershell/01-Set-StaticIP.ps1 -Hostname DC01`
   Check: the script prints `VERIFY PASS static-ip` and the address is `10.10.10.10`.
3. `scripts/powershell/02-Rename-Computer.ps1 -Hostname DC01`
   Check: `VERIFY PASS hostname pending DC01`. Reboot. The script does not reboot.
4. Snapshot: after the rename reboot, before the forest.
5. `scripts/powershell/10-Install-ADDS-Forest.ps1`
   The DSRM password is prompted. `Install-ADDSForest` reboots DC01. Check after the reboot: the script, run again, prints `VERIFY PASS forest sentinelforge.lab`.
6. Snapshot: after the forest is up, before user creation.
7. `scripts/powershell/11-New-LabOUsAndUsers.ps1`
   Passwords are prompted. `sf-test-admin` goes in the Lab Admins group and not Domain Admins.
   Check: `VERIFY PASS ou-users`.
8. Snapshot: before telemetry.
9. Record the Sysmon zip hash in `configs/sysmon/SYSMON_ZIP_SHA256.txt`. Then `scripts/powershell/30-Apply-Telemetry.ps1`.
   Check: `VERIFY PASS telemetry`.
10. Snapshot: after telemetry, before the agent.
11. Record the MSI hash in `scripts/powershell/WAZUH_AGENT_MSI_SHA256.txt`. The URL checked on 2026-10-26 was `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi` (HTTP 200, file not downloaded). Confirm it that day.
    `scripts/powershell/40-Install-WazuhAgent.ps1`
    Check: `VERIFY PASS agent`.
12. `scripts/powershell/99-Get-LabStatus.ps1`
    Check: `VERIFY PASS lab-status`.

## WS01

1. Snapshot: clean Windows install.
2. `01-Set-StaticIP.ps1 -Hostname WS01`
   Check: `10.10.10.20`, DNS `10.10.10.10`.
3. `02-Rename-Computer.ps1 -Hostname WS01`, then reboot.
4. Snapshot: after the rename reboot, before the domain join.
5. `20-Join-Domain.ps1`
   The join account is prompted. It must be allowed to join a computer. `sf-test-admin` is not a Domain Admin. The script reboots on success.
6. Snapshot: after domain join, before telemetry.
7. Record the Sysmon hash, then `30-Apply-Telemetry.ps1`.
8. Snapshot: after telemetry, before the agent.
9. Record the MSI hash, then `40-Install-WazuhAgent.ps1`.
10. `99-Get-LabStatus.ps1`
    Check: domain `sentinelforge.lab` and `VERIFY PASS lab-status`.

## UBU01

1. Snapshot: clean Ubuntu 24.04 install.
2. From a checkout, as root: `scripts/bash/ubu01-setup.sh`
   If more than one NIC is up, set `IFACE` first.
   Check: the script's `VERIFY PASS` lines for static IP `10.10.10.30`, hostname `ubu01`, `auth.log`, auditd, and `wazuh-agent` `4.14.9-1`. The apt revision is **VERIFY** if apt cannot find that version.

## WAZUH01

This runbook does not install the all-in-one. After that install:

1. `docs/runbooks/03-wazuh-config.md`
2. `scripts/bash/wazuh01-checks.sh` with the API and indexer variables set.
   Check: services `active`, and `VERIFY PASS rule-count`. An empty archives index is `VERIFY FAIL` until Filebeat has shipped one event. That failure is expected before the first event.

Do not run attack simulations from this runbook.
