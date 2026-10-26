# Lab simulations

Status: **NOT TESTED**. Every script under `scripts/powershell/simulations/` has `REQUIRES WINDOWS VALIDATION`. Nothing in this runbook has been run on a VM. A clean PowerShell parse on the Mac is not a lab result.

These scripts generate telemetry inside `sentinelforge.lab`. They do not install malware, dump credentials, or run Mimikatz. Nothing is aimed outside `10.10.10.0/24`.

Snapshot the VMs in this runbook before the first script. Restore the snapshot if a host is left in a state you do not want.

## Before any script

1. The host is joined to `sentinelforge.lab`.
2. The host name is `WS01` or `DC01`, as the section says.
3. Every IPv4 address on the host is inside `10.10.10.0/24`. An extra NIC with another address makes the guard refuse.
4. Run from an elevated Windows PowerShell 5.1 window. `pwsh` 7 is not the lab host shell for these scripts.
5. Pass `-IUnderstandLabOnly`.
6. Type `I have a snapshot` when asked. The words are case-sensitive.
7. A default route produces a loud warning and does not, by itself, stop the script. Stop if that route can reach the internet.

`-WhatIf` still runs the guard. It prints the action and does not change the host.

There is no `10.10.10.200` VM. `Add-AttackerIP.ps1` adds that address on the WS01 NIC that already has `10.10.10.20`. `Remove-AttackerIP.ps1` removes it. Each cleanup below removes it when it is present.

## Source address

| Script | Address you should expect in the event | Why |
|---|---|---|
| SF-001, SF-002, SF-003 | `10.10.10.20` | `net use` cannot bind a source address. |
| SF-004, SF-005, SF-007, SF-009 | the host that ran the script | Local events. No attacker address is required. |
| SF-006 SSH control | `10.10.10.200` | `ssh.exe -o BindAddress=10.10.10.200` |
| SF-006 Sysmon event 3 | `10.10.10.20` | `Invoke-WebRequest` on Windows PowerShell 5.1 has no local-address parameter. |
| SF-008 | DC01 | The 4728 is local to the domain controller. |
| SF-010 | `10.10.10.20` | `mstsc` cannot bind. |
| SF-011, SF-012 | `10.10.10.20` | `net use` and `Invoke-Command` cannot bind. |
| SF-013, SF-014 | `10.10.10.200` | `ssh.exe` bind. If bind fails, the script stops and does not use `.20`. |

If a Security event shows the other address, write that down. Do not edit `tests/logs/` to match either value. Those files are synthetic logtest input.

## SSH client

SF-006, SF-013, and SF-014 use the Windows OpenSSH Client, `C:\Windows\System32\OpenSSH\ssh.exe`.

- It is a Windows feature. The scripts do not download a client and do not vendor `plink.exe`, so there is no hash to invent.
- `plink -pw` would put the password on the command line and cannot set a source address.
- Python is not installed on WS01, so paramiko is not used.
- The password is passed with `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE=force`. **VERIFY** both options on the WS01 build. The password is not an argument and is not written to the run record.
- **VERIFY** `BindAddress`. A bind failure stops the script.

`ubu01-setup.sh` does not create `sf-test-alice`. Before SF-006, SF-013, or SF-014, on UBU01:

```bash
sudo adduser --disabled-password --gecos '' sf-test-alice
sudo passwd sf-test-alice
```

Password authentication in `sshd` must already be on. The scripts do not edit `sshd_config`. **VERIFY** that on UBU01. `python3` must already be installed for SF-006. The script does not install it.

## How to record evidence

Do this for every detection you actually run. Do not commit the files.

1. The script writes `C:\SentinelForge\evidence\runs\<timestamp>_SF-XXX.json` with the host, user, start and end UTC, redacted commands, expected rule IDs, and cleanup status.
2. In the Wazuh dashboard, open the alert and export the alert JSON next to that run record.
3. Take a screenshot of the same alert.
4. Fill one row of the Step 18 table at the bottom of this file. Copy the table into your lab notes. Leave the status `NOT TESTED` until you have the run record, the alert JSON, and the screenshot.

SentinelForge `/detections/SF-XXX` shows the rule definition. It does not list this run's alert. A fired alert is in the Wazuh dashboard. Step 14 is the correlation step and is not part of this runbook.

Dashboard queries below use the 4.14 field names already used in this repo. **VERIFY** them on WAZUH01.

## SF-001 failed logon burst

- Prerequisites: WS01, `sf-test-alice` on DC01, Script Block Logging is not required. Security logon failures are.
- Snapshot: WS01 and DC01.
- Command, from `scripts\powershell\simulations` on WS01:

```powershell
.\SF-001-FailedLogon.ps1 -IUnderstandLabOnly
```

- What it does: six `net use \\DC01\IPC$` failures for `SENTINELFORGE\sf-test-alice`. The wrong value is a fixed marker, not a password list, and the run record redacts it. Mirrors the SMB shape of Atomic Red Team `T1110.001` Test #1. That test's password file is not used.
- Expected: six 4625 events, then rule `100100` level 11. Five failures stay on the stock 4625 rule. `100110` can also match the same six events from one IP. Level 11 is `100100`. Whether both alerts are stored **REQUIRES WINDOWS VALIDATION**.
- Wazuh: `rule.id:100100 AND data.win.eventdata.targetUserName:sf-test-alice`
- Cleanup:

```powershell
.\SF-001-FailedLogon-Cleanup.ps1 -IUnderstandLabOnly
```

The cleanup deletes the IPC$ mapping and removes `.200`. `Unlock-ADAccount` runs only when the ActiveDirectory module is on that host. Otherwise it prints the DC01 command. It does not reset the password.

## SF-002 same-IP failures

- Prerequisites: WS01, accounts `sf-test-alice`, `sf-test-bob`, and `sf-test-carol`.
- Snapshot: WS01 and DC01.
- Command:

```powershell
.\SF-002-PasswordSpray.ps1 -IUnderstandLabOnly
```

- What it does: two failures each for those three accounts (six failures). The rule `100110` is six failures from one IP. It does not count distinct users. Only four `sf-test-*` accounts exist, so "six accounts" is not the test. Two per account stays under the six-failure same-account rule `100100`. Distinct-user correlation is Step 14. Technique `T1110.003`. The Atomic test number is **VERIFY**. No Atomic body is downloaded.
- Expected: rule `100110` level 10. `100100` should not fire, because no account reached six.
- Wazuh: `rule.id:100110 AND data.win.eventdata.ipAddress:10.10.10.20`
- Cleanup:

```powershell
.\SF-002-PasswordSpray-Cleanup.ps1 -IUnderstandLabOnly
```

Unlock is attempted for the three accounts when the AD module is present. Passwords are not reset.

## SF-003 failures then success

- Prerequisites: same as SF-001. You will type the real `sf-test-alice` password at the `net use` prompt. It is not stored. The `*` form keeps it off the command line.
- Snapshot: WS01 and DC01.
- Command:

```powershell
.\SF-003-FailureThenSuccess.ps1 -IUnderstandLabOnly
```

- What it does: the SF-001 burst, then one successful `\\DC01\IPC$` map, then an immediate delete. The success has to fall inside 120 seconds of rule `100100`.
- Expected: `100100`, then `100120` level 12 for the same account and the same source IP. A successful IPC$ map can also produce `100511` (IPC$, level 4) and `100512` (4624 type 3, level 5). Those are side effects.
- Wazuh: `rule.id:100120 AND data.win.eventdata.targetUserName:sf-test-alice`
- Cleanup:

```powershell
.\SF-003-FailureThenSuccess-Cleanup.ps1 -IUnderstandLabOnly
```

## SF-004 script block markers

- Prerequisites: WS01, Script Block Logging already enabled. The script does not enable it.
- Snapshot: WS01.
- Command:

```powershell
.\SF-004-ScriptBlockMarkers.ps1 -IUnderstandLabOnly
```

- What it does: runs a script block whose text is `Write-Output` of the strings `IEX`, `Invoke-Expression`, and `FromBase64String`. Those strings are not commands. Atomic `T1059.001` Test #1 is Mimikatz and is not used.
- Expected: event 4104 and rule `100200` level 12.
- Wazuh: `rule.id:100200`
- Cleanup:

```powershell
.\SF-004-ScriptBlockMarkers-Cleanup.ps1 -IUnderstandLabOnly
```

Nothing was written to disk.

## SF-005 encoded command

- Prerequisites: WS01, Sysmon process creation already installed.
- Snapshot: WS01.
- Command:

```powershell
.\SF-005-EncodedCommand.ps1 -IUnderstandLabOnly
```

- What it does: `powershell.exe -NoProfile -NonInteractive -EncodedCommand` of Unicode base64 for `Write-Output "sentinelforge-lab"`. The script refuses to launch if the token is shorter than 20 characters. This is the shape of Atomic `T1059.001` Test #15 only. AtomicTestHarnesses is not installed and not downloaded.
- Expected: Sysmon event 1 and rule `100210` level 13. This is not a 4688 rule.
- Wazuh: `rule.id:100210`
- Cleanup:

```powershell
.\SF-005-EncodedCommand-Cleanup.ps1 -IUnderstandLabOnly
```

The child process exits by itself.

## SF-006 download from the lab HTTP server

- Prerequisites: WS01 OpenSSH Client, UBU01 `python3`, local user `sf-test-alice`, Script Block Logging, and Sysmon network events.
- Snapshot: WS01 and UBU01.
- Command:

```powershell
.\SF-006-DownloadCradle.ps1 -IUnderstandLabOnly
```

- What it does: SSH to UBU01 starts `python3 -m http.server 8080 --bind 10.10.10.30` serving one text file, `Invoke-WebRequest` downloads `http://10.10.10.30:8080/sentinelforge-lab.txt`, and the same script stops the server. The URL is checked before the request. Shape of Atomic `T1105` Test #29 only. The Atomic URL is not used.
- Expected: 4104 rule `100220`, and a PowerShell TCP connection rule `100221`. `IEX` alone does not fire `100220`.
- Wazuh: `rule.id:100220 OR rule.id:100221`
- Cleanup, if the server or the address is still up:

```powershell
.\SF-006-DownloadCradle-Cleanup.ps1 -IUnderstandLabOnly
```

If SSH cannot stop it, on UBU01: `kill` the pid in `/tmp/sentinelforge-lab-http/server.pid`.

## SF-007 local Administrators

- Prerequisites: WS01, domain user `sf-test-bob`.
- Snapshot: WS01.
- Command:

```powershell
.\SF-007-LocalAdmins.ps1 -IUnderstandLabOnly
```

- What it does: `Add-LocalGroupMember` for `SENTINELFORGE\sf-test-bob` in local Administrators. Technique `T1098`. Atomic test number **VERIFY**. No Atomic body is downloaded.
- Expected: 4732 with `targetSid` `S-1-5-32-544`, rule `100300` level 13. A display name without that SID does not fire it.
- Wazuh: `rule.id:100300 AND data.win.eventdata.targetSid:S-1-5-32-544`
- Cleanup, immediately:

```powershell
.\SF-007-LocalAdmins-Cleanup.ps1 -IUnderstandLabOnly
```

## SF-008 Domain Admins

- Prerequisites: DC01, `sf-test-carol`, ActiveDirectory module. This is the only script that changes Domain Admins.
- Snapshot: DC01. Take it before you pass the extra confirmation.
- Command:

```powershell
.\SF-008-DomainAdmins.ps1 -IUnderstandLabOnly -IUnderstandDomainAdmins
```

Type `I will remove sf-test-carol` when asked.

- What it does: `Add-ADGroupMember` of `sf-test-carol` to Domain Admins. Technique `T1098`. Atomic test number **VERIFY**.
- Expected: 4728 for RID 512, rule `100310` level 15. Rule `100311` is the other privileged RIDs and is not this test.
- Wazuh: `rule.id:100310`
- Cleanup, immediately, on DC01:

```powershell
.\SF-008-DomainAdmins-Cleanup.ps1 -IUnderstandLabOnly
```

Do not leave `sf-test-carol` in Domain Admins.

## SF-009 create a user

- Prerequisites: DC01, OU `Lab Users` from `11-New-LabOUsAndUsers.ps1`.
- Snapshot: DC01.
- Command:

```powershell
.\SF-009-CreateUser.ps1 -IUnderstandLabOnly
```

The password is prompted and is not stored. It must satisfy the domain password policy.

- What it does: `New-ADUser sf-test-temp`. Technique `T1136.001`. Atomic test number **VERIFY**. The rule matches any 4720. The name is not the match.
- Expected: 4720, rule `100320` level 10.
- Wazuh: `rule.id:100320`
- Cleanup:

```powershell
.\SF-009-CreateUser-Cleanup.ps1 -IUnderstandLabOnly
```

## SF-010 RDP

- Prerequisites: WS01 can reach DC01 on 3389. The account you type into the client is your choice. `sf-test-admin` is the 100501 case. DC01 as the target is the 100502 case.
- Snapshot: WS01 and DC01.
- Command:

```powershell
.\SF-010-Rdp.ps1 -IUnderstandLabOnly
```

Add `-LaunchClient` only if you want the script to open `mstsc.exe /v:DC01.sentinelforge.lab`. You still click Connect, check the certificate name, sign in, and sign out. The script does not type a password.

- Expected: 4624 logon type 10. Rules `100500`, and `100501` or `100502` when those fields match. One type-10 event is enough for `100500`. Technique `T1021.001`. Atomic test number **VERIFY**.
- Wazuh: `rule.id:100500 AND data.win.eventdata.logonType:10`
- Cleanup: sign out of the RDP window, then:

```powershell
.\SF-010-Rdp-Cleanup.ps1 -IUnderstandLabOnly
```

The cleanup does not call `logoff`.

## SF-011 admin share

- Prerequisites: WS01. The current logon must be allowed to open `\\DC01\C$`. A standard user such as `sf-test-alice` is expected to be denied. The script uses the current session so the password is not on the command line.
- Snapshot: WS01 and DC01.
- Command:

```powershell
.\SF-011-AdminShare.ps1 -IUnderstandLabOnly
```

- What it does: `net use \\DC01\C$`. Technique `T1021.002`. Atomic test number **VERIFY**.
- Expected: 5140 or 5145 for `C$`, rule `100510` level 12, and a type-3 4624, rule `100512` level 5. IPC$ is `100511` and is not this test.
- Wazuh: `rule.id:100510`
- Cleanup:

```powershell
.\SF-011-AdminShare-Cleanup.ps1 -IUnderstandLabOnly
```

## SF-012 WinRM

- Prerequisites: WinRM is already enabled on DC01. The script does not call `Enable-PSRemoting`. The current user must be allowed to connect. No WinRM Operational event ID is claimed.
- Snapshot: WS01 and DC01.
- Command:

```powershell
.\SF-012-WinRm.ps1 -IUnderstandLabOnly
```

- What it does: `Invoke-Command` to `DC01.sentinelforge.lab` running `hostname.exe`. Technique `T1021.006`. Atomic test number **VERIFY**.
- Expected: Sysmon 1 `wsmprovhost.exe` rule `100520`, and destination port 5985 rule `100521`.
- Wazuh: `rule.id:100520 OR rule.id:100521`
- Cleanup:

```powershell
.\SF-012-WinRm-Cleanup.ps1 -IUnderstandLabOnly
```

`Invoke-Command` returns before the cleanup. There is no session to close.

## SF-013 SSH failures

- Prerequisites: the SSH section above. Snapshot UBU01 and WS01.
- Command, on WS01:

```powershell
.\SF-013-SshFailures.ps1 -IUnderstandLabOnly
```

- What it does: six failed password attempts as `sf-test-alice` at `10.10.10.30`, sourced from `10.10.10.200`. It stops at six. A connection error is not counted as a failure; the script stops.
- Expected: rule `100701` (invalid user) or `100702` (known user, bad password), level 10, on the sixth line. Five lines stay on stock `5710`.
- Wazuh: `rule.id:100701 OR rule.id:100702`
- Cleanup:

```powershell
.\SF-013-SshFailures-Cleanup.ps1 -IUnderstandLabOnly
```

The cleanup checks `/etc/pam.d` for `pam_faillock` or `pam_tally` first. It resets `sf-test-alice` only when one of those is present. If the reset needs root, it prints the command and does not send a root password.

## SF-014 SSH failures then success

- Prerequisites: same as SF-013. Type the real UBU01 password when asked, after the six failures, inside the 120 second window.
- Snapshot: UBU01 and WS01.
- Command:

```powershell
.\SF-014-SshSuccess.ps1 -IUnderstandLabOnly
```

- Expected: an SF-013 alert, then `100710` or `100711` level 12 for the accepted password from the same source IP.
- Wazuh: `rule.id:100710 OR rule.id:100711`
- Cleanup:

```powershell
.\SF-014-SshSuccess-Cleanup.ps1 -IUnderstandLabOnly
```

Same faillock rule as SF-013. Log out if a shell stayed open. `AuthSuccess` runs `exit`, so there should be no shell.

## Attack story

Run this on WS01 after the single-detection scripts are understood. Snapshot WS01 and DC01 first.

```powershell
.\Invoke-AttackStory.ps1 -IUnderstandLabOnly
```

Optional: `-PauseSeconds 15` (0 through 90). `-RemoteStage Share` is the default and maps `\\DC01\C$` (SF-011). `-RemoteStage WinRM` runs SF-012 instead and still does not enable WinRM.

Stages, with the pause between them:

1. SF-001 failed-logon burst.
2. SF-003 success only, so the six failures are not repeated. Type the `sf-test-alice` password at the prompt.
3. SF-004 script-block markers.
4. SF-007 add `sf-test-bob` to local Administrators.
5. SF-011, or SF-012 when `-RemoteStage WinRM`.

The script prints a UTC line at each start, pause, and cleanup. It writes one `STORY` run record plus the per-stage records. `finally` runs the SF-007, SF-011, SF-003, SF-001, SF-004, and SF-012 cleanups even when a stage throws.

Expected alerts for the default story: `100100`, `100120`, `100200`, `100300`, and `100510`. WinRM expects `100520` or `100521` instead of `100510`. Step 14 should merge those alerts into one incident. This script does not do that.

A pause over 60 seconds, or a slow password prompt, can miss the 120 second window for `100120`.

## Step 18 results

Copy this table. Leave Status as `NOT TESTED` until that row has a run record, an alert JSON export, and a screenshot. Do not fill it from this Mac.

| Detection | Script | Run UTC | Host | Source IP in the event | Event IDs seen | SF rule IDs | Run record | Alert JSON | Screenshot | Cleanup | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| SF-001 | `SF-001-FailedLogon.ps1` | | | | | | | | | | NOT TESTED |
| SF-002 | `SF-002-PasswordSpray.ps1` | | | | | | | | | | NOT TESTED |
| SF-003 | `SF-003-FailureThenSuccess.ps1` | | | | | | | | | | NOT TESTED |
| SF-004 | `SF-004-ScriptBlockMarkers.ps1` | | | | | | | | | | NOT TESTED |
| SF-005 | `SF-005-EncodedCommand.ps1` | | | | | | | | | | NOT TESTED |
| SF-006 | `SF-006-DownloadCradle.ps1` | | | | | | | | | | NOT TESTED |
| SF-007 | `SF-007-LocalAdmins.ps1` | | | | | | | | | | NOT TESTED |
| SF-008 | `SF-008-DomainAdmins.ps1` | | | | | | | | | | NOT TESTED |
| SF-009 | `SF-009-CreateUser.ps1` | | | | | | | | | | NOT TESTED |
| SF-010 | `SF-010-Rdp.ps1` | | | | | | | | | | NOT TESTED |
| SF-011 | `SF-011-AdminShare.ps1` | | | | | | | | | | NOT TESTED |
| SF-012 | `SF-012-WinRm.ps1` | | | | | | | | | | NOT TESTED |
| SF-013 | `SF-013-SshFailures.ps1` | | | | | | | | | | NOT TESTED |
| SF-014 | `SF-014-SshSuccess.ps1` | | | | | | | | | | NOT TESTED |
| Story | `Invoke-AttackStory.ps1` | | | | | | | | | | NOT TESTED |
