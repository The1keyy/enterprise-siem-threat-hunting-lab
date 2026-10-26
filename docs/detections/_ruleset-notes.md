# Ruleset notes (Wazuh 4.14.9)

Confirmed from the `wazuh/wazuh-manager:4.14.9` image. A fact in this file was read from that image or from a logtest response. It is not a guess.

## SF-013 and SF-014 — sshd

File: `/var/ossec/ruleset/rules/0095-sshd_rules.xml`

Evidence command (rule ids and correlation attributes):

```bash
docker exec wazuh-logtest grep -n -E 'id="57(00|10|12|15|16|20|60|63)"|frequency=|same_source_ip|if_matched_sid|if_sid' /var/ossec/ruleset/rules/0095-sshd_rules.xml
```

The rule bodies below were read from that file inside the image.

| Rule | Level | Chain | What it matches |
|---|---|---|---|
| 5700 | 0, `noalert` | `decoded_as sshd` | Groups sshd messages |
| 5710 | 5 | `if_sid 5700`, match `illegal user\|invalid user` | Invalid user. MITRE `T1110.001`, `T1021.004` |
| 5716 | 5 | `if_sid 5700`, match `^Failed\|PAM: Authentication` | Authentication failed. MITRE `T1110` |
| 5760 | 5 | `if_sid 5700,5716`, match `Failed password\|Failed keyboard\|authentication error` | The alert id logtest returned for `Failed password for sf-test-bob` (a real user). 5716 is the parent; 5760 is what fires |
| 5715 | 3 | `if_sid 5700`, match `^Accepted\|authenticated.$` | Authentication success. MITRE `T1078`, `T1021` |
| 5712 | 10 | `frequency 8`, `timeframe 120`, `ignore 60`, `if_matched_sid 5710`, `same_source_ip` | Stock invalid-user brute force. MITRE `T1110` |
| 5720 | 10 | `frequency 8`, no `timeframe` attribute, `if_matched_sid 5716`, `same_source_ip` | Stock multiple authentication failures. MITRE `T1110` |
| 5763 | 10 | `frequency 8`, `timeframe 120`, `ignore 60`, `if_matched_sid 5760`, `same_source_ip` | Stock brute force on 5760. MITRE `T1110` |

Options present in this 4.14.9 ruleset (counted across `/var/ossec/ruleset/rules/*.xml`):

| Option | Present |
|---|---|
| `frequency`, `timeframe`, `if_matched_sid`, `if_sid` | Yes |
| `same_source_ip` | Yes, in `0095-sshd_rules.xml` |
| `same_field` | Yes (14 uses, not in the sshd file). Example: `0580-win-security_rules.xml` rule 60203 |
| `if_sid` together with `if_matched_sid` | Yes. Rule 2509 in `0020-syslog_rules.xml` |
| `different_field` | No. Zero matches |

`same_source_ip` is what the sshd brute-force rules use. SF-013 uses that, not `same_field`.

### How SF-013 differs from 5712 / 5720 / 5763

Those stock rules wait for 8 matches and tag MITRE `T1110`. SF-013 uses `frequency="6"` and `timeframe="120"` on the ids logtest actually fires:

- 100701 matches 5710 (invalid user). The 6th event in one session fired 100701. The 5th stayed 5710.
- 100702 matches 5760 (known-user `Failed password`). The 6th event fired 100702. The stock rule 5763 did not fire until 8.

Six is more than a couple of typos and still shorter than the stock 8, so a lab burst is visible here while 5712 and 5763 stay quiet. Level 10 is the same band as those stock rules (medium, ADR 0004).

Alternating the source between `10.10.10.200` and `10.10.10.30` for six invalid-user lines did not fire 100701. `same_source_ip` held.

### How SF-014 is built

There is no built-in sshd rule that requires 5715 after repeated failures. The 6th failure is no longer rule 5710 or 5760; it is 100701 or 100702. SF-014 therefore matches that alert:

- 100710: `if_sid 5715`, `if_matched_sid 100701`, `same_source_ip`, `frequency 2`, `timeframe 120`
- 100711: the same with `if_matched_sid 100702`

Logtest: six invalid-user failures then `Accepted password` from the same IP ended on 100710 level 12. Five failures then `Accepted password` ended on 5715. A lone `Accepted password` ended on 5715. `frequency 2` fired when one SF-013 alert was already in the window. Level 12 is high (ADR 0004). Stock success 5715 is level 3.

### Collection path

Logtest used `log_format: syslog` and `location: /var/log/auth.log`. The decoder matched the line text. The agent snippet reads that same file. 12C installs rsyslog so Ubuntu 24.04 writes it. The file is still **VERIFY** on UBU01 until that script has been run and the file is observed.

## SF-001, SF-002, and SF-003 — Windows 4625 / 4624

Evidence commands, run inside `wazuh/wazuh-manager:4.14.9`:

```bash
docker exec wazuh-logtest grep -n -E 'id="6000[01]"|decoded_as|win.system.channel' /var/ossec/ruleset/rules/0575-win-base_rules.xml
docker exec wazuh-logtest grep -n -E 'id="6010[3456]"|id="60122"|id="6020[345]"|MS_FREQ|same_field|if_matched' /var/ossec/ruleset/rules/0580-win-security_rules.xml
docker exec wazuh-logtest sh -c 'grep -c different_field /var/ossec/ruleset/rules/*.xml | grep -v ":0" || echo ZERO'
```

A second scan of every `<rule>` body in `/var/ossec/ruleset/rules/*.xml` found no rule with two `<same_field>` elements, and no `frequency` rule that also contains a `<field>` element.

### Chain

| Rule | Level | File | What it matches |
|---|---|---|---|
| 60000 | 0 | `0575-win-base_rules.xml` | `decoded_as windows_eventchannel`, `win.system.providerName` `.+` |
| 60001 | 0 | same | `if_sid 60000`, `win.system.channel` `^Security$` |
| 60104 | 5 | `0580-win-security_rules.xml` | `if_sid 60001`, severity `AUDIT_FAILURE` or `failure` |
| 60105 | 5 | same | `if_sid 60104`, eventID list includes `4625`. Description "Windows Logon Failure". MITRE `T1078` |
| 60122 | 5 | same | `if_sid 60105`, eventID `^529$\|^4625$`. Description "Logon Failure - Unknown user or bad password". MITRE `T1531` |
| 60103 | 0 | same | `if_sid 60001`, severity `AUDIT_SUCCESS` or `success` |
| 60106 | 3 | same | `if_sid 60103`, eventID `^528$\|^540$\|^673$\|^4624$\|^4769$`. "Windows Logon Success". MITRE `T1078` |

60122 is the fired id for a 4625, the same way 5760 is the fired id for a known-user sshd failure. Its eventID check is every 4625, not a bad-password status code. There is no status or substatus check on that rule.

`<var name="MS_FREQ">8</var>` is line 12 of `0580-win-security_rules.xml`.

### Fields

These names are in that file, not guessed:

| Field | Where |
|---|---|
| `win.eventdata.targetUserName` | 60203 `same_field`; 60232 match |
| `win.eventdata.ipAddress` | 60204 and 60205 `same_field`; 92651 in `0840-win_event_channel.xml` |
| `win.eventdata.logonType` | 60118 (`^2$`), 60200 (`^8$`), 60232 (`^5$`), 92653 (`10`) |
| `win.eventdata.workstationName` | 60118 |

The sample JSON comment above rule 60106 uses the same four names. `different_field` is still zero matches.

`type="pcre2" negate="yes"` on a `win.eventdata` field is rule 92651 (`ipAddress` not `127.0.0.1`). A literal trailing `$` needs pcre2. The default field matcher treats `$` as an end anchor.

### Stock bursts, and how ours differ

| Rule | What it actually is |
|---|---|
| 60203 | `frequency` 8, `timeframe` 240, `if_matched_sid` 60107, `same_field` `targetUserName`. 60107 is event 577 or 4673, a failed privileged operation. Not a 4625 rule. MITRE `T1110` |
| 60204 | `frequency` 8, `timeframe` 240, `if_matched_group` `authentication_failed`, `same_field` `ipAddress`. "Multiple Windows Logon Failures". MITRE `T1110` |
| 60205 | `frequency` 8, `timeframe` 240, `if_matched_sid` 60104 (any audit failure), `same_field` `ipAddress` |

No stock rule does `same_field` `targetUserName` on 60122.

- SF-001 (100100) is 60122, same account, frequency 6, timeframe 120, level 11, MITRE `T1110.001`. Level 11 is still medium (ADR 0004). It is above 100110 and 60204 so one account is not relabeled as a spray.
- SF-002 (100110) is 60122, same IP, frequency 6, timeframe 120, level 10, MITRE `T1110.003`. It is not a distinct-user count. Step 14 does that count. A six-account spray does not meet SF-001. A six-failure single account matches both, and 100100 wins on level.
- SF-003 (100120) is `if_sid` 60106, eventID `^4624$`, `if_matched_sid` 100100, frequency 2, timeframe 120, level 12, MITRE `T1078` only. 60106 also matches 4769. The eventID field drops that. Two `same_field` elements (account and IP) are written. This image never does that, so both being required is not proven until Windows.

A `<field>` exclusion on a frequency rule is also unused in this image. The exclusions are still in the XML. Load success does not prove the match.

### Exclusions written in `sentinelforge_100100_auth.xml`

- Every rule: `targetUserName` matching pcre2 `\$$` is negated (machine account).
- SF-002 only: `ipAddress` matching pcre2 `^-$` is negated. A dash is not a source IP.
- No other exclusion. SYSTEM, LOCAL SERVICE, NETWORK SERVICE, ANONYMOUS LOGON, logon type, and `127.0.0.1` are not excluded.

### Collection

4624 and 4625 are written on the computer that handled the logon. Domain account logons aimed at DC01 are on DC01. Local account logons are on WS01. A domain account logon to WS01 is a WS01 event. Grep of `0580-win-security_rules.xml` found no 4771 and no 4776. Those are not parents of these rules.

## SF-004, SF-005, and SF-006 — PowerShell and Sysmon

Evidence commands:

```bash
docker exec wazuh-logtest grep -n -E 'id="9180[129]"|id="91837"|scriptBlockText' /var/ossec/ruleset/rules/0915-win-powershell_rules.xml
docker exec wazuh-logtest grep -n -E 'id="60004"|id="6160[035]"' /var/ossec/ruleset/rules/0575-win-base_rules.xml /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
docker exec wazuh-logtest grep -n -E 'id="92057"|id="92071"|id="92101"|EncodedCommand|pwsh' /var/ossec/ruleset/rules/0800-sysmon_id_1.xml /var/ossec/ruleset/rules/0810-sysmon_id_3.xml
docker exec wazuh-logtest grep -n 'eventID">4688\|id="67027"' /var/ossec/ruleset/rules/0955-WEF-baseline_rules.xml
```

`(?i)` is inside `type="pcre2"` on 42 of the script-block checks in `0915-win-powershell_rules.xml`, and on the Sysmon command-line rules below. `pwsh` has zero matches in `0800-sysmon_id_1.xml` and `0810-sysmon_id_3.xml`. A ruleset-wide search found no `DownloadString`, `DownloadFile`, `WebClient`, `Invoke-WebRequest`, `BitsTransfer`, `Invoke-Mimikatz`, or `AmsiUtils`.

### Chain

| Rule | Level | File | What it matches |
|---|---|---|---|
| 91801 | 0 | `0915-win-powershell_rules.xml` | `if_sid` 60000 or 60010, channel `Microsoft-Windows-PowerShell/Operational` |
| 91802 | 0 | same | `if_sid` 91801, `win.eventdata.ScriptBlockId` `.+` |
| 91809 | 10 | same | `if_sid` 91802, `scriptBlockText` `(?i)FromBase64String`. MITRE `T1140` |
| 91837 | 4 | same | `if_sid` 91802, `scriptBlockText` `(?i)(Get-Content.+\-Stream\|IEX\|Invoke-Expresion)`. MITRE `T1059.001` |
| 60004 | 0 | `0575-win-base_rules.xml` | `if_sid` 60000, channel `Microsoft-Windows-Sysmon/Operational` |
| 61603 | 0 | `0595-win-sysmon_rules.xml` | `if_sid` 61600, eventID `^1$`. Group `sysmon_event1` |
| 61605 | 0 | same | `if_sid` 61600, eventID `^3$`. Group `sysmon_event3` |
| 92057 | 12 | `0800-sysmon_id_1.xml` | `if_group` `sysmon_event1`, parent image powershell.exe, command line powershell.exe plus an encoded-command flag. MITRE `T1059.001` |
| 92071 | 12 | same | Encoded command only after WMI rule 92070. MITRE `T1047` and `T1059.001` |
| 92101 | 0 | `0810-sysmon_id_3.xml` | `if_group` `sysmon_event3`, image powershell.exe, protocol tcp. MITRE `T1095` |
| 67027 | 3 | `0955-WEF-baseline_rules.xml` | `if_sid` 60103, eventID 4688, "A process was created." No commandLine check |

91802 does not check event ID 4104. Rule 61603's description uses `win.eventdata.description`. The encoded-command rules in `0800-sysmon_id_1.xml` use `win.eventdata.commandLine`, `image`, and `parentImage`. Rule 61605's description names `destinationIp` and `image`.

### How ours differ

- SF-004 (100200) is 91802 plus eventID `^4104$`, level 12, MITRE `T1059.001`. It adds spelled `Invoke-Expression`, `Invoke-Mimikatz`, `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer`, and `-nop -w hidden`. It does not include the SF-006 cradle strings. Stock `IEX` stays available at level 4, and stock `FromBase64String` at level 10, until this higher rule matches.
- SF-005 (100210) is 61603, level 13, MITRE `T1059.001` only. Image is powershell.exe or pwsh.exe. The command line needs `-EncodedCommand`, `-enc`, or `-e`, then whitespace, then a base64 token of at least 20 characters. `-e` does not match `-ExecutionPolicy` or `-ep`, because those have no whitespace after `-e`. 92057 does not list pwsh and requires a powershell parent. 67027 is why 4688 is not used.
- SF-006 (100220) is 4104 with the five cradle strings, level 12, MITRE `T1105`. Nothing in the stock ruleset matches those strings. 100221 is 61605, powershell.exe or pwsh.exe, tcp, level 10, and it skips loopback `destinationIp`. 92101 is the level 0 powershell.exe version of that connection and does not include pwsh.

### Exclusions

Content markers were removed. A string inside `scriptBlockText` or `commandLine` is attacker-controlled.

```bash
docker exec wazuh-logtest grep -R -n "win.eventdata.path" /var/ossec/ruleset/rules
docker exec wazuh-logtest grep -n "parentImage" /var/ossec/ruleset/rules/0810-sysmon_id_3.xml
```

`win.eventdata.path` appears only in `0600-win-wdefender_rules.xml` description strings. It is not a `<field>` check, and `0915-win-powershell_rules.xml` has zero hits. 100200 and 100220 therefore have no exclusion. Accept lab noise; tune after a lab baseline.

100210 negates `image` and `parentImage` only when the whole value is the Wazuh agent executable. The 4.14.9 Windows agent page says the default directory is `C:\Program Files (x86)\ossec-agent` (MSI `wazuh-agent-4.14.9-1.msi`). VERIFY: `wazuh-agent.exe` is the image in 4.14.1 and 4.14.3 crash reports at that path, not a checked 4.14.9 install on WS01. Rule 92019 writes Windows separators as four backslashes. This exclusion accepts one or two. A custom install directory is not excluded. 100221 uses the same image anchor. `0810-sysmon_id_3.xml` has no `parentImage`, so 100221 does not negate that field.

## SF-007, SF-008, and SF-009 — accounts and groups

Evidence commands:

```bash
docker exec wazuh-logtest sed -n '100,170p' /var/ossec/ruleset/rules/0580-win-security_rules.xml
docker exec wazuh-logtest sed -n '450,780p' /var/ossec/ruleset/rules/0580-win-security_rules.xml
```

### Chain

| Rule | Level | What it matches |
|---|---|---|
| 60001 | 0 | `if_sid` 60000, channel Security. File `0575-win-base_rules.xml` |
| 60103 | 0 | `if_sid` 60001, severity `AUDIT_SUCCESS` or `success` |
| 60109 | 8 | `if_sid` 60103, event 624, 626, 4720, or 4722. MITRE `T1098`. Group `adduser` |
| 60113 | 5 | `if_sid` 60103, group-account changed, including 4728, 4732, and 4756. MITRE `T1484` |
| 60141 | 5 | `if_sid` 60113, event 632 or 4728. Description interpolates `memberSid` |
| 60144 | 5 | `if_sid` 60113, event 636 or 4732. Description interpolates `memberSid` |
| 60151 | 5 | `if_sid` 60113, event 660 or 4756 |
| 60154 | 12 | `if_sid` 60144 or 60145, `targetSid` `^S-1-5-32-544$`. Add and remove. MITRE `T1484` |
| 60159 | 12 | `if_sid` 60141 or 60142, `targetSid` `^S-1-5-\S+-512$`. MITRE `T1484` |
| 60164 | 12 | `if_sid` 60141 or 60142, `targetSid` `^S-1-5-\S+-516$` |
| 60166 | 12 | `if_sid` 60149, 60150, 60151, or 60152, `targetSid` `^S-1-5-\S+-518$` |
| 60167 | 12 | same parents as 60166, `targetSid` `^S-1-5-\S+-519$` |

`targetSid` checks in this file have no `type` attribute. `memberSid` and `memberName` appear in descriptions, not as `<field>` checks. `subjectUserName` is a `<field>` check later in the same file (line 1052: `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`). `targetUserName` is used by the 4625 rules, not by these group rules. `targetDomainName` is not a `<field>` check in this file.

### How ours differ

- SF-007 (100300) is 60144 plus eventID `^4732$` and `targetSid` `^S-1-5-32-544$`, level 13, MITRE `T1098`. 60154 also matches a 4733 removal and uses `T1484`.
- SF-008 (100310) is 60141 or 60151, event 4728 or 4756, RID 512 or 519, level 15, MITRE `T1098`. Level 15 is critical because those two groups are domain or forest admin, one step above stock level 12. 100311 is the same parents and events for RID 518 or 516, level 13. Removals stay on the stock rules. The group display name is not matched.
- SF-009 (100320) is 60109 plus eventID `^4720$`, level 10, MITRE `T1136.001`. 60109 also matches 4722 and uses `T1098`. Level 10 stays medium and is above 60109. 4741 is a different parent and is not this rule.

### Exclusions

None. The SID or the event ID is the detection. A group name or an account name is not an exclusion.

## SF-010, SF-011, and SF-012 — lateral movement

Evidence commands:

```bash
docker exec wazuh-logtest sed -n '70,90p' /var/ossec/ruleset/rules/0580-win-security_rules.xml
docker exec wazuh-logtest sed -n '1,120p' /var/ossec/ruleset/rules/0840-win_event_channel.xml
docker exec wazuh-logtest sed -n '70,100p' /var/ossec/ruleset/rules/0955-WEF-baseline_rules.xml
docker exec wazuh-logtest sed -n '90,120p' /var/ossec/ruleset/rules/0810-sysmon_id_3.xml
docker exec wazuh-logtest grep -n 'win.system.channel' /var/ossec/ruleset/rules/0575-win-base_rules.xml
docker exec wazuh-logtest grep -n '5145\|relativeTargetName\|Microsoft-Windows-WinRM' /var/ossec/ruleset/rules/*.xml || echo ZERO
```

The last command prints no 5145, no `relativeTargetName`, and no WinRM channel. `wsmprovhost.exe` appears on rule 92220 (Sysmon file create), not on event 1.

### Chain

| Rule | Level | What it matches |
|---|---|---|
| 60106 | 3 | `if_sid` 60103, event 528, 540, 673, 4624, or 4769. MITRE `T1078` |
| 92651 | 0 | `if_sid` 60106, IPv4 `ipAddress`, not `127.0.0.1`. File `0840-win_event_channel.xml` |
| 92653 | 3 | `if_sid` 92651, `logonType` pcre2 `10` with no anchors. MITRE `T1021.001` and `T1078.002` |
| 92656 | 15 | `if_sid` 60106, `logonType` `^10$`, loopback `ipAddress` |
| 67017 | 3 | `if_sid` 60103, eventID `5140` (no anchors), `shareName` not `IPC$` or `NetLogon`. MITRE `T1021.002` |
| 61603 | 0 | Sysmon event 1 |
| 92110 | 4 | `if_sid` 92101 or 61605, `destinationPort` `^5985$`. MITRE `T1021.006` |

`logonType` is a `<field>` check (60118, 60200, 60232, 92653, 92656). `shareName` is a `<field>` check on 67017. `ipAddress` is a `<field>` check on 92651. `win.system.computer` is in the 4624 sample comment and is not a `<field>` check. `processName` is in that same comment and is not a `<field>` check.

### How ours differ

- SF-010 (100500) is 60106, event `^4624$`, logon type `^10$`, level 10. 100501 is level 12 for `targetUserName` `^sf-test-admin$`. 100502 is level 12 for computer DC01. Loopback RDP stays 92656.
- SF-011 (100510) is 60103, event `^5140$|^5145$`, share ending in `\ADMIN$` or `\C$`, level 12. 100511 is IPC$ at level 4. 100512 is 4624 type 3 at level 5 and does not wait for the share event. Level 5 stays under 92652.
- SF-012 (100520) is 61603 and image `\wsmprovhost.exe`, level 12. 100521 is 92110, level 10. No WinRM Operational event ID is matched.

### Exclusions

Machine accounts end with `$`. Source `10.10.10.1` is the lab host adapter. WS01 `10.10.10.20` is not excluded. The Wazuh agent path is on 100520 (`image` and `parentImage`) and on 100521 (`image` only). 4624 does not negate `processName`.

