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

Logtest used `log_format: syslog` and `location: /var/log/auth.log`. The decoder matched the line text. Which file or journal the Ubuntu 24.04 agent reads is not in this ruleset. That path stays **VERIFY** until UBU01 is checked.
