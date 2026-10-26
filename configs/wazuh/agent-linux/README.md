# agent-linux

> Run on: UBU01
> Status: SYNTAX VALID after the Mac XML parse. Not installed.

## What it does

`ossec.conf.snippet` sends UBU01 to `<WAZUH_MANAGER_IP>` and reads three files.

| File | Format | Why |
|---|---|---|
| `/var/log/auth.log` | syslog | SF-013 and SF-014. The logtest cases use this path and this format. |
| `/var/log/syslog` | syslog | Host messages beside auth. No current rule. |
| `/var/log/audit/audit.log` | audit | The auditd rules in `configs/linux/auditd/`. No current rule. |

## journald alternative

Ubuntu 24.04 can keep sshd lines in the journal and leave `auth.log` missing. Wazuh can read that with `location` `journald` and `log_format` `journald`, plus a `_SYSTEMD_UNIT` filter for `ssh.service`.

That input emits syslog-shaped text, but it is not the file the SF-013 and SF-014 cases used. A journal-only host would make the lab events depend on the agent's journal reader. rsyslog writing `auth.log` keeps the bytes on disk in the format logtest already matched. The cost is an extra package and a file to rotate. 12C installs rsyslog and checks the file. This snippet does not switch to journald.

## Where it goes

`/var/ossec/etc/ossec.conf` on UBU01. Replace `<WAZUH_MANAGER_IP>` with `10.10.10.40`.

## How to verify

`pytest tests/configs/test_agent_snippets.py` on the Mac. On UBU01, after 12C, `ls -l /var/log/auth.log` and a failed local ssh that is not an attack. Not done.
