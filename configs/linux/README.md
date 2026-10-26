# configs/linux/

> Run on: UBU01
> Status: NOT TESTED. The audit rules have not been loaded.

Audit rules live in `auditd/`. rsyslog, so `/var/log/auth.log` exists for SF-013 and SF-014, is installed by the Step 12C UBU01 script. This folder does not start that script.

The agent reads the files from `configs/wazuh/agent-linux/`.
