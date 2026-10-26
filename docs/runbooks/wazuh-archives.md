# Enable Wazuh archives

**REQUIRES LAB VALIDATION.** Archives are raw events, not just alerts. They are off until WAZUH01 is configured. Snapshot the VM first.

The hunt runner queries `wazuh-archives-4.x-*`. **VERIFY (4.14.9)** that index pattern. If the index does not exist, the API returns:

`Archives not enabled on WAZUH01, see docs/runbooks/wazuh-archives.md`

It does not serve fixture hunt hits instead.

## What has to be on

Both of these, or the index stays missing:

1. Manager `ossec.conf`: `<logall_json>yes</logall_json>` inside `<global>`. **VERIFY (4.14.9)** the element name and that a manager restart is required.
2. Filebeat's Wazuh archives module enabled on WAZUH01. **VERIFY (4.14.9)** the module path and whether the change is `archives.yml` `enabled: true` plus a Filebeat restart.

Alerts (`wazuh-alerts-4.x-*`) still exist without archives. Hunts do not.

## Storage

`logall_json` writes every decoded event, not only the ones that match a rule. On a small lab that is usually the largest index. A busy Windows Security channel (4624 alone) can grow much faster than the alerts index.

Before enabling it on WAZUH01:

- Check free disk. The health page reads indexer filesystem stats, but those numbers are only real after the indexer is up.
- Decide a retention window and delete or roll over the archives indices on that window. **VERIFY (4.14.9)** the indexer ISM or ILM policy name that ships with the all-in-one, and the default archives retention if one exists.
- A reasonable lab starting point is 7 days, matching the hunt query limit in the console. That number is a storage choice, not a measured Wazuh default.

## What this does not prove

Enabling archives proves the manager is writing JSON events and Filebeat is indexing them. It does not prove a Windows agent is collecting the right channel, or that `data.win.eventdata.*` names match a real 4625. Those stay **REQUIRES WINDOWS VALIDATION**.
