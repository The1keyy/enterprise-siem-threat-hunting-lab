# Filebeat archives and index retention

> Run on: WAZUH01
> Status: NOT TESTED. The steps below are copied from the Wazuh 4.14 event-logging page. They have not been run on this lab.

Snapshot WAZUH01 first. Archives store every decoded event, not only alerts.

## Enable the archives module

Source: [Wazuh 4.14 event logging](https://documentation.wazuh.com/4.14/user-manual/manager/event-logging.html), "Configuring event archiving". **VERIFY** the same keys exist in the installed `/etc/filebeat/filebeat.yml`. The page shows this edit:

1. Set `<logall_json>yes</logall_json>` with `configs/wazuh/manager/ossec.conf.snippet`, then `systemctl restart wazuh-manager`.
2. In `/etc/filebeat/filebeat.yml`, under the Wazuh module, change:

```yaml
archives:
  enabled: true
```

3. `systemctl restart filebeat`.
4. Check: `systemctl is-active filebeat` prints `active`, and after an agent event `ls /var/ossec/logs/archives/archives.json` shows the file growing.

The dashboard index pattern on that page is `wazuh-archives-*` with time field `timestamp`. The console queries `wazuh-archives-4.x-*`. **VERIFY** the real index name. `wazuh-archives-*` matches a `wazuh-archives-4.x-...` index if that is the name Filebeat creates.

`logall` (plaintext `archives.log`) stays off. The JSON file is the one Filebeat reads.

## Local files are not the ISM policy

The manager rotates `/var/ossec/logs/archives/archives.json` into `/var/ossec/logs/archives/<year>/<Mon>/`. The ISM policies delete indexer indices only. They do not delete those compressed files. **VERIFY** a cleanup for that directory before the 100 GB disk fills. No cron is shipped here.

## Retention math for the 100 GB disk

No events have been ingested. There is no GB-per-day number, and this file does not invent one.

Planning budget, not a measurement:

| Slice | Size | Why |
|---|---|---|
| Disk | 100 GB | `architecture/ARCHITECTURE.md` WAZUH01 disk |
| OS and Wazuh packages | 20 GB reserved | **VERIFY** on the installed VM. 20 GB is a reserve, not a measured install size. |
| Free-space floor | 15 GB | 15% of the disk. **VERIFY** the indexer flood watermark. OpenSearch defaults are often 85/90/95, and this build may differ. Stay under the watermark. |
| Left for indices and local archives | 65 GB | 100 minus 20 minus 15 |

Alerts are kept 30 days (`ism-wazuh-alerts-30d.json`). Archives are kept 7 days (`ism-wazuh-archives-7d.json`). Archives hold every event and alerts hold rule matches, so the short window is the control. If the archives index or `archives.json` approaches that 65 GB budget inside 7 days, shorten the window. Do not wait for a flood watermark.

`ism_template` applies to new indices. Existing indices need a separate add-policy call. **VERIFY** `PUT _plugins/_ism/policies/<name>` on this indexer.

```bash
curl --cacert "$WAZUH_API_CA" --user "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X PUT 'https://127.0.0.1:9200/_plugins/_ism/policies/sentinelforge-archives-7d' \
  --data-binary @ism-wazuh-archives-7d.json
```

Repeat with `ism-wazuh-alerts-30d.json` and policy name `sentinelforge-alerts-30d`. Do not put the indexer password in the shell history if you can avoid it. The password is the install password, not a value from this repo.
