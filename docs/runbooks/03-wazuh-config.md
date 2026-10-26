# 03 — Wazuh manager config

> Run on: WAZUH01
> Status: NOT TESTED. Do this after the 4.14.9 all-in-one is installed. Snapshot the VM first.

Each step ends with a check. Stop if the check fails. Do not invent a passing result.

## 1. Apply the manager snippet

Edit `/var/ossec/etc/ossec.conf`. Set `<logall_json>yes</logall_json>` inside `<global>`, as in `configs/wazuh/manager/ossec.conf.snippet`. Leave `<logall>` unset or `no`.

Confirm the stock ruleset already has both of these before adding either one again:

```bash
grep -n 'rule_dir\|decoder_dir' /var/ossec/etc/ossec.conf
```

Check: the grep shows `etc/rules` and `etc/decoders`. **VERIFY** those are the 4.14.9 lines. Then:

```bash
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager && systemctl is-active wazuh-manager
```

Check: `is-active` prints `active`.

## 2. Enable archives

Follow `configs/wazuh/manager/filebeat-archives.md`. Set the Filebeat Wazuh module `archives.enabled` to `true` and restart Filebeat.

Check:

```bash
systemctl is-active filebeat
test -f /var/ossec/logs/archives/archives.json && echo archives.json
```

The JSON file appears after the manager receives an event. An empty new install may not have it yet. **VERIFY** the file path on 4.14.9.

## 3. Apply the ISM policies

Use the two JSON files and the `curl` in `filebeat-archives.md`. Set `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASSWORD` from the install. Set `WAZUH_API_CA` to the indexer CA. **VERIFY** `PUT _plugins/_ism/policies/` on this indexer.

Check:

```bash
curl --silent --cacert "$WAZUH_API_CA" --user "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASSWORD" \
  'https://127.0.0.1:9200/_plugins/_ism/policies/sentinelforge-archives-7d' \
  'https://127.0.0.1:9200/_plugins/_ism/policies/sentinelforge-alerts-30d'
```

Check: both responses contain the policy id and not an error body. The templates do not delete indices that already exist until those indices are added to the policy. **VERIFY** that add-policy call if indices are already there.

## 4. Deploy rules

From the Mac, with SSH to WAZUH01:

```bash
scripts/bash/deploy_rules.sh --ssh <USER>@10.10.10.40
```

Or on WAZUH01, from a checkout, as root: `scripts/bash/deploy_rules.sh`.

The script backs up, copies `sentinelforge_*.xml`, runs `wazuh-analysisd -t`, restarts `wazuh-manager` only if that passes, and compares the API rule count with the XML count. A mismatch restores the backup.

Check: the script prints `loaded 23 = 23` (the current XML total) and exits 0. There are no custom decoders today. The script says so by copying none.

## 5. Create the read-only users

Follow `docs/runbooks/wazuh-readonly-users.md`. Put the passwords in the Mac `.env`. Do not commit them.

Check: a `GET /rules?filename=sentinelforge_100100_auth.xml` as `sentinelforge-api-ro` returns the three auth rules, and a delete call is refused. **VERIFY** the RBAC action names on 4.14.9 before treating a refusal as proof.

## 6. Verify the manager is serving the lab rules

```bash
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
curl --silent --cacert "$WAZUH_API_CA" --user "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASSWORD" \
  'https://127.0.0.1:9200/_cat/indices/wazuh-alerts-*?h=index'
```

Check: the four units are `active`. The alerts index may be absent until the first alert. The archives index may be absent until Filebeat ships one JSON event. Do not mark this runbook LAB VALIDATED from this Mac.
