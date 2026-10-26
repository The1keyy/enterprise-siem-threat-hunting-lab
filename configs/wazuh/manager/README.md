# manager

> Run on: WAZUH01
> Status: SYNTAX VALID for the XML and the two JSON files. Not applied.

## What it does

`ossec.conf.snippet` turns on `<logall_json>`. It does not turn on plaintext `logall`. Custom rules are not included here. `scripts/bash/deploy_rules.sh` copies them to `/var/ossec/etc/rules/`, which a stock manager already loads. **VERIFY** `rule_dir` `etc/rules` is present before adding a second one.

`filebeat-archives.md` is the 4.14 archives procedure and the 100 GB retention math. The ISM JSON files delete `wazuh-archives-*` after 7 days and `wazuh-alerts-*` after 30 days. They have not been applied.

## Where it goes

Manager file: `/var/ossec/etc/ossec.conf`. Filebeat file: `/etc/filebeat/filebeat.yml`. ISM policies: the indexer API in the archives note.

## How to verify

Follow `docs/runbooks/03-wazuh-config.md`. Each step has a check. None of those checks have been run.
