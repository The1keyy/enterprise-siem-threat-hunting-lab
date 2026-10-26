# Local wazuh-logtest

This runs only the Wazuh 4.14.9 manager (`wazuh/wazuh-manager:4.14.9`) so custom rules and decoders can be checked on a Mac. There is no indexer and no dashboard.

## What a pass proves

`LOGTEST VALID` means `wazuh-logtest` decoded the synthetic event and the expected rule fired (or, for a negative case, that rule did not fire). It proves decoder and rule logic against the labeled input in `tests/logs/<ID>.yml`.

## What a pass does not prove

It does not prove agent collection, real Windows field names, or delivery into the indexer. Those are `LAB VALIDATED`, after a simulation in the isolated lab.

Status ladder: `SYNTAX VALID` → `LOGTEST VALID` → `LAB VALIDATED`.

`REQUIRES WINDOWS VALIDATION / logtest-limited` means the event was sent and the built-in Windows rule did not fire through logtest. That result is not a pass.

## Apple Silicon

`docker image inspect` reported `linux/arm64` for `wazuh/wazuh-manager:4.14.9`. The container started on this Mac without `platform: linux/amd64`, and `uname -m` inside the container was `aarch64`. If a later host fails to start that image, set `platform: linux/amd64` on the service and record it here.

Filebeat has no indexer in this compose file. On the first start it logged `lookup wazuh.indexer ... no such host` and indexer-connector warnings, plus a seccomp warning (`unsupported arch: arm64`). Analysisd still reached `is running`. Those messages do not fail the healthcheck.

## Commands

```bash
cp scripts/validation/logtest/.env.example scripts/validation/logtest/.env
# Set a password that is not change-me. The file is gitignored.

make logtest-up
docker exec wazuh-logtest ls /var/ossec/etc/rules/sentinelforge
make logtest
make logtest ID=CANARY-001
make logtest-down
```

`make logtest` does not start the container. If it is not healthy, the runner prints the compose command and exits 1.

With no `tests/logs/SF-*.yml` files, the runner prints `0 detections found` and still runs canaries. `--update-status` writes `LOGTEST VALID` only when every case for that `SF-XXX` passes. It never writes `LAB VALIDATED`.

## Troubleshooting

```bash
docker exec wazuh-logtest tail -n 50 /var/ossec/logs/ossec.log
docker logs wazuh-logtest
docker exec wazuh-logtest grep sentinelforge /var/ossec/etc/ossec.conf
```

The entrypoint script `ossec-override/apply-ruleset.sh` inserts `etc/rules/sentinelforge` and `etc/decoders/sentinelforge` before `</ruleset>`. It does not edit files under `/var/ossec/ruleset`. The image copies `/wazuh-config-mount` over `/var/ossec`, so a partial `ossec.conf` is not mounted there.

API calls stay inside the container (`docker exec` + `curl` to `https://127.0.0.1:55000`). The host port `55000` is bound to `127.0.0.1` only. Credentials come from `scripts/validation/logtest/.env`.
