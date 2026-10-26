# Local wazuh-logtest

This runs only the Wazuh 4.14.9 manager (`wazuh/wazuh-manager:4.14.9`) so custom rules and decoders can be checked on a Mac. There is no indexer and no dashboard.

## What a pass proves

`LOGTEST VALID` means `wazuh-logtest` decoded the synthetic event and the expected rule fired (or, for a negative case, that rule did not fire). It proves decoder and rule logic against the labeled input in `tests/logs/<ID>.yml`.

## What a pass does not prove

It does not prove agent collection, real Windows field names, or delivery into the indexer. Those are `LAB VALIDATED`, after a simulation in the isolated lab.

Status ladder: `SYNTAX VALID` → `LOGTEST VALID` → `LAB VALIDATED`.

`REQUIRES WINDOWS VALIDATION / logtest-limited` means the event was sent and the built-in Windows rule did not fire through logtest. That result is not a pass.

Windows eventchannel events can't be faithfully replayed in logtest; Windows detections are validated in the lab. A second `PUT /logtest` with `log_format: eventchannel` and `location: EventChannel` still returned decoder `json`, rule 1002, `alert: false`. Rule 60122 did not fire. Step 10 must not mark a Windows detection `LOGTEST VALID` from this harness.

## Apple Silicon

`docker image inspect` reported `linux/arm64` for `wazuh/wazuh-manager:4.14.9`. The container started on this Mac without `platform: linux/amd64`, and `uname -m` inside the container was `aarch64`. If a later host fails to start that image, set `platform: linux/amd64` on the service and record it here.

Filebeat is not started. The 4.14.9 image has `/etc/services.d/filebeat/run`, which execs Filebeat, and `/etc/cont-init.d/1-config-filebeat` only rewrites `filebeat.yml`. There is no disable env var. `/etc/s6/init/init-stage2` runs `cont-init.d` before it scans `/etc/services.d`. A `down` file stops the Filebeat binary but leaves `s6-supervise filebeat` running, so the entrypoint script deletes `/etc/services.d/filebeat` before that scan.

## Commands

```bash
cp scripts/validation/logtest/.env.example scripts/validation/logtest/.env
# Set a password that is not change-me. The file is gitignored.

make logtest-up
docker exec wazuh-logtest ls /var/ossec/etc/rules/sentinelforge
make logtest
make logtest ID=CANARY-001
make logtest-down
make logtest-clean
```

`make logtest-up` runs `docker compose up -d --wait --wait-timeout 120`. It returns when the healthcheck is healthy, or it fails if that takes longer than 120 seconds. `make logtest` does not start the container. If it is not healthy, the runner prints the compose command and exits 1.

With no `tests/logs/SF-*.yml` files, the runner prints `0 detections found` and still runs canaries. `--update-status` writes `LOGTEST VALID` only when every case for that `SF-XXX` passes. It never writes `LAB VALIDATED`.

## Troubleshooting

```bash
docker exec wazuh-logtest tail -n 50 /var/ossec/logs/ossec.log
docker logs wazuh-logtest
docker exec wazuh-logtest grep sentinelforge /var/ossec/etc/ossec.conf
```

The entrypoint script `ossec-override/apply-ruleset.sh` inserts `etc/rules/sentinelforge` and `etc/decoders/sentinelforge` before `</ruleset>`. It does not edit files under `/var/ossec/ruleset`. The image copies `/wazuh-config-mount` over `/var/ossec`, so a partial `ossec.conf` is not mounted there.

API calls stay inside the container (`docker exec` + `curl` to `https://127.0.0.1:55000`). The host port `55000` is bound to `127.0.0.1` only. Credentials come from `scripts/validation/logtest/.env`.

## Disk usage

`docker system df` on this Mac listed `wazuh/wazuh-manager:4.14.9` at 2.73GB (`docker image inspect` Size was 2726080148 bytes). That image is the expected cost of this harness. The compose file adds no named volumes. Alert and archive directories are tmpfs mounts capped at 32m, owned by uid/gid 999 (`wazuh` in this image). Docker json logs are capped at 10m × 3 files.

Check space:

```bash
docker system df
```

Clean up this project only:

```bash
make logtest-down
make logtest-clean
```

Both remove the `wazuh-logtest` container and this compose project's volumes. The image stays. They do not run `docker system prune` and they do not touch other projects (minikube, Postgres, and the rest of `docker system df` are not this repo).

Set a disk image limit in Docker Desktop: Settings → Resources → Disk usage limit. That stops the Docker VM disk from growing until the Mac is full.
