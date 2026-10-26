# Detection batch standard

Later Step 10 batches follow this. `docs/ROADMAP.md` is the source of truth for id, MITRE, and telemetry. One detection per roadmap row.

## A. Research first

Inside the logtest container, grep `/var/ossec/ruleset/rules` and the decoders for each detection's built-in parents and field names.

Record rule id, file, level, fields, and the chain, plus the grep command, in `docs/detections/_ruleset-notes.md`.

Only use rule options that appear in the 4.14.9 built-in rules: `frequency`, `timeframe`, `if_matched_sid`, `same_field`, `different_field`, `pcre2`, and the sshd `same_source_ip` element. `different_field` does not appear in this image. Do not invent it.

A fact confirmed by grep or by a logtest response is not `VERIFY`.

## B. Five files per detection

1. Wazuh rule in `detections/wazuh/rules/sentinelforge_<rangeStart>_<category>.xml`
   - Ids come from the category range in `.cursor/rules/30-detections.mdc`.
   - Chain on the built-in parents.
   - `<description>SF-XXX: ...</description>`
   - `<mitre><id>` exactly as the roadmap.
   - `<group>sentinelforge,<category>,</group>`
   - Level per ADR 0004.
   - Exclusions must use anchored paths/IDs/SIDs, never attacker-controlled content.
   - Comment block: SF id, objective, parents and source file, status. Windows rules also say `REQUIRES WINDOWS VALIDATION`.
2. `detections/sigma/SF-XXX.yml`, logically equivalent. If Sigma cannot express the threshold, say that the threshold lives in the Wazuh rule.
3. `detections/metadata/SF-XXX.yml`
   - Every field required by `.cursor/rules/30-detections.mdc`.
   - `logtest_mode: full` for Linux, `limited` for Windows.
   - `parent_rules`, `wazuh_rule_ids`
   - `required_telemetry` (audit policy, Sysmon, or log path)
   - `windows_validation_required`
   - `observed_result: "NOT YET VALIDATED"` until a lab run
   - `lab_validation: { simulation: "planned Step 13", evidence: null }`
4. `tests/logs/SF-XXX.yml`
   - `comment: SYNTHETIC TEST INPUT`
   - Cases: `positive`, `negative_below_threshold` for a burst, `negative_benign`
   - Linux cases are runnable (`log_format: syslog`).
   - Windows cases set `mode: lab_reference` and use Wazuh eventchannel shape (`win.system.*`, `win.eventdata.*`). The runner reports those as `LIMITED` and does not call logtest.
   - Lab values: DC01 `10.10.10.10`, WS01 `10.10.10.20`, UBU01 `10.10.10.30`, attacker `10.10.10.200`, users `sf-test-*`.
   - Strings only. Nothing that would perform the attack.
5. `docs/detections/SF-XXX.md`
   - Telemetry requirements, why this threshold, false positives, investigation steps, planned lab simulation and cleanup.

## C. Validate

Restart the container after a rule change. analysisd reads rules at start.

```bash
docker exec wazuh-logtest grep -iE 'error|warning|sentinelforge' /var/ossec/logs/ossec.log | tail -n 30
```

Indexer-connector warnings are expected. There is no indexer. A line about our XML is a failure.

`make logtest` prints the full table.

Statuses:

- Linux, every case `PASS`: `scripts/validation/run_logtest.py --update-status` sets `LOGTEST VALID`.
- Windows, clean load: set `SYNTAX VALID` and record the date plus the load-log excerpt in metadata.
- Never `LAB VALIDATED`.
- On a failure: leave the status, show `--verbose`, and explain it. Do not loosen a rule to force a pass.

Then:

```bash
backend/.venv/bin/python scripts/validation/build_detection_fixtures.py
make test
make logtest-down
```

The fixture builder rewrites `fixtures/detections.json` from metadata, the rule XML, and Sigma. `lastTriggered` and `alertCount` stay null. The `_notice` still starts with `DEMO DATA`. Rows with a metadata file use the real rule text and status. Other rows stay placeholders.

## D. Finish

Update `docs/PROJECT_STATUS.md` with a status table and real counts. Commit `Step 10 batch N: <IDs>`. Push. Do not start the next batch.
