# tests/logs/

One YAML file per detection (`SF-XXX.yml`), plus canaries. These replace plain `.log` files.

Each file is **synthetic test input, not real telemetry**. A case that matches `expect` is `LOGTEST VALID`, not `LAB VALIDATED`.

Required shape:

- `comment: SYNTHETIC TEST INPUT`
- `id`, `description`
- `cases[]`: `name`, `log_format` (`syslog`, `json`, or `eventchannel`), `location`, `event` or `events`, `expect.fires`, `expect.rule_id`, `expect.level`, optional `expect.mitre`
- A negative case sets `expect.fires: false` for that rule. Another rule may still fire.
- Every detection eventually needs at least one positive case and one negative case.
- `logtest_limited: true` with `limited_reason` means the Windows event was tried and the built-in rule did not fire through logtest. That is not a pass.

`CANARY-001.yml` checks built-in sshd rules. `CANARY-002.yml` is the Windows 4625 case and is logtest-limited until a real agent event fires the Windows rule.

**Status:** One file per written detection, plus two canaries. Windows cases are logtest-limited. Linux sshd cases can run in Docker.
