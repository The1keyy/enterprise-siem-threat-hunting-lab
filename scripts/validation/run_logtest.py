#!/usr/bin/env python3
"""Run tests/logs/*.yml through the local wazuh-logtest container.

The container is not started here. If it is not healthy, the exact compose
command is printed and the process exits 1.

VERIFY (4.14.9): PUT /logtest body is event, log_format, location, and an
optional session token. DELETE /logtest/sessions/{token} closes the session.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
LOG_DIR = REPO / "tests" / "logs"
META_DIR = REPO / "detections" / "metadata"
RESULT_DIR = REPO / "tests" / "results"
COMPOSE_FILE = REPO / "scripts" / "validation" / "logtest" / "docker-compose.yml"
ENV_FILE = REPO / "scripts" / "validation" / "logtest" / ".env"
CONTAINER = "wazuh-logtest"
UP_COMMAND = (
    "docker compose --env-file scripts/validation/logtest/.env "
    "-f scripts/validation/logtest/docker-compose.yml up -d"
)

# VERIFY (4.14.9): these phase labels come from /var/ossec/bin/wazuh-logtest.
_RULE_ID_RE = re.compile(r"^\s*id:\s*'?(?P<id>\d+)'?\s*$", re.M)
_LEVEL_RE = re.compile(r"^\s*level:\s*'?(?P<level>\d+)'?\s*$", re.M)
_MITRE_RE = re.compile(r"^\s*id:\s*'?(?P<id>T\d{4}(?:\.\d{3})?)'?\s*$", re.M)


def main() -> int:
    args = _parse_args()
    if not _container_healthy():
        return 1
    user, password = _api_credentials()
    token = _authenticate(user, password)
    files = _case_files(args.id)
    sf_files = [path for path in files if path.stem.startswith("SF-")]
    if not sf_files and (args.update_status or args.mark_needs_tuning or args.id is None):
        if args.id is None or args.id.startswith("SF-"):
            print("0 detections found")
    if args.id and args.id.startswith("SF-") and not sf_files:
        return 0
    rows: list[dict[str, Any]] = []
    failed = False
    for path in files:
        if path.stem.startswith("SF-") and args.id is None:
            pass
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            print(f"{path.name}: file is not a mapping", file=sys.stderr)
            failed = True
            continue
        case_id = str(document.get("id") or path.stem)
        for case in document.get("cases") or []:
            row = _run_case(case_id, case, token, verbose=args.verbose)
            rows.append(row)
            if row["status"] == "FAIL":
                failed = True
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    result_name = f"logtest-{stamp}.json"
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    result_path = RESULT_DIR / result_name
    result_path.write_text(
        json.dumps(
            {
                "generatedAt": datetime.now(UTC).replace(microsecond=0).isoformat(),
                "notice": "SYNTHETIC TEST INPUT results. Not lab telemetry.",
                "cases": rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    _print_table(rows)
    print(f"result file: {result_path.relative_to(REPO)}")
    if args.update_status or args.mark_needs_tuning:
        _update_metadata(rows, result_name, mark_needs_tuning=args.mark_needs_tuning)
    return 1 if failed else 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SentinelForge wazuh-logtest cases.")
    parser.add_argument("--id", help="Run one tests/logs/<ID>.yml file, for example SF-001.")
    parser.add_argument("--verbose", action="store_true", help="Print the decoder and rule chain.")
    parser.add_argument(
        "--update-status",
        action="store_true",
        help="Set LOGTEST VALID on SF-XXX metadata whose cases all passed.",
    )
    parser.add_argument(
        "--mark-needs-tuning",
        action="store_true",
        help="Set NEEDS TUNING on SF-XXX metadata that had a failing case.",
    )
    return parser.parse_args()


def _container_healthy() -> bool:
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Health.Status}}", CONTAINER],
        capture_output=True,
        text=True,
        check=False,
    )
    status = inspect.stdout.strip()
    if inspect.returncode != 0 or status != "healthy":
        detail = status or inspect.stderr.strip() or "container not found"
        print(f"wazuh-logtest is not healthy ({detail}).")
        print("Start it with:")
        print(f"  {UP_COMMAND}")
        print("or: make logtest-up")
        return False
    return True


def _api_credentials() -> tuple[str, str]:
    if not ENV_FILE.is_file():
        print(f"Missing {ENV_FILE.relative_to(REPO)}. Copy .env.example and set a password.")
        raise SystemExit(1)
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        values[key.strip()] = value.strip()
    user = values.get("WAZUH_LOGTEST_API_USER", "")
    password = values.get("WAZUH_LOGTEST_API_PASSWORD", "")
    if not user or not password or password == "change-me":
        print("Set WAZUH_LOGTEST_API_USER and a non-default WAZUH_LOGTEST_API_PASSWORD.")
        raise SystemExit(1)
    return user, password


def _authenticate(user: str, password: str) -> str:
    # VERIFY (4.14.9): POST /security/user/authenticate, Basic auth, token in data.token.
    body = _curl(
        "POST",
        "/security/user/authenticate",
        user=user,
        password=password,
    )
    token = ((body or {}).get("data") or {}).get("token")
    if not isinstance(token, str) or not token:
        print("Wazuh API authentication did not return data.token.", file=sys.stderr)
        raise SystemExit(1)
    return token


def _case_files(only_id: str | None) -> list[Path]:
    if only_id:
        path = LOG_DIR / f"{only_id}.yml"
        if not path.is_file():
            if only_id.startswith("SF-"):
                return []
            print(f"No logtest file for {only_id}: {path.relative_to(REPO)}", file=sys.stderr)
            raise SystemExit(1)
        return [path]
    return sorted(path for path in LOG_DIR.glob("*.yml") if path.is_file())


def _run_case(case_id: str, case: dict[str, Any], auth_token: str, *, verbose: bool) -> dict[str, Any]:
    name = str(case.get("name") or "unnamed")
    limited = bool(case.get("logtest_limited"))
    limited_reason = str(case.get("limited_reason") or "logtest-limited")
    events = _events(case)
    session: str | None = None
    raw_calls: list[dict[str, Any]] = []
    parsed: list[dict[str, Any]] = []
    try:
        for event in events:
            payload: dict[str, Any] = {
                "event": event,
                "log_format": case.get("log_format"),
                "location": case.get("location"),
            }
            if session:
                payload["token"] = session
            response = _logtest(payload, auth_token)
            raw_calls.append(response)
            if response.get("transport") == "cli":
                parsed.append(response["parsed"])
                continue
            data = response.get("data") if isinstance(response.get("data"), dict) else {}
            session = data.get("token") if isinstance(data.get("token"), str) else session
            parsed.append(_parse_api(data))
            if verbose:
                _print_verbose(case_id, name, data)
    finally:
        if session:
            try:
                _curl("DELETE", f"/logtest/sessions/{session}", bearer=auth_token)
            except RuntimeError:
                pass
    expect = case.get("expect") if isinstance(case.get("expect"), dict) else {}
    ok, actual = _compare(expect, parsed)
    status = "PASS" if ok else "FAIL"
    reason = None
    if limited and not ok:
        status = "LIMITED"
        reason = limited_reason
        print(f"{case_id} {name}: REQUIRES WINDOWS VALIDATION / logtest-limited")
        print(limited_reason)
    return {
        "id": case_id,
        "name": name,
        "status": status,
        "expected": expect,
        "actual": actual,
        "reason": reason,
        "raw": raw_calls,
    }


def _events(case: dict[str, Any]) -> list[str]:
    if "events" in case:
        values = case["events"]
        if not isinstance(values, list) or not values:
            raise SystemExit(f"{case.get('name')}: events must be a non-empty list")
        return [str(item) for item in values]
    if "event" not in case:
        raise SystemExit(f"{case.get('name')}: case needs event or events")
    return [str(case["event"]).strip("\n")]


def _logtest(payload: dict[str, Any], bearer: str) -> dict[str, Any]:
    try:
        body = _curl("PUT", "/logtest", bearer=bearer, payload=payload)
    except RuntimeError as exc:
        cli = _logtest_cli(str(payload["event"]))
        return {"transport": "cli", "error": str(exc), "parsed": cli, "raw_text": cli.get("text")}
    if not isinstance(body, dict) or body.get("error") not in (0, None):
        cli = _logtest_cli(str(payload["event"]))
        return {"transport": "cli", "api": body, "parsed": cli, "raw_text": cli.get("text")}
    body["transport"] = "api"
    return body


def _parse_api(data: dict[str, Any]) -> dict[str, Any]:
    output = data.get("output") if isinstance(data.get("output"), dict) else {}
    rule = output.get("rule") if isinstance(output.get("rule"), dict) else {}
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    mitre_ids = mitre.get("id") if isinstance(mitre.get("id"), list) else []
    decoder = output.get("decoder") if isinstance(output.get("decoder"), dict) else {}
    rule_id = rule.get("id")
    level = rule.get("level")
    alert = data.get("alert")
    fires = bool(alert) and rule_id not in (None, "0")
    return {
        "fires": fires,
        "rule_id": str(rule_id) if rule_id is not None else None,
        "level": int(level) if isinstance(level, int) or (isinstance(level, str) and level.isdigit()) else None,
        "mitre": [str(item) for item in mitre_ids],
        "decoder": decoder.get("name"),
        "description": rule.get("description"),
    }


def _compare(expect: dict[str, Any], parsed: list[dict[str, Any]]) -> tuple[bool, dict[str, Any]]:
    last = parsed[-1] if parsed else {"fires": False, "rule_id": None, "level": None, "mitre": []}
    wanted_id = str(expect.get("rule_id")) if expect.get("rule_id") is not None else None
    fired = [item for item in parsed if item.get("fires") and item.get("rule_id") == wanted_id]
    if expect.get("fires"):
        matched = fired[-1] if fired else None
        ok = matched is not None
        if ok and "level" in expect:
            ok = matched["level"] == int(expect["level"])
        if ok and "mitre" in expect:
            ok = set(str(item) for item in expect["mitre"]) <= set(matched["mitre"])
        actual = matched or last
    else:
        ok = wanted_id is None or not fired
        actual = {
            "fires": bool(fired),
            "rule_id": fired[-1]["rule_id"] if fired else last.get("rule_id"),
            "level": last.get("level"),
            "mitre": last.get("mitre") or [],
            "decoder": last.get("decoder"),
            "description": last.get("description"),
        }
    return ok, {
        "fires": actual.get("fires"),
        "rule_id": actual.get("rule_id"),
        "level": actual.get("level"),
        "mitre": actual.get("mitre") or [],
        "decoder": actual.get("decoder"),
        "description": actual.get("description"),
    }


def _logtest_cli(event: str) -> dict[str, Any]:
    # VERIFY (4.14.9): piping one line into wazuh-logtest uses one session until EOF.
    try:
        completed = subprocess.run(
            ["docker", "exec", "-i", CONTAINER, "/var/ossec/bin/wazuh-logtest"],
            input=(event.strip("\n") + "\n").encode(),
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {
            "fires": False,
            "rule_id": None,
            "level": None,
            "mitre": [],
            "decoder": None,
            "description": None,
            "text": "wazuh-logtest CLI timed out after 30s",
        }
    text = completed.stdout.decode("utf-8", "replace")
    rule_ids = _RULE_ID_RE.findall(text)
    levels = _LEVEL_RE.findall(text)
    # The rule id line is the phase-3 id. MITRE ids also match the id regex, so
    # keep the first numeric id after "Phase 3" when present.
    phase3 = text.split("Phase 3", 1)[-1] if "Phase 3" in text else text
    rule_match = _RULE_ID_RE.search(phase3)
    level_match = _LEVEL_RE.search(phase3)
    rule_id = rule_match.group("id") if rule_match else (rule_ids[-1] if rule_ids else None)
    level = int(level_match.group("level")) if level_match else (int(levels[-1]) if levels else None)
    mitre = [item for item in _MITRE_RE.findall(text)]
    fires = rule_id not in (None, "0") and "Alert to be generated" in text
    return {
        "fires": fires,
        "rule_id": rule_id,
        "level": level,
        "mitre": mitre,
        "decoder": None,
        "description": None,
        "text": text,
    }


def _curl(
    method: str,
    path: str,
    *,
    bearer: str | None = None,
    user: str | None = None,
    password: str | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    command = [
        "docker",
        "exec",
        "-i",
        CONTAINER,
        "curl",
        "-sk",
        "--max-time",
        "25",
        "-X",
        method,
        f"https://127.0.0.1:55000{path}",
        "-H",
        "Content-Type: application/json",
    ]
    if bearer:
        command.extend(["-H", f"Authorization: Bearer {bearer}"])
    if user is not None and password is not None:
        command.extend(["-u", f"{user}:{password}"])
    if payload is not None:
        command.extend(["--data-binary", "@-"])
    completed = subprocess.run(
        command,
        input=None if payload is None else json.dumps(payload).encode(),
        capture_output=True,
        check=False,
    )
    text = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 or not text:
        detail = completed.stderr.decode("utf-8", "replace").strip() or text or "empty response"
        raise RuntimeError(detail)
    try:
        body = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Wazuh API returned non-JSON for {method} {path}") from exc
    if not isinstance(body, dict):
        raise RuntimeError(f"Wazuh API returned a non-object for {method} {path}")
    return body


def _print_verbose(case_id: str, name: str, data: dict[str, Any]) -> None:
    output = data.get("output") if isinstance(data.get("output"), dict) else {}
    decoder = output.get("decoder")
    rule = output.get("rule")
    print(f"--- {case_id} {name} decoder: {json.dumps(decoder, default=str)}")
    print(f"--- {case_id} {name} rule: {json.dumps(rule, default=str)}")


def _print_table(rows: list[dict[str, Any]]) -> None:
    use_color = sys.stdout.isatty()

    def paint(status: str) -> str:
        label = f"{status:<8}"
        if not use_color:
            return label
        color = {"PASS": "32", "FAIL": "31", "LIMITED": "33"}.get(status, "0")
        return f"\033[{color}m{label}\033[0m"

    print(f"{'STATUS':<8} {'ID':<12} {'CASE':<24} {'EXPECTED':<28} ACTUAL")
    for row in rows:
        expected = _brief(row.get("expected"))
        actual = _brief(row.get("actual"))
        print(f"{paint(row['status'])} {row['id']:<12} {row['name']:<24} {expected:<28} {actual}")


def _brief(value: Any) -> str:
    if not isinstance(value, dict):
        return "-"
    fires = value.get("fires")
    rule_id = value.get("rule_id")
    level = value.get("level")
    return f"fires={fires} rule={rule_id} level={level}"


def _update_metadata(rows: list[dict[str, Any]], result_name: str, *, mark_needs_tuning: bool) -> None:
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if str(row["id"]).startswith("SF-"):
            by_id.setdefault(str(row["id"]), []).append(row)
    if not by_id:
        print("0 detections found")
        return
    today = datetime.now(UTC).date().isoformat()
    for detection_id, detection_rows in by_id.items():
        path = META_DIR / f"{detection_id}.yml"
        if not path.is_file():
            print(f"{detection_id}: no metadata file at {path.relative_to(REPO)}")
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"^status:\s*LAB VALIDATED\s*$", text, flags=re.M):
            print(f"{detection_id}: status is LAB VALIDATED; left unchanged")
            continue
        failed = any(row["status"] == "FAIL" for row in detection_rows)
        if failed:
            if mark_needs_tuning:
                _write_status(path, text, "NEEDS TUNING", today, result_name)
                print(f"{detection_id}: status set to NEEDS TUNING")
            else:
                print(f"{detection_id}: failed; metadata not changed")
            continue
        if any(row["status"] != "PASS" for row in detection_rows):
            print(f"{detection_id}: not all cases passed; metadata not changed")
            continue
        _write_status(path, text, "LOGTEST VALID", today, result_name)
        print(f"{detection_id}: status set to LOGTEST VALID")


def _write_status(path: Path, text: str, status: str, today: str, result_name: str) -> None:
    if re.search(r"^status:", text, flags=re.M):
        text = re.sub(r"^status:.*$", f"status: {status}", text, count=1, flags=re.M)
    else:
        text = text.rstrip() + f"\nstatus: {status}\n"
    text = _upsert(text, "logtest_date", today)
    text = _upsert(text, "logtest_result", result_name)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def _upsert(text: str, key: str, value: str) -> str:
    line = f"{key}: {value}"
    if re.search(rf"^{key}:", text, flags=re.M):
        return re.sub(rf"^{key}:.*$", line, text, count=1, flags=re.M)
    return text.rstrip() + f"\n{line}\n"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
