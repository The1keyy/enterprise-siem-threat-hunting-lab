"""Windows and Linux agent snippets match the telemetry matrix and channels.md."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = ROOT / "configs" / "wazuh" / "agent-windows" / "ossec.conf.snippet"
LINUX = ROOT / "configs" / "wazuh" / "agent-linux" / "ossec.conf.snippet"
MANAGER = ROOT / "configs" / "wazuh" / "manager" / "ossec.conf.snippet"
CHANNELS = ROOT / "configs" / "windows" / "channels.md"
MATRIX = ROOT / "docs" / "TELEMETRY_MATRIX.md"
MANAGER_DIR = ROOT / "configs" / "wazuh" / "manager"

NO_QUERY = (
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-WinRM/Operational",
)


def _parse(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def _localfiles(root: ET.Element) -> dict[str, ET.Element]:
    found: dict[str, ET.Element] = {}
    for node in root.findall("localfile"):
        location = node.findtext("location")
        assert location, "localfile without location"
        assert location not in found, location
        found[location] = node
    return found


def _channel_names() -> list[str]:
    names: list[str] = []
    for line in CHANNELS.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if not cells or cells[0] in {"Channel", ""} or set(cells[0]) <= {"-", " "}:
            continue
        names.append(cells[0])
    return names


def _security_event_ids() -> set[str]:
    ids: set[str] = set()
    for line in MATRIX.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| SF-"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        channel = cells[2]
        if channel != "Security" and not channel.startswith("Security "):
            continue
        ids.update(re.findall(r"\b\d{4}\b", cells[3]))
    return ids


def _matrix_log_paths() -> set[str]:
    return set(re.findall(r"/var/log/[A-Za-z0-9_./-]+", MATRIX.read_text(encoding="utf-8")))


def test_snippets_are_well_formed() -> None:
    for path in (WINDOWS, LINUX, MANAGER):
        root = _parse(path)
        assert root.tag == "ossec_config"


def test_windows_snippet_has_every_channel() -> None:
    channels = _channel_names()
    assert channels == [
        "Security",
        "System",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-WinRM/Operational",
    ]
    found = _localfiles(_parse(WINDOWS))
    assert set(found) == set(channels)
    for name in channels:
        assert found[name].findtext("log_format") == "eventchannel"


def test_security_query_keeps_matrix_ids_and_5145() -> None:
    security = _localfiles(_parse(WINDOWS))["Security"]
    query = security.findtext("query") or ""
    ids = _security_event_ids()
    assert ids == {"4624", "4625", "4720", "4728", "4732", "4756", "5140", "5145"}
    for event_id in ids:
        assert re.search(rf"EventID={event_id}\b", query), event_id
    assert re.search(r"EventID=4688\b", query)
    assert "5156" not in query
    assert "5145" in query


def test_unlisted_channels_have_no_query() -> None:
    found = _localfiles(_parse(WINDOWS))
    for name in NO_QUERY:
        assert found[name].find("query") is None, name
    powershell = found["Microsoft-Windows-PowerShell/Operational"].findtext("query") or ""
    assert re.search(r"EventID=4104\b", powershell)
    assert "4103" not in powershell


def test_manager_address_placeholder() -> None:
    for path in (WINDOWS, LINUX):
        address = _parse(path).findtext("./client/server/address")
        assert address == "<WAZUH_MANAGER_IP>"


def test_linux_snippet_has_every_matrix_log() -> None:
    paths = _matrix_log_paths()
    assert paths == {
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/audit/audit.log",
    }
    found = _localfiles(_parse(LINUX))
    assert set(found) == paths
    assert found["/var/log/auth.log"].findtext("log_format") == "syslog"
    assert found["/var/log/syslog"].findtext("log_format") == "syslog"
    assert found["/var/log/audit/audit.log"].findtext("log_format") == "audit"


def test_manager_enables_json_archives_only() -> None:
    root = _parse(MANAGER)
    assert root.findtext("./global/logall_json") == "yes"
    assert root.find("global/logall") is None


def test_ism_policies_parse() -> None:
    archives = json.loads((MANAGER_DIR / "ism-wazuh-archives-7d.json").read_text(encoding="utf-8"))
    alerts = json.loads((MANAGER_DIR / "ism-wazuh-alerts-30d.json").read_text(encoding="utf-8"))
    assert archives["policy"]["ism_template"][0]["index_patterns"] == ["wazuh-archives-*"]
    assert alerts["policy"]["ism_template"][0]["index_patterns"] == ["wazuh-alerts-*"]
    assert archives["policy"]["states"][0]["transitions"][0]["conditions"]["min_index_age"] == "7d"
    assert alerts["policy"]["states"][0]["transitions"][0]["conditions"]["min_index_age"] == "30d"
