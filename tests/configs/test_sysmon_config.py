"""The merged Sysmon config keeps the Step 12A process and network includes."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MERGED = ROOT / "configs" / "sysmon" / "sysmonconfig-sentinelforge.xml"
PROCESS_IMAGES = ("powershell.exe", "pwsh.exe", "wsmprovhost.exe", "schtasks.exe", "sc.exe")
NETWORK_IMAGES = ("powershell.exe", "pwsh.exe")


def _tree() -> ET.Element:
    return ET.parse(MERGED).getroot()


def _tokens(text: str | None) -> set[str]:
    if not text:
        return set()
    raw = text.replace(";", " ").replace(",", " ").split()
    return {part.strip().lower() for part in raw if part.strip()}


def _group(root: ET.Element, name: str) -> ET.Element:
    found = [node for node in root.iter("RuleGroup") if node.get("name") == name]
    assert len(found) == 1, name
    return found[0]


def test_merged_config_is_schema_4_91() -> None:
    root = _tree()
    assert root.tag == "Sysmon"
    assert root.get("schemaversion") == "4.91"


def test_process_includes_are_unconditional() -> None:
    group = _group(_tree(), "sentinelforge-process")
    event = group.find("ProcessCreate")
    assert event is not None
    assert event.get("onmatch") == "include"
    images = set()
    originals = set()
    for child in list(event):
        assert child.tag != "Rule", "a sentinelforge process include must not be an AND rule"
        if child.tag == "Image":
            images |= _tokens(child.text)
        if child.tag == "OriginalFileName":
            originals |= _tokens(child.text)
    for image in PROCESS_IMAGES:
        assert image in images, image
    assert "pwsh.exe" in originals


def test_network_includes_powershell_and_winrm() -> None:
    group = _group(_tree(), "sentinelforge-network")
    event = group.find("NetworkConnect")
    assert event is not None
    assert event.get("onmatch") == "include"
    images = set()
    ports = set()
    for child in list(event):
        assert child.tag != "Rule"
        if child.tag == "Image":
            images |= _tokens(child.text)
        if child.tag == "DestinationPort":
            ports |= _tokens(child.text)
    for image in NETWORK_IMAGES:
        assert image in images, image
    assert "5985" in ports


def test_excludes_do_not_name_the_same_images() -> None:
    root = _tree()
    banned = set(PROCESS_IMAGES) | {"5985"}
    for event_name in ("ProcessCreate", "NetworkConnect"):
        for event in root.iter(event_name):
            if event.get("onmatch") != "exclude":
                continue
            for node in event.iter():
                overlap = _tokens(node.text) & banned
                assert not overlap, f"{event_name} exclude contains {sorted(overlap)}"
