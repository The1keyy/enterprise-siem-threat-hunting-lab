#!/usr/bin/env python3
"""Check SentinelForge detection files. Exit 1 when any error is found.

Uses PyYAML and the standard library. ATT&CK IDs come from the committed
scripts/validation/attack_techniques.json. This script does not use the network.
"""

from __future__ import annotations

import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import yaml

STATUSES = (
    "NOT TESTED",
    "SYNTAX VALID",
    "LOGTEST VALID",
    "LAB VALIDATED",
    "NEEDS TUNING",
)
SEVERITIES = ("low", "medium", "high", "critical")
TELEMETRY = {
    "windows_security",
    "sysmon",
    "powershell",
    "linux_auth",
    "auditd",
    "suricata",
}
REQUIRED_METADATA = (
    "id",
    "name",
    "description",
    "severity",
    "mitre",
    "telemetry",
    "wazuh_rule_ids",
    "sigma_file",
    "version",
    "status",
    "windows_validation_required",
    "false_positives",
    "tuning_notes",
    "test_procedure",
    "expected_event",
    "expected_alert",
    "observed_result",
)
HUNT_FIELDS = (
    "id",
    "name",
    "hypothesis",
    "data_source",
    "query",
    "time_window_default",
    "expected_behavior",
    "suspicious_behavior",
    "mitre",
    "related_detections",
    "differs_from_detections",
    "investigation_guidance",
    "pivot_fields",
    "status",
)
HUNT_ID = re.compile(r"^HUNT-\d{3}$")
HUNT_INDEXES = {"alerts", "archives"}
HUNT_WINDOWS = {"24h", "7d"}
# A query_string cannot express these. The YAML must carry aggregation.
HUNT_NEEDS_AGG = re.compile(r"\b(rare|unusual|first seen)\b", re.IGNORECASE)
# Filename token -> inclusive rule-id span. 100100 means 100100–100199.
CATEGORY_STARTS = {
    100100: "auth",
    100200: "powershell",
    100300: "accounts",
    100400: "persistence",
    100500: "lateral",
    100600: "credential",
    100700: "linux",
    100800: "defense",
    100900: "network",
    101000: "correlation",
}
SF_ID = re.compile(r"^SF-\d{3}$")
SF_DESCRIPTION = re.compile(r"^(SF-\d{3}):")
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
SIGMA_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RULE_FILE = re.compile(r"^sentinelforge_(\d{6})_[a-z0-9]+\.xml$")


@dataclass(frozen=True)
class Finding:
    level: str
    code: str
    location: str
    message: str


def validate_repo(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rules = _load_rules(root, findings)
    attack = _load_attack(root, findings)
    metadata = _load_metadata(root, findings)
    _check_rule_ownership(root, rules, metadata, findings)
    _check_metadata_rules(root, rules, metadata, attack, findings)
    _check_hunts(root, attack, metadata, findings)
    _check_sigma_files(root, findings)
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    findings = validate_repo(root)
    _print_table(findings)
    errors = [item for item in findings if item.level == "error"]
    return 1 if errors else 0


def _load_rules(root: Path, findings: list[Finding]) -> dict[str, dict]:
    rules: dict[str, dict] = {}
    folder = root / "detections" / "wazuh" / "rules"
    if not folder.is_dir():
        findings.append(Finding("error", "xml_missing", str(folder), "rules directory is missing"))
        return rules
    for path in sorted(folder.glob("sentinelforge_*.xml")):
        text = path.read_text(encoding="utf-8")
        _flag_comment_dashes(path, text, findings)
        match = RULE_FILE.match(path.name)
        start = int(match.group(1)) if match else None
        if start not in CATEGORY_STARTS:
            findings.append(
                Finding(
                    "error",
                    "rule_filename",
                    _rel(root, path),
                    "filename must be sentinelforge_<range>_<category>.xml "
                    "using a category start "
                    + ", ".join(str(item) for item in CATEGORY_STARTS),
                )
            )
        try:
            tree = ET.fromstring(f"<sentinelforge-root>{text}</sentinelforge-root>")
        except ET.ParseError as exc:
            findings.append(Finding("error", "xml_parse", _rel(root, path), str(exc)))
            continue
        for rule in tree.findall(".//rule"):
            rule_id = (rule.get("id") or "").strip()
            location = f"{_rel(root, path)}:{rule_id or '?'}"
            if not rule_id.isdigit():
                findings.append(Finding("error", "rule_id_range", location, "rule id is not an integer"))
                continue
            number = int(rule_id)
            if rule_id in rules:
                findings.append(
                    Finding(
                        "error",
                        "duplicate_rule_id",
                        location,
                        f"rule id {rule_id} also appears in {rules[rule_id]['location']}",
                    )
                )
            if not 100000 <= number <= 109999:
                findings.append(
                    Finding(
                        "error",
                        "rule_id_range",
                        location,
                        f"{rule_id} is outside 100000–109999",
                    )
                )
            elif start in CATEGORY_STARTS and not start <= number <= start + 99:
                findings.append(
                    Finding(
                        "error",
                        "rule_category_range",
                        location,
                        f"{rule_id} is outside {start}–{start + 99} ({CATEGORY_STARTS[start]})",
                    )
                )
            description = (rule.findtext("description") or "").strip()
            sf_match = SF_DESCRIPTION.match(description)
            if sf_match is None:
                findings.append(
                    Finding(
                        "error",
                        "rule_description",
                        location,
                        "description must start with SF-XXX:",
                    )
                )
            mitre_ids = [
                (item.text or "").strip()
                for item in rule.findall("mitre/id")
                if (item.text or "").strip()
            ]
            if not mitre_ids:
                findings.append(
                    Finding("error", "rule_mitre", location, "rule needs at least one <mitre><id>")
                )
            if not _group_has_sentinelforge(rule):
                findings.append(
                    Finding(
                        "error",
                        "rule_group",
                        location,
                        "<group> must contain sentinelforge",
                    )
                )
            rules[rule_id] = {
                "location": location,
                "sf_id": sf_match.group(1) if sf_match else None,
                "mitre": mitre_ids,
            }
    return rules


def _flag_comment_dashes(path: Path, text: str, findings: list[Finding]) -> None:
    for match in re.finditer(r"<!--(.*?)-->", text, flags=re.DOTALL):
        if "--" in match.group(1):
            findings.append(
                Finding(
                    "error",
                    "xml_comment",
                    str(path.name),
                    "XML comment contains '--', which is not allowed",
                )
            )
            return


def _group_has_sentinelforge(rule: ET.Element) -> bool:
    for group in rule.findall("group"):
        tokens = [part.strip() for part in (group.text or "").split(",")]
        if "sentinelforge" in tokens:
            return True
    return False


def _load_attack(root: Path, findings: list[Finding]) -> dict:
    path = root / "scripts" / "validation" / "attack_techniques.json"
    if not path.is_file():
        findings.append(Finding("error", "attack_list", _rel(root, path), "pinned ATT&CK list is missing"))
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(Finding("error", "attack_list", _rel(root, path), str(exc)))
        return {}
    techniques = document.get("techniques")
    if not isinstance(techniques, dict):
        findings.append(Finding("error", "attack_list", _rel(root, path), "techniques must be an object"))
        return {}
    return techniques


def _load_metadata(root: Path, findings: list[Finding]) -> dict[str, dict]:
    folder = root / "detections" / "metadata"
    loaded: dict[str, dict] = {}
    if not folder.is_dir():
        findings.append(Finding("error", "meta_missing", str(folder), "metadata directory is missing"))
        return loaded
    for path in sorted(folder.glob("SF-*.yml")):
        stem = path.stem
        location = _rel(root, path)
        if not SF_ID.match(stem):
            findings.append(Finding("error", "meta_id_format", location, "filename must match SF-XXX"))
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            findings.append(Finding("error", "meta_parse", location, str(exc)))
            continue
        if not isinstance(data, dict):
            findings.append(Finding("error", "meta_parse", location, "metadata must be a mapping"))
            continue
        meta_id = str(data.get("id") or "")
        if meta_id != stem:
            findings.append(
                Finding("error", "meta_filename", location, f"id {meta_id or '(missing)'} does not match filename")
            )
        if not SF_ID.match(meta_id):
            findings.append(Finding("error", "meta_id_format", location, f"id {meta_id!r} must match SF-XXX"))
        for field in REQUIRED_METADATA:
            if field not in data or data[field] in (None, "", []):
                findings.append(Finding("error", "meta_required", location, f"missing {field}"))
        if data.get("severity") not in SEVERITIES:
            findings.append(
                Finding("error", "meta_severity", location, f"severity must be one of {', '.join(SEVERITIES)}")
            )
        if data.get("status") not in STATUSES:
            findings.append(
                Finding("error", "meta_status", location, f"status must be one of {', '.join(STATUSES)}")
            )
        telemetry = data.get("telemetry")
        if isinstance(telemetry, list):
            unknown = [item for item in telemetry if item not in TELEMETRY]
            if unknown:
                findings.append(
                    Finding("error", "meta_telemetry", location, f"unknown telemetry {unknown}")
                )
        if not isinstance(data.get("windows_validation_required"), bool):
            findings.append(
                Finding(
                    "error",
                    "meta_required",
                    location,
                    "windows_validation_required must be true or false",
                )
            )
        loaded[stem] = data
        _check_status(root, stem, data, findings)
        _check_completeness(root, stem, data, findings)
    return loaded


def _check_status(root: Path, sf_id: str, data: dict, findings: list[Finding]) -> None:
    location = f"detections/metadata/{sf_id}.yml"
    status = data.get("status")
    if data.get("windows_validation_required") is True and status == "LOGTEST VALID":
        findings.append(
            Finding(
                "error",
                "status_windows_logtest",
                location,
                "windows_validation_required rules cannot be LOGTEST VALID",
            )
        )
    if status == "LOGTEST VALID":
        if not DATE.match(str(data.get("logtest_date") or "")):
            findings.append(
                Finding("error", "status_logtest_date", location, "LOGTEST VALID needs logtest_date YYYY-MM-DD")
            )
        _check_logtest_cases(root, sf_id, findings)
    if status == "LAB VALIDATED":
        lab = data.get("lab_validation")
        evidence = lab.get("evidence") if isinstance(lab, dict) else None
        if evidence in (None, ""):
            findings.append(
                Finding(
                    "error",
                    "status_lab_evidence",
                    location,
                    "LAB VALIDATED needs lab_validation.evidence",
                )
            )
        observed = data.get("observed_result")
        if observed in (None, "", "NOT YET VALIDATED"):
            findings.append(
                Finding(
                    "error",
                    "status_lab_observed",
                    location,
                    "LAB VALIDATED needs an observed_result other than NOT YET VALIDATED",
                )
            )
    if status == "SYNTAX VALID" and not DATE.match(str(data.get("syntax_valid_date") or "")):
        findings.append(
            Finding(
                "error",
                "status_syntax_date",
                location,
                "SYNTAX VALID needs syntax_valid_date YYYY-MM-DD from a clean analysisd load",
            )
        )


def _check_logtest_cases(root: Path, sf_id: str, findings: list[Finding]) -> None:
    path = root / "tests" / "logs" / f"{sf_id}.yml"
    location = _rel(root, path)
    if not path.is_file():
        findings.append(
            Finding("error", "status_logtest_cases", location, "LOGTEST VALID needs a tests/logs file")
        )
        return
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        findings.append(Finding("error", "status_logtest_cases", location, str(exc)))
        return
    cases = document.get("cases") if isinstance(document, dict) else None
    if not isinstance(cases, list):
        findings.append(Finding("error", "status_logtest_cases", location, "cases must be a list"))
        return
    runnable = [case for case in cases if isinstance(case, dict) and case.get("mode") != "lab_reference"]
    positives = [case for case in runnable if (case.get("expect") or {}).get("fires") is True]
    negatives = [case for case in runnable if (case.get("expect") or {}).get("fires") is False]
    if not positives or not negatives:
        findings.append(
            Finding(
                "error",
                "status_logtest_cases",
                location,
                "LOGTEST VALID needs at least one positive and one negative runnable case",
            )
        )


def _check_completeness(root: Path, sf_id: str, data: dict, findings: list[Finding]) -> None:
    location = f"detections/metadata/{sf_id}.yml"
    sigma_file = data.get("sigma_file")
    sigma_path = root / str(sigma_file) if sigma_file else None
    if sigma_path is None or not sigma_path.is_file():
        findings.append(Finding("error", "missing_sigma", location, "sigma_file is missing"))
    if not (root / "tests" / "logs" / f"{sf_id}.yml").is_file():
        findings.append(Finding("error", "missing_tests", location, f"tests/logs/{sf_id}.yml is missing"))
    if not (root / "docs" / "detections" / f"{sf_id}.md").is_file():
        findings.append(Finding("error", "missing_doc", location, f"docs/detections/{sf_id}.md is missing"))


def _check_rule_ownership(
    root: Path,
    rules: dict[str, dict],
    metadata: dict[str, dict],
    findings: list[Finding],
) -> None:
    for rule_id, rule in rules.items():
        sf_id = rule["sf_id"]
        if sf_id is None:
            continue
        owners = [
            owner
            for owner, data in metadata.items()
            if rule_id in _rule_id_list(data)
        ]
        if sf_id not in owners:
            findings.append(
                Finding(
                    "error",
                    "orphan_rule",
                    rule["location"],
                    f"{rule_id} is tagged {sf_id} but that metadata file does not list it",
                )
            )


def _check_metadata_rules(
    root: Path,
    rules: dict[str, dict],
    metadata: dict[str, dict],
    attack: dict,
    findings: list[Finding],
) -> None:
    for sf_id, data in metadata.items():
        location = f"detections/metadata/{sf_id}.yml"
        rule_mitre: set[str] = set()
        for rule_id in _rule_id_list(data):
            rule = rules.get(rule_id)
            if rule is None:
                findings.append(
                    Finding(
                        "error",
                        "unknown_rule_id",
                        location,
                        f"wazuh_rule_ids contains {rule_id}, which is not in the XML",
                    )
                )
                continue
            rule_mitre.update(rule["mitre"])
        meta_mitre = _string_set(data.get("mitre"))
        sigma_mitre = _sigma_techniques(root, data.get("sigma_file"), findings, location)
        if sigma_mitre is None:
            continue
        if meta_mitre != rule_mitre or meta_mitre != sigma_mitre:
            findings.append(
                Finding(
                    "error",
                    "mitre_mismatch",
                    location,
                    "MITRE IDs differ across metadata "
                    f"{sorted(meta_mitre)}, rules {sorted(rule_mitre)}, sigma {sorted(sigma_mitre)}",
                )
            )
        for technique_id in sorted(meta_mitre):
            _check_technique(attack, technique_id, location, findings)


def _sigma_techniques(
    root: Path,
    sigma_file: object,
    findings: list[Finding],
    location: str,
) -> set[str] | None:
    if not isinstance(sigma_file, str):
        return set()
    path = root / sigma_file
    if not path.is_file():
        return set()
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        findings.append(Finding("error", "sigma_parse", sigma_file, str(exc)))
        return None
    if not isinstance(document, dict):
        findings.append(Finding("error", "sigma_parse", sigma_file, "Sigma file must be a mapping"))
        return None
    tags = document.get("tags") or []
    found: set[str] = set()
    if isinstance(tags, list):
        for tag in tags:
            match = SIGMA_TECHNIQUE.match(str(tag))
            if match:
                found.add(match.group(1).upper())
    return found


def _check_technique(attack: dict, technique_id: str, location: str, findings: list[Finding]) -> None:
    if MITRE_ID.match(technique_id) is None:
        findings.append(
            Finding("error", "mitre_format", location, f"{technique_id} must look like T1059 or T1059.001")
        )
        return
    record = attack.get(technique_id)
    if not isinstance(record, dict):
        findings.append(
            Finding("error", "mitre_unknown", location, f"{technique_id} is not in the pinned ATT&CK list")
        )
        return
    if record.get("revoked") or record.get("deprecated"):
        state = "revoked" if record.get("revoked") else "deprecated"
        findings.append(
            Finding("error", "mitre_revoked", location, f"{technique_id} is {state} in the pinned ATT&CK list")
        )


def _check_sigma_files(root: Path, findings: list[Finding]) -> None:
    folder = root / "detections" / "sigma"
    if not folder.is_dir():
        return
    for path in sorted(folder.glob("*.yml")):
        location = _rel(root, path)
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            findings.append(Finding("error", "sigma_parse", location, str(exc)))
            continue
        if not isinstance(document, dict):
            findings.append(Finding("error", "sigma_parse", location, "Sigma file must be a mapping"))
            continue
        for field in ("title", "id", "logsource", "detection", "level"):
            if field not in document or document[field] in (None, "", []):
                findings.append(Finding("error", "sigma_field", location, f"missing {field}"))
        detection = document.get("detection")
        if not isinstance(detection, dict) or not detection.get("condition"):
            findings.append(Finding("error", "sigma_field", location, "detection.condition is missing"))
        if not isinstance(document.get("logsource"), dict) or not document.get("logsource"):
            findings.append(Finding("error", "sigma_field", location, "logsource must be a mapping"))
        try:
            uuid.UUID(str(document.get("id")))
        except (ValueError, TypeError, AttributeError):
            findings.append(Finding("error", "sigma_uuid", location, "id must be a UUID"))
        tags = document.get("tags") if isinstance(document.get("tags"), list) else []
        if not any(SIGMA_TECHNIQUE.match(str(tag)) for tag in tags):
            findings.append(
                Finding("error", "sigma_attack_tag", location, "needs an attack.t#### tag")
            )


def _check_hunts(
    root: Path,
    attack: dict,
    metadata: dict[str, dict],
    findings: list[Finding],
) -> None:
    """Syntax and field names only. This does not prove the hunt returns the right events."""

    folder = root / "hunting"
    if not folder.is_dir():
        return
    paths = sorted(folder.glob("HUNT-*.yml"))
    if not paths:
        return
    allowed = _indexed_fields(root, findings)
    seen: set[str] = set()
    for path in paths:
        location = _rel(root, path)
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            findings.append(Finding("error", "hunt_parse", location, str(exc)))
            continue
        if not isinstance(document, dict):
            findings.append(Finding("error", "hunt_parse", location, "hunt file must be a mapping"))
            continue
        for field in HUNT_FIELDS:
            if field not in document or document[field] in (None, "", []):
                findings.append(Finding("error", "hunt_required", location, f"missing {field}"))
        hunt_id = str(document.get("id") or "")
        if not HUNT_ID.match(hunt_id):
            findings.append(Finding("error", "hunt_id", location, f"id {hunt_id!r} must match HUNT-XXX"))
        elif path.stem != hunt_id:
            findings.append(Finding("error", "hunt_id", location, "filename must match id"))
        elif hunt_id in seen:
            findings.append(Finding("error", "hunt_id", location, f"duplicate {hunt_id}"))
        else:
            seen.add(hunt_id)
        status = document.get("status")
        if status not in STATUSES:
            findings.append(Finding("error", "hunt_status", location, f"status {status!r} is not a validation status"))
        window = document.get("time_window_default")
        if window not in HUNT_WINDOWS:
            findings.append(
                Finding("error", "hunt_window", location, "time_window_default must be 24h or 7d")
            )
        _check_hunt_source(document.get("data_source"), location, findings)
        _check_hunt_mitre(document.get("mitre"), attack, location, findings)
        _check_hunt_related(document.get("related_detections"), metadata, location, findings)
        _check_hunt_guidance(document.get("investigation_guidance"), location, findings)
        _check_hunt_differs(document, location, findings)
        query = document.get("query")
        fields = _query_fields(query, location, findings) if isinstance(query, str) else set()
        aggregation = document.get("aggregation")
        if HUNT_NEEDS_AGG.search(str(document.get("name") or "")) and not isinstance(aggregation, dict):
            findings.append(
                Finding(
                    "error",
                    "hunt_aggregation",
                    location,
                    "a rare, unusual, or first-seen hunt needs aggregation; a query_string cannot express it",
                )
            )
        if isinstance(aggregation, dict):
            agg_field = aggregation.get("field")
            if aggregation.get("type") != "terms" or not isinstance(agg_field, str):
                findings.append(
                    Finding("error", "hunt_aggregation", location, "aggregation must be a terms agg with a field")
                )
            else:
                fields.add(agg_field)
            size = aggregation.get("size")
            cap = aggregation.get("max_doc_count")
            if type(size) is not int or not 1 <= size <= 100:
                findings.append(Finding("error", "hunt_aggregation", location, "aggregation size must be 1..100"))
            if type(cap) is not int or cap < 1:
                findings.append(
                    Finding("error", "hunt_aggregation", location, "max_doc_count must be a positive integer")
                )
        pivots = document.get("pivot_fields")
        if isinstance(pivots, list):
            fields.update(str(item) for item in pivots)
        unknown = sorted(field for field in fields if field not in allowed)
        for field in unknown:
            findings.append(
                Finding("error", "hunt_field", location, f"{field} is not in indexed_fields.txt")
            )
    _check_hunt_fixture(root, findings)


def _indexed_fields(root: Path, findings: list[Finding]) -> set[str]:
    path = root / "scripts" / "validation" / "indexed_fields.txt"
    if not path.is_file():
        findings.append(Finding("error", "hunt_fields", _rel(root, path), "indexed field allow-list is missing"))
        return set()
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text:
            names.add(text)
    return names


def _query_fields(query: str, location: str, findings: list[Finding]) -> set[str]:
    from luqum.exceptions import ParseError, ParseSyntaxError
    from luqum.parser import parser as luqum_parser

    try:
        tree = luqum_parser.parse(query)
    except (ParseError, ParseSyntaxError) as exc:
        findings.append(Finding("error", "hunt_query", location, f"query_string did not parse: {exc}"))
        return set()
    found: set[str] = set()

    def walk(node: object) -> None:
        if type(node).__name__ == "SearchField":
            name = getattr(node, "name", None)
            if name is not None:
                found.add(str(name))
        for child in getattr(node, "children", ()) or ():
            walk(child)

    walk(tree)
    if not found:
        findings.append(Finding("error", "hunt_query", location, "query_string has no field:value clause"))
    return found


def _check_hunt_source(source: object, location: str, findings: list[Finding]) -> None:
    if not isinstance(source, dict):
        findings.append(Finding("error", "hunt_source", location, "data_source must name an index and a channel or log"))
        return
    index = source.get("index")
    if index not in HUNT_INDEXES:
        findings.append(
            Finding("error", "hunt_source", location, "data_source.index must be alerts or archives")
        )
    channel = str(source.get("channel") or "").strip()
    log = str(source.get("log") or "").strip()
    if not channel and not log:
        findings.append(Finding("error", "hunt_source", location, "data_source needs a channel or a log"))


def _check_hunt_mitre(mitre: object, attack: dict, location: str, findings: list[Finding]) -> None:
    if not isinstance(mitre, list):
        return
    for item in mitre:
        technique_id = item.get("id") if isinstance(item, dict) else item
        technique_id = str(technique_id or "")
        if not MITRE_ID.match(technique_id):
            findings.append(Finding("error", "hunt_mitre", location, f"{technique_id!r} is not a technique id"))
            continue
        row = attack.get(technique_id)
        if not isinstance(row, dict):
            findings.append(Finding("error", "hunt_mitre", location, f"{technique_id} is not in the pinned ATT&CK list"))
            continue
        if row.get("revoked") or row.get("deprecated"):
            findings.append(Finding("error", "hunt_mitre", location, f"{technique_id} is revoked or deprecated"))


def _check_hunt_related(
    related: object,
    metadata: dict[str, dict],
    location: str,
    findings: list[Finding],
) -> None:
    if not isinstance(related, list):
        return
    for item in related:
        detection_id = str(item)
        if detection_id not in metadata:
            findings.append(
                Finding("error", "hunt_related", location, f"{detection_id} is not a detection in this repo")
            )


def _check_hunt_guidance(guidance: object, location: str, findings: list[Finding]) -> None:
    if not isinstance(guidance, list) or not guidance:
        findings.append(Finding("error", "hunt_guidance", location, "investigation_guidance must be a list of steps"))
        return
    for step in guidance:
        if not isinstance(step, str) or not step.strip():
            findings.append(Finding("error", "hunt_guidance", location, "each investigation step must be text"))


def _check_hunt_differs(document: dict, location: str, findings: list[Finding]) -> None:
    text = document.get("differs_from_detections")
    if not isinstance(text, str) or not text.strip():
        return
    related = document.get("related_detections")
    if isinstance(related, list) and related and "SF-" not in text:
        findings.append(
            Finding("error", "hunt_differs", location, "differs_from_detections must name the related SF detection")
        )


def _check_hunt_fixture(root: Path, findings: list[Finding]) -> None:
    import json

    from hunt_files import render_fixture

    path = root / "fixtures" / "hunts.json"
    if not path.is_file():
        findings.append(Finding("error", "hunt_fixture", "fixtures/hunts.json", "hunt fixture is missing"))
        return
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(Finding("error", "hunt_fixture", "fixtures/hunts.json", str(exc)))
        return
    expected = render_fixture(root)
    if current != expected:
        findings.append(
            Finding(
                "error",
                "hunt_fixture",
                "fixtures/hunts.json",
                "stale hunt fixture; run scripts/validation/build_hunt_fixtures.py",
            )
        )


def _rule_id_list(data: dict) -> list[str]:
    values = data.get("wazuh_rule_ids") or []
    if not isinstance(values, list):
        return []
    return [str(item) for item in values]


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item).strip() for item in value if str(item).strip()}


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _print_table(findings: list[Finding]) -> None:
    errors = sum(1 for item in findings if item.level == "error")
    warnings = sum(1 for item in findings if item.level == "warning")
    print(f"errors: {errors}  warnings: {warnings}")
    if not findings:
        print("OK")
        return
    print(f"{'LEVEL':<8} {'CODE':<24} {'LOCATION':<44} MESSAGE")
    for item in findings:
        print(f"{item.level.upper():<8} {item.code:<24} {item.location:<44} {item.message}")


if __name__ == "__main__":
    sys.exit(main())
