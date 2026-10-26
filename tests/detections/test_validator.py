"""The detection validator rejects broken fixtures and accepts this repo."""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "validation"))

from validate_detections import Finding, validate_repo  # noqa: E402

ATTACK = {
    "attack_version": "20.0",
    "source_url": "https://example.test/enterprise-attack.json",
    "techniques": {
        "T1059.001": {"name": "PowerShell", "revoked": False, "deprecated": False},
        "T1086": {"name": "PowerShell", "revoked": True, "deprecated": False},
    },
}


def test_real_repo_passes() -> None:
    findings = validate_repo(ROOT)
    errors = [item for item in findings if item.level == "error"]
    assert errors == []


def test_duplicate_rule_id(tmp_path: Path) -> None:
    _write_repo(tmp_path, extra_rule=_rule(rule_id="100100"))
    assert "duplicate_rule_id" in _codes(tmp_path)


def test_out_of_range_rule_id(tmp_path: Path) -> None:
    _write_repo(tmp_path, rule_id="110000")
    assert "rule_id_range" in _codes(tmp_path)


def test_unknown_mitre_id(tmp_path: Path) -> None:
    _write_repo(tmp_path, technique="T9999.001")
    assert "mitre_unknown" in _codes(tmp_path)


def test_revoked_mitre_id(tmp_path: Path) -> None:
    _write_repo(tmp_path, technique="T1086")
    assert "mitre_revoked" in _codes(tmp_path)


def test_windows_cannot_be_logtest_valid(tmp_path: Path) -> None:
    _write_repo(tmp_path, status="LOGTEST VALID", windows=True)
    assert "status_windows_logtest" in _codes(tmp_path)


def test_lab_validated_requires_evidence(tmp_path: Path) -> None:
    _write_repo(tmp_path, status="LAB VALIDATED", evidence=None, observed="NOT YET VALIDATED")
    codes = _codes(tmp_path)
    assert "status_lab_evidence" in codes
    assert "status_lab_observed" in codes


def test_orphan_rule(tmp_path: Path) -> None:
    _write_repo(
        tmp_path,
        extra_rule=_rule(rule_id="100101", sf_id="SF-002"),
    )
    assert "orphan_rule" in _codes(tmp_path)


def test_hunt_allowlist_rejects_an_unknown_field(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    allow = tmp_path / "scripts" / "validation" / "indexed_fields.txt"
    allow.write_text("agent.name\n", encoding="utf-8")
    hunts = tmp_path / "hunting"
    hunts.mkdir()
    (hunts / "HUNT-001.yml").write_text(
        textwrap.dedent(
            """\
            id: HUNT-001
            name: Fixture hunt
            hypothesis: Something the detection misses.
            data_source:
              index: archives
              channel: Security
            query: not.a.field:1
            time_window_default: 24h
            expected_behavior: Quiet.
            suspicious_behavior: Noisy.
            mitre:
              - id: T1059.001
                tactic: Execution
            related_detections:
              - SF-001
            differs_from_detections: SF-001 alerts on a threshold. This lists the events.
            investigation_guidance:
              - Read the field.
            pivot_fields:
              - agent.name
            status: NOT TESTED
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "fixtures").mkdir(exist_ok=True)
    (tmp_path / "fixtures" / "hunts.json").write_text("{}\n", encoding="utf-8")
    assert "hunt_field" in _codes(tmp_path)


def test_missing_doc(tmp_path: Path) -> None:
    _write_repo(tmp_path, include_doc=False)
    assert "missing_doc" in _codes(tmp_path)


def _codes(root: Path) -> set[str]:
    findings: list[Finding] = validate_repo(root)
    return {item.code for item in findings if item.level == "error"}


def _write_repo(
    root: Path,
    *,
    rule_id: str = "100100",
    technique: str = "T1059.001",
    status: str = "SYNTAX VALID",
    windows: bool = True,
    evidence: object = None,
    observed: str = "NOT YET VALIDATED",
    include_doc: bool = True,
    extra_rule: str = "",
) -> None:
    rules = root / "detections" / "wazuh" / "rules"
    rules.mkdir(parents=True)
    (rules / "sentinelforge_100100_auth.xml").write_text(
        _rule(rule_id=rule_id, sf_id="SF-001", technique=technique) + extra_rule,
        encoding="utf-8",
    )
    meta = root / "detections" / "metadata"
    meta.mkdir(parents=True)
    listed = rule_id if rule_id != "110000" else "110000"
    (meta / "SF-001.yml").write_text(
        textwrap.dedent(
            f"""\
            id: SF-001
            name: Fixture
            description: Fixture detection.
            severity: medium
            mitre:
              - {technique}
            telemetry:
              - windows_security
            wazuh_rule_ids:
              - "{listed}"
            sigma_file: detections/sigma/SF-001.yml
            version: "1"
            status: {status}
            windows_validation_required: {"true" if windows else "false"}
            false_positives: none
            tuning_notes: none
            test_procedure: none
            expected_event: none
            expected_alert: none
            observed_result: "{observed}"
            syntax_valid_date: 2026-10-26
            logtest_date: 2026-10-26
            lab_validation:
              simulation: planned
              evidence: {json.dumps(evidence)}
            """
        ),
        encoding="utf-8",
    )
    sigma = root / "detections" / "sigma"
    sigma.mkdir(parents=True)
    (sigma / "SF-001.yml").write_text(
        textwrap.dedent(
            f"""\
            title: Fixture
            id: 11111111-1111-4111-8111-111111111111
            logsource:
              product: windows
              service: security
            detection:
              selection:
                EventID: 1
              condition: selection
            level: medium
            tags:
              - attack.{technique.lower()}
            """
        ),
        encoding="utf-8",
    )
    logs = root / "tests" / "logs"
    logs.mkdir(parents=True)
    (logs / "SF-001.yml").write_text(
        textwrap.dedent(
            """\
            comment: SYNTHETIC TEST INPUT
            id: SF-001
            description: fixture
            cases:
              - name: positive
                log_format: syslog
                location: /var/log/auth.log
                event: "fixture"
                expect:
                  fires: true
                  rule_id: 100100
              - name: negative_benign
                log_format: syslog
                location: /var/log/auth.log
                event: "fixture"
                expect:
                  fires: false
                  rule_id: 100100
            """
        ),
        encoding="utf-8",
    )
    if include_doc:
        docs = root / "docs" / "detections"
        docs.mkdir(parents=True)
        (docs / "SF-001.md").write_text("# SF-001\n", encoding="utf-8")
    attack = root / "scripts" / "validation"
    attack.mkdir(parents=True)
    (attack / "attack_techniques.json").write_text(json.dumps(ATTACK), encoding="utf-8")


def _rule(*, rule_id: str, sf_id: str = "SF-001", technique: str = "T1059.001") -> str:
    return textwrap.dedent(
        f"""\
        <group name="windows,">
          <rule id="{rule_id}" level="10">
            <description>{sf_id}: fixture</description>
            <mitre><id>{technique}</id></mitre>
            <group>sentinelforge,auth,</group>
          </rule>
        </group>
        """
    )
