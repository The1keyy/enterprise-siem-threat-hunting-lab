"""SYNTHETIC TEST INPUT. Not lab telemetry and not a LAB VALIDATED result.

Alert documents follow the fields the 13B simulations are expected to produce:
auth on DC01 with ipAddress 10.10.10.20, SF-004 and SF-007 on WS01, SF-011 on
DC01 from 10.10.10.20. SF-002 is included even though Invoke-AttackStory.ps1
does not run it, so the auth_burst category can be shown counting once.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.services.correlation import (
    correlate,
    entity_risk,
    load_risk_config,
    normalize_source_ip,
    normalize_user,
)
from app.services.risk import final_score

LABEL = "SYNTHETIC TEST INPUT"
BASE = datetime(2026, 10, 27, 15, 0, tzinfo=UTC)
CONFIG = load_risk_config()


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _windows(
    *,
    alert_id: str,
    when: datetime,
    sf_id: str,
    rule_id: str,
    level: int,
    host: str,
    description: str,
    technique: str,
    event_id: str,
    target: str | None = None,
    subject: str | None = None,
    ip: str | None = None,
) -> dict:
    eventdata: dict[str, str] = {}
    if target is not None:
        eventdata["targetUserName"] = target
    if subject is not None:
        eventdata["subjectUserName"] = subject
    if ip is not None:
        eventdata["ipAddress"] = ip
    return {
        "_label": LABEL,
        "_id": alert_id,
        "timestamp": _iso(when),
        "agent": {"name": host},
        "rule": {
            "id": rule_id,
            "level": level,
            "description": f"{sf_id}: {description} {LABEL}",
            "mitre": {"id": [technique], "tactic": []},
        },
        "data": {"win": {"system": {"eventID": event_id}, "eventdata": eventdata}},
    }


def _ssh(
    *,
    alert_id: str,
    when: datetime,
    sf_id: str,
    rule_id: str,
    level: int,
    user: str,
    ip: str,
    technique: str,
    description: str,
) -> dict:
    return {
        "_label": LABEL,
        "_id": alert_id,
        "timestamp": _iso(when),
        "agent": {"name": "UBU01"},
        "rule": {
            "id": rule_id,
            "level": level,
            "description": f"{sf_id}: {description} {LABEL}",
            "mitre": {"id": [technique], "tactic": []},
        },
        "data": {"srcip": ip, "srcuser": user},
    }


def _story(host: str | None = None) -> list[dict]:
    """One synthetic story. host= replaces every agent name (the WS01-only case)."""

    auth_host = host or "DC01"
    workstation = host or "WS01"
    return [
        _windows(
            alert_id="syn-sf-001",
            when=BASE,
            sf_id="SF-001",
            rule_id="100100",
            level=11,
            host=auth_host,
            description="repeated 4625 failures for one target account",
            technique="T1110.001",
            event_id="4625",
            target="sf-test-alice",
            ip="10.10.10.20",
        ),
        _windows(
            alert_id="syn-sf-002",
            when=BASE + timedelta(minutes=1),
            sf_id="SF-002",
            rule_id="100110",
            level=10,
            host=auth_host,
            description="repeated 4625 failures from one source IP",
            technique="T1110.003",
            event_id="4625",
            target="sf-test-bob",
            ip="10.10.10.20",
        ),
        _windows(
            alert_id="syn-sf-003",
            when=BASE + timedelta(minutes=2),
            sf_id="SF-003",
            rule_id="100120",
            level=12,
            host=auth_host,
            description="4624 after repeated failures",
            technique="T1078",
            event_id="4624",
            target="sf-test-alice",
            ip="10.10.10.20",
        ),
        _windows(
            alert_id="syn-sf-004",
            when=BASE + timedelta(minutes=3),
            sf_id="SF-004",
            rule_id="100200",
            level=12,
            host=workstation,
            description="suspicious PowerShell script block",
            technique="T1059.001",
            event_id="4104",
            # 4104 often has no account. This synthetic event sets the WS01
            # session so it can join the admin who later adds bob.
            subject=r"SENTINELFORGE\sf-test-admin",
        ),
        _windows(
            alert_id="syn-sf-007",
            when=BASE + timedelta(minutes=4),
            sf_id="SF-007",
            rule_id="100300",
            level=13,
            host=workstation,
            description="member added to local Administrators",
            technique="T1098",
            event_id="4732",
            subject=r"SENTINELFORGE\sf-test-admin",
            target="sf-test-bob",
        ),
        _windows(
            alert_id="syn-sf-011",
            when=BASE + timedelta(minutes=5),
            sf_id="SF-011",
            rule_id="100510",
            level=12,
            host=auth_host,
            description="admin share access",
            technique="T1021.002",
            event_id="5140",
            subject="sf-test-admin",
            ip="10.10.10.20",
        ),
    ]


def _ssh_pair(
    when: datetime | None = None,
    user: str = "sf-test-carol",
    suffix: str = "",
) -> list[dict]:
    # The lab SSH scripts use sf-test-alice. This pair uses a different user
    # so it does not join the Windows story by account. Source stays .200.
    start = when or BASE
    return [
        _ssh(
            alert_id=f"syn-sf-013-{user}{suffix}",
            when=start,
            sf_id="SF-013",
            rule_id="100701",
            level=10,
            user=user,
            ip="10.10.10.200",
            technique="T1110.001",
            description="sshd failure burst",
        ),
        _ssh(
            alert_id=f"syn-sf-014-{user}{suffix}",
            when=start + timedelta(minutes=1),
            sf_id="SF-014",
            rule_id="100710",
            level=12,
            user=user,
            ip="10.10.10.200",
            technique="T1078",
            description="sshd success after failures",
        ),
    ]


def _assert_labeled(alerts: list[dict]) -> None:
    assert alerts
    assert all(item.get("_label") == LABEL for item in alerts)


def test_attack_story_is_one_critical_incident() -> None:
    alerts = _story()
    _assert_labeled(alerts)
    incidents = correlate(alerts)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.subtotal == 135
    assert incident.multiplier == pytest.approx(1.7)
    assert incident.multiplier_hosts == ("DC01",)
    assert incident.final == 230
    assert incident.final == final_score(135, 1.7)
    assert incident.band == "critical"
    assert incident.forced_critical is False
    assert [entry.time for entry in incident.timeline] == sorted(
        entry.time for entry in incident.timeline
    )
    assert incident.alert_ids == (
        "syn-sf-001",
        "syn-sf-002",
        "syn-sf-003",
        "syn-sf-004",
        "syn-sf-007",
        "syn-sf-011",
    )
    counted = {row.sf_id: row for row in incident.breakdown if row.counted}
    assert set(counted) == {"SF-001", "SF-003", "SF-004", "SF-007", "SF-011"}
    spray = next(row for row in incident.breakdown if row.sf_id == "SF-002")
    assert spray.counted is False
    assert spray.points == 15
    assert spray.reason == "category already counted"
    assert sum(row.points for row in incident.breakdown if row.counted) == 135
    assert "linked by user sf-test-alice" in incident.link_reasons
    assert "linked by source 10.10.10.20" in incident.link_reasons
    assert incident.entities.hosts == ("DC01", "WS01")
    assert "sf-test-alice" in incident.entities.users
    assert "10.10.10.20" in incident.entities.source_ips
    assert set(incident.mitre) == {
        "T1110.001",
        "T1110.003",
        "T1078",
        "T1059.001",
        "T1098",
        "T1021.002",
    }


def test_story_on_ws01_only_uses_the_workstation_multiplier() -> None:
    incidents = correlate(_story(host="WS01"))
    assert len(incidents) == 1
    incident = incidents[0]
    assert "DC01" not in incident.entities.hosts
    assert incident.multiplier_hosts == ("WS01",)
    assert incident.multiplier == pytest.approx(1.0)
    assert incident.subtotal == 135
    assert incident.final == 135
    assert incident.band == "high"


def test_unrelated_ssh_is_a_separate_incident() -> None:
    alerts = _story() + _ssh_pair()
    _assert_labeled(alerts)
    incidents = correlate(alerts)
    assert len(incidents) == 2
    ssh = next(item for item in incidents if "UBU01" in item.entities.hosts)
    windows = next(item for item in incidents if item is not ssh)
    assert windows.final == 230
    assert ssh.subtotal == 40
    assert ssh.multiplier == pytest.approx(1.3)
    assert ssh.multiplier_hosts == ("UBU01",)
    assert ssh.final == 52
    assert ssh.final == final_score(40, 1.3)
    assert ssh.band == "medium"
    assert ssh.entities.users == ("sf-test-carol",)
    assert ssh.entities.source_ips == ("10.10.10.200",)
    assert "sf-test-alice" not in ssh.entities.users


def test_alerts_three_hours_apart_stay_separate() -> None:
    first = _windows(
        alert_id="gap-a",
        when=BASE,
        sf_id="SF-004",
        rule_id="100200",
        level=12,
        host="WS01",
        description="suspicious PowerShell script block",
        technique="T1059.001",
        event_id="4104",
        subject="sf-test-alice",
    )
    second = _windows(
        alert_id="gap-b",
        when=BASE + timedelta(hours=3),
        sf_id="SF-004",
        rule_id="100200",
        level=12,
        host="WS01",
        description="suspicious PowerShell script block",
        technique="T1059.001",
        event_id="4104",
        subject="sf-test-alice",
    )
    _assert_labeled([first, second])
    incidents = correlate([first, second])
    assert len(incidents) == 2
    assert all(len(item.alert_ids) == 1 for item in incidents)


@pytest.mark.parametrize("status", CONFIG.closed_statuses)
def test_closed_incident_does_not_take_a_later_alert(status: str) -> None:
    opened = correlate(_story())
    assert len(opened) == 1
    closed = replace(opened[0], status=status)
    later = _windows(
        alert_id="syn-sf-005",
        when=BASE + timedelta(minutes=15),
        sf_id="SF-005",
        rule_id="100210",
        level=13,
        host="WS01",
        description="encoded PowerShell process",
        technique="T1059.001",
        event_id="1",
        subject="sf-test-admin",
    )
    result = correlate([later], existing=[closed])
    assert len(result) == 2
    kept = next(item for item in result if item.id == closed.id)
    fresh = next(item for item in result if item.id != closed.id)
    assert kept.status == status
    assert kept.alert_ids == closed.alert_ids
    assert fresh.status == "New"
    assert fresh.alert_ids == ("syn-sf-005",)
    assert fresh.subtotal == 30


@pytest.mark.parametrize("status", CONFIG.open_statuses)
def test_open_incident_appends_inside_the_window(status: str) -> None:
    opened = correlate(_story())
    current = replace(opened[0], status=status)
    extra = _windows(
        alert_id="syn-sf-010",
        when=BASE + timedelta(minutes=15),
        sf_id="SF-010",
        rule_id="100501",
        level=12,
        host="WS01",
        description="inbound RDP logon",
        technique="T1021.001",
        event_id="4624",
        target="sf-test-admin",
    )
    result = correlate([extra], existing=[current])
    assert len(result) == 1
    incident = result[0]
    assert incident.id == current.id
    assert incident.status == status
    assert "syn-sf-010" in incident.alert_ids
    assert len(incident.alert_ids) == 7
    assert incident.subtotal == 155
    assert incident.final == final_score(155, 1.7)


def test_reprocessing_the_same_alerts_does_not_change_the_incident() -> None:
    alerts = _story()
    first = correlate(alerts)
    again = correlate(alerts)
    assert [(item.id, item.alert_ids, item.final, item.breakdown) for item in again] == [
        (item.id, item.alert_ids, item.final, item.breakdown) for item in first
    ]
    second = correlate(alerts, existing=first)
    assert len(second) == 1
    assert second[0].id == first[0].id
    assert second[0].alert_ids == first[0].alert_ids
    assert second[0].subtotal == 135
    assert second[0].final == 230
    auth = [row for row in second[0].breakdown if row.category == "auth_burst" and row.counted]
    assert len(auth) == 1


def test_machine_accounts_and_gateway_do_not_link() -> None:
    assert normalize_user(r"SENTINELFORGE\DC01$", CONFIG) is None
    assert normalize_user("WS01$", CONFIG) is None
    assert normalize_user("-", CONFIG) is None
    assert normalize_user("", CONFIG) is None
    assert normalize_user("sf-test-alice@sentinelforge.lab", CONFIG) == "sf-test-alice"
    assert normalize_source_ip("10.10.10.1", CONFIG) is None
    assert normalize_source_ip("127.0.0.1", CONFIG) is None
    assert normalize_source_ip("::1", CONFIG) is None

    alerts = [
        _windows(
            alert_id="machine-dc",
            when=BASE,
            sf_id="SF-004",
            rule_id="100200",
            level=12,
            host="DC01",
            description="suspicious PowerShell script block",
            technique="T1059.001",
            event_id="4104",
            subject="DC01$",
        ),
        _windows(
            alert_id="machine-ws",
            when=BASE + timedelta(minutes=1),
            sf_id="SF-004",
            rule_id="100200",
            level=12,
            host="DC01",
            description="suspicious PowerShell script block",
            technique="T1059.001",
            event_id="4104",
            subject="WS01$",
            ip="10.10.10.1",
        ),
        _windows(
            alert_id="gateway-alice",
            when=BASE + timedelta(minutes=2),
            sf_id="SF-004",
            rule_id="100200",
            level=12,
            host="WS01",
            description="suspicious PowerShell script block",
            technique="T1059.001",
            event_id="4104",
            subject="sf-test-alice",
            ip="10.10.10.1",
        ),
        _windows(
            alert_id="loopback-bob",
            when=BASE + timedelta(minutes=3),
            sf_id="SF-004",
            rule_id="100200",
            level=12,
            host="WS01",
            description="suspicious PowerShell script block",
            technique="T1059.001",
            event_id="4104",
            subject="sf-test-bob",
            ip="127.0.0.1",
        ),
        _windows(
            alert_id="ipv6-loopback",
            when=BASE + timedelta(minutes=4),
            sf_id="SF-004",
            rule_id="100200",
            level=12,
            host="WS01",
            description="suspicious PowerShell script block",
            technique="T1059.001",
            event_id="4104",
            subject="sf-test-carol",
            ip="::1",
        ),
    ]
    _assert_labeled(alerts)
    incidents = correlate(alerts)
    assert len(incidents) == len(alerts)
    assert all(len(item.alert_ids) == 1 for item in incidents)
    assert all(item.link_reasons == () for item in incidents)

    linked = correlate(
        [
            _windows(
                alert_id="norm-a",
                when=BASE,
                sf_id="SF-004",
                rule_id="100200",
                level=12,
                host="WS01",
                description="suspicious PowerShell script block",
                technique="T1059.001",
                event_id="4104",
                subject=r"SENTINELFORGE\sf-test-alice",
            ),
            _windows(
                alert_id="norm-b",
                when=BASE + timedelta(minutes=1),
                sf_id="SF-005",
                rule_id="100210",
                level=13,
                host="WS01",
                description="encoded PowerShell process",
                technique="T1059.001",
                event_id="1",
                subject="sf-test-alice@sentinelforge.lab",
            ),
        ]
    )
    assert len(linked) == 1
    assert linked[0].entities.users == ("sf-test-alice",)
    assert "linked by user sf-test-alice" in linked[0].link_reasons


def test_hub_key_does_not_build_a_mega_incident() -> None:
    alerts = []
    for index in range(6):
        alerts.append(
            _windows(
                alert_id=f"hub-{index}",
                when=BASE + timedelta(minutes=index),
                sf_id="SF-004",
                rule_id="100200",
                level=12,
                host="WS01",
                description="suspicious PowerShell script block",
                technique="T1059.001",
                event_id="4104",
                subject=f"user-{index}",
                ip="10.10.10.60",
            )
        )
    _assert_labeled(alerts)
    merged = correlate(alerts)
    assert len(merged) == 1
    assert len(merged[0].alert_ids) == 6

    guarded = correlate(alerts, config=replace(CONFIG, hub_user_limit=2))
    assert len(guarded) == 6
    assert all(len(item.alert_ids) == 1 for item in guarded)


def test_max_incident_size_stops_a_group_growing() -> None:
    alerts = [
        _windows(
            alert_id=f"cap-{index}",
            when=BASE + timedelta(minutes=index),
            sf_id="SF-004",
            rule_id="100200",
            level=12,
            host="WS01",
            description="suspicious PowerShell script block",
            technique="T1059.001",
            event_id="4104",
            subject="sf-test-alice",
        )
        for index in range(4)
    ]
    incidents = correlate(alerts, config=replace(CONFIG, max_incident_alerts=2))
    assert len(incidents) == 2
    assert sorted(len(item.alert_ids) for item in incidents) == [2, 2]
    assert sum(len(item.alert_ids) for item in incidents) == 4


def test_entity_risk_halves_at_one_half_life() -> None:
    assert CONFIG.half_life_hours == 24
    early = correlate(_ssh_pair(BASE))
    late = correlate(_ssh_pair(BASE + timedelta(hours=24), suffix="-later"))
    assert early[0].subtotal == 40
    assert late[0].id != early[0].id
    now = late[0].last_seen
    assert entity_risk("users", "sf-test-carol", early, now, CONFIG) == pytest.approx(20)
    assert entity_risk("users", "sf-test-carol", late, now, CONFIG) == pytest.approx(40)
    assert entity_risk("users", "sf-test-carol", early + late, now, CONFIG) == pytest.approx(60)
    assert entity_risk(
        "hosts",
        "UBU01",
        early,
        early[0].last_seen + timedelta(hours=48),
        CONFIG,
    ) == pytest.approx(10)
    assert entity_risk("users", "sf-test-alice", early, now, CONFIG) == 0


def test_level_15_forces_critical_without_raising_the_points() -> None:
    alert = _windows(
        alert_id="syn-sf-008",
        when=BASE,
        sf_id="SF-008",
        rule_id="100310",
        level=15,
        host="DC01",
        description="member added to Domain Admins or Enterprise Admins",
        technique="T1098",
        event_id="4728",
        target="sf-test-alice",
        subject="sf-test-admin",
    )
    _assert_labeled([alert])
    incidents = correlate([alert])
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.subtotal == 35
    assert incident.final == final_score(35, 1.7)
    assert incident.final == 60
    assert CONFIG.band_medium <= incident.final < CONFIG.band_high
    assert incident.band == "critical"
    assert incident.forced_critical is True


def test_unknown_alert_stays_attached_and_scores_zero() -> None:
    noise = {
        "_label": LABEL,
        "_id": "syn-noise",
        "timestamp": _iso(BASE + timedelta(minutes=6)),
        "agent": {"name": "WS01"},
        "rule": {
            "id": "5715",
            "level": 3,
            "description": f"sshd session opened {LABEL}",
            "mitre": {"id": [], "tactic": []},
        },
        "data": {"srcuser": "sf-test-admin"},
    }
    incidents = correlate(_story() + [noise])
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.subtotal == 135
    assert incident.final == 230
    row = next(item for item in incident.breakdown if item.alert_id == "syn-noise")
    assert row.counted is False
    assert row.points == 0
    assert row.reason == "not an SF category"
    assert "syn-noise" in incident.alert_ids


def test_low_score_without_a_high_level_does_not_open() -> None:
    alert = _windows(
        alert_id="syn-sf-009",
        when=BASE,
        sf_id="SF-009",
        rule_id="100320",
        level=10,
        host="WS01",
        description="new user account created",
        technique="T1136.001",
        event_id="4720",
        target="sf-test-dave",
    )
    assert correlate([alert]) == []
