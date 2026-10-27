"""Group Wazuh alerts into incidents and score them from risk_config.yml.

Pure functions. This module does not read the indexer or write SQLite.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from app.services.risk import final_score

CONFIG_PATH = Path(__file__).resolve().parents[1] / "core" / "risk_config.yml"
_SF_ID = re.compile(r"^(SF-\d{3})\b")


@dataclass(frozen=True)
class RiskConfig:
    window_minutes: int
    max_incident_alerts: int
    hub_user_limit: int
    open_level: int
    critical_level: int
    half_life_hours: float
    band_medium: int
    band_high: int
    band_critical: int
    categories: dict[str, int]
    sf_category: dict[str, str]
    hosts: dict[str, str]
    multipliers: dict[str, float]
    excluded_source_ips: frozenset[str]
    ignored_user_values: frozenset[str]
    machine_account_suffix: str
    user_prefixes: tuple[str, ...]
    user_suffixes: tuple[str, ...]
    open_statuses: tuple[str, ...]
    closed_statuses: tuple[str, ...]
    default_asset_class: str

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)


@dataclass(frozen=True)
class ScoreRow:
    category: str | None
    sf_id: str | None
    alert_id: str
    time: datetime
    points: int
    counted: bool
    reason: str


@dataclass(frozen=True)
class TimelineEntry:
    alert_id: str
    time: datetime
    sf_id: str | None
    host: str | None
    level: int
    rule_id: str | None
    description: str


@dataclass(frozen=True)
class Entities:
    users: tuple[str, ...]
    hosts: tuple[str, ...]
    source_ips: tuple[str, ...]


@dataclass(frozen=True)
class CorrelatedIncident:
    id: str
    status: str
    alerts: tuple[dict[str, Any], ...]
    timeline: tuple[TimelineEntry, ...]
    entities: Entities
    mitre: tuple[str, ...]
    breakdown: tuple[ScoreRow, ...]
    subtotal: int
    multiplier: float
    multiplier_hosts: tuple[str, ...]
    final: int
    band: str
    forced_critical: bool
    link_reasons: tuple[str, ...]
    alert_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class _Alert:
    alert_id: str
    time: datetime
    raw: dict[str, Any]
    sf_id: str | None
    level: int
    host: str | None
    users: frozenset[str]
    source_ips: frozenset[str]
    mitre: frozenset[str]
    rule_id: str | None
    description: str
    link_keys: frozenset[tuple[str, str]]


class _UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._size: dict[str, int] = {}

    def add(self, item: str) -> None:
        if item not in self._parent:
            self._parent[item] = item
            self._size[item] = 1

    def find(self, item: str) -> str:
        parent = self._parent[item]
        if parent != item:
            self._parent[item] = self.find(parent)
        return self._parent[item]

    def union(self, left: str, right: str, limit: int | None) -> None:
        ra, rb = self.find(left), self.find(right)
        if ra == rb:
            return
        if limit is not None and self._size[ra] + self._size[rb] > limit:
            return
        if self._size[ra] < self._size[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        self._size[ra] += self._size[rb]

    def size_of(self, item: str) -> int:
        return self._size[self.find(item)]


def load_risk_config(path: Path | None = None) -> RiskConfig:
    raw = yaml.safe_load((path or CONFIG_PATH).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("risk_config.yml must be a mapping")
    categories: dict[str, int] = {}
    sf_category: dict[str, str] = {}
    for name, body in (raw.get("categories") or {}).items():
        points = int(body["points"])
        categories[str(name)] = points
        for detection in body.get("detections") or []:
            sf_id = str(detection)
            if sf_id in sf_category:
                raise ValueError(f"{sf_id} is listed in two categories")
            sf_category[sf_id] = str(name)
    hosts = {str(host): str(asset) for host, asset in (raw.get("hosts") or {}).items()}
    multipliers = {
        str(name): float(value) for name, value in (raw.get("multipliers") or {}).items()
    }
    bands = raw.get("bands") or {}
    config = RiskConfig(
        window_minutes=int(raw["window_minutes"]),
        max_incident_alerts=int(raw["max_incident_alerts"]),
        hub_user_limit=int(raw["hub_user_limit"]),
        open_level=int(raw["open_level"]),
        critical_level=int(raw["critical_level"]),
        half_life_hours=float(raw["half_life_hours"]),
        band_medium=int(bands["medium"]),
        band_high=int(bands["high"]),
        band_critical=int(bands["critical"]),
        categories=categories,
        sf_category=sf_category,
        hosts=hosts,
        multipliers=multipliers,
        excluded_source_ips=frozenset(
            str(item).strip().lower() for item in raw.get("excluded_source_ips") or []
        ),
        ignored_user_values=frozenset(
            str(item).strip().lower() for item in raw.get("ignored_user_values") or []
        ),
        machine_account_suffix=str(raw.get("machine_account_suffix") or "$"),
        user_prefixes=tuple(
            str(item).strip().lower() for item in raw.get("user_prefixes") or []
        ),
        user_suffixes=tuple(
            str(item).strip().lower() for item in raw.get("user_suffixes") or []
        ),
        open_statuses=tuple(str(item) for item in raw.get("open_statuses") or []),
        closed_statuses=tuple(str(item) for item in raw.get("closed_statuses") or []),
        default_asset_class=str(raw.get("default_asset_class") or "workstation"),
    )
    _validate(config)
    return config


def normalize_user(value: object, config: RiskConfig) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in config.ignored_user_values:
        return None
    for prefix in config.user_prefixes:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    for suffix in config.user_suffixes:
        if text.endswith(suffix):
            text = text[: -len(suffix)]
            break
    text = text.strip()
    if text in config.ignored_user_values or text.endswith(config.machine_account_suffix):
        return None
    return text or None


def normalize_source_ip(value: object, config: RiskConfig) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in config.ignored_user_values or text in config.excluded_source_ips:
        return None
    return text or None


def correlate(
    alerts: list[dict[str, Any]],
    existing: list[CorrelatedIncident] | None = None,
    config: RiskConfig | None = None,
) -> list[CorrelatedIncident]:
    """Link alerts, append only to open incidents, and score each group once."""

    cfg = config or load_risk_config()
    prior = list(existing or [])
    closed_ids = {
        alert_id
        for incident in prior
        if incident.status not in cfg.open_statuses
        for alert_id in incident.alert_ids
    }
    open_incidents = [incident for incident in prior if incident.status in cfg.open_statuses]

    working: dict[str, _Alert] = {}
    for incident in open_incidents:
        for raw in incident.alerts:
            parsed = _parse_alert(raw, cfg)
            working.setdefault(parsed.alert_id, parsed)
    for raw in alerts:
        parsed = _parse_alert(raw, cfg)
        if parsed.alert_id in closed_ids:
            continue
        working.setdefault(parsed.alert_id, parsed)

    groups = _group_alerts(list(working.values()), open_incidents, cfg)
    emitted: list[CorrelatedIncident] = []
    consumed: set[str] = set()
    for members in groups:
        member_ids = {item.alert_id for item in members}
        owners = [
            incident
            for incident in open_incidents
            if set(incident.alert_ids) & member_ids
        ]
        built = _build_incident(members, cfg, owners[0] if owners else None)
        if owners:
            consumed.update(incident.id for incident in owners)
            emitted.append(built)
        elif _opens(built, members, cfg):
            emitted.append(built)

    for incident in prior:
        if incident.status not in cfg.open_statuses:
            emitted.append(incident)
        elif incident.id not in consumed:
            emitted.append(incident)
    emitted.sort(key=lambda item: (item.first_seen, item.id))
    return emitted


def entity_risk(
    kind: str,
    value: str,
    incidents: list[CorrelatedIncident],
    now: datetime,
    config: RiskConfig | None = None,
) -> float:
    """Sum counted points for incidents that include this entity, then decay.

    Age is measured from the incident's last alert. At one half-life the
    subtotal is worth half. The asset multiplier is not applied again.
    """

    cfg = config or load_risk_config()
    total = 0.0
    for incident in incidents:
        entities = getattr(incident.entities, kind, ())
        if value not in entities:
            continue
        age_hours = (now - incident.last_seen).total_seconds() / 3600
        total += _decay(incident.subtotal, max(age_hours, 0.0), cfg.half_life_hours)
    return total


def _validate(config: RiskConfig) -> None:
    if config.band_medium >= config.band_high or config.band_high >= config.band_critical:
        raise ValueError("risk bands must increase: medium < high < critical")
    if config.window_minutes <= 0 or config.max_incident_alerts <= 0:
        raise ValueError("window_minutes and max_incident_alerts must be positive")
    if config.half_life_hours <= 0:
        raise ValueError("half_life_hours must be positive")
    if config.default_asset_class not in config.multipliers:
        raise ValueError("default_asset_class has no multiplier")
    for asset in config.hosts.values():
        if asset not in config.multipliers:
            raise ValueError(f"asset class {asset} has no multiplier")
    if not config.open_statuses:
        raise ValueError("open_statuses is empty")


def _decay(points: int, age_hours: float, half_life_hours: float) -> float:
    return points * (0.5 ** (age_hours / half_life_hours))


def _parse_alert(raw: dict[str, Any], config: RiskConfig) -> _Alert:
    alert_id = raw.get("_id")
    if not isinstance(alert_id, str) or not alert_id:
        raise ValueError("alert is missing indexer _id")
    timestamp = raw.get("timestamp")
    if not isinstance(timestamp, str):
        raise ValueError(f"{alert_id} is missing timestamp")
    description = str(_dig(raw, "rule", "description") or "")
    match = _SF_ID.match(description.strip())
    sf_id = match.group(1) if match else None
    users = frozenset(
        user
        for user in (
            normalize_user(_dig(raw, "data", "win", "eventdata", "targetUserName"), config),
            normalize_user(_dig(raw, "data", "win", "eventdata", "subjectUserName"), config),
            normalize_user(_dig(raw, "data", "srcuser"), config),
            normalize_user(_dig(raw, "data", "dstuser"), config),
        )
        if user
    )
    source_ips = frozenset(
        ip
        for ip in (
            normalize_source_ip(_dig(raw, "data", "win", "eventdata", "ipAddress"), config),
            normalize_source_ip(_dig(raw, "data", "srcip"), config),
            normalize_source_ip(_dig(raw, "data", "win", "eventdata", "sourceIp"), config),
        )
        if ip
    )
    host = _canonical_host(_dig(raw, "agent", "name"), config)
    mitre_raw = _dig(raw, "rule", "mitre", "id") or []
    if isinstance(mitre_raw, str):
        mitre_raw = [mitre_raw]
    rule_id = _dig(raw, "rule", "id")
    keys = frozenset({("user", user) for user in users} | {("source", ip) for ip in source_ips})
    return _Alert(
        alert_id=alert_id,
        time=_parse_time(timestamp),
        raw=raw,
        sf_id=sf_id,
        level=_as_int(_dig(raw, "rule", "level")),
        host=host,
        users=users,
        source_ips=source_ips,
        mitre=frozenset(str(item) for item in mitre_raw),
        rule_id=str(rule_id) if rule_id is not None else None,
        description=description,
        link_keys=keys,
    )


def _group_alerts(
    alerts: list[_Alert],
    open_incidents: list[CorrelatedIncident],
    config: RiskConfig,
) -> list[list[_Alert]]:
    if not alerts:
        return []
    by_id = {item.alert_id: item for item in alerts}
    hubs = _hub_keys(alerts, config.hub_user_limit)
    union = _UnionFind()
    for alert_id in by_id:
        union.add(alert_id)
    for incident in open_incidents:
        ids = [alert_id for alert_id in incident.alert_ids if alert_id in by_id]
        for other in ids[1:]:
            union.union(ids[0], other, None)

    keyed: dict[tuple[str, str], list[_Alert]] = defaultdict(list)
    for alert in alerts:
        for key in alert.link_keys:
            if key not in hubs:
                keyed[key].append(alert)
    for members in keyed.values():
        members.sort(key=lambda item: (item.time, item.alert_id))
        for index, left in enumerate(members):
            for right in members[index + 1 :]:
                if right.time - left.time > config.window:
                    break
                union.union(left.alert_id, right.alert_id, config.max_incident_alerts)

    grouped: dict[str, list[_Alert]] = defaultdict(list)
    for alert in alerts:
        grouped[union.find(alert.alert_id)].append(alert)
    return [
        sorted(members, key=lambda item: (item.time, item.alert_id))
        for members in grouped.values()
    ]


def _hub_keys(alerts: list[_Alert], limit: int) -> set[tuple[str, str]]:
    users_by_key: dict[tuple[str, str], set[str]] = defaultdict(set)
    for alert in alerts:
        for key in alert.link_keys:
            users_by_key[key].update(alert.users)
    return {key for key, users in users_by_key.items() if len(users) > limit}


def _build_incident(
    members: list[_Alert],
    config: RiskConfig,
    owner: CorrelatedIncident | None,
) -> CorrelatedIncident:
    ordered = sorted(members, key=lambda item: (item.time, item.alert_id))
    breakdown = tuple(_score_rows(ordered, config))
    subtotal = sum(row.points for row in breakdown if row.counted)
    hosts = tuple(sorted({item.host for item in ordered if item.host}))
    multiplier, multiplier_hosts = _multiplier(hosts, config)
    score = final_score(subtotal, multiplier)
    forced = any(item.level >= config.critical_level for item in ordered)
    alert_ids = tuple(item.alert_id for item in ordered)
    incident_id = owner.id if owner is not None else _new_id(alert_ids)
    status = owner.status if owner is not None else config.open_statuses[0]
    return CorrelatedIncident(
        id=incident_id,
        status=status,
        alerts=tuple(item.raw for item in ordered),
        timeline=tuple(
            TimelineEntry(
                alert_id=item.alert_id,
                time=item.time,
                sf_id=item.sf_id,
                host=item.host,
                level=item.level,
                rule_id=item.rule_id,
                description=item.description,
            )
            for item in ordered
        ),
        entities=Entities(
            users=tuple(sorted({user for item in ordered for user in item.users})),
            hosts=hosts,
            source_ips=tuple(sorted({ip for item in ordered for ip in item.source_ips})),
        ),
        mitre=tuple(sorted({technique for item in ordered for technique in item.mitre})),
        breakdown=breakdown,
        subtotal=subtotal,
        multiplier=multiplier,
        multiplier_hosts=multiplier_hosts,
        final=score,
        band=_band(score, forced, config),
        forced_critical=forced,
        link_reasons=tuple(_link_reasons(ordered, config)),
        alert_ids=alert_ids,
        first_seen=ordered[0].time,
        last_seen=ordered[-1].time,
    )


def _score_rows(alerts: list[_Alert], config: RiskConfig) -> list[ScoreRow]:
    counted: set[str] = set()
    rows: list[ScoreRow] = []
    for alert in alerts:
        category = config.sf_category.get(alert.sf_id or "")
        if category is None:
            rows.append(
                ScoreRow(
                    category=None,
                    sf_id=alert.sf_id,
                    alert_id=alert.alert_id,
                    time=alert.time,
                    points=0,
                    counted=False,
                    reason="not an SF category",
                )
            )
            continue
        points = config.categories[category]
        if category in counted:
            rows.append(
                ScoreRow(
                    category=category,
                    sf_id=alert.sf_id,
                    alert_id=alert.alert_id,
                    time=alert.time,
                    points=points,
                    counted=False,
                    reason="category already counted",
                )
            )
            continue
        counted.add(category)
        rows.append(
            ScoreRow(
                category=category,
                sf_id=alert.sf_id,
                alert_id=alert.alert_id,
                time=alert.time,
                points=points,
                counted=True,
                reason="counted",
            )
        )
    return rows


def _multiplier(hosts: tuple[str, ...], config: RiskConfig) -> tuple[float, tuple[str, ...]]:
    if not hosts:
        return config.multipliers[config.default_asset_class], ()
    classes = [
        config.hosts.get(host, config.default_asset_class) for host in hosts
    ]
    best = max(config.multipliers[asset] for asset in classes)
    named = tuple(
        host
        for host in hosts
        if host in config.hosts
        and config.multipliers[config.hosts[host]] == best
    )
    return best, named


def _band(score: int, forced: bool, config: RiskConfig) -> str:
    if forced or score >= config.band_critical:
        return "critical"
    if score >= config.band_high:
        return "high"
    if score >= config.band_medium:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _opens(incident: CorrelatedIncident, members: list[_Alert], config: RiskConfig) -> bool:
    if incident.final >= config.band_medium:
        return True
    return any(item.level >= config.open_level for item in members)


def _link_reasons(alerts: list[_Alert], config: RiskConfig) -> list[str]:
    hubs = _hub_keys(alerts, config.hub_user_limit)
    found: list[str] = []
    by_key: dict[tuple[str, str], list[_Alert]] = defaultdict(list)
    for alert in alerts:
        for key in alert.link_keys:
            if key not in hubs:
                by_key[key].append(alert)
    for key, members in sorted(by_key.items()):
        members.sort(key=lambda item: item.time)
        linked = False
        for index, left in enumerate(members):
            for right in members[index + 1 :]:
                if right.time - left.time > config.window:
                    break
                linked = True
                break
            if linked:
                break
        if not linked:
            continue
        kind, value = key
        if kind == "user":
            found.append(f"linked by user {value}")
        else:
            found.append(f"linked by source {value}")
    return found


def _new_id(alert_ids: tuple[str, ...]) -> str:
    digest = hashlib.sha256(",".join(sorted(alert_ids)).encode()).hexdigest()[:8]
    return f"INC-{digest}"


def _canonical_host(value: object, config: RiskConfig) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in config.ignored_user_values:
        return None
    for host in config.hosts:
        if host.lower() == text.lower():
            return host
    return text


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _as_int(value: object) -> int:
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _dig(document: object, *path: str) -> object:
    current = document
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current
