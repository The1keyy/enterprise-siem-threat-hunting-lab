"""Group Wazuh alerts into incidents and score them from risk_config.yml.

Pure functions. This module does not read the indexer or write SQLite.
SID rows are written by app.services.sid_map.
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
    host_proximity_minutes: int
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
    spray_min_distinct_users: int
    spray_timeframe_seconds: int

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)

    @property
    def host_window(self) -> timedelta:
        return timedelta(minutes=self.host_proximity_minutes)


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
    link_strength: str | None = None
    link_reason: str | None = None


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
class SidObservation:
    sid: str
    user: str
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

    def attach_singleton(self, item: str, target: str, limit: int | None) -> bool:
        """Move a lone alert into a component. Refuse when that would merge two groups."""

        if self.size_of(item) != 1:
            return False
        if self.find(item) == self.find(target):
            return False
        if limit is not None and self.size_of(target) + 1 > limit:
            return False
        self.union(item, target, None)
        return True


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
        host_proximity_minutes=int(raw["host_proximity_minutes"]),
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
        spray_min_distinct_users=int(raw.get("spray_min_distinct_users") or 3),
        spray_timeframe_seconds=int(raw.get("spray_timeframe_seconds") or 120),
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
    sid_map: dict[str, str] | None = None,
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
    resolved = _merged_sid_map(alerts, prior, sid_map, cfg)

    working: dict[str, _Alert] = {}
    for incident in open_incidents:
        for raw in incident.alerts:
            parsed = _parse_alert(raw, cfg, resolved)
            working.setdefault(parsed.alert_id, parsed)
    for raw in alerts:
        parsed = _parse_alert(raw, cfg, resolved)
        if parsed.alert_id in closed_ids:
            continue
        working.setdefault(parsed.alert_id, parsed)

    groups, weak = _group_alerts(list(working.values()), open_incidents, cfg)
    emitted: list[CorrelatedIncident] = []
    consumed: set[str] = set()
    for members in groups:
        member_ids = {item.alert_id for item in members}
        owners = [
            incident
            for incident in open_incidents
            if set(incident.alert_ids) & member_ids
        ]
        built = _build_incident(members, cfg, owners[0] if owners else None, weak)
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
        total += decay_points(incident.subtotal, incident.last_seen, now, cfg)
    return total


def decay_points(
    points: int,
    last_seen: datetime,
    now: datetime,
    config: RiskConfig | None = None,
) -> float:
    """Half-life of a counted subtotal. The asset multiplier is not applied."""

    cfg = config or load_risk_config()
    age_hours = (now - last_seen).total_seconds() / 3600
    return _decay(points, max(age_hours, 0.0), cfg.half_life_hours)


def _validate(config: RiskConfig) -> None:
    if config.band_medium >= config.band_high or config.band_high >= config.band_critical:
        raise ValueError("risk bands must increase: medium < high < critical")
    if (
        config.window_minutes <= 0
        or config.host_proximity_minutes <= 0
        or config.max_incident_alerts <= 0
    ):
        raise ValueError("windows and max_incident_alerts must be positive")
    if config.half_life_hours <= 0:
        raise ValueError("half_life_hours must be positive")
    if config.default_asset_class not in config.multipliers:
        raise ValueError("default_asset_class has no multiplier")
    for asset in config.hosts.values():
        if asset not in config.multipliers:
            raise ValueError(f"asset class {asset} has no multiplier")
    if not config.open_statuses:
        raise ValueError("open_statuses is empty")
    if config.spray_min_distinct_users < 2 or config.spray_timeframe_seconds <= 0:
        raise ValueError("spray confirmation settings must be positive")


def _decay(points: int, age_hours: float, half_life_hours: float) -> float:
    return points * (0.5 ** (age_hours / half_life_hours))


# VERIFY: these SID paths are not in scripts/validation/indexed_fields.txt or
# docs/detections/_ruleset-notes.md. Eventchannel decoders often keep EventData
# names and System/Security UserID. Confirm on a lab 4624 and a lab 4104
# before using them in a hunt. They are not hunt fields.
_SID_PATHS = (
    ("data", "win", "eventdata", "targetUserSid"),
    ("data", "win", "eventdata", "subjectUserSid"),
    ("data", "win", "system", "security", "userID"),
    ("data", "win", "eventdata", "userId"),
    ("data", "win", "eventdata", "userID"),
)
_SID_NAME_PAIRS = (
    ("targetUserSid", "targetUserName"),
    ("subjectUserSid", "subjectUserName"),
)


def normalize_sid(value: object, config: RiskConfig) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in config.ignored_user_values:
        return None
    if not text.upper().startswith("S-1-"):
        return None
    return text.upper()


def sid_observations(
    alerts: list[dict[str, Any]],
    config: RiskConfig | None = None,
) -> list[SidObservation]:
    """Pairs seen on the same alert. A later timestamp replaces an earlier one."""

    cfg = config or load_risk_config()
    found: dict[str, SidObservation] = {}
    for raw in alerts:
        timestamp = raw.get("timestamp")
        if not isinstance(timestamp, str):
            continue
        when = _parse_time(timestamp)
        eventdata = _dig(raw, "data", "win", "eventdata")
        if not isinstance(eventdata, dict):
            eventdata = {}
        paired: set[str] = set()
        for sid_key, name_key in _SID_NAME_PAIRS:
            sid = normalize_sid(eventdata.get(sid_key), cfg)
            user = normalize_user(eventdata.get(name_key), cfg)
            if sid and user:
                paired.add(sid)
                _keep_sid(found, sid, user, when)
        names = _named_users(raw, cfg)
        if len(names) == 1:
            user = next(iter(names))
            for sid in _sid_values(raw, cfg):
                if sid not in paired:
                    _keep_sid(found, sid, user, when)
    return list(found.values())


def _keep_sid(
    found: dict[str, SidObservation],
    sid: str,
    user: str,
    when: datetime,
) -> None:
    current = found.get(sid)
    if current is None or when >= current.last_seen:
        found[sid] = SidObservation(sid=sid, user=user, last_seen=when)


def _merged_sid_map(
    alerts: list[dict[str, Any]],
    prior: list[CorrelatedIncident],
    sid_map: dict[str, str] | None,
    config: RiskConfig,
) -> dict[str, str]:
    raw_alerts = list(alerts)
    for incident in prior:
        raw_alerts.extend(incident.alerts)
    merged = dict(sid_map or {})
    for observation in sid_observations(raw_alerts, config):
        merged[observation.sid] = observation.user
    return merged


def _named_users(raw: dict[str, Any], config: RiskConfig) -> set[str]:
    values = (
        _dig(raw, "data", "win", "eventdata", "targetUserName"),
        _dig(raw, "data", "win", "eventdata", "subjectUserName"),
        _dig(raw, "data", "srcuser"),
        _dig(raw, "data", "dstuser"),
        # VERIFY: Sysmon EventData User. Not in indexed_fields.txt.
        _dig(raw, "data", "win", "eventdata", "user"),
    )
    return {user for user in (normalize_user(value, config) for value in values) if user}


def _sid_values(raw: dict[str, Any], config: RiskConfig) -> list[str]:
    found: list[str] = []
    for path in _SID_PATHS:
        sid = normalize_sid(_dig(raw, *path), config)
        if sid and sid not in found:
            found.append(sid)
    return found


def _parse_alert(
    raw: dict[str, Any],
    config: RiskConfig,
    sid_map: dict[str, str] | None = None,
) -> _Alert:
    alert_id = raw.get("_id")
    if not isinstance(alert_id, str) or not alert_id:
        raise ValueError("alert is missing indexer _id")
    timestamp = raw.get("timestamp")
    if not isinstance(timestamp, str):
        raise ValueError(f"{alert_id} is missing timestamp")
    description = str(_dig(raw, "rule", "description") or "")
    match = _SF_ID.match(description.strip())
    sf_id = match.group(1) if match else None
    users = set(_named_users(raw, config))
    for sid in _sid_values(raw, config):
        resolved = normalize_user((sid_map or {}).get(sid), config)
        if resolved:
            users.add(resolved)
    users_frozen = frozenset(users)
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
    keys = frozenset(
        {("user", user) for user in users_frozen} | {("source", ip) for ip in source_ips}
    )
    return _Alert(
        alert_id=alert_id,
        time=_parse_time(timestamp),
        raw=raw,
        sf_id=sf_id,
        level=_as_int(_dig(raw, "rule", "level")),
        host=host,
        users=users_frozen,
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
) -> tuple[list[list[_Alert]], dict[str, str]]:
    if not alerts:
        return [], {}
    by_id = {item.alert_id: item for item in alerts}
    hubs = _hub_keys(alerts, config.hub_user_limit)
    union = _UnionFind()
    for alert_id in by_id:
        union.add(alert_id)
    preexisting = {alert_id for incident in open_incidents for alert_id in incident.alert_ids}
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

    weak = _attach_by_host(alerts, preexisting, union, config)
    grouped: dict[str, list[_Alert]] = defaultdict(list)
    for alert in alerts:
        grouped[union.find(alert.alert_id)].append(alert)
    groups = [
        sorted(members, key=lambda item: (item.time, item.alert_id))
        for members in grouped.values()
    ]
    return groups, weak


def _attach_by_host(
    alerts: list[_Alert],
    preexisting: set[str],
    union: _UnionFind,
    config: RiskConfig,
) -> dict[str, str]:
    """Attach an alert that has no user and no source IP to one open group.

    The alert must already be a singleton. Attaching it cannot union two groups.
    """

    weak: dict[str, str] = {}
    orphans = sorted(
        (alert for alert in alerts if not alert.link_keys and alert.host),
        key=lambda item: (item.time, item.alert_id),
    )
    for orphan in orphans:
        best: tuple[tuple[float, datetime, str, str], str] | None = None
        for other in alerts:
            if other.alert_id == orphan.alert_id or other.host != orphan.host:
                continue
            if not other.link_keys and other.alert_id not in preexisting:
                continue
            delta = abs(other.time - orphan.time)
            if delta > config.host_window:
                continue
            root = union.find(other.alert_id)
            if root == union.find(orphan.alert_id):
                continue
            rank = (delta.total_seconds(), other.time, other.alert_id, root)
            if best is None or rank < best[0]:
                best = (rank, root)
        if best is None:
            continue
        if union.attach_singleton(orphan.alert_id, best[1], config.max_incident_alerts):
            minutes = config.host_proximity_minutes
            weak[orphan.alert_id] = (
                f"linked by host {orphan.host} within {minutes} min (no user in event)"
            )
    return weak


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
    weak: dict[str, str] | None = None,
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
        timeline=tuple(_timeline_entry(item, ordered, config, weak or {}) for item in ordered),
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
        link_reasons=tuple(_link_reasons(ordered, config, weak or {})),
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


def _timeline_entry(
    alert: _Alert,
    members: list[_Alert],
    config: RiskConfig,
    weak: dict[str, str],
) -> TimelineEntry:
    strength, reason = _alert_link(alert, members, config, weak)
    return TimelineEntry(
        alert_id=alert.alert_id,
        time=alert.time,
        sf_id=alert.sf_id,
        host=alert.host,
        level=alert.level,
        rule_id=alert.rule_id,
        description=alert.description,
        link_strength=strength,
        link_reason=reason,
    )


def _alert_link(
    alert: _Alert,
    members: list[_Alert],
    config: RiskConfig,
    weak: dict[str, str],
) -> tuple[str | None, str | None]:
    weak_reason = weak.get(alert.alert_id)
    if weak_reason:
        return "weak", weak_reason
    reasons = _keys_shared_with(alert, members, config)
    if not reasons:
        return None, None
    user_reason = next((item for item in reasons if item.startswith("linked by user ")), None)
    return "strong", user_reason or reasons[0]


def _keys_shared_with(alert: _Alert, members: list[_Alert], config: RiskConfig) -> list[str]:
    hubs = _hub_keys(members, config.hub_user_limit)
    reasons: list[str] = []
    for key in sorted(alert.link_keys):
        if key in hubs:
            continue
        for other in members:
            if other.alert_id == alert.alert_id or key not in other.link_keys:
                continue
            if abs(other.time - alert.time) <= config.window:
                kind, value = key
                text = f"linked by user {value}" if kind == "user" else f"linked by source {value}"
                if text not in reasons:
                    reasons.append(text)
                break
    return reasons


def _link_reasons(
    alerts: list[_Alert],
    config: RiskConfig,
    weak: dict[str, str] | None = None,
) -> list[str]:
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
    for alert in alerts:
        reason = (weak or {}).get(alert.alert_id)
        if reason and reason not in found:
            found.append(reason)
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
