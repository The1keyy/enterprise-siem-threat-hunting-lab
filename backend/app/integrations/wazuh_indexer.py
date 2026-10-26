"""Async client for the Wazuh indexer (OpenSearch).

VERIFY (4.14.9):
- Base URL https://<WAZUH_MANAGER_IP>:9200 with HTTP Basic auth
- Index patterns wazuh-alerts-4.x-* and wazuh-archives-4.x-*
- Alert time field is `timestamp` (not @timestamp)
- Terms aggregations do not need a `.keyword` suffix on these fields
- rule.groups values used below (authentication_failed, windows, sysmon, ...)
- GET /_cluster/health and GET /_nodes/stats/fs
- date_histogram fixed_interval and max.value_as_string
"""

import json
import re
from datetime import datetime, timedelta
from typing import Any

import httpx

from app.core.config import REPO_ROOT, Settings
from app.integrations.errors import (
    ArchivesNotEnabled,
    HuntQueryRejected,
    WazuhResponseError,
    WazuhUnavailable,
)
from app.integrations.tls import tls_verify

# VERIFY (4.14.9): pattern names on the all-in-one indexer.
ALERTS_INDEX = "wazuh-alerts-4.x-*"
ARCHIVES_INDEX = "wazuh-archives-4.x-*"

# Hunt query_string clauses may name only these fields. Values are passed as JSON,
# never concatenated into the request body. The file is the same list CI checks.
def load_allowed_hunt_fields() -> frozenset[str]:
    path = REPO_ROOT / "scripts" / "validation" / "indexed_fields.txt"
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text:
            names.add(text)
    return frozenset(names)


ALLOWED_HUNT_FIELDS = load_allowed_hunt_fields()


def resolve_hunt_index(name: str) -> str:
    """Map a hunt's logical index onto the 4.x pattern this client queries.

    VERIFY (4.14.9): the indexed names are wazuh-alerts-4.x-* and
    wazuh-archives-4.x-*, not the unsuffixed patterns written in the YAML.
    """

    if name in {"wazuh-archives-*", ARCHIVES_INDEX}:
        return ARCHIVES_INDEX
    if name in {"wazuh-alerts-*", ALERTS_INDEX}:
        return ALERTS_INDEX
    raise HuntQueryRejected(f"Unknown hunt index: {name}")

# VERIFY (4.14.9): group names Wazuh assigns to these sources.
SOURCE_FILTERS: dict[str, dict[str, Any]] = {
    "windows-security": {
        "bool": {
            "filter": [{"term": {"rule.groups": "windows"}}],
            "must_not": [
                {"term": {"rule.groups": "sysmon"}},
                {"term": {"rule.groups": "windows_powershell"}},
                {"term": {"agent.name": "DC01"}},
            ],
        }
    },
    "sysmon": {"term": {"rule.groups": "sysmon"}},
    "powershell": {"term": {"rule.groups": "windows_powershell"}},
    "ad-security": {
        "bool": {
            "filter": [
                {"term": {"agent.name": "DC01"}},
                {"term": {"rule.groups": "windows"}},
            ]
        }
    },
    "linux-auth": {"term": {"rule.groups": "sshd"}},
    "auditd": {"term": {"rule.groups": "audit"}},
    "suricata": {"term": {"rule.groups": "suricata"}},
}

_MAX_PAGE = 500
_FIELD_RE = re.compile(r"(?<![\w./])([A-Za-z_][\w.]*)\s*:(?!/)")
_QUOTED_RE = re.compile(r'"[^"]*"')


def validate_hunt_query(query: str, start: str, end: str, *, max_days: int = 7) -> None:
    """Reject over-wide windows and field names outside the allow-list."""

    text = query.strip()
    if not text:
        raise HuntQueryRejected("Hunt query is empty")
    if "{" in text or "}" in text:
        raise HuntQueryRejected("Hunt query must be a query string, not JSON")
    start_at = _parse_time(start)
    end_at = _parse_time(end)
    if start_at is None or end_at is None:
        raise HuntQueryRejected("Hunt time window is required and must be at most 7 days")
    if end_at < start_at:
        raise HuntQueryRejected("Hunt time window ends before it starts")
    if end_at - start_at > timedelta(days=max_days):
        raise HuntQueryRejected("Hunt time window exceeds 7 days")
    bare = _QUOTED_RE.sub(" ", text)
    fields = set(_FIELD_RE.findall(bare))
    rejected = sorted(field for field in fields if field not in ALLOWED_HUNT_FIELDS)
    if rejected:
        names = ", ".join(rejected)
        raise HuntQueryRejected(f"Hunt query uses disallowed fields: {names}")


def _parse_time(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if len(text) == 10:
        text = f"{text}T00:00:00+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def build_alert_search(
    *,
    start: str | None,
    end: str | None,
    hosts: list[str] | None,
    users: list[str] | None,
    rule_ids: list[str] | None,
    min_level: int | None,
    size: int,
    search_after: list[Any] | None,
    sort_desc: bool,
) -> dict[str, Any]:
    """Build an alerts search body. There is no `from` offset."""

    filters: list[dict[str, Any]] = []
    if start or end:
        bounds: dict[str, str] = {}
        if start:
            bounds["gte"] = start
        if end:
            bounds["lte"] = end
        filters.append({"range": {"timestamp": bounds}})
    if hosts:
        filters.append({"terms": {"agent.name": hosts}})
    if users:
        filters.append({"terms": {"data.win.eventdata.targetUserName": users}})
    if rule_ids:
        filters.append({"terms": {"rule.id": rule_ids}})
    if min_level is not None:
        filters.append({"range": {"rule.level": {"gte": min_level}}})
    direction = "desc" if sort_desc else "asc"
    body: dict[str, Any] = {
        "size": size,
        "sort": [{"timestamp": direction}, {"_id": direction}],
        "query": {"bool": {"filter": filters}},
    }
    if search_after:
        body["search_after"] = search_after
    return body


def _severity_ranges() -> dict[str, Any]:
    # Bounds match config.wazuh_level_severity: 0–6, 7–11, 12–14, 15+.
    return {
        "range": {
            "field": "rule.level",
            "ranges": [
                {"key": "low", "from": 0, "to": 7},
                {"key": "medium", "from": 7, "to": 12},
                {"key": "high", "from": 12, "to": 15},
                {"key": "critical", "from": 15},
            ],
        }
    }


def build_overview_aggs(start: str, end: str) -> dict[str, Any]:
    histogram = {
        "date_histogram": {"field": "timestamp", "fixed_interval": "1h"},
        "aggs": {"by_severity": _severity_ranges()},
    }
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": start, "lte": end}}}]}},
        "aggs": {
            "over_time": histogram,
            "by_severity": _severity_ranges(),
            "by_tactic": {"terms": {"field": "rule.mitre.tactic", "size": 20}},
            "auth_failures": {
                # VERIFY (4.14.9): authentication_failed group name.
                "filter": {"term": {"rule.groups": "authentication_failed"}},
                "aggs": {
                    "over_time": {
                        "date_histogram": {"field": "timestamp", "fixed_interval": "1h"}
                    }
                },
            },
            "top_srcip": {"terms": {"field": "data.srcip", "size": 5}},
            "top_users": {"terms": {"field": "data.win.eventdata.targetUserName", "size": 5}},
            "top_hosts": {"terms": {"field": "agent.name", "size": 5}},
        },
    }


def build_archive_search(
    query: str,
    start: str,
    end: str,
    *,
    host: str = "",
    user: str = "",
    source: str = "",
    aggregation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_hunt_query(query, start, end)
    filters: list[dict[str, Any]] = [
        {"range": {"timestamp": {"gte": start, "lte": end}}},
        {
            "query_string": {
                "query": query,
                "fields": sorted(ALLOWED_HUNT_FIELDS),
                "lenient": False,
            }
        },
    ]
    if host:
        filters.append({"term": {"agent.name": host}})
    if user:
        filters.append({"term": {"data.win.eventdata.targetUserName": user}})
    if source:
        if source not in SOURCE_FILTERS:
            raise HuntQueryRejected(f"Unknown hunt source filter: {source}")
        filters.append(SOURCE_FILTERS[source])
    body: dict[str, Any] = {
        "size": 200,
        "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
        "query": {"bool": {"filter": filters}},
    }
    if aggregation:
        field = str(aggregation.get("field") or "")
        if field not in ALLOWED_HUNT_FIELDS:
            raise HuntQueryRejected(f"Hunt aggregation uses a disallowed field: {field}")
        size = aggregation.get("size")
        if type(size) is not int or not 1 <= size <= 100:
            raise HuntQueryRejected("Hunt aggregation size must be 1..100")
        body["aggs"] = {"hunt_terms": {"terms": {"field": field, "size": size}}}
    return body


class WazuhIndexerClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.wazuh_indexer_url.rstrip("/"),
            timeout=settings.wazuh_timeout_seconds,
            verify=tls_verify(settings),
            transport=transport,
            trust_env=False,
            auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(self, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if "from" in body:
            raise WazuhResponseError("Indexer search must not use from offsets")
        try:
            response = await self._client.post(path, json=body)
        except httpx.HTTPError as exc:
            raise WazuhUnavailable("Wazuh indexer unreachable") from exc
        return self._read(response)

    async def _get(self, path: str) -> tuple[int, dict[str, Any]]:
        try:
            response = await self._client.get(path)
        except httpx.HTTPError as exc:
            raise WazuhUnavailable("Wazuh indexer unreachable") from exc
        return self._read(response)

    def _read(self, response: httpx.Response) -> tuple[int, dict[str, Any]]:
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise WazuhResponseError(
                f"Wazuh indexer returned HTTP {response.status_code} without JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise WazuhResponseError("Wazuh indexer response was not an object")
        return response.status_code, payload

    async def search_alerts(
        self,
        *,
        start: str | None = None,
        end: str | None = None,
        hosts: list[str] | None = None,
        users: list[str] | None = None,
        rule_ids: list[str] | None = None,
        min_level: int | None = None,
        size: int = 100,
        search_after: list[Any] | None = None,
        sort_desc: bool = False,
    ) -> dict[str, Any]:
        page = min(max(size, 1), _MAX_PAGE)
        body = build_alert_search(
            start=start,
            end=end,
            hosts=hosts,
            users=users,
            rule_ids=rule_ids,
            min_level=min_level,
            size=page,
            search_after=search_after,
            sort_desc=sort_desc,
        )
        status, payload = await self._post(f"/{ALERTS_INDEX}/_search", body)
        self._raise_for_status(status, payload)
        return _parse_hits(payload, page)

    async def aggregations(self, start: str, end: str) -> dict[str, Any]:
        status, payload = await self._post(
            f"/{ALERTS_INDEX}/_search",
            build_overview_aggs(start, end),
        )
        self._raise_for_status(status, payload)
        return parse_aggregations(payload)

    async def source_stats(self, start: str, end: str) -> dict[str, Any]:
        filters = {key: {"bool": {"filter": [value]}} for key, value in SOURCE_FILTERS.items()}
        body = {
            "size": 0,
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": start, "lte": end}}}]}},
            "aggs": {
                "sources": {
                    "filters": {"filters": filters},
                    "aggs": {
                        "last": {"max": {"field": "timestamp"}},
                        "hosts": {"terms": {"field": "agent.name", "size": 20}},
                        "volume": {
                            "date_histogram": {"field": "timestamp", "fixed_interval": "1h"}
                        },
                    },
                }
            },
        }
        status, payload = await self._post(f"/{ALERTS_INDEX}/_search", body)
        self._raise_for_status(status, payload)
        return parse_source_stats(payload)

    async def rule_activity(self, rule_ids: list[str], start: str, end: str) -> dict[str, Any]:
        if not rule_ids:
            return {}
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"timestamp": {"gte": start, "lte": end}}},
                        {"terms": {"rule.id": rule_ids}},
                    ]
                }
            },
            "aggs": {
                "rules": {
                    "terms": {"field": "rule.id", "size": max(len(rule_ids), 1)},
                    "aggs": {"last": {"max": {"field": "timestamp"}}},
                }
            },
        }
        status, payload = await self._post(f"/{ALERTS_INDEX}/_search", body)
        self._raise_for_status(status, payload)
        return parse_rule_activity(payload)

    async def entity_activity(self, start: str, end: str) -> dict[str, Any]:
        body = {
            "size": 0,
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": start, "lte": end}}}]}},
            "aggs": {
                "hosts": {
                    "terms": {"field": "agent.name", "size": 100},
                    "aggs": {"last": {"max": {"field": "timestamp"}}},
                },
                "users": {
                    "terms": {"field": "data.win.eventdata.targetUserName", "size": 100},
                    "aggs": {"last": {"max": {"field": "timestamp"}}},
                },
            },
        }
        status, payload = await self._post(f"/{ALERTS_INDEX}/_search", body)
        self._raise_for_status(status, payload)
        aggs = payload.get("aggregations")
        if not isinstance(aggs, dict):
            raise WazuhResponseError("Indexer response missing aggregations")
        return {
            "hosts": _terms_with_last(aggs.get("hosts")),
            "users": _terms_with_last(aggs.get("users")),
        }

    async def search_archives(
        self,
        query: str,
        start: str,
        end: str,
        *,
        host: str = "",
        user: str = "",
        source: str = "",
        index: str = ARCHIVES_INDEX,
        aggregation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = build_archive_search(
            query,
            start,
            end,
            host=host,
            user=user,
            source=source,
            aggregation=aggregation,
        )
        status, payload = await self._post(f"/{index}/_search", body)
        if _index_missing(status, payload):
            if index == ARCHIVES_INDEX:
                raise ArchivesNotEnabled()
            raise WazuhResponseError("Wazuh alerts index was not found")
        self._raise_for_status(status, payload)
        parsed = _parse_hits(payload, body["size"])
        parsed["buckets"] = _hunt_buckets(payload) if aggregation else []
        return parsed

    async def health(self) -> dict[str, Any]:
        # VERIFY (4.14.9): cluster health and node filesystem stats paths.
        status, cluster = await self._get("/_cluster/health")
        self._raise_for_status(status, cluster)
        fs_status, nodes = await self._get("/_nodes/stats/fs")
        self._raise_for_status(fs_status, nodes)
        return {
            "status": cluster.get("status") if isinstance(cluster.get("status"), str) else None,
            "nodes": _disk_nodes(nodes),
        }

    def _raise_for_status(self, status: int, payload: dict[str, Any]) -> None:
        if _index_missing(status, payload):
            raise WazuhResponseError("Wazuh alerts index was not found")
        if status >= 500:
            raise WazuhUnavailable(f"Wazuh indexer returned HTTP {status}")
        if status >= 400:
            raise WazuhResponseError(f"Wazuh indexer returned HTTP {status}")


def _index_missing(status: int, payload: dict[str, Any]) -> bool:
    error = payload.get("error")
    error_type = error.get("type") if isinstance(error, dict) else None
    return status == 404 or error_type == "index_not_found_exception"


def _parse_hits(payload: dict[str, Any], size: int) -> dict[str, Any]:
    hits_block = payload.get("hits")
    if not isinstance(hits_block, dict) or not isinstance(hits_block.get("hits"), list):
        raise WazuhResponseError("Indexer response missing hits")
    rows = hits_block["hits"]
    events: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("_source"), dict):
            events.append(row["_source"])
    cursor = None
    if len(rows) >= size and rows and isinstance(rows[-1], dict):
        sort = rows[-1].get("sort")
        if isinstance(sort, list):
            cursor = sort
    return {"events": events, "search_after": cursor, "total": _total(hits_block.get("total"))}


def _total(value: Any) -> int | None:
    if isinstance(value, dict) and isinstance(value.get("value"), int):
        return value["value"]
    if isinstance(value, int):
        return value
    return None


def _bucket_time(bucket: dict[str, Any]) -> str | None:
    stamp = bucket.get("key_as_string")
    return stamp if isinstance(stamp, str) else None


def _max_time(agg: Any) -> str | None:
    if not isinstance(agg, dict):
        return None
    stamp = agg.get("value_as_string")
    if isinstance(stamp, str):
        return stamp
    return None


def _hunt_buckets(payload: dict[str, Any]) -> list[dict[str, Any]]:
    aggs = payload.get("aggregations")
    if not isinstance(aggs, dict):
        raise WazuhResponseError("Indexer response missing aggregations")
    return [{"key": row["label"], "count": row["count"]} for row in _terms(aggs.get("hunt_terms"))]


def _terms(agg: Any) -> list[dict[str, Any]]:
    if not isinstance(agg, dict) or not isinstance(agg.get("buckets"), list):
        return []
    rows: list[dict[str, Any]] = []
    for bucket in agg["buckets"]:
        if isinstance(bucket, dict) and isinstance(bucket.get("key"), str):
            count = bucket.get("doc_count")
            rows.append({"label": bucket["key"], "count": count if isinstance(count, int) else 0})
    return rows


def _terms_with_last(agg: Any) -> list[dict[str, Any]]:
    if not isinstance(agg, dict) or not isinstance(agg.get("buckets"), list):
        return []
    rows: list[dict[str, Any]] = []
    for bucket in agg["buckets"]:
        if not isinstance(bucket, dict) or not isinstance(bucket.get("key"), str):
            continue
        count = bucket.get("doc_count")
        rows.append(
            {
                "name": bucket["key"],
                "count": count if isinstance(count, int) else 0,
                "last": _max_time(bucket.get("last")),
            }
        )
    return rows


def parse_aggregations(payload: dict[str, Any]) -> dict[str, Any]:
    aggs = payload.get("aggregations")
    if not isinstance(aggs, dict):
        raise WazuhResponseError("Indexer response missing aggregations")
    over_time = []
    over = aggs.get("over_time")
    if isinstance(over, dict):
        for bucket in over.get("buckets") or []:
            if not isinstance(bucket, dict):
                continue
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            severity = bucket.get("by_severity")
            if isinstance(severity, dict):
                for item in severity.get("buckets") or []:
                    if isinstance(item, dict) and item.get("key") in counts:
                        doc_count = item.get("doc_count")
                        counts[item["key"]] = doc_count if isinstance(doc_count, int) else 0
            over_time.append(
                {
                    "bucketStart": _bucket_time(bucket),
                    "critical": counts["critical"],
                    "high": counts["high"],
                    "medium": counts["medium"],
                    "low": counts["low"],
                }
            )
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    severity_agg = aggs.get("by_severity")
    if isinstance(severity_agg, dict):
        for item in severity_agg.get("buckets") or []:
            if isinstance(item, dict) and item.get("key") in by_severity:
                doc_count = item.get("doc_count")
                by_severity[item["key"]] = doc_count if isinstance(doc_count, int) else 0
    auth = []
    auth_agg = aggs.get("auth_failures")
    if isinstance(auth_agg, dict) and isinstance(auth_agg.get("over_time"), dict):
        for bucket in auth_agg["over_time"].get("buckets") or []:
            if isinstance(bucket, dict):
                doc_count = bucket.get("doc_count")
                auth.append(
                    {
                        "bucketStart": _bucket_time(bucket),
                        "count": doc_count if isinstance(doc_count, int) else 0,
                    }
                )
    hits = payload.get("hits")
    total = _total(hits.get("total")) if isinstance(hits, dict) else None
    return {
        "events_total": total,
        "alerts_over_time": over_time,
        "by_severity": by_severity,
        "by_tactic": _terms(aggs.get("by_tactic")),
        "auth_failures": auth,
        "top_srcip": _terms(aggs.get("top_srcip")),
        "top_users": _terms(aggs.get("top_users")),
        "top_hosts": _terms(aggs.get("top_hosts")),
    }


def parse_source_stats(payload: dict[str, Any]) -> dict[str, Any]:
    aggs = payload.get("aggregations")
    if not isinstance(aggs, dict) or not isinstance(aggs.get("sources"), dict):
        raise WazuhResponseError("Indexer response missing source aggregations")
    buckets = aggs["sources"].get("buckets")
    if not isinstance(buckets, dict):
        raise WazuhResponseError("Indexer source aggregation was not a keyed filter")
    parsed: dict[str, Any] = {}
    for key, bucket in buckets.items():
        if not isinstance(bucket, dict):
            continue
        volume = []
        histogram = bucket.get("volume")
        if isinstance(histogram, dict):
            for item in histogram.get("buckets") or []:
                if isinstance(item, dict):
                    doc_count = item.get("doc_count")
                    volume.append(
                        {
                            "bucketStart": _bucket_time(item),
                            "count": doc_count if isinstance(doc_count, int) else 0,
                        }
                    )
        hosts = [
            row["label"]
            for row in _terms(bucket.get("hosts"))
        ]
        doc_count = bucket.get("doc_count")
        parsed[key] = {
            "count": doc_count if isinstance(doc_count, int) else 0,
            "last": _max_time(bucket.get("last")),
            "hosts": hosts,
            "volume": volume,
        }
    return parsed


def parse_rule_activity(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    aggs = payload.get("aggregations")
    if not isinstance(aggs, dict):
        raise WazuhResponseError("Indexer response missing aggregations")
    found: dict[str, dict[str, Any]] = {}
    for row in _terms_with_last(aggs.get("rules")):
        found[row["name"]] = {"count": row["count"], "last": row["last"]}
    return found


def _disk_nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = payload.get("nodes")
    if not isinstance(nodes, dict):
        return []
    rows: list[dict[str, Any]] = []
    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        filesystem = node.get("fs") if isinstance(node.get("fs"), dict) else {}
        total = filesystem.get("total") if isinstance(filesystem.get("total"), dict) else {}
        total_bytes = total.get("total_in_bytes") if isinstance(total, dict) else None
        available = total.get("available_in_bytes") if isinstance(total, dict) else None
        percent = None
        if isinstance(total_bytes, int) and isinstance(available, int) and total_bytes > 0:
            percent = round((total_bytes - available) * 100 / total_bytes, 1)
        name = node.get("name")
        rows.append(
            {
                "name": name if isinstance(name, str) else None,
                "disk_used_percent": percent,
            }
        )
    return rows
