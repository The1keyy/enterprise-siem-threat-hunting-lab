"""Demo matcher for a hunt query_string.

This is a field lookup with AND, OR, parentheses, and * wildcards.
It is not an OpenSearch parser. luqum checks syntax in CI.
The same rules live in frontend/src/lib/huntQuery.ts.
"""

from __future__ import annotations

import re
from typing import Any


def event_matches_query(query: str, event: dict[str, Any]) -> bool:
    raw = event.get("raw")
    document = raw if isinstance(raw, dict) else {}
    text = query.strip()
    if not text:
        return False
    return _match_or(text, document)


def low_count_buckets(
    buckets: list[dict[str, Any]],
    max_doc_count: int,
) -> list[dict[str, Any]]:
    kept = [
        bucket
        for bucket in buckets
        if isinstance(bucket.get("count"), int) and bucket["count"] <= max_doc_count
    ]
    return sorted(kept, key=lambda bucket: (bucket["count"], str(bucket.get("key"))))


def demo_buckets(
    events: list[dict[str, Any]],
    field: str,
    *,
    size: int,
    max_doc_count: int,
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for event in events:
        for value in _event_values(event, field):
            counts[value] = counts.get(value, 0) + 1
    buckets = [{"key": key, "count": count} for key, count in counts.items()]
    return low_count_buckets(buckets, max_doc_count)[:size]


def events_in_buckets(
    events: list[dict[str, Any]],
    field: str,
    buckets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    keys = {str(bucket.get("key")) for bucket in buckets}
    return [
        event
        for event in events
        if any(value in keys for value in _event_values(event, field))
    ]


def _event_values(event: dict[str, Any], field: str) -> list[str]:
    raw = event.get("raw")
    document = raw if isinstance(raw, dict) else event
    return _values(document, field)


def _match_or(expr: str, document: dict[str, Any]) -> bool:
    expr = _strip_parens(expr.strip())
    parts = _split_top(expr, "OR")
    return any(_match_and(part, document) for part in parts if part.strip())


def _match_and(expr: str, document: dict[str, Any]) -> bool:
    expr = _strip_parens(expr.strip())
    parts = [part for part in _split_top(expr, "AND") if part.strip()]
    return bool(parts) and all(_match_term(part, document) for part in parts)


def _match_term(term: str, document: dict[str, Any]) -> bool:
    text = _strip_parens(term.strip())
    if ":" not in text:
        return False
    field, _, value = text.rpartition(":")
    field = field.strip()
    value = value.strip().strip('"').strip()
    if not field or not value:
        return False
    return any(_wildcard(value, item) for item in _values(document, field))


def _values(document: dict[str, Any], field: str) -> list[str]:
    current: list[Any] = [document]
    for part in field.split("."):
        found: list[Any] = []
        for item in current:
            if isinstance(item, dict) and part in item:
                found.append(item[part])
        current = found
    values: list[str] = []
    for item in current:
        if isinstance(item, list):
            values.extend(str(entry) for entry in item if not isinstance(entry, (dict, list)))
        elif item is not None and not isinstance(item, dict):
            values.append(str(item))
    return values


def _wildcard(pattern: str, value: str) -> bool:
    escaped = re.escape(pattern).replace(r"\*", ".*")
    return re.fullmatch(escaped, value, flags=re.IGNORECASE) is not None


def _strip_parens(text: str) -> str:
    while text.startswith("(") and text.endswith(")") and _balanced(text[1:-1]):
        text = text[1:-1].strip()
    return text


def _balanced(text: str) -> bool:
    depth = 0
    quote = False
    for char in text:
        if char == '"':
            quote = not quote
        elif quote:
            continue
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not quote


def _split_top(expr: str, keyword: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = False
    token = f" {keyword} "
    index = 0
    while index < len(expr):
        char = expr[index]
        if char == '"':
            quote = not quote
            buf.append(char)
            index += 1
            continue
        if not quote and char == "(":
            depth += 1
        elif not quote and char == ")":
            depth = max(0, depth - 1)
        if depth == 0 and not quote and expr[index : index + len(token)].upper() == token:
            parts.append("".join(buf))
            buf = []
            index += len(token)
            continue
        buf.append(char)
        index += 1
    parts.append("".join(buf))
    return parts
