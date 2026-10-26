#!/usr/bin/env python3
"""Build scripts/validation/attack_techniques.json from MITRE ATT&CK STIX.

The validator reads the generated file and does not download anything.
Run this only when the pinned ATT&CK version changes.

Source (ATT&CK v20.0, tag v20.0, published 2026-10-13):
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.0/enterprise-attack/enterprise-attack.json
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.request
from pathlib import Path

ATTACK_VERSION = "20.0"
SOURCE_TAG = "v20.0"
SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "v20.0/enterprise-attack/enterprise-attack.json"
)
SOURCE_REPO = "https://github.com/mitre-attack/attack-stix-data"
GENERATED_ON = "2026-10-26"
OUT = Path(__file__).resolve().parent / "attack_techniques.json"


def main() -> int:
    print(f"downloading {SOURCE_URL}")
    bundle = json.loads(_fetch(SOURCE_URL))
    techniques: dict[str, dict[str, object]] = {}
    collection_version = None
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            collection_version = obj.get("x_mitre_version")
            continue
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = _external_id(obj)
        if technique_id is None:
            continue
        techniques[technique_id] = {
            "name": obj.get("name") or technique_id,
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
        }
    if collection_version != ATTACK_VERSION:
        print(
            f"error: collection version is {collection_version!r}, expected {ATTACK_VERSION}",
            file=sys.stderr,
        )
        return 1
    document = {
        "attack_version": ATTACK_VERSION,
        "source_tag": SOURCE_TAG,
        "source_repo": SOURCE_REPO,
        "source_url": SOURCE_URL,
        "generated_on": GENERATED_ON,
        "techniques": dict(sorted(techniques.items())),
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    revoked = sum(1 for item in techniques.values() if item["revoked"])
    deprecated = sum(1 for item in techniques.values() if item["deprecated"])
    print(f"wrote {OUT.name}: {len(techniques)} techniques, {revoked} revoked, {deprecated} deprecated")
    return 0


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") != "mitre-attack":
            continue
        value = ref.get("external_id")
        if isinstance(value, str) and value.startswith("T"):
            return value
    return None


def _fetch(url: str) -> bytes:
    context = ssl.create_default_context()
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    request = urllib.request.Request(url, headers={"User-Agent": "sentinelforge"})
    with urllib.request.urlopen(request, context=context, timeout=120) as response:
        return response.read()


if __name__ == "__main__":
    sys.exit(main())
