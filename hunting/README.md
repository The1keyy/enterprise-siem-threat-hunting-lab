# hunting/

One YAML file per saved hunt. The API loads these files in demo mode and in live mode.
`fixtures/hunts.json` is generated from them so the demo page shows the same text.

```bash
backend/.venv/bin/python scripts/validation/build_hunt_fixtures.py
```

A hunt is for what the related SF detection does not catch: a longer window, no
frequency threshold, or a low-count terms aggregation. `differs_from_detections`
says how. Rare and first-seen hunts set `aggregation`. A query string cannot
express a low count. The backend keeps buckets at or below `max_doc_count`.

Field names must be listed in `scripts/validation/indexed_fields.txt`. CI parses
each query with luqum. That check is syntax and field names. It does not prove
the hunt returns the right events. That waits for a lab run. Every hunt here is
`NOT TESTED`.

`data_source.index` is `alerts` or `archives`. The patterns those keys use are
`ALERTS_INDEX` and `ARCHIVES_INDEX` in `backend/app/core/config.py`. VERIFY
those defaults on WAZUH01. Leading `*` wildcards in a query string are allowed
by OpenSearch by default. VERIFY that too.

**Status:** 10 hunts, all `NOT TESTED`.
