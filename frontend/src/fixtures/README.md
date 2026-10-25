# Fixtures

DEMO DATA. Every fixture in this folder is fake sample content for the console.
It is not telemetry from the lab, and it is not a test result.

Files added here must start with a `DEMO DATA` comment. The UI shows the demo
banner whenever `VITE_DATA_MODE=demo`.

The shared copies are JSON files in `/fixtures` at the repo root. Each file has
a top-level `_notice` of `DEMO DATA — synthetic, not real telemetry`.
`overview.ts`, `incidents.ts`, `detections.ts`, and `hunts.ts` import those
files. They do not keep a second copy of the rows.
`detections.ts` is detection metadata only. Every status is `NOT TESTED`.
Rule XML and Sigma text are not written. `hunts.ts` is ten saved-hunt drafts.
Queries are OpenSearch query-string drafts and are not lab results.
Entity, source, and health pages are derived from these incidents. The matching
JSON files in `/fixtures` are that same derivation, exported for the API.
