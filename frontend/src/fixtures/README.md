# Fixtures

DEMO DATA. Every fixture in this folder is fake sample content for the console.
It is not telemetry from the lab, and it is not a test result.

Files added here must start with a `DEMO DATA` comment. The UI shows the demo
banner whenever `VITE_DATA_MODE=demo`.

`overview.ts` is the SOC Overview fixture. Every number in it is synthetic.
`incidents.ts` is the incident queue fixture. Risk totals are computed from the
breakdown. They are not lab measurements.
`detections.ts` is detection metadata only. Every status is `NOT TESTED`.
Rule XML and Sigma text are not written. `hunts.ts` is ten saved-hunt drafts.
Queries are OpenSearch query-string drafts and are not lab results.
Entity, source, and health pages are derived from these incidents. They are
not a second telemetry set.
