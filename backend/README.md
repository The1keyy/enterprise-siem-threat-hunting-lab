# backend/

FastAPI service between the console and Wazuh.

## Responsibilities
- **Query Wazuh** using read-only users:
  - Manager API (`:55000`): agents, health, rules
  - Indexer (`:9200`): `wazuh-alerts-*`, `wazuh-archives-*`
- **Store what Wazuh doesn't** (SQLite): incidents, status, owners, notes, risk events, saved
  hunts, audit log.
- **Run correlation and explainable risk scoring.**
- **Keep Wazuh credentials server-side.** They are never sent to the browser.

**Status:** Not started (created in Step 7).
