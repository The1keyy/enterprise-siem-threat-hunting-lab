# Read-only Wazuh users

**REQUIRES LAB VALIDATION.** Do this on WAZUH01 after the all-in-one install. Do not run it on the Mac. Snapshot the VM first.

The console backend is the only process that should hold these passwords. They go in the Mac's gitignored `.env`, not in the frontend.

## Manager API user

**VERIFY (4.14.9)** the RBAC resource names, the default read role, and the exact API calls. The intended limit is read actions only: agents, manager status, manager info, and rules. No agent delete, no active response, no rule upload.

Expected shape, to confirm in the lab before relying on it:

1. On WAZUH01, authenticate to `https://127.0.0.1:55000` as an admin and create a user such as `sentinelforge-api-ro`.
2. Create or reuse a role whose policies allow only `agent:read`, `manager:read`, and `rules:read` (those action names are **VERIFY**).
3. Map the user to that role.
4. Put the username and password in `.env` as `WAZUH_API_USER` and `WAZUH_API_PASSWORD`.

A failed login must surface as an API error. The backend must not fall back to demo fixtures.

## Indexer user

**VERIFY (4.14.9)** the OpenSearch Security role and index-pattern syntax on the bundled indexer.

The intended limit is read on `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*` only. No cluster write, no index delete.

Expected shape:

1. Add an internal user such as `sentinelforge-indexer-ro`.
2. Give it a role with `read` on those two index patterns.
3. Map the user to the role.
4. Put the username and password in `.env` as `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASSWORD`.

## CA bundle on the Mac

Lab certificates are self-signed. Copy the indexer/manager root CA to the Mac:

`configs/wazuh/secrets/root-ca.pem`

That directory is gitignored (`configs/**/secrets/` and `*.pem`). Point `WAZUH_CA_BUNDLE` at the file. Leave `WAZUH_TLS_INSECURE=false`.

`WAZUH_TLS_INSECURE=true` is **LAB ONLY**. The API logs `LAB ONLY: TLS verification disabled` at startup when it is set. Turn it off once the CA file is in place.

**VERIFY (4.14.9)** the on-disk path of `root-ca.pem` on the Wazuh 4.14.9 all-in-one (commonly under the indexer certs directory). Do not commit the file.
