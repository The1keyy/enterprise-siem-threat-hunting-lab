#!/usr/bin/env bash
# Run on: WAZUH01
# Requires: root. Read-only. Does not restart services or copy rules.
# Status: SYNTAX VALID after shellcheck. Not run on WAZUH01.
# Set WAZUH_API_USER, WAZUH_API_PASSWORD, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD.
# Set WAZUH_API_CA if the default CA path is wrong.

set -euo pipefail

log_dir=/var/log/sentinelforge
log_file=$log_dir/wazuh01-checks.log
# VERIFY (4.14.9): API port 55000, indexer port 9200, and this CA path.
api_url=https://127.0.0.1:55000
indexer_url=https://127.0.0.1:9200
api_ca=${WAZUH_API_CA:-/etc/filebeat/certs/root-ca.pem}
fail=0

log_line() {
  mkdir -p "$log_dir"
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$log_file"
}

check() {
  local result=$1
  local name=$2
  local detail=$3
  log_line "VERIFY $result $name $detail"
  if [[ "$result" == FAIL ]]; then
    fail=1
  fi
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root on WAZUH01." >&2
  exit 1
fi

for unit in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
  if systemctl is-active --quiet "$unit"; then
    check PASS "service $unit" active
  else
    check FAIL "service $unit" "$(systemctl is-active "$unit" || true)"
  fi
done

disk_line=$(df -P / | awk 'NR==2 {print}')
disk_use=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')
if [[ "$disk_use" -ge 85 ]]; then
  check FAIL disk "$disk_line"
else
  check PASS disk "$disk_line"
fi

if [[ -x /var/ossec/bin/agent_control ]]; then
  if agent_list=$(/var/ossec/bin/agent_control -l); then
    check PASS agents "$agent_list"
  else
    check FAIL agents "agent_control -l failed"
  fi
else
  check FAIL agents "missing /var/ossec/bin/agent_control. VERIFY the 4.14.9 binary name."
fi

if [[ ! -f "$api_ca" ]]; then
  check FAIL ca "not found at $api_ca"
elif [[ -z "${WAZUH_INDEXER_USER:-}" || -z "${WAZUH_INDEXER_PASSWORD:-}" ]]; then
  check FAIL archives-index "set WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD"
else
  archives=$(curl --silent --show-error --cacert "$api_ca" --user "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}" \
    "${indexer_url}/_cat/indices/wazuh-archives-*?h=index" || true)
  if [[ -n "${archives//[[:space:]]/}" ]]; then
    check PASS archives-index "$archives"
  else
    check FAIL archives-index "no wazuh-archives-* index"
  fi
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
rules_dir=$root/detections/wazuh/rules
if [[ -z "${WAZUH_API_USER:-}" || -z "${WAZUH_API_PASSWORD:-}" ]]; then
  check FAIL rule-count "set WAZUH_API_USER and WAZUH_API_PASSWORD"
elif [[ ! -f "$api_ca" ]]; then
  check FAIL rule-count "CA missing"
elif ! WAZUH_API_URL="$api_url" WAZUH_API_CA="$api_ca" python3 - "$rules_dir" <<'PY'
import base64
import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

rules_dir = Path(sys.argv[1])
paths = sorted(rules_dir.glob("sentinelforge_*.xml"))
if not paths:
    print(f"No rules in {rules_dir}", file=sys.stderr)
    sys.exit(1)

def request(method, path, bearer):
    headers = {}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    else:
        user = os.environ["WAZUH_API_USER"]
        password = os.environ["WAZUH_API_PASSWORD"]
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers["Authorization"] = "Basic " + token
    url = os.environ["WAZUH_API_URL"] + path
    req = urllib.request.Request(url, method=method, headers=headers)
    import ssl
    context = ssl.create_default_context(cafile=os.environ["WAZUH_API_CA"])
    try:
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        print(exc.read().decode(errors="replace"), file=sys.stderr)
        sys.exit(1)

def xml_count(path):
    text = path.read_text(encoding="utf-8")
    root = ET.fromstring(f"<sentinelforge-root>{text}</sentinelforge-root>")
    return sum(1 for rule in root.iter("rule") if rule.get("id"))

def api_count(bearer, filename):
    offset = 0
    limit = 500
    seen = 0
    total = None
    while True:
        path = f"/rules?filename={quote(filename)}&limit={limit}&offset={offset}"
        body = request("GET", path, bearer)
        data = body.get("data")
        if not isinstance(data, dict):
            print("missing data", file=sys.stderr)
            sys.exit(1)
        items = data.get("affected_items")
        if not isinstance(items, list):
            print("missing affected_items", file=sys.stderr)
            sys.exit(1)
        if total is None:
            total = data.get("total_affected_items")
            if not isinstance(total, int):
                print("missing total_affected_items", file=sys.stderr)
                sys.exit(1)
        seen += len(items)
        if seen >= total or len(items) < limit:
            break
        offset += limit
    if seen != total:
        print(f"{filename}: listed {seen} total {total}", file=sys.stderr)
        sys.exit(1)
    return total

auth = request("POST", "/security/user/authenticate", None)
token = ((auth or {}).get("data") or {}).get("token")
if not isinstance(token, str) or not token:
    print("no data.token", file=sys.stderr)
    sys.exit(1)
xml_total = 0
api_total = 0
ok = True
for path in paths:
    xml_n = xml_count(path)
    api_n = api_count(token, path.name)
    xml_total += xml_n
    api_total += api_n
    print(f"{path.name} xml={xml_n} api={api_n}")
    if xml_n != api_n:
        ok = False
print(f"loaded {xml_total} = {api_total}")
if not ok or xml_total != api_total:
    sys.exit(1)
PY
then
  check FAIL rule-count "API count did not match the XML"
else
  check PASS rule-count "loaded counts match"
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
