#!/usr/bin/env bash
# Run on: WAZUH01 (or from the Mac with --ssh user@host)
# Requires: root on WAZUH01, python3, curl, systemctl
# Status: SYNTAX VALID after shellcheck. Not run on a manager.
# Copies detections/wazuh/rules/sentinelforge_*.xml and any decoder XML into
# /var/ossec/etc/. Owner wazuh:wazuh is VERIFY on the 4.14.9 package.
# analysisd -t must pass before wazuh-manager restarts. A failed test or a
# rule-count mismatch restores the backup.

set -euo pipefail
shopt -s nullglob

dest_rules=/var/ossec/etc/rules
dest_decoders=/var/ossec/etc/decoders
# VERIFY (4.14.9): API on 127.0.0.1:55000 and this CA path on the all-in-one.
api_url=https://127.0.0.1:55000
api_ca=${WAZUH_API_CA:-/etc/filebeat/certs/root-ca.pem}

usage() {
  echo "Usage: deploy_rules.sh [--ssh user@host]" >&2
  echo "On WAZUH01, run as root. From the Mac, --ssh copies the files and runs there." >&2
  echo "Set WAZUH_API_USER and WAZUH_API_PASSWORD, or the script prompts." >&2
  echo "Set WAZUH_API_CA if the default CA path is wrong." >&2
}

restore_dir() {
  local backup_dir=$1
  local dest_dir=$2
  local base
  local item
  if [[ -f "$backup_dir/added.list" ]]; then
    while IFS= read -r base; do
      [[ -n "$base" ]] || continue
      rm -f "$dest_dir/$base"
    done < "$backup_dir/added.list"
  fi
  for item in "$backup_dir"/*; do
    [[ -f "$item" ]] || continue
    base=$(basename "$item")
    [[ "$base" == "added.list" ]] && continue
    cp -a "$item" "$dest_dir/$base"
  done
}

restore_all() {
  local backup=$1
  restore_dir "$backup/rules" "$dest_rules"
  restore_dir "$backup/decoders" "$dest_decoders"
}

copy_one() {
  local src=$1
  local dest_dir=$2
  local backup_dir=$3
  local base
  base=$(basename "$src")
  if [[ -f "$dest_dir/$base" ]]; then
    cp -a "$dest_dir/$base" "$backup_dir/$base"
  else
    printf '%s\n' "$base" >> "$backup_dir/added.list"
  fi
  # VERIFY (4.14.9): the package user and group are both wazuh, mode 0640.
  install -o wazuh -g wazuh -m 0640 "$src" "$dest_dir/$base"
}

wait_for_api() {
  local code
  for _ in $(seq 1 30); do
    code=$(curl --silent --output /dev/null --write-out '%{http_code}' --cacert "$api_ca" "$api_url/" || true)
    if [[ -n "$code" && "$code" != "000" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "Manager API did not answer at $api_url" >&2
  return 1
}

count_rules() {
  local rules_dir=$1
  local api_user=$2
  local api_password=$3
  WAZUH_API_USER="$api_user" \
    WAZUH_API_PASSWORD="$api_password" \
    WAZUH_API_CA="$api_ca" \
    WAZUH_API_URL="$api_url" \
    python3 - "$rules_dir" <<'PY'
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

def xml_count(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    root = ET.fromstring(f"<sentinelforge-root>{text}</sentinelforge-root>")
    return sum(1 for rule in root.iter("rule") if rule.get("id"))

def request(method: str, path: str, bearer: str | None) -> dict:
    headers = {}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    else:
        user = os.environ["WAZUH_API_USER"]
        password = os.environ["WAZUH_API_PASSWORD"]
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    url = os.environ["WAZUH_API_URL"] + path
    req = urllib.request.Request(url, method=method, headers=headers)
    context = ssl_context()
    try:
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            body = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        print(f"{method} {path} HTTP {exc.code}: {detail}", file=sys.stderr)
        sys.exit(1)
    return body

def ssl_context():
    import ssl
    return ssl.create_default_context(cafile=os.environ["WAZUH_API_CA"])

def api_count(bearer: str, filename: str) -> int:
    # VERIFY (4.14.9): GET /rules?filename=<basename>&limit=&offset=
    offset = 0
    limit = 500
    seen = 0
    total = None
    while True:
        path = f"/rules?filename={quote(filename)}&limit={limit}&offset={offset}"
        body = request("GET", path, bearer)
        if body.get("error") not in (0, None):
            print(f"{path} error={body.get('error')} {body.get('message')}", file=sys.stderr)
            sys.exit(1)
        data = body.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("affected_items"), list):
            print(f"{path} did not return data.affected_items", file=sys.stderr)
            sys.exit(1)
        items = data["affected_items"]
        if total is None:
            reported = data.get("total_affected_items")
            if not isinstance(reported, int):
                print(f"{path} did not return total_affected_items", file=sys.stderr)
                sys.exit(1)
            total = reported
        seen += len(items)
        if seen >= total or len(items) < limit:
            break
        offset += limit
    if seen != total:
        print(f"{filename}: listed {seen} but total_affected_items is {total}", file=sys.stderr)
        sys.exit(1)
    return total

auth = request("POST", "/security/user/authenticate", None)
token = ((auth or {}).get("data") or {}).get("token")
if not isinstance(token, str) or not token:
    print("Authentication did not return data.token", file=sys.stderr)
    sys.exit(1)

xml_total = 0
api_total = 0
ok = True
for path in paths:
    xml_n = xml_count(path)
    api_n = api_count(token, path.name)
    xml_total += xml_n
    api_total += api_n
    print(f"{path.name}  xml={xml_n}  api={api_n}")
    if xml_n != api_n:
        ok = False
print(f"loaded {xml_total} = {api_total}")
if not ok or xml_total != api_total:
    print("loaded rule count does not match the XML", file=sys.stderr)
    sys.exit(1)
PY
}

read_api_password() {
  local user=${WAZUH_API_USER:-}
  local password=${WAZUH_API_PASSWORD:-}
  if [[ -z "$user" ]]; then
    read -rp "Wazuh API user: " user
  fi
  if [[ -z "$password" ]]; then
    read -rsp "Wazuh API password: " password
    printf '\n' >&2
  fi
  if [[ -z "$user" || -z "$password" ]]; then
    echo "API user and password are required." >&2
    exit 1
  fi
  printf '%s\n' "$user"
  printf '%s\n' "$password"
}

deploy_here() {
  local rules_dir=$1
  local decoders_dir=$2
  local stamp
  local backup
  local src
  local creds
  local api_user
  local api_password
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root on WAZUH01." >&2
    exit 1
  fi
  if ! id wazuh >/dev/null 2>&1 || ! getent group wazuh >/dev/null 2>&1; then
    echo "User or group wazuh is missing. VERIFY the 4.14.9 package owner before installing as someone else." >&2
    exit 1
  fi
  for tool in curl python3 systemctl install; do
    command -v "$tool" >/dev/null 2>&1 || {
      echo "Missing $tool" >&2
      exit 1
    }
  done
  if [[ ! -d "$dest_rules" || ! -d "$dest_decoders" ]]; then
    echo "Missing $dest_rules or $dest_decoders. VERIFY the manager layout." >&2
    exit 1
  fi
  if [[ ! -f "$api_ca" ]]; then
    echo "CA not found at $api_ca. Set WAZUH_API_CA. Refusing to skip TLS verification." >&2
    exit 1
  fi
  if [[ ! -x /var/ossec/bin/wazuh-analysisd ]]; then
    echo "Missing /var/ossec/bin/wazuh-analysisd" >&2
    exit 1
  fi
  local rule_files=("$rules_dir"/sentinelforge_*.xml)
  if [[ ${#rule_files[@]} -eq 0 ]]; then
    echo "No sentinelforge_*.xml in $rules_dir" >&2
    exit 1
  fi
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  backup=/var/ossec/backup/sentinelforge-"$stamp"
  mkdir -p "$backup/rules" "$backup/decoders"
  for src in "${rule_files[@]}"; do
    copy_one "$src" "$dest_rules" "$backup/rules"
  done
  local decoder_files=("$decoders_dir"/*.xml)
  for src in "${decoder_files[@]}"; do
    copy_one "$src" "$dest_decoders" "$backup/decoders"
  done
  if ! /var/ossec/bin/wazuh-analysisd -t; then
    echo "wazuh-analysisd -t failed. Restoring $backup" >&2
    restore_all "$backup"
    exit 1
  fi
  systemctl restart wazuh-manager
  if ! wait_for_api; then
    echo "Restarted, but the API did not answer. Backup remains $backup" >&2
    exit 1
  fi
  mapfile -t creds < <(read_api_password)
  api_user=${creds[0]:-}
  api_password=${creds[1]:-}
  if [[ -z "$api_user" || -z "$api_password" ]]; then
    echo "Could not read API credentials." >&2
    exit 1
  fi
  if ! count_rules "$rules_dir" "$api_user" "$api_password"; then
    echo "Count mismatch. Restoring $backup and restarting." >&2
    restore_all "$backup"
    systemctl restart wazuh-manager
    exit 1
  fi
  unset api_password
  echo "Deployed. Backup: $backup"
}

deploy_ssh() {
  local remote=$1
  local root
  local remote_src
  local decoder_files
  root=$(cd "$(dirname "$0")/../.." && pwd)
  if [[ ! "$remote" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$ ]]; then
    echo "--ssh target must look like user@host" >&2
    exit 1
  fi
  remote_src=$(ssh "$remote" 'mktemp -d /tmp/sentinelforge-deploy.XXXXXXXX')
  remote_src=${remote_src//$'\r'/}
  remote_src=${remote_src//$'\n'/}
  if [[ ! "$remote_src" =~ ^/tmp/sentinelforge-deploy\.[A-Za-z0-9]+$ ]]; then
    echo "Unexpected remote directory: $remote_src" >&2
    exit 1
  fi
  ssh "$remote" mkdir -p "$remote_src/rules" "$remote_src/decoders"
  scp "$root/detections/wazuh/rules"/sentinelforge_*.xml "$remote:$remote_src/rules/"
  decoder_files=("$root/detections/wazuh/decoders"/*.xml)
  if [[ ${#decoder_files[@]} -gt 0 ]]; then
    scp "${decoder_files[@]}" "$remote:$remote_src/decoders/"
  fi
  scp "$0" "$remote:$remote_src/deploy_rules.sh"
  # Prompt for the API password on WAZUH01. Do not put it on the ssh command line.
  ssh -t "$remote" sudo env "SENTINELFORGE_SRC=$remote_src" bash "$remote_src/deploy_rules.sh"
  ssh "$remote" rm -rf "$remote_src"
}

if [[ "${SENTINELFORGE_SRC:-}" != "" ]]; then
  deploy_here "$SENTINELFORGE_SRC/rules" "$SENTINELFORGE_SRC/decoders"
  exit 0
fi

case "${1:-}" in
  "")
    root=$(cd "$(dirname "$0")/../.." && pwd)
    deploy_here "$root/detections/wazuh/rules" "$root/detections/wazuh/decoders"
    ;;
  --ssh)
    [[ $# -eq 2 ]] || {
      usage
      exit 1
    }
    deploy_ssh "$2"
    ;;
  *)
    usage
    exit 1
    ;;
esac
