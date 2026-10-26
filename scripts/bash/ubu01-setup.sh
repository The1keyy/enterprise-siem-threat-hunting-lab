#!/usr/bin/env bash
# Run on: UBU01
# Requires: root, Ubuntu 24.04
# Status: SYNTAX VALID after shellcheck. Not run on UBU01.
# Static IP 10.10.10.30/24, hostname ubu01, rsyslog auth.log, auditd rules,
# and Wazuh agent 4.14.9. Snapshot the VM before the first run.
# IFACE=eth0 ./ubu01-setup.sh when more than one NIC is up.

set -euo pipefail

log_dir=/var/log/sentinelforge
log_file=$log_dir/ubu01-setup.log
address=10.10.10.30
prefix=24
gateway=10.10.10.1
dns=10.10.10.10
manager=10.10.10.40
hostname_want=ubu01
# VERIFY (4.14.9): apt package revision matches the Windows MSI wazuh-agent-4.14.9-1.
agent_version=4.14.9-1
fail=0

usage() {
  echo "Usage: IFACE=<nic> $0" >&2
}

log_line() {
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
  echo "Run as root on UBU01." >&2
  exit 1
fi
mkdir -p "$log_dir"
root=$(cd "$(dirname "$0")/../.." && pwd)
rules=$root/configs/linux/auditd/sentinelforge.rules
snippet=$root/configs/wazuh/agent-linux/ossec.conf.snippet
if [[ ! -f "$rules" || ! -f "$snippet" ]]; then
  echo "Run this from a checkout that contains configs/." >&2
  exit 1
fi

if [[ -z "${IFACE:-}" ]]; then
  mapfile -t ifaces < <(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1)
  if [[ ${#ifaces[@]} -ne 1 ]]; then
    echo "Set IFACE. Found: ${ifaces[*]:-none}" >&2
    usage
    exit 1
  fi
  IFACE=${ifaces[0]}
fi
log_line "IFACE=$IFACE"

netplan_file=/etc/netplan/99-sentinelforge.yaml
tmp=$(mktemp)
cat > "$tmp" <<EOF
network:
  version: 2
  ethernets:
    ${IFACE}:
      dhcp4: false
      addresses:
        - ${address}/${prefix}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses:
          - ${dns}
EOF
if [[ ! -f "$netplan_file" ]] || ! cmp -s "$tmp" "$netplan_file"; then
  install -m 0600 "$tmp" "$netplan_file"
  netplan generate
  netplan apply
else
  log_line "netplan unchanged"
fi
rm -f "$tmp"

if [[ "$(hostnamectl --static)" != "$hostname_want" ]]; then
  hostnamectl set-hostname "$hostname_want"
fi
if ! grep -qE "^${address}[[:space:]]+${hostname_want}([[:space:]]|\$)" /etc/hosts; then
  printf '%s %s\n' "$address" "$hostname_want" >> /etc/hosts
fi

export DEBIAN_FRONTEND=noninteractive
apt-get install -y rsyslog
auth_line='auth,authpriv.* /var/log/auth.log'
if ! grep -RqsE '^[^#]*auth,authpriv\.\*.*/var/log/auth\.log' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null; then
  printf '%s\n' "$auth_line" > /etc/rsyslog.d/20-sentinelforge-auth.conf
fi
systemctl enable rsyslog
systemctl restart rsyslog
logger -p auth.notice -t sentinelforge "rsyslog auth.log check"
sleep 2

apt-get install -y auditd
install -m 0640 "$rules" /etc/audit/rules.d/sentinelforge.rules
systemctl enable auditd
systemctl restart auditd
augenrules --load

apt-get install -y gnupg apt-transport-https curl
if [[ ! -f /usr/share/keyrings/wazuh.gpg ]]; then
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
fi
repo_line='deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main'
repo_file=/etc/apt/sources.list.d/wazuh.list
if [[ ! -f "$repo_file" ]] || ! grep -qxF "$repo_line" "$repo_file"; then
  printf '%s\n' "$repo_line" > "$repo_file"
fi

installed=$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null || true)
if [[ -n "$installed" && "$installed" != "$agent_version" ]]; then
  echo "wazuh-agent is $installed, not $agent_version. Refusing to replace it." >&2
  exit 1
fi
if [[ "$installed" != "$agent_version" ]]; then
  apt-get update
  # VERIFY: the Linux package reads WAZUH_AGENT_NAME. The Windows deployment page documents that name.
  WAZUH_MANAGER="$manager" WAZUH_AGENT_NAME="$hostname_want" apt-get install -y "wazuh-agent=${agent_version}"
  apt-mark hold wazuh-agent
fi

agent_conf=/var/ossec/etc/ossec.conf
python3 - "$agent_conf" "$snippet" "$manager" <<'PY'
import shutil
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

agent_path = Path(sys.argv[1])
snippet_path = Path(sys.argv[2])
want = sys.argv[3]
agent = ET.parse(agent_path)
snippet = ET.parse(snippet_path)
root = agent.getroot()
address = None
for node in root.iter("address"):
    address = node
    break
if address is None:
    print("No address element in ossec.conf", file=sys.stderr)
    sys.exit(1)
def signature(node):
    return tuple((child.tag, (child.text or "").strip()) for child in list(node))

changed = (address.text or "").strip() != want
address.text = want
parents = {child: parent for parent in root.iter() for child in list(parent)}
config = root if root.tag == "ossec_config" else root.find("ossec_config")
if config is None:
    print("No ossec_config element", file=sys.stderr)
    sys.exit(1)
for localfile in list(snippet.getroot().iter("localfile")):
    location = (localfile.findtext("location") or "").strip()
    existing = None
    for have in root.iter("localfile"):
        if (have.findtext("location") or "").strip() == location:
            existing = have
            break
    fresh = ET.fromstring(ET.tostring(localfile, encoding="unicode"))
    if existing is not None and signature(existing) == signature(fresh):
        continue
    changed = True
    if existing is not None:
        parent = parents[existing]
        index = list(parent).index(existing)
        parent.remove(existing)
        parent.insert(index, fresh)
    else:
        config.append(fresh)
if not changed:
    print("ossec.conf unchanged")
    sys.exit(0)
stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backup = agent_path.with_name(agent_path.name + ".bak-" + stamp)
shutil.copy2(agent_path, backup)
agent.write(agent_path, encoding="utf-8", xml_declaration=True)
print(f"Backed up ossec.conf to {backup}")
PY

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

if ip -4 -o addr show dev "$IFACE" | grep -q "$address"; then
  check PASS static-ip "$address on $IFACE"
else
  check FAIL static-ip "$IFACE"
fi
if [[ "$(hostnamectl --static)" == "$hostname_want" ]]; then
  check PASS hostname "$hostname_want"
else
  check FAIL hostname "$(hostnamectl --static)"
fi
if [[ -f /var/log/auth.log ]] && grep -q 'sentinelforge: rsyslog auth.log check' /var/log/auth.log; then
  check PASS auth.log /var/log/auth.log
else
  check FAIL auth.log "missing sentinelforge line in /var/log/auth.log"
fi
if auditctl -l | grep -q sentinelforge_execve; then
  check PASS auditd sentinelforge_execve
else
  check FAIL auditd "auditctl -l has no sentinelforge_execve"
fi
ver=$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null || true)
if [[ "$ver" == "$agent_version" ]]; then
  check PASS wazuh-agent "$ver"
else
  check FAIL wazuh-agent "${ver:-missing}"
fi
if systemctl is-active --quiet wazuh-agent; then
  check PASS wazuh-agent-service active
else
  check FAIL wazuh-agent-service "$(systemctl is-active wazuh-agent || true)"
fi
if grep -q "$manager" "$agent_conf"; then
  check PASS manager-address "$manager"
else
  check FAIL manager-address "not in ossec.conf"
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
