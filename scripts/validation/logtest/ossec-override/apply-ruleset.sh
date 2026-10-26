#!/bin/sh
# Apply the mounted ruleset snippet to the image's generated ossec.conf.
# The 4.14.9 manager image copies a full file from /wazuh-config-mount over
# /var/ossec, so a partial ossec.conf cannot be mounted by itself.
# Built-in files under /var/ossec/ruleset are not modified.
# VERIFY (4.14.9): the ruleset block and </ruleset> still exist in the image config.
set -eu
# init-stage2 runs cont-init.d (this script, via 2-manager) before it scans
# /etc/services.d. A "down" file keeps s6-supervise filebeat in the process list.
# Removing the service directory before that scan means Filebeat is not started.
if [ -d /etc/services.d/filebeat ]; then
  rm -rf /etc/services.d/filebeat
  echo "sentinelforge: removed /etc/services.d/filebeat"
fi
CONF=/var/ossec/etc/ossec.conf
SNIPPET=/opt/sentinelforge/ruleset.xml
if [ ! -f "$CONF" ]; then
  echo "sentinelforge: $CONF is missing; ruleset override not applied" >&2
  exit 1
fi
if grep -q 'etc/rules/sentinelforge' "$CONF"; then
  exit 0
fi
if ! grep -q '</ruleset>' "$CONF"; then
  echo "sentinelforge: $CONF has no </ruleset> element" >&2
  exit 1
fi
awk '
  BEGIN { inserted = 0 }
  /<\/ruleset>/ && inserted == 0 {
    while ((getline line < snippet) > 0) {
      print line
    }
    inserted = 1
  }
  { print }
' snippet="$SNIPPET" "$CONF" > /tmp/ossec.conf.sentinelforge
mv /tmp/ossec.conf.sentinelforge "$CONF"
chown root:wazuh "$CONF"
chmod 640 "$CONF"
echo "sentinelforge: loaded rule_dir etc/rules/sentinelforge and decoder_dir etc/decoders/sentinelforge"
