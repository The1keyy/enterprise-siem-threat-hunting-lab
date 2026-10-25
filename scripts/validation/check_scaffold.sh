#!/usr/bin/env bash
# Purpose: Verify the SentinelForge repo scaffold is complete.
# Run on:  macOS or Linux, from the repo root.
# Status:  Runs locally; verify with: bash scripts/validation/check_scaffold.sh
set -euo pipefail

required_dirs=(
  frontend backend
  detections/wazuh/rules detections/wazuh/decoders detections/sigma detections/metadata
  hunting
  scripts/powershell/simulations scripts/bash scripts/validation
  configs/windows configs/sysmon configs/linux configs/wazuh configs/suricata
  incidents architecture
  docs/adr docs/detections docs/runbooks
  screenshots tests/logs tests/detections
  .github/workflows .cursor/rules
)

required_files=(
  README.md LICENSE .gitignore .gitattributes .editorconfig .env.example
  docs/PROJECT_STATUS.md docs/VERSIONS.md
)

missing=0

for d in "${required_dirs[@]}"; do
  if [[ ! -d "$d" ]]; then
    echo "MISSING DIR:  $d"; missing=$((missing + 1))
  elif [[ "$d" != ".github/workflows" && "$d" != ".cursor/rules" && ! -f "$d/README.md" ]]; then
    echo "NO README:    $d"; missing=$((missing + 1))
  fi
done

for f in "${required_files[@]}"; do
  [[ -f "$f" ]] || { echo "MISSING FILE: $f"; missing=$((missing + 1)); }
done

# Safety: a real .env must never be tracked by git.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    echo "DANGER: .env is tracked by git. Run: git rm --cached .env"
    missing=$((missing + 1))
  fi
fi

if [[ $missing -eq 0 ]]; then
  echo "OK: scaffold complete (${#required_dirs[@]} dirs, ${#required_files[@]} files checked)"
else
  echo "FAILED: $missing problem(s)"; exit 1
fi
