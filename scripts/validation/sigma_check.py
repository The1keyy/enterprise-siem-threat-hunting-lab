#!/usr/bin/env python3
"""Run sigma check and convert every rule to OpenSearch Lucene.

Verified with sigma-cli 3.1.0, pySigma 1.5.1, pySigma-backend-opensearch 2.0.3:

    sigma check detections/sigma
    sigma list pipelines opensearch_lucene
    sigma convert -t opensearch_lucene --without-pipeline detections/sigma/<file>.yml

`sigma list pipelines opensearch_lucene` returns no pipelines. The backend
still refuses to convert unless `--without-pipeline` is set. That flag is
required for this pin.

`sigma check` exits 0 when it finds medium issues and no parse errors
(`--pass-on-issues` is the default). Those issues are printed as warnings.
pySigma 1.5 compares tactic tags to ATT&CK shortnames, which use hyphens
(`lateral-movement`). These rules use the SigmaHQ underscore form
(`lateral_movement`), so those nine tactic tags warn. Technique tags and
`sigma convert` still succeed.
A convert failure is a warning with the backend's reason. It is not skipped.
A sigma check parse error exits 1.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = ROOT / "detections" / "sigma"
TARGET = "opensearch_lucene"


def main() -> int:
    sigma = Path(sys.executable).parent / "sigma"
    if not sigma.is_file():
        print("error: sigma is not installed next to this Python")
        return 1
    check = _run([str(sigma), "check", str(SIGMA_DIR)])
    print(check.stdout)
    if check.stderr:
        print(check.stderr, file=sys.stderr)
    warnings: list[str] = []
    converted = 0
    if "=== Issues ===" in check.stdout:
        for line in check.stdout.splitlines():
            if line.startswith("issue="):
                warnings.append(line)
    if check.returncode != 0:
        print(f"ERROR  sigma_check  detections/sigma  sigma check exited {check.returncode}")
        return 1
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        result = _run(
            [
                str(sigma),
                "convert",
                "-t",
                TARGET,
                "--without-pipeline",
                str(path),
            ]
        )
        if result.returncode != 0:
            reason = (result.stderr or result.stdout).strip().replace("\n", " ")
            warnings.append(f"{path.name}: convert failed: {reason}")
            continue
        query = " ".join(line for line in result.stdout.splitlines() if line and not line.startswith("Parsing"))
        if not query:
            warnings.append(f"{path.name}: convert produced no query")
            continue
        converted += 1
    print(f"sigma convert -t {TARGET} --without-pipeline: {converted} rules converted")
    print(f"warnings: {len(warnings)}")
    for item in warnings:
        print(f"WARNING  {item}")
    if not warnings:
        print("OK")
    return 0


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
