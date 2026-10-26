# audit-policy

> REQUIRES WINDOWS VALIDATION
> Run on: both for the script. DC01 for the GPO.
> Status: SYNTAX VALID

`apply-audit-policy.ps1` sets the subcategories in `docs/TELEMETRY_MATRIX.md` by GUID, turns on command-line text for Security 4688, and sets the Security log maximum to 1 GB. `-WhatIf` prints the `auditpol` commands and does not run them. It still prints `auditpol /get` before and after, because that is a read.

`GPO-NOTES.md` is how to put the same settings in a domain GPO, including "force advanced audit policy subcategory settings".

Detailed File Share on DC01 is high volume because of SYSVOL. SF-011 still needs 5145.
