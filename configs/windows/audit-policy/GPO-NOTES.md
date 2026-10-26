# Group Policy notes for the audit script

> REQUIRES WINDOWS VALIDATION
> Run on: DC01
> Status: SYNTAX VALID as documentation. The GPO itself is not created from this Mac.

`apply-audit-policy.ps1` changes the local advanced audit policy. Use a GPO when the same settings should survive a local policy refresh on both DC01 and WS01.

1. On DC01, open Group Policy Management. Create a GPO linked to an OU that contains DC01 and WS01, or link it to the `sentinelforge.lab` domain if those are the only computers. Do not link it to a machine outside the lab.
2. Turn on **Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings**.
   Path: Computer Configuration, Policies, Windows Settings, Security Settings, Local Policies, Security Options.
   Without this, the older category policy can ignore the advanced subcategories.
3. Set the subcategories under Computer Configuration, Policies, Windows Settings, Security Settings, Advanced Audit Policy Configuration, Audit Policies.

| Subcategory | Policy folder | Success | Failure |
|---|---|---|---|
| Logon | Logon/Logoff | Enabled | Enabled |
| Security Group Management | Account Management | Enabled | leave the GPO unset |
| User Account Management | Account Management | Enabled | leave the GPO unset |
| Process Creation | Detailed Tracking | Enabled | leave the GPO unset |
| File Share | Object Access | Enabled | leave the GPO unset |
| Detailed File Share | Object Access | Enabled | leave the GPO unset |

4. Enable **Include command line in process creation events**.
   Path: Computer Configuration, Policies, Administrative Templates, System, Audit Process Creation.
   That writes `ProcessCreationIncludeCmdLine_Enabled`. It affects Security 4688. It does not affect Sysmon event 1. SF-005 does not alert on 4688.
5. Raise the Security log maximum size to 1073741824 bytes (1 GB) with a GPO log setting or `wevtutil` on each host. A short maximum overwrites a test before it is collected.
6. Detailed File Share on DC01 records SYSVOL access. That volume is expected. SF-011 still needs 5145.
7. Run `gpupdate /force` on DC01 and WS01, then `auditpol /get /category:*` on each. The GUIDs in the local script are the check if the display language is not English.

Not in this GPO, because no detection reads them: Special Logon, Other Object Access Events, Security System Extension.
