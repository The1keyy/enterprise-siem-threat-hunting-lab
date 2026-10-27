/** Names from docs/ROADMAP.md. Metadata only. No rule bodies. */
export const DETECTION_NAMES: Record<string, string> = {
  'SF-001': 'Repeated failed logons',
  'SF-002': 'Password spray',
  'SF-003': 'Successful logon after failures',
  'SF-004': 'Suspicious PowerShell script block',
  'SF-005': 'Encoded PowerShell process',
  'SF-006': 'PowerShell download cradle',
  'SF-007': 'User added to local Administrators',
  'SF-008': 'User added to a privileged domain group',
  'SF-009': 'New local or domain user',
  'SF-010': 'Inbound RDP logon',
  'SF-011': 'SMB / admin-share remote logon',
  'SF-012': 'WinRM / PowerShell remoting',
  'SF-013': 'Linux SSH failure burst',
  'SF-014': 'Linux SSH success after failures',
  'SF-015': 'Suspicious Linux command execution',
  'SF-016': 'LSASS memory access',
  'SF-017': 'Scheduled task created',
  'SF-018': 'Security log cleared',
  'SF-019': 'New service installed',
  'SF-020': 'Multi-stage correlated incident',
}

export function detectionName(ruleId: string): string {
  return DETECTION_NAMES[ruleId] ?? ruleId
}
