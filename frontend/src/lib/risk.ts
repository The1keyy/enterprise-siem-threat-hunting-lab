import type { Severity } from '../types/domain.ts'
import type { RiskAssetType, RiskMultiplier } from '../types/incident.ts'

/**
 * Fixture weights and cutoffs so a breakdown can show a band.
 * Step 14 replaces these weights and bands. This is not a measured model.
 */
export const RISK_EVENT_WEIGHTS = [
  { id: 'failed_auth', label: 'Failed-auth burst', points: 15 },
  {
    id: 'success_after_failures',
    label: 'Successful login after failures',
    points: 25,
  },
  { id: 'encoded_powershell', label: 'Encoded PowerShell', points: 30 },
  { id: 'privileged_group', label: 'Privileged group change', points: 35 },
  { id: 'remote_connection', label: 'Remote connection', points: 20 },
  { id: 'new_account', label: 'New account', points: 10 },
  { id: 'suspicious_command', label: 'Suspicious command', points: 20 },
  { id: 'scheduled_task', label: 'Scheduled task', points: 15 },
] as const

export const ASSET_MULTIPLIERS = {
  workstation: 1,
  server: 1.3,
  domain_controller: 1.7,
} as const satisfies Record<RiskAssetType, RiskMultiplier>

export const SEVERITY_THRESHOLDS = {
  critical: 100,
  high: 60,
  medium: 30,
} as const

export function severityBandFor(finalScore: number): Severity {
  if (finalScore >= SEVERITY_THRESHOLDS.critical) return 'critical'
  if (finalScore >= SEVERITY_THRESHOLDS.high) return 'high'
  if (finalScore >= SEVERITY_THRESHOLDS.medium) return 'medium'
  if (finalScore > 0) return 'low'
  return 'info'
}

export function eventWeight(
  id: (typeof RISK_EVENT_WEIGHTS)[number]['id'],
): number {
  const found = RISK_EVENT_WEIGHTS.find((item) => item.id === id)
  if (!found) {
    throw new Error(`Missing risk weight ${id}`)
  }
  return found.points
}

export function finalRiskScore(
  subtotal: number,
  multiplier: RiskMultiplier,
): number {
  return Math.round(subtotal * multiplier)
}
