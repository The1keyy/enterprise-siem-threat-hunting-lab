import type { Severity } from '../types/domain.ts'
import type { RiskMultiplier } from '../types/incident.ts'

/**
 * Fixture cutoffs so the breakdown can show a band.
 * Step 14 replaces these weights and bands. This is not a measured model.
 */
export function severityBandFor(finalScore: number): Severity {
  if (finalScore >= 100) return 'critical'
  if (finalScore >= 60) return 'high'
  if (finalScore >= 30) return 'medium'
  if (finalScore > 0) return 'low'
  return 'info'
}

export function finalRiskScore(
  subtotal: number,
  multiplier: RiskMultiplier,
): number {
  return Math.round(subtotal * multiplier)
}
