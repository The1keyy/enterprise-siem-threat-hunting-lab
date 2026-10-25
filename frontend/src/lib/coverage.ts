import type { ValidationStatus } from '../types/domain.ts'
import type { Detection } from '../types/detection.ts'

const RANK: Record<ValidationStatus, number> = {
  'NOT TESTED': 0,
  'NEEDS TUNING': 1,
  'SYNTAX VALID': 2,
  'LOGTEST VALID': 3,
  'LAB VALIDATED': 4,
}

export function bestValidationStatus(
  statuses: readonly ValidationStatus[],
): ValidationStatus {
  return statuses.reduce((best, status) =>
    RANK[status] > RANK[best] ? status : best,
  )
}

export function coverageSummary(detections: readonly Detection[]): {
  mapped: number
  labValidated: number
} {
  const byTechnique = new Map<string, ValidationStatus[]>()
  for (const detection of detections) {
    for (const item of detection.mitre) {
      const current = byTechnique.get(item.id) ?? []
      current.push(detection.status)
      byTechnique.set(item.id, current)
    }
  }
  let labValidated = 0
  for (const statuses of byTechnique.values()) {
    if (bestValidationStatus(statuses) === 'LAB VALIDATED') {
      labValidated += 1
    }
  }
  return { mapped: byTechnique.size, labValidated }
}

/**
 * VERIFY: ATT&CK Navigator layer format version. The "versions" strings below
 * are placeholders, not a confirmed Navigator release.
 */
export function attackNavigatorLayer(detections: readonly Detection[]) {
  const techniques = new Map<string, ValidationStatus[]>()
  for (const detection of detections) {
    for (const item of detection.mitre) {
      const current = techniques.get(item.id) ?? []
      current.push(detection.status)
      techniques.set(item.id, current)
    }
  }
  return {
    name: 'SentinelForge demo coverage',
    versions: {
      attack: 'VERIFY',
      navigator: 'VERIFY',
      layer: 'VERIFY',
    },
    domain: 'enterprise-attack',
    description:
      'DEMO DATA — synthetic fixtures for UI development. Not real telemetry.',
    techniques: [...techniques.entries()].map(([techniqueID, statuses]) => ({
      techniqueID,
      comment: bestValidationStatus(statuses),
      score: RANK[bestValidationStatus(statuses)],
    })),
  }
}
