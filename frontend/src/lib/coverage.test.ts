import { describe, expect, it } from 'vitest'
import { detectionFixtures } from '../fixtures/detections.ts'
import { coverageSummary } from './coverage.ts'

describe('ATT&CK coverage', () => {
  it('counts mapped techniques from the detection library', () => {
    const summary = coverageSummary(detectionFixtures)
    expect(summary.mapped).toBeGreaterThan(0)
    expect(summary.labValidated).toBe(0)

    const withOneLabHit = detectionFixtures.map((item, index) =>
      index === 0 ? { ...item, status: 'LAB VALIDATED' as const } : item,
    )
    expect(coverageSummary(withOneLabHit).labValidated).toBe(1)
  })

  it('keeps every detection at NOT TESTED', () => {
    expect(detectionFixtures).toHaveLength(20)
    for (const detection of detectionFixtures) {
      expect(detection.status).toBe('NOT TESTED')
      expect(detection.observedResult).toBe('NOT YET VALIDATED')
      expect(detection.lastTriggered).toBeNull()
      expect(detection.alertCount).toBeNull()
    }
  })
})
