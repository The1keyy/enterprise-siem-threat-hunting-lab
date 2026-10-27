import { finalRiskScore } from '../lib/risk.ts'
import { incidentFixtures, storyIncidentId } from './incidents.ts'
import { describe, expect, it } from 'vitest'

function byId(id: string) {
  const incident = incidentFixtures.find((item) => item.id === id)
  if (!incident) throw new Error(`missing ${id}`)
  return incident
}

describe('incident fixture risk math', () => {
  it('computes the attack story as round(135 × 1.7) = 230', () => {
    const incident = byId(storyIncidentId)
    expect(incident.risk.subtotal).toBe(135)
    expect(incident.risk.multiplier).toBe(1.7)
    expect(incident.risk.assetType).toBe('domain_controller')
    expect(incident.risk.final).toBe(
      finalRiskScore(incident.risk.subtotal, incident.risk.multiplier),
    )
    expect(incident.risk.final).toBe(230)
    expect(incident.riskScore).toBe(incident.risk.final)
    expect(incident.severity).toBe('critical')
    expect(incident.hosts).toContain('DC01')
  })

  it('computes the SSH pair as round(40 × 1.3) = 52', () => {
    const incident = incidentFixtures.find((item) => item.hosts.includes('UBU01'))
    if (!incident) throw new Error('missing UBU01 incident')
    expect(incident.risk.subtotal).toBe(40)
    expect(incident.risk.multiplier).toBe(1.3)
    expect(incident.risk.final).toBe(
      finalRiskScore(incident.risk.subtotal, incident.risk.multiplier),
    )
    expect(incident.risk.final).toBe(52)
    expect(incident.riskScore).toBe(incident.risk.final)
  })
})
