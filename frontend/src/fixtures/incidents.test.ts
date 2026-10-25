import { finalRiskScore } from '../lib/risk.ts'
import { incidentFixtures } from './incidents.ts'
import { describe, expect, it } from 'vitest'

function byId(id: string) {
  const incident = incidentFixtures.find((item) => item.id === id)
  if (!incident) throw new Error(`missing ${id}`)
  return incident
}

describe('incident fixture risk math', () => {
  it('computes INC-0001 as round(125 × 1.0)', () => {
    const incident = byId('INC-0001')
    expect(incident.risk.subtotal).toBe(125)
    expect(incident.risk.multiplier).toBe(1)
    expect(incident.risk.assetType).toBe('workstation')
    expect(incident.risk.final).toBe(
      finalRiskScore(incident.risk.subtotal, incident.risk.multiplier),
    )
    expect(incident.risk.final).toBe(125)
    expect(incident.riskScore).toBe(incident.risk.final)
  })

  it('computes INC-0002 as round(subtotal × 1.7)', () => {
    const incident = byId('INC-0002')
    expect(incident.risk.assetType).toBe('domain_controller')
    expect(incident.risk.multiplier).toBe(1.7)
    expect(incident.risk.final).toBe(
      Math.round(incident.risk.subtotal * incident.risk.multiplier),
    )
    expect(incident.risk.final).toBe(
      finalRiskScore(incident.risk.subtotal, incident.risk.multiplier),
    )
    expect(incident.riskScore).toBe(incident.risk.final)
    expect(incident.hosts).toContain('DC01')
  })
})
