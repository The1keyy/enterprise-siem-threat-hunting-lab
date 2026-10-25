import { describe, expect, it } from 'vitest'
import { incidentFixtures } from '../fixtures/incidents.ts'
import { ASSET_MULTIPLIERS, finalRiskScore } from './risk.ts'
import { buildHost, buildUser } from './entityModel.ts'
import { buildHealth, buildSettings, buildSources } from './operationsModel.ts'

describe('entity risk', () => {
  it('sums incident scores with the shared multiplier', () => {
    const profile = buildUser(incidentFixtures, 'sf-test-alice')
    expect(profile).not.toBeNull()
    if (!profile) return
    const expected = profile.lines.reduce(
      (sum, line) => sum + finalRiskScore(line.subtotal, line.multiplier),
      0,
    )
    expect(profile.riskScore).toBe(expected)
    expect(profile.riskScore).toBeGreaterThan(0)
    expect(profile.lines.some((line) => line.multiplier === 1)).toBe(true)
  })

  it('keeps the domain controller multiplier on DC01', () => {
    const profile = buildHost(incidentFixtures, 'DC01')
    expect(profile?.multiplier).toBe(ASSET_MULTIPLIERS.domain_controller)
    expect(profile?.multiplier).toBe(1.7)
    expect(profile?.agentStatus).toBe('never connected')
  })
})

describe('operations fixtures', () => {
  it('marks Suricata optional and leaves every agent disconnected', () => {
    const sources = buildSources(incidentFixtures)
    const suricata = sources.find((item) => item.id === 'suricata')
    expect(suricata?.optional).toBe(true)
    expect(suricata?.lastEvent).toBeNull()
    expect(
      sources.filter((item) => item.windowsValidationRequired),
    ).toHaveLength(4)
    const health = buildHealth(12)
    expect(
      health.agents.every((agent) => agent.status === 'never connected'),
    ).toBe(true)
    expect(health.diskPercent).toBeNull()
    expect(health.activeRules).toBe(12)
  })

  it('reads risk weights from the shared table', () => {
    const settings = buildSettings({
      dataMode: 'demo',
      apiUrl: 'http://127.0.0.1:8000',
    })
    expect(settings.wazuhVersion).toBe('4.14.9')
    expect(settings.weights.find((row) => row.points === 15)?.label).toBe(
      'Failed-auth burst',
    )
    expect(settings.multipliers).toEqual([
      { assetType: 'workstation', multiplier: 1 },
      { assetType: 'server', multiplier: 1.3 },
      { assetType: 'domain_controller', multiplier: 1.7 },
    ])
  })
})
