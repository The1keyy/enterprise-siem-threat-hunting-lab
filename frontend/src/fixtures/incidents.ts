// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
// The incidents live in /fixtures/incidents.json so the API and the UI share one copy.
// scripts/validation/build_demo_incidents.py writes that file from the correlation engine.
import raw from '../../../fixtures/incidents.json'
import type { IncidentDetail } from '../types/incident.ts'

type IncidentFile = {
  _notice: string
  incidents: IncidentDetail[]
}

const file = raw as IncidentFile

if (!file._notice.startsWith('DEMO DATA')) {
  throw new Error('Incident fixtures are missing the DEMO DATA notice')
}

export const incidentFixtures: readonly IncidentDetail[] = file.incidents

export const storyIncident = incidentFixtures.find(
  (item) => item.risk.final === 230 && item.severity === 'critical',
)

if (
  !storyIncident ||
  storyIncident.risk.subtotal !== 135 ||
  storyIncident.risk.multiplier !== 1.7 ||
  storyIncident.risk.assetType !== 'domain_controller' ||
  !storyIncident.risk.multiplierHosts?.includes('DC01')
) {
  throw new Error('The attack-story incident must be 135 × 1.7 = 230, critical, set by DC01')
}

const ssh = incidentFixtures.find((item) => item.hosts.includes('UBU01'))
if (
  !ssh ||
  ssh.risk.subtotal !== 40 ||
  ssh.risk.multiplier !== 1.3 ||
  ssh.risk.final !== 52
) {
  throw new Error('The SSH pair must be 40 × 1.3 = 52')
}

export const storyIncidentId = storyIncident.id
