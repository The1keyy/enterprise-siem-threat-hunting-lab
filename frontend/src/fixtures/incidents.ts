// DEMO DATA — synthetic fixtures for UI development. Not real telemetry.
// The incidents live in /fixtures/incidents.json so the API and the UI share one copy.
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

const story = incidentFixtures.find((item) => item.id === 'INC-0001')
const dc = incidentFixtures.find((item) => item.id === 'INC-0002')
if (
  !story ||
  story.risk.subtotal !== 125 ||
  story.risk.multiplier !== 1 ||
  story.risk.final !== 125
) {
  throw new Error('INC-0001 must be 125 × 1.0 workstation = 125')
}
if (
  !dc ||
  dc.risk.subtotal !== 70 ||
  dc.risk.multiplier !== 1.7 ||
  dc.risk.assetType !== 'domain_controller' ||
  dc.risk.final !== Math.round(70 * 1.7)
) {
  throw new Error('INC-0002 must show the 1.7 domain controller multiplier')
}
