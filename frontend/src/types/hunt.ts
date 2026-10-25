import type { ValidationStatus } from './domain.ts'
import type { MitreTechnique, TimelineEvent } from './incident.ts'

/** Shape Step 7 will return for a saved hunt. */
export type Hunt = {
  id: string
  name: string
  hypothesis: string
  dataSource: string
  query: string
  expectedBehavior: string
  suspiciousBehavior: string
  mitre: MitreTechnique[]
  investigationGuidance: string
  status: ValidationStatus
  demo?: boolean
}

export type HuntFilters = {
  from: string
  to: string
  host: string
  user: string
  source: string
}

export type HuntHit = TimelineEvent & {
  incidentId: string
}

export type HuntRunResult = {
  demo: true
  notice: string
  huntId: string
  hits: HuntHit[]
}
