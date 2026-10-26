import type { ValidationStatus } from './domain.ts'
import type { MitreTechnique, TimelineEvent } from './incident.ts'

/** Saved hunt. Definitions are hunting/*.yml. status stays NOT TESTED until a lab run. */
export type HuntAggregation = {
  type: 'terms'
  field: string
  size: number
  maxDocCount: number
}

export type Hunt = {
  id: string
  name: string
  hypothesis: string
  dataSource: string
  index: string
  channel: string
  log: string
  query: string
  timeWindowDefault: '24h' | '7d'
  expectedBehavior: string
  suspiciousBehavior: string
  mitre: MitreTechnique[]
  relatedDetections: string[]
  differsFromDetections: string
  investigationGuidance: string
  pivotFields: string[]
  aggregation: HuntAggregation | null
  status: ValidationStatus
  demo?: boolean
}

export type HuntBucket = {
  key: string
  count: number
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
  demo: boolean
  notice: string
  huntId: string
  hits: HuntHit[]
  buckets?: HuntBucket[]
}
