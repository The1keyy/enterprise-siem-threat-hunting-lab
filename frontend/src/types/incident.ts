import type { IncidentStatus, Severity } from './domain.ts'

export type MitreTechnique = {
  id: string
  name: string
  tactic: string
}

/** Shape Step 7 will return from the incident list. */
export type Incident = {
  id: string
  title: string
  severity: Severity
  riskScore: number
  status: IncidentStatus
  owner: string
  users: string[]
  hosts: string[]
  mitre: MitreTechnique[]
  firstSeen: string
  lastSeen: string
  demo?: boolean
}

export type TimelineSource =
  'windows_security' | 'sysmon' | 'powershell' | 'linux_auth' | 'auditd'

export type TimelineEvent = {
  time: string
  title: string
  source: TimelineSource
  host: string
  user: string
  eventId: string
  ruleId: string
  severity: Severity
  raw: Record<string, unknown>
}

export type Entities = {
  users: string[]
  hosts: string[]
  srcIps: string[]
  dstIps: string[]
  processes: string[]
  domains: string[]
  hashes: string[]
}

export type RiskAssetType = 'workstation' | 'server' | 'domain_controller'

export type RiskMultiplier = 1 | 1.3 | 1.7

export type RiskItem = {
  event: string
  ruleId: string
  points: number
}

export type RiskBreakdown = {
  items: RiskItem[]
  subtotal: number
  assetType: RiskAssetType
  multiplier: RiskMultiplier
  final: number
  severityBand: Severity
}

export type Note = {
  id: string
  author: string
  time: string
  text: string
}

export const DISPOSITIONS = [
  'Undetermined',
  'True positive',
  'Benign',
  'False positive',
] as const

export type Disposition = (typeof DISPOSITIONS)[number]

export const INCIDENT_OWNERS = ['Unassigned', 'Analyst'] as const

export const DRY_RUN_MESSAGE =
  'Dry run: no action executed (backend in Step 7)' as const

export type ResponseActionName =
  'Isolate lab endpoint' | 'Disable test account' | 'Block test IP'

export type ResponseAuditEntry = {
  id: string
  action: ResponseActionName
  target: string
  time: string
  message: typeof DRY_RUN_MESSAGE
}

/**
 * Shape Step 7 will return from GET /incidents/:id.
 * `audit` is the dry-run log. Nothing in it was executed.
 */
export type IncidentDetail = Incident & {
  timeline: TimelineEvent[]
  entities: Entities
  risk: RiskBreakdown
  notes: Note[]
  disposition: Disposition
  summary: string
  recommendedContainment: string[]
  audit: ResponseAuditEntry[]
}

export type IncidentPatch = {
  status?: IncidentStatus
  owner?: string
}

export type AnalystPatch = {
  disposition?: Disposition
  summary?: string
}
