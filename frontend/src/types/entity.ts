import type {
  MitreTechnique,
  RiskAssetType,
  RiskMultiplier,
} from './incident.ts'

export type EntityRow = {
  name: string
  riskScore: number
  incidentIds: string[]
  lastActivity: string | null
}

export type RiskLine = {
  incidentId: string
  title: string
  subtotal: number
  multiplier: RiskMultiplier
  assetType: RiskAssetType
  final: number
}

export type LoginRow = {
  time: string
  host: string
  sourceIp: string
  logonType: string
  result: 'success' | 'fail'
}

export type NamedLink = {
  id: string
  name: string
}

export type UserProfile = EntityRow & {
  sourceIps: string[]
  endpoints: string[]
  detections: NamedLink[]
  incidents: NamedLink[]
  mitre: MitreTechnique[]
  logins: LoginRow[]
  history: { label: string; score: number }[]
  lines: RiskLine[]
}

export type HostConnection = {
  time: string
  src: string
  dst: string
  detail: string
}

export type HostProfile = EntityRow & {
  ip: string
  os: string
  assetType: RiskAssetType
  multiplier: RiskMultiplier
  agentStatus: 'never connected'
  users: string[]
  processes: { name: string; count: number }[]
  detections: NamedLink[]
  incidents: NamedLink[]
  connections: HostConnection[]
  history: { label: string; score: number }[]
  lines: RiskLine[]
}
