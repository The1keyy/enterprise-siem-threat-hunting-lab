import type { HealthStatus } from './domain.ts'
import type { RiskAssetType, RiskMultiplier } from './incident.ts'
import type { Severity } from './domain.ts'

export type DataSourceCard = {
  id: string
  name: string
  status: HealthStatus
  optional: boolean
  hosts: string[]
  agent: string
  lastEvent: string | null
  volume: { label: string; count: number }[]
  ingestionErrors: number | null
  windowsValidationRequired: boolean
}

export type HealthComponent = {
  id: string
  name: string
  status: HealthStatus
  version: string
  lastCheck: string | null
}

export type AgentRow = {
  name: string
  ip: string
  os: string
  status: 'active' | 'disconnected' | 'never connected'
  version: string | null
  lastKeepAlive: string | null
  lastTelemetry: string | null
}

export type CorrelationStatus = {
  enabled: boolean
  lastRun: string | null
  checkpoint: { timestamp: string; id: string } | null
  alertsProcessed: number
  error: string | null
  note: string
}

export type HealthReport = {
  components: HealthComponent[]
  pipeline: string[]
  agents: AgentRow[]
  diskPercent: number | null
  failedIngestion: number | null
  activeRules: number
  correlation: CorrelationStatus
}

export type Workflow = {
  id: string
  name: string
  trigger: string
  steps: string[]
  destructive: string
  status: string
}

export type CorrelationSettings = {
  windowMinutes: number
  hostProximityMinutes: number
  halfLifeHours: number
  sprayMinDistinctUsers: number
  openLevel: number
  criticalLevel: number
}

export type SettingsView = {
  dataMode: 'demo' | 'live'
  apiUrl: string
  wazuhVersion: string
  weights: { label: string; points: number }[]
  multipliers: { assetType: RiskAssetType; multiplier: RiskMultiplier }[]
  bands: { severity: Severity; rule: string }[]
  correlation: CorrelationSettings
}
