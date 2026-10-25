import type { HealthStatus, IncidentStatus, Severity } from './domain.ts'

export type AlertSeverity = Exclude<Severity, 'info'>

export type OverviewKpis = {
  demo: true
  activeIncidents: number
  criticalAlerts24h: number
  highAlerts24h: number
  monitoredEndpoints: number
  detectionRulesEnabled: number
  eventsIngested24h: number
  meanTimeToInvestigateMinutes: number | null
}

export type AlertTimeBucket = {
  demo: true
  bucketStart: string
  label: string
  critical: number
  high: number
  medium: number
  low: number
}

export type SeverityTotal = {
  demo: true
  severity: AlertSeverity
  count: number
}

export type TacticTotal = {
  demo: true
  tactic: string
  count: number
}

export type CountBucket = {
  demo: true
  bucketStart: string
  label: string
  count: number
}

export type RankedCount = {
  demo: true
  label: string
  count: number
}

export type RankedRisk = {
  demo: true
  name: string
  detail: string
  riskScore: number
}

export type OverviewIncident = {
  demo: true
  id: string
  title: string
  severity: AlertSeverity
  status: IncidentStatus
  host: string
  user: string
  lastSeen: string
}

export type RecentDetection = {
  demo: true
  id: string
  name: string
  severity: AlertSeverity
  host: string
  time: string
}

export type TechniqueChip = {
  demo: true
  id: string
  name: string
}

export type HealthSignal = {
  demo: true
  name: string
  status: HealthStatus
  lastEvent: string
}

/** Shape the Step 7 backend will return from GET /overview. */
export type OverviewData = {
  demo: true
  generatedAt: string
  kpis: OverviewKpis
  alertsOverTime: AlertTimeBucket[]
  alertsBySeverity: SeverityTotal[]
  alertsByTactic: TacticTotal[]
  authFailuresOverTime: CountBucket[]
  topSourceIps: RankedCount[]
  topTargetedUsers: RankedCount[]
  topRiskyHosts: RankedRisk[]
  topRiskyUsers: RankedRisk[]
  incidents: OverviewIncident[]
  recentDetections: RecentDetection[]
  activeTechniques: TechniqueChip[]
  health: HealthSignal[]
}
