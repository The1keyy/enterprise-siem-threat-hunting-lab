export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]

export const INCIDENT_STATUSES = [
  'New',
  'Investigating',
  'Contained',
  'Resolved',
  'False Positive',
] as const
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number]

export const VALIDATION_STATUSES = [
  'NOT TESTED',
  'SYNTAX VALID',
  'LOGTEST VALID',
  'LAB VALIDATED',
  'NEEDS TUNING',
] as const
export type ValidationStatus = (typeof VALIDATION_STATUSES)[number]

export const HEALTH_STATUSES = ['Healthy', 'Degraded', 'Offline'] as const
export type HealthStatus = (typeof HEALTH_STATUSES)[number]

export type DataMode = 'demo' | 'live'
