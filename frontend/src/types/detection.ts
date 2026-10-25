import type { ValidationStatus } from './domain.ts'
import type { MitreTechnique } from './incident.ts'

export const TELEMETRY_SOURCES = [
  'windows_security',
  'sysmon',
  'powershell',
  'linux_auth',
  'auditd',
  'suricata',
] as const

export type TelemetrySource = (typeof TELEMETRY_SOURCES)[number]

export type DetectionSeverity = 'critical' | 'high' | 'medium' | 'low'

export type TuningChange = {
  time: string
  author: string
  note: string
}

/** Shape Step 7 will return for a detection. Mirrors detections/metadata. */
export type Detection = {
  id: string
  name: string
  description: string
  severity: DetectionSeverity
  mitre: MitreTechnique[]
  telemetry: TelemetrySource[]
  wazuhRuleIds: string[]
  version: string
  enabled: boolean
  status: ValidationStatus
  windowsValidationRequired: boolean
  falsePositives: string
  tuningNotes: string
  testProcedure: string
  expectedEvent: string
  expectedAlert: string
  observedResult: string
  lastTriggered: string | null
  alertCount: number | null
  wazuhRuleXml: string
  sigmaYaml: string
  tuningHistory: TuningChange[]
  demo?: boolean
}
