import { overviewFixture } from '../fixtures/overview.ts'
import { labAsset } from './labAssets.ts'
import {
  ASSET_MULTIPLIERS,
  RISK_EVENT_WEIGHTS,
  SEVERITY_THRESHOLDS,
} from './risk.ts'
import { WAZUH_VERSION } from './versions.ts'
import type { DataMode, Severity } from '../types/domain.ts'
import type { IncidentDetail, TimelineEvent } from '../types/incident.ts'
import type {
  AgentRow,
  DataSourceCard,
  HealthReport,
  SettingsView,
  Workflow,
} from '../types/operations.ts'

const HOUR_MS = 60 * 60 * 1000
const DEMO_END = Date.parse(overviewFixture.generatedAt)

type SourceDraft = {
  id: string
  name: string
  optional?: boolean
  windowsValidationRequired: boolean
  match: (event: TimelineEvent) => boolean
}

const SOURCE_DRAFTS: readonly SourceDraft[] = [
  {
    id: 'windows-security',
    name: 'Windows Security',
    windowsValidationRequired: true,
    match: (event) =>
      event.source === 'windows_security' && event.host !== 'DC01',
  },
  {
    id: 'sysmon',
    name: 'Sysmon',
    windowsValidationRequired: true,
    match: (event) => event.source === 'sysmon',
  },
  {
    id: 'powershell',
    name: 'PowerShell Operational',
    windowsValidationRequired: true,
    match: (event) => event.source === 'powershell',
  },
  {
    id: 'ad-security',
    name: 'Active Directory (DC01 Security)',
    windowsValidationRequired: true,
    match: (event) =>
      event.source === 'windows_security' && event.host === 'DC01',
  },
  {
    id: 'linux-auth',
    name: 'Linux auth',
    windowsValidationRequired: false,
    match: (event) => event.source === 'linux_auth',
  },
  {
    id: 'auditd',
    name: 'auditd',
    windowsValidationRequired: false,
    match: (event) => event.source === 'auditd',
  },
  {
    id: 'suricata',
    name: 'Suricata',
    optional: true,
    windowsValidationRequired: false,
    match: () => false,
  },
]

function volume(
  events: readonly TimelineEvent[],
): { label: string; count: number }[] {
  return Array.from({ length: 24 }, (_, index) => {
    const start = DEMO_END - 24 * HOUR_MS + index * HOUR_MS
    const label = new Date(start).toISOString().slice(11, 16)
    const count = events.filter((event) => {
      const time = Date.parse(event.time)
      return time >= start && time < start + HOUR_MS
    }).length
    return { label, count }
  })
}

export function buildSources(
  incidents: readonly IncidentDetail[],
): DataSourceCard[] {
  const events = incidents.flatMap((incident) => incident.timeline)
  return SOURCE_DRAFTS.map((draft) => {
    const matched = events.filter(draft.match)
    const last =
      matched
        .map((event) => event.time)
        .sort()
        .at(-1) ?? null
    const hosts = [...new Set(matched.map((event) => event.host))]
    return {
      id: draft.id,
      name: draft.name,
      status: 'Offline',
      optional: draft.optional === true,
      hosts,
      agent: hosts.length === 0 ? '—' : hosts.join(', '),
      lastEvent: last,
      volume: volume(matched),
      ingestionErrors: null,
      windowsValidationRequired: draft.windowsValidationRequired,
    }
  })
}

const AGENTS = ['DC01', 'WS01', 'UBU01', 'SURI01'] as const

export function buildHealth(activeRules: number): HealthReport {
  const components = [
    { id: 'manager', name: 'Wazuh manager' },
    { id: 'indexer', name: 'Wazuh indexer' },
    { id: 'dashboard', name: 'Wazuh dashboard' },
    { id: 'pipeline', name: 'Event pipeline' },
  ].map((item) => ({
    id: item.id,
    name: item.name,
    status: 'Offline' as const,
    version: WAZUH_VERSION,
    lastCheck: null,
  }))
  const agents: AgentRow[] = AGENTS.map((name) => {
    const asset = labAsset(name)
    return {
      name,
      ip: asset?.ip ?? '—',
      os: asset?.os ?? '—',
      status: 'never connected',
      version: null,
      lastKeepAlive: null,
      lastTelemetry: null,
    }
  })
  return {
    components,
    pipeline: ['Agent', 'Manager', 'Indexer'],
    agents,
    diskPercent: null,
    failedIngestion: null,
    activeRules,
  }
}

export function buildWorkflows(): Workflow[] {
  return [
    {
      id: 'enrichment',
      name: 'Alert enrichment',
      trigger: 'New alert',
      steps: [
        'Alert',
        'Extract IP/domain/hash',
        'Local/free enrichment',
        'Attach to incident',
      ],
      destructive: 'Destructive actions: none (approval required)',
      status: 'Not implemented (Step 14+)',
    },
    {
      id: 'escalation',
      name: 'High-risk escalation',
      trigger: `Risk ≥ ${SEVERITY_THRESHOLDS.high} (high band)`,
      steps: [
        'Risk ≥ threshold',
        'Create incident',
        'Set severity',
        'Generate analyst checklist',
      ],
      destructive: 'Destructive actions: none (approval required)',
      status: 'Not implemented (Step 14+)',
    },
    {
      id: 'context',
      name: 'Investigation context',
      trigger: 'Alert opened for investigation',
      steps: [
        'Alert',
        'Identify entity',
        'Gather related events',
        'Calculate risk',
        'Display context',
      ],
      destructive: 'Destructive actions: none (approval required)',
      status: 'Not implemented (Step 14+)',
    },
  ]
}

export function buildSettings(input: {
  dataMode: DataMode
  apiUrl: string
}): SettingsView {
  const bands: { severity: Severity; rule: string }[] = [
    {
      severity: 'critical',
      rule: `${SEVERITY_THRESHOLDS.critical} or higher`,
    },
    {
      severity: 'high',
      rule: `${SEVERITY_THRESHOLDS.high} to ${SEVERITY_THRESHOLDS.critical - 1}`,
    },
    {
      severity: 'medium',
      rule: `${SEVERITY_THRESHOLDS.medium} to ${SEVERITY_THRESHOLDS.high - 1}`,
    },
    { severity: 'low', rule: `1 to ${SEVERITY_THRESHOLDS.medium - 1}` },
    { severity: 'info', rule: '0' },
  ]
  return {
    dataMode: input.dataMode,
    apiUrl: input.apiUrl,
    wazuhVersion: WAZUH_VERSION,
    weights: RISK_EVENT_WEIGHTS.map((item) => ({
      label: item.label,
      points: item.points,
    })),
    multipliers: (
      Object.entries(ASSET_MULTIPLIERS) as [
        keyof typeof ASSET_MULTIPLIERS,
        (typeof ASSET_MULTIPLIERS)[keyof typeof ASSET_MULTIPLIERS],
      ][]
    ).map(([assetType, multiplier]) => ({ assetType, multiplier })),
    bands,
  }
}
