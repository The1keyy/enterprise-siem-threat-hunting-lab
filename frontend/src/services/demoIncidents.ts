import { detectionFixtures } from '../fixtures/detections.ts'
import { incidentFixtures } from '../fixtures/incidents.ts'
import { matchesFilters, type IncidentFilters } from '../lib/incidentFilters.ts'
import { finalRiskScore, severityBandFor } from '../lib/risk.ts'
import type {
  AnalystPatch,
  Incident,
  IncidentDetail,
  IncidentPatch,
  MitreTechnique,
  Note,
  ResponseActionName,
  ResponseAuditEntry,
  RiskAssetType,
  RiskMultiplier,
  TimelineEvent,
} from '../types/incident.ts'
import type { Severity } from '../types/domain.ts'
import { DRY_RUN_MESSAGE } from '../types/incident.ts'
import { ApiError } from './apiError.ts'
import { DEMO_SAVE_TOAST, pushToast } from './toasts.ts'

let records: IncidentDetail[] | null = null
let noteCounter = 1
let auditCounter = 0

function seed(): IncidentDetail[] {
  if (!records) {
    records = structuredClone(incidentFixtures) as IncidentDetail[]
    noteCounter = records.reduce(
      (highest, incident) => highest + incident.notes.length,
      0,
    )
  }
  return records
}

export function resetDemoIncidents(): void {
  records = null
  noteCounter = 1
  auditCounter = 0
}

function toIncident(detail: IncidentDetail): Incident {
  return {
    id: detail.id,
    title: detail.title,
    severity: detail.severity,
    riskScore: detail.riskScore,
    status: detail.status,
    owner: detail.owner,
    users: detail.users,
    hosts: detail.hosts,
    mitre: detail.mitre,
    firstSeen: detail.firstSeen,
    lastSeen: detail.lastSeen,
    demo: true,
  }
}

function findIndex(id: string): number {
  const index = seed().findIndex((incident) => incident.id === id)
  if (index < 0) {
    throw new ApiError(`Incident ${id} was not found.`, 404)
  }
  return index
}

function save(index: number, next: IncidentDetail): IncidentDetail {
  seed()[index] = next
  pushToast(DEMO_SAVE_TOAST)
  return next
}

export function listDemoIncidentDetails(): IncidentDetail[] {
  return seed()
}

export function listDemoIncidents(filters: IncidentFilters): Incident[] {
  return seed()
    .map(toIncident)
    .filter((incident) => matchesFilters(incident, filters))
    .sort((left, right) => {
      const byRisk = right.riskScore - left.riskScore
      if (byRisk !== 0) return byRisk
      return right.lastSeen.localeCompare(left.lastSeen)
    })
}

export function getDemoIncident(id: string): IncidentDetail {
  const index = findIndex(id)
  const found = seed()[index]
  if (!found) {
    throw new ApiError(`Incident ${id} was not found.`, 404)
  }
  return found
}

export function updateDemoIncident(
  id: string,
  patch: IncidentPatch,
): IncidentDetail {
  const index = findIndex(id)
  const current = seed()[index]
  if (!current) {
    throw new ApiError(`Incident ${id} was not found.`, 404)
  }
  return save(index, {
    ...current,
    status: patch.status ?? current.status,
    owner: patch.owner ?? current.owner,
  })
}

export function addDemoNote(id: string, text: string): IncidentDetail {
  const trimmed = text.trim()
  if (!trimmed) {
    throw new ApiError('Note text is empty.')
  }
  const index = findIndex(id)
  const current = seed()[index]
  if (!current) {
    throw new ApiError(`Incident ${id} was not found.`, 404)
  }
  noteCounter += 1
  const note: Note = {
    id: `NOTE-${String(noteCounter).padStart(4, '0')}`,
    author: 'Analyst',
    time: new Date().toISOString(),
    text: trimmed,
  }
  return save(index, { ...current, notes: [...current.notes, note] })
}

export function saveDemoAnalyst(
  id: string,
  patch: AnalystPatch,
): IncidentDetail {
  const index = findIndex(id)
  const current = seed()[index]
  if (!current) {
    throw new ApiError(`Incident ${id} was not found.`, 404)
  }
  return save(index, {
    ...current,
    disposition: patch.disposition ?? current.disposition,
    summary: patch.summary ?? current.summary,
  })
}

export function logDemoDryRun(
  id: string,
  action: ResponseActionName,
  target: string,
): IncidentDetail {
  const index = findIndex(id)
  const current = seed()[index]
  if (!current) {
    throw new ApiError(`Incident ${id} was not found.`, 404)
  }
  auditCounter += 1
  const entry: ResponseAuditEntry = {
    id: `AUDIT-${String(auditCounter).padStart(4, '0')}`,
    action,
    target,
    time: new Date().toISOString(),
    message: DRY_RUN_MESSAGE,
  }
  return save(index, { ...current, audit: [...current.audit, entry] })
}

function assetFor(hosts: readonly string[]): {
  assetType: RiskAssetType
  multiplier: RiskMultiplier
} {
  if (hosts.includes('DC01')) {
    return { assetType: 'domain_controller', multiplier: 1.7 }
  }
  if (hosts.some((host) => host === 'UBU01' || host === 'WAZUH01')) {
    return { assetType: 'server', multiplier: 1.3 }
  }
  return { assetType: 'workstation', multiplier: 1 }
}

/** 10 points per promoted event Promotion weights stay at 10 until a written model replaces them. */
const PROMOTE_POINTS = 10

export function createDemoIncident(input: {
  title: string
  severity: Severity
  owner: string
  events: TimelineEvent[]
}): IncidentDetail {
  if (input.events.length === 0) {
    throw new ApiError('Select at least one hunt result.')
  }
  const events = [...input.events].sort((left, right) =>
    left.time.localeCompare(right.time),
  )
  const numbers = seed().map((item) => Number(item.id.replace('INC-', '')))
  const id = `INC-${String(Math.max(0, ...numbers) + 1).padStart(4, '0')}`
  const hosts = [...new Set(events.map((event) => event.host))]
  const users = [...new Set(events.map((event) => event.user))]
  const { assetType, multiplier } = assetFor(hosts)
  const subtotal = events.length * PROMOTE_POINTS
  const final = finalRiskScore(subtotal, multiplier)
  const mitre = new Map<string, MitreTechnique>()
  for (const event of events) {
    const detection = detectionFixtures.find((item) => item.id === event.ruleId)
    for (const technique of detection?.mitre ?? []) {
      mitre.set(technique.id, technique)
    }
  }
  const first = events[0]
  const last = events[events.length - 1]
  if (!first || !last) {
    throw new ApiError('Select at least one hunt result.')
  }
  const detail: IncidentDetail = {
    id,
    title: input.title.trim() || 'Promoted hunt',
    severity: input.severity,
    riskScore: final,
    status: 'New',
    owner: input.owner,
    users,
    hosts,
    mitre: [...mitre.values()],
    firstSeen: first.time,
    lastSeen: last.time,
    demo: true,
    timeline: events,
    entities: {
      users,
      hosts,
      srcIps: [],
      dstIps: [],
      processes: [],
      domains: [],
      hashes: [],
    },
    risk: {
      items: events.map((event) => ({
        event: event.title,
        ruleId: event.ruleId,
        points: PROMOTE_POINTS,
      })),
      subtotal,
      assetType,
      multiplier,
      final,
      severityBand: severityBandFor(final),
    },
    notes: [],
    disposition: 'Undetermined',
    summary: 'Promoted from a demo hunt. Not a lab finding.',
    recommendedContainment: ['Snapshot the lab VM before any change.'],
    audit: [],
  }
  seed().push(detail)
  pushToast(DEMO_SAVE_TOAST)
  return detail
}
