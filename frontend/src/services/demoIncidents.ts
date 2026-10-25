import { incidentFixtures } from '../fixtures/incidents.ts'
import { matchesFilters, type IncidentFilters } from '../lib/incidentFilters.ts'
import type {
  AnalystPatch,
  Incident,
  IncidentDetail,
  IncidentPatch,
  Note,
  ResponseActionName,
  ResponseAuditEntry,
} from '../types/incident.ts'
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
