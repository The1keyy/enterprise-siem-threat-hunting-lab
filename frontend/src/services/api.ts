import { overviewFixture } from '../fixtures/overview.ts'
import type { IncidentFilters } from '../lib/incidentFilters.ts'
import type {
  AnalystPatch,
  Incident,
  IncidentDetail,
  IncidentPatch,
  ResponseActionName,
} from '../types/incident.ts'
import { ApiError } from './apiError.ts'
import { getApiUrl, getDataMode } from './config.ts'
import {
  addDemoNote,
  createDemoIncident,
  getDemoIncident,
  listDemoIncidents,
  logDemoDryRun,
  saveDemoAnalyst,
  updateDemoIncident,
} from './demoIncidents.ts'
import {
  getDemoDetection,
  listDemoDetections,
  listDemoHunts,
  runDemoHunt,
  setDemoDetectionEnabled,
} from './demoCatalog.ts'
import type { Detection } from '../types/detection.ts'
import type { Hunt, HuntFilters, HuntRunResult } from '../types/hunt.ts'
import type { Severity } from '../types/domain.ts'
import type { TimelineEvent } from '../types/incident.ts'

export { ApiError } from './apiError.ts'

/**
 * Typed data client. Components import this module and do not call fetch.
 * Demo mode reads src/fixtures. Live mode calls the backend.
 * executeResponseAction is intentionally unused by the UI. Calling it is a bug.
 */

const demoFixtures = new Map<string, unknown>([['/overview', overviewFixture]])

function loadDemoFixture<T>(path: string): T {
  if (!demoFixtures.has(path)) {
    throw new ApiError(`No demo fixture for ${path}.`)
  }
  return demoFixtures.get(path) as T
}

async function liveSend<T>(
  path: string,
  method: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(`${getApiUrl()}${path}`, {
    method,
    headers:
      body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    throw new ApiError(`Request failed (${response.status})`, response.status)
  }
  return (await response.json()) as T
}

export async function apiGet<T>(path: string): Promise<T> {
  if (getDataMode() === 'demo') {
    return loadDemoFixture<T>(path)
  }
  return liveSend<T>(path, 'GET')
}

function incidentQuery(filters: IncidentFilters): string {
  const params = new URLSearchParams()
  if (filters.severities.length > 0) {
    params.set('severity', filters.severities.join(','))
  }
  if (filters.statuses.length > 0) {
    params.set('status', filters.statuses.join(','))
  }
  if (filters.user.trim()) params.set('user', filters.user.trim())
  if (filters.host) params.set('host', filters.host)
  if (filters.technique) params.set('technique', filters.technique)
  if (filters.from) params.set('from', filters.from)
  if (filters.to) params.set('to', filters.to)
  const query = params.toString()
  return query ? `?${query}` : ''
}

export async function listIncidents(
  filters: IncidentFilters,
): Promise<Incident[]> {
  if (getDataMode() === 'demo') {
    return listDemoIncidents(filters)
  }
  return liveSend<Incident[]>(`/incidents${incidentQuery(filters)}`, 'GET')
}

export async function getIncident(id: string): Promise<IncidentDetail> {
  if (getDataMode() === 'demo') {
    return getDemoIncident(id)
  }
  return liveSend<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`, 'GET')
}

export async function updateIncident(
  id: string,
  patch: IncidentPatch,
): Promise<IncidentDetail> {
  if (getDataMode() === 'demo') {
    return updateDemoIncident(id, patch)
  }
  return liveSend<IncidentDetail>(
    `/incidents/${encodeURIComponent(id)}`,
    'PATCH',
    patch,
  )
}

export async function addNote(
  id: string,
  text: string,
): Promise<IncidentDetail> {
  if (getDataMode() === 'demo') {
    return addDemoNote(id, text)
  }
  return liveSend<IncidentDetail>(
    `/incidents/${encodeURIComponent(id)}/notes`,
    'POST',
    { text },
  )
}

export async function saveAnalyst(
  id: string,
  patch: AnalystPatch,
): Promise<IncidentDetail> {
  if (getDataMode() === 'demo') {
    return saveDemoAnalyst(id, patch)
  }
  return liveSend<IncidentDetail>(
    `/incidents/${encodeURIComponent(id)}/analyst`,
    'PATCH',
    patch,
  )
}

export async function logResponseDryRun(
  id: string,
  action: ResponseActionName,
  target: string,
): Promise<IncidentDetail> {
  if (getDataMode() === 'demo') {
    return logDemoDryRun(id, action, target)
  }
  return liveSend<IncidentDetail>(
    `/incidents/${encodeURIComponent(id)}/response`,
    'POST',
    { action, target, dryRun: true },
  )
}

export async function listDetections(): Promise<Detection[]> {
  if (getDataMode() === 'demo') return listDemoDetections()
  return liveSend<Detection[]>('/detections', 'GET')
}

export async function getDetection(id: string): Promise<Detection> {
  if (getDataMode() === 'demo') return getDemoDetection(id)
  return liveSend<Detection>(`/detections/${encodeURIComponent(id)}`, 'GET')
}

export async function setDetectionEnabled(
  id: string,
  enabled: boolean,
): Promise<Detection> {
  if (getDataMode() === 'demo') return setDemoDetectionEnabled(id, enabled)
  return liveSend<Detection>(`/detections/${encodeURIComponent(id)}`, 'PATCH', {
    enabled,
  })
}

export async function listHunts(): Promise<Hunt[]> {
  if (getDataMode() === 'demo') return listDemoHunts()
  return liveSend<Hunt[]>('/hunts', 'GET')
}

export async function runHunt(
  id: string,
  filters: HuntFilters,
  query: string,
): Promise<HuntRunResult> {
  if (getDataMode() === 'demo') return runDemoHunt(id, filters, query)
  return liveSend<HuntRunResult>('/hunts/run', 'POST', {
    id,
    query,
    ...filters,
  })
}

export async function promoteHunt(input: {
  title: string
  severity: Severity
  owner: string
  events: TimelineEvent[]
}): Promise<IncidentDetail> {
  if (getDataMode() === 'demo') return createDemoIncident(input)
  return liveSend<IncidentDetail>('/incidents', 'POST', input)
}

/** Lab actions are not executed from the browser. The UI must not call this. */
export function executeResponseAction(): never {
  throw new Error('LAB ONLY response actions are not executed from the browser')
}
