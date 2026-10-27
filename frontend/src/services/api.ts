import { incidentFixtures } from '../fixtures/incidents.ts'
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
import { noteDemo } from './demoNotice.ts'
import { pushToast } from './toasts.ts'
import {
  addDemoNote,
  createDemoIncident,
  getDemoIncident,
  listDemoIncidentDetails,
  listDemoIncidents,
  logDemoDryRun,
  saveDemoAnalyst,
  setDemoChecklist,
  updateDemoIncident,
} from './demoIncidents.ts'
import {
  buildHost,
  buildUser,
  listHosts,
  listUsers,
} from '../lib/entityModel.ts'
import {
  buildHealth,
  buildSettings,
  buildSources,
  buildWorkflows,
  demoCorrelationStatus,
} from '../lib/operationsModel.ts'
import type { EntityRow, HostProfile, UserProfile } from '../types/entity.ts'
import type {
  CorrelationStatus,
  DataSourceCard,
  HealthReport,
  SettingsView,
  Workflow,
} from '../types/operations.ts'
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

type SendOptions = {
  redirectOn401?: boolean
  notify?: boolean
}

const ACTION_CODES = {
  'Isolate lab endpoint': 'isolate_endpoint',
  'Disable test account': 'disable_account',
  'Block test IP': 'block_ip',
} as const

function apiPath(path: string): string {
  if (
    path.startsWith('/auth') ||
    path === '/health' ||
    path.startsWith('/api/')
  ) {
    return path
  }
  return `/api${path}`
}

function payloadIsDemo(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    'demo' in value &&
    value.demo === true
  )
}

function noteDemoPayload(payload: unknown): void {
  if (Array.isArray(payload)) {
    noteDemo(payload.some((item) => payloadIsDemo(item)))
    return
  }
  noteDemo(payloadIsDemo(payload))
}

function redirectToLogin(): void {
  if (window.location.pathname === '/login') return
  window.location.assign('/login')
}

async function liveSend<T>(
  path: string,
  method: string,
  body?: unknown,
  options: SendOptions = {},
): Promise<T> {
  const notify = options.notify !== false
  let response: Response
  try {
    response = await fetch(`${getApiUrl()}${apiPath(path)}`, {
      method,
      credentials: 'include',
      headers:
        body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    const error = new ApiError('Cannot reach the API.')
    if (notify) pushToast(error.message)
    throw error
  }
  if (response.status === 401) {
    if (options.redirectOn401 !== false) redirectToLogin()
    throw new ApiError('Sign in required.', 401)
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const payload = (await response.json()) as { detail?: unknown }
      if (typeof payload.detail === 'string' && payload.detail.length > 0) {
        detail = payload.detail
      }
    } catch {
      detail = `Request failed (${response.status})`
    }
    if (notify) pushToast(detail)
    throw new ApiError(detail, response.status)
  }
  const payload = (await response.json()) as T
  noteDemoPayload(payload)
  return payload
}

export type ServiceHealth = {
  status: string
  mode: 'demo' | 'live'
  version: string
}

export async function fetchServiceHealth(): Promise<ServiceHealth> {
  return liveSend<ServiceHealth>('/health', 'GET', undefined, {
    redirectOn401: false,
  })
}

export async function login(
  username: string,
  password: string,
): Promise<{ username: string }> {
  return liveSend('/auth/login', 'POST', { username, password }, {
    redirectOn401: false,
    notify: false,
  })
}

export async function logout(): Promise<void> {
  await liveSend('/auth/logout', 'POST', undefined, {
    redirectOn401: false,
    notify: false,
  })
}

export async function currentUser(): Promise<{ username: string } | null> {
  try {
    return await liveSend<{ username: string }>('/auth/me', 'GET', undefined, {
      redirectOn401: false,
      notify: false,
    })
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null
    throw error
  }
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

export async function getCorrelationStatus(): Promise<CorrelationStatus> {
  if (getDataMode() === 'demo') return demoCorrelationStatus(incidentFixtures)
  const body = await liveSend<{
    enabled: boolean
    lastRun: string | null
    checkpoint: { timestamp: string; id: string } | null
    alertsProcessed: number
    error: string | null
    note?: string
  }>('/correlation/status', 'GET')
  return {
    enabled: body.enabled,
    lastRun: body.lastRun,
    checkpoint: body.checkpoint,
    alertsProcessed: body.alertsProcessed,
    error: body.error,
    note:
      body.note ??
      (body.error
        ? body.error
        : body.enabled
          ? 'The poller reads alerts whose rule group is sentinelforge.'
          : 'The background poller is off.'),
  }
}

export async function setChecklistItem(
  id: string,
  itemId: string,
  checked: boolean,
): Promise<IncidentDetail> {
  if (getDataMode() === 'demo') return setDemoChecklist(id, itemId, checked)
  return liveSend<IncidentDetail>(
    `/incidents/${encodeURIComponent(id)}/checklist/${encodeURIComponent(itemId)}`,
    'PATCH',
    { checked },
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
  const result = await liveSend<{ message: string }>(
    `/incidents/${encodeURIComponent(id)}/actions`,
    'POST',
    { action: ACTION_CODES[action], target, confirm: true },
  )
  pushToast(result.message)
  return getIncident(id)
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

export async function listEntityUsers(): Promise<EntityRow[]> {
  if (getDataMode() === 'demo') return listUsers(listDemoIncidentDetails())
  return liveSend<EntityRow[]>('/entities/users', 'GET')
}

export async function listEntityHosts(): Promise<EntityRow[]> {
  if (getDataMode() === 'demo') return listHosts(listDemoIncidentDetails())
  return liveSend<EntityRow[]>('/entities/hosts', 'GET')
}

export async function getUserProfile(name: string): Promise<UserProfile> {
  if (getDataMode() === 'demo') {
    const profile = buildUser(listDemoIncidentDetails(), name)
    if (!profile) throw new ApiError(`User ${name} was not found.`, 404)
    return profile
  }
  return liveSend<UserProfile>(
    `/entities/users/${encodeURIComponent(name)}`,
    'GET',
  )
}

export async function getHostProfile(name: string): Promise<HostProfile> {
  if (getDataMode() === 'demo') {
    const profile = buildHost(listDemoIncidentDetails(), name)
    if (!profile) throw new ApiError(`Host ${name} was not found.`, 404)
    return profile
  }
  return liveSend<HostProfile>(
    `/entities/hosts/${encodeURIComponent(name)}`,
    'GET',
  )
}

export async function listSources(): Promise<DataSourceCard[]> {
  if (getDataMode() === 'demo') return buildSources(listDemoIncidentDetails())
  return liveSend<DataSourceCard[]>('/sources', 'GET')
}

export async function getHealth(): Promise<HealthReport> {
  if (getDataMode() === 'demo') {
    const enabled = listDemoDetections().filter((item) => item.enabled).length
    return buildHealth(enabled)
  }
  return liveSend<HealthReport>('/system/health', 'GET')
}

export async function listWorkflows(): Promise<Workflow[]> {
  if (getDataMode() === 'demo') return buildWorkflows()
  return liveSend<Workflow[]>('/automation', 'GET')
}

export async function getSettings(): Promise<SettingsView> {
  if (getDataMode() === 'demo') {
    return buildSettings({ dataMode: getDataMode(), apiUrl: getApiUrl() })
  }
  return liveSend<SettingsView>('/settings', 'GET')
}

/** Lab actions are not executed from the browser. The UI must not call this. */
export function executeResponseAction(): never {
  throw new Error('LAB ONLY response actions are not executed from the browser')
}
