import {
  INCIDENT_STATUSES,
  SEVERITIES,
  type IncidentStatus,
  type Severity,
} from '../types/domain.ts'
import type { Incident } from '../types/incident.ts'

export const LAB_HOSTS = ['DC01', 'WS01', 'UBU01', 'WAZUH01'] as const

export const TECHNIQUE_OPTIONS = [
  { id: 'T1021.001', name: 'Remote Desktop Protocol' },
  { id: 'T1021.002', name: 'SMB / Windows Admin Shares' },
  { id: 'T1021.006', name: 'Windows Remote Management' },
  { id: 'T1053.005', name: 'Scheduled Task' },
  { id: 'T1059.001', name: 'PowerShell' },
  { id: 'T1059.004', name: 'Unix Shell' },
  { id: 'T1078', name: 'Valid Accounts' },
  { id: 'T1098', name: 'Account Manipulation' },
  { id: 'T1110.001', name: 'Password Guessing' },
  { id: 'T1110.003', name: 'Password Spraying' },
  { id: 'T1136.001', name: 'Local Account' },
] as const

export type IncidentFilters = {
  severities: Severity[]
  statuses: IncidentStatus[]
  user: string
  host: string
  technique: string
  from: string
  to: string
}

export const EMPTY_FILTERS: IncidentFilters = {
  severities: [],
  statuses: [],
  user: '',
  host: '',
  technique: '',
  from: '',
  to: '',
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value)
}

function isStatus(value: string): value is IncidentStatus {
  return (INCIDENT_STATUSES as readonly string[]).includes(value)
}

function readList<T extends string>(
  params: URLSearchParams,
  key: string,
  guard: (value: string) => value is T,
): T[] {
  const raw = params.get(key)
  if (!raw) return []
  return raw.split(',').filter(guard)
}

export function filtersFromSearch(params: URLSearchParams): IncidentFilters {
  return {
    severities: readList(params, 'severity', isSeverity),
    statuses: readList(params, 'status', isStatus),
    user: params.get('user') ?? '',
    host: params.get('host') ?? '',
    technique: params.get('technique') ?? '',
    from: params.get('from') ?? '',
    to: params.get('to') ?? '',
  }
}

export function searchFromFilters(filters: IncidentFilters): URLSearchParams {
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
  return params
}

function day(iso: string): string {
  return iso.slice(0, 10)
}

export function matchesFilters(
  incident: Incident,
  filters: IncidentFilters,
): boolean {
  if (
    filters.severities.length > 0 &&
    !filters.severities.includes(incident.severity)
  ) {
    return false
  }
  if (
    filters.statuses.length > 0 &&
    !filters.statuses.includes(incident.status)
  ) {
    return false
  }
  const userQuery = filters.user.trim().toLowerCase()
  if (
    userQuery &&
    !incident.users.some((user) => user.toLowerCase().includes(userQuery))
  ) {
    return false
  }
  if (filters.host && !incident.hosts.includes(filters.host)) {
    return false
  }
  if (
    filters.technique &&
    !incident.mitre.some((item) => item.id === filters.technique)
  ) {
    return false
  }
  const seen = day(incident.lastSeen)
  if (filters.from && seen < filters.from) return false
  if (filters.to && seen > filters.to) return false
  return true
}
