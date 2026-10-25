import { overviewFixture } from '../fixtures/overview.ts'
import { detectionName } from './detectionCatalog.ts'
import { labAsset } from './labAssets.ts'
import { finalRiskScore } from './risk.ts'
import type {
  EntityRow,
  HostConnection,
  HostProfile,
  LoginRow,
  RiskLine,
  UserProfile,
} from '../types/entity.ts'
import type {
  IncidentDetail,
  MitreTechnique,
  TimelineEvent,
} from '../types/incident.ts'

const DEMO_END = Date.parse(overviewFixture.generatedAt)

function record(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return null
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

function eventData(event: TimelineEvent): Record<string, unknown> | null {
  const data = record(event.raw.data)
  const win = record(data?.win)
  return record(win?.eventdata)
}

function involvesUser(incident: IncidentDetail, name: string): boolean {
  if (incident.users.includes(name) || incident.entities.users.includes(name)) {
    return true
  }
  return incident.timeline.some((event) => event.user === name)
}

function involvesHost(incident: IncidentDetail, name: string): boolean {
  if (incident.hosts.includes(name) || incident.entities.hosts.includes(name)) {
    return true
  }
  return incident.timeline.some((event) => event.host === name)
}

function linesFor(incidents: readonly IncidentDetail[]): RiskLine[] {
  return incidents.map((incident) => ({
    incidentId: incident.id,
    title: incident.title,
    subtotal: incident.risk.subtotal,
    multiplier: incident.risk.multiplier,
    assetType: incident.risk.assetType,
    final: finalRiskScore(incident.risk.subtotal, incident.risk.multiplier),
  }))
}

function historyFor(
  incidents: readonly IncidentDetail[],
): { label: string; score: number }[] {
  const end = new Date(DEMO_END)
  return Array.from({ length: 7 }, (_, index) => {
    const day = new Date(end)
    day.setUTCDate(end.getUTCDate() - (6 - index))
    const key = day.toISOString().slice(0, 10)
    const score = incidents
      .filter((incident) => incident.lastSeen.slice(0, 10) === key)
      .reduce(
        (sum, incident) =>
          sum +
          finalRiskScore(incident.risk.subtotal, incident.risk.multiplier),
        0,
      )
    return { label: key.slice(5), score }
  })
}

function lastActivity(incidents: readonly IncidentDetail[]): string | null {
  const times = incidents.flatMap((incident) =>
    incident.timeline.map((event) => event.time),
  )
  if (times.length === 0) return null
  return times.sort().at(-1) ?? null
}

function summary(
  name: string,
  incidents: readonly IncidentDetail[],
): EntityRow {
  const lines = linesFor(incidents)
  return {
    name,
    riskScore: lines.reduce((sum, line) => sum + line.final, 0),
    incidentIds: incidents.map((incident) => incident.id),
    lastActivity: lastActivity(incidents),
  }
}

function loginFrom(event: TimelineEvent): LoginRow | null {
  const data = record(event.raw.data)
  const fields = eventData(event)
  if (event.eventId === '4624' || event.eventId === '4625') {
    return {
      time: event.time,
      host: event.host,
      sourceIp: text(fields?.ipAddress) ?? '—',
      logonType: text(fields?.logonType) ?? '—',
      result: event.eventId === '4624' ? 'success' : 'fail',
    }
  }
  if (event.eventId === 'sshd-accepted' || event.eventId === 'sshd-failed') {
    return {
      time: event.time,
      host: event.host,
      sourceIp: text(data?.srcip) ?? '—',
      logonType: 'ssh',
      result: event.eventId === 'sshd-accepted' ? 'success' : 'fail',
    }
  }
  return null
}

function uniqueMitre(incidents: readonly IncidentDetail[]): MitreTechnique[] {
  const seen = new Map<string, MitreTechnique>()
  for (const incident of incidents) {
    for (const technique of incident.mitre) seen.set(technique.id, technique)
  }
  return [...seen.values()]
}

function detectionLinks(events: readonly TimelineEvent[]) {
  const ids = [...new Set(events.map((event) => event.ruleId))]
  return ids.map((id) => ({ id, name: detectionName(id) }))
}

export function listUsers(incidents: readonly IncidentDetail[]): EntityRow[] {
  const names = new Set<string>()
  for (const incident of incidents) {
    for (const name of incident.users) names.add(name)
    for (const name of incident.entities.users) names.add(name)
    for (const event of incident.timeline) names.add(event.user)
  }
  return [...names]
    .map((name) =>
      summary(
        name,
        incidents.filter((incident) => involvesUser(incident, name)),
      ),
    )
    .sort((left, right) => right.riskScore - left.riskScore)
}

export function listHosts(incidents: readonly IncidentDetail[]): EntityRow[] {
  const names = new Set<string>()
  for (const incident of incidents) {
    for (const name of incident.hosts) names.add(name)
    for (const name of incident.entities.hosts) names.add(name)
    for (const event of incident.timeline) names.add(event.host)
  }
  return [...names]
    .map((name) =>
      summary(
        name,
        incidents.filter((incident) => involvesHost(incident, name)),
      ),
    )
    .sort((left, right) => right.riskScore - left.riskScore)
}

export function buildUser(
  incidents: readonly IncidentDetail[],
  name: string,
): UserProfile | null {
  const related = incidents.filter((incident) => involvesUser(incident, name))
  if (related.length === 0) return null
  const events = related.flatMap((incident) =>
    incident.timeline.filter(
      (event) => event.user === name || incident.users.includes(name),
    ),
  )
  const logins = events
    .map(loginFrom)
    .filter((row): row is LoginRow => row !== null)
    .sort((left, right) => right.time.localeCompare(left.time))
  const sourceIps = [
    ...new Set([
      ...logins.map((row) => row.sourceIp).filter((ip) => ip !== '—'),
      ...related.flatMap((incident) => incident.entities.srcIps),
    ]),
  ]
  const endpoints = [...new Set(related.flatMap((incident) => incident.hosts))]
  return {
    ...summary(name, related),
    sourceIps,
    endpoints,
    detections: detectionLinks(events),
    incidents: related.map((incident) => ({
      id: incident.id,
      name: incident.title,
    })),
    mitre: uniqueMitre(related),
    logins,
    history: historyFor(related),
    lines: linesFor(related),
  }
}

function processName(event: TimelineEvent): string | null {
  const fields = eventData(event)
  const image = text(fields?.image)
  if (image) {
    const parts = image.split('\\')
    return parts.at(-1) ?? image
  }
  const data = record(event.raw.data)
  const audit = record(data?.audit)
  const exe = text(audit?.exe)
  if (exe) return exe.split('/').at(-1) ?? exe
  return null
}

function connectionsFor(
  events: readonly TimelineEvent[],
  host: string,
): HostConnection[] {
  const asset = labAsset(host)
  const dst = asset?.ip ?? host
  const rows: HostConnection[] = []
  for (const event of events) {
    const fields = eventData(event)
    const data = record(event.raw.data)
    const src = text(fields?.ipAddress) ?? text(data?.srcip)
    if (!src) continue
    const share = text(fields?.shareName)
    rows.push({
      time: event.time,
      src,
      dst,
      detail: share ? `${event.title} (${share})` : event.title,
    })
  }
  return rows.sort((left, right) => right.time.localeCompare(left.time))
}

export function buildHost(
  incidents: readonly IncidentDetail[],
  name: string,
): HostProfile | null {
  const asset = labAsset(name)
  const related = incidents.filter((incident) => involvesHost(incident, name))
  if (!asset || related.length === 0) return null
  const events = related.flatMap((incident) =>
    incident.timeline.filter((event) => event.host === name),
  )
  const counts = new Map<string, number>()
  for (const incident of related) {
    if (
      !incident.hosts.includes(name) &&
      !incident.entities.hosts.includes(name)
    ) {
      continue
    }
    for (const process of incident.entities.processes) {
      counts.set(process, (counts.get(process) ?? 0) + 1)
    }
  }
  for (const event of events) {
    const process = processName(event)
    if (process) counts.set(process, (counts.get(process) ?? 0) + 1)
  }
  return {
    ...summary(name, related),
    ip: asset.ip,
    os: asset.os,
    assetType: asset.assetType,
    multiplier: asset.multiplier,
    agentStatus: 'never connected',
    users: [...new Set(related.flatMap((incident) => incident.users))],
    processes: [...counts.entries()]
      .map(([processName, count]) => ({ name: processName, count }))
      .sort((left, right) => right.count - left.count),
    detections: detectionLinks(events),
    incidents: related.map((incident) => ({
      id: incident.id,
      name: incident.title,
    })),
    connections: connectionsFor(events, name),
    history: historyFor(related),
    lines: linesFor(related),
  }
}
