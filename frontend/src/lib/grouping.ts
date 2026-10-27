export type LinkChip = {
  strength: 'strong' | 'weak'
  label: string
}

type GroupEvent = {
  user: string
  host: string
  raw: Record<string, unknown>
}

const SKIP_IP = new Set(['', '-', '10.10.10.1', '127.0.0.1', '::1'])

function usableUser(user: string): string | null {
  const trimmed = user.trim()
  if (!trimmed || trimmed === '-' || trimmed.endsWith('$')) return null
  return trimmed
}

function readIp(raw: Record<string, unknown>): string | null {
  const data = raw.data
  if (!data || typeof data !== 'object') return null
  const record = data as Record<string, unknown>
  const direct = record.srcip
  if (typeof direct === 'string' && !SKIP_IP.has(direct)) return direct
  const win = record.win
  if (!win || typeof win !== 'object') return null
  const eventdata = (win as Record<string, unknown>).eventdata
  if (!eventdata || typeof eventdata !== 'object') return null
  const ip = (eventdata as Record<string, unknown>).ipAddress
  if (typeof ip === 'string' && !SKIP_IP.has(ip)) return ip
  return null
}

/**
 * Chips are read from fields already on the events. They are not a
 * correlation-engine result.
 */
export function groupingChips(
  events: readonly GroupEvent[],
): readonly (LinkChip | null)[] {
  return events.map((event, index) => {
    if (index === 0) return null
    const prior = events.slice(0, index)
    const user = usableUser(event.user)
    if (user && prior.some((item) => usableUser(item.user) === user)) {
      return { strength: 'strong', label: `Same user ${user}` }
    }
    const ip = readIp(event.raw)
    if (ip && prior.some((item) => readIp(item.raw) === ip)) {
      return { strength: 'strong', label: `Same source IP ${ip}` }
    }
    if (event.host && prior.some((item) => item.host === event.host)) {
      return { strength: 'weak', label: `Same host ${event.host} only` }
    }
    return null
  })
}
