export type ProcessView = {
  image: string | null
  commandLine: string | null
  parent: string | null
}

export type AuthView = {
  logonType: string | null
  sourceIp: string | null
  account: string | null
}

function record(value: unknown): Record<string, unknown> | null {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return null
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

function eventData(
  raw: Record<string, unknown>,
): Record<string, unknown> | null {
  const data = record(raw.data)
  const win = record(data?.win)
  return record(win?.eventdata)
}

export function readProcess(raw: Record<string, unknown>): ProcessView | null {
  const fields = eventData(raw)
  const audit = record(record(raw.data)?.audit)
  const image = text(fields?.image) ?? text(audit?.exe)
  const commandLine = text(fields?.commandLine) ?? text(audit?.command)
  const parent = text(fields?.parentImage) ?? text(fields?.parentCommandLine)
  if (!image && !commandLine && !parent) return null
  return { image, commandLine, parent }
}

export function readAuth(raw: Record<string, unknown>): AuthView | null {
  const fields = eventData(raw)
  const data = record(raw.data)
  const logonType = text(fields?.logonType)
  const sourceIp = text(fields?.ipAddress) ?? text(data?.srcip)
  const account =
    text(fields?.targetUserName) ?? text(data?.dstuser) ?? text(fields?.user)
  if (!logonType && !sourceIp && !account) return null
  return { logonType, sourceIp, account }
}
