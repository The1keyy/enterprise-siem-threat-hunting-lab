export type PeriodDelta = {
  previous: number
  current: number
  delta: number
}

function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0)
}

/** Split a fixture series in half. Returns null when there is no earlier half. */
export function periodDelta(values: readonly number[]): PeriodDelta | null {
  if (values.length < 2) return null
  const mid = Math.floor(values.length / 2)
  const previous = sum(values.slice(0, mid))
  const current = sum(values.slice(mid))
  return { previous, current, delta: current - previous }
}

export function formatDelta(delta: number): string {
  const sign = delta > 0 ? '+' : ''
  return `${sign}${delta} vs earlier half of this fixture`
}
