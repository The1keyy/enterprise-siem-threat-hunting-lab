import { describe, expect, it } from 'vitest'
import { overviewFixture } from '../fixtures/overview.ts'
import { periodDelta } from './periodDelta.ts'

describe('periodDelta', () => {
  it('compares the two halves of the overview alert buckets', () => {
    const critical = overviewFixture.alertsOverTime.map(
      (bucket) => bucket.critical,
    )
    const high = overviewFixture.alertsOverTime.map((bucket) => bucket.high)
    expect(periodDelta(critical)).toEqual({
      previous: 1,
      current: 5,
      delta: 4,
    })
    expect(periodDelta(high)).toEqual({
      previous: 6,
      current: 11,
      delta: 5,
    })
  })

  it('returns null when the series has no earlier half', () => {
    expect(periodDelta([])).toBeNull()
    expect(periodDelta([4])).toBeNull()
  })
})
