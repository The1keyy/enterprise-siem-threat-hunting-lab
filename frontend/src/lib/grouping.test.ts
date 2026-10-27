import { describe, expect, it } from 'vitest'
import { groupingChips } from './grouping.ts'

describe('groupingChips', () => {
  it('marks a shared user as strong and a host-only match as weak', () => {
    const chips = groupingChips([
      {
        user: 'sf-test-alice',
        host: 'WS01',
        raw: { data: { win: { eventdata: { ipAddress: '10.10.10.20' } } } },
      },
      {
        user: 'sf-test-alice',
        host: 'WS01',
        raw: {},
      },
      {
        user: '-',
        host: 'WS01',
        raw: {},
      },
    ])
    expect(chips[0]).toBeNull()
    expect(chips[1]).toEqual({
      strength: 'strong',
      label: 'Same user sf-test-alice',
    })
    expect(chips[2]).toEqual({
      strength: 'weak',
      label: 'Same host WS01 only',
    })
  })
})
