import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

const script = path.resolve('scripts/assert-demo-build.mjs')

function run(extra) {
  return spawnSync(process.execPath, [script], {
    env: { VERCEL: '1', ...extra },
    encoding: 'utf8',
  })
}

describe('assert-demo-build', () => {
  it('allows the Vercel observability variable', () => {
    const result = run({ VITE_VERCEL_OBSERVABILITY_CLIENT_CONFIG: '{}' })
    expect(result.status).toBe(0)
    expect(result.stdout).toContain(
      'Allowing Vercel system variables: VITE_VERCEL_OBSERVABILITY_CLIENT_CONFIG',
    )
  })

  it('refuses VITE_API_URL', () => {
    const result = run({ VITE_API_URL: 'http://x' })
    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('VITE_API_URL')
  })

  it('refuses live mode', () => {
    const result = run({ VITE_DATA_MODE: 'live' })
    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('demo-only')
  })
})
