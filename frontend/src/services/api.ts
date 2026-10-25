import { overviewFixture } from '../fixtures/overview.ts'
import { getApiUrl, getDataMode } from './config.ts'

/**
 * Typed data client. Components import this module and do not call fetch.
 * Demo mode reads src/fixtures. Live mode calls the backend.
 */

export class ApiError extends Error {
  readonly status: number | undefined

  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

const demoFixtures = new Map<string, unknown>([['/overview', overviewFixture]])

function loadDemoFixture<T>(path: string): T {
  if (!demoFixtures.has(path)) {
    throw new ApiError(`No demo fixture for ${path}.`)
  }
  return demoFixtures.get(path) as T
}

async function liveGet<T>(path: string): Promise<T> {
  const response = await fetch(`${getApiUrl()}${path}`)
  if (!response.ok) {
    throw new ApiError(`Request failed (${response.status})`, response.status)
  }
  return (await response.json()) as T
}

export async function apiGet<T>(path: string): Promise<T> {
  if (getDataMode() === 'demo') {
    return loadDemoFixture<T>(path)
  }
  return liveGet<T>(path)
}
