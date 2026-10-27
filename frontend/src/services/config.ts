import type { DataMode } from '../types/domain.ts'

const MODE: DataMode =
  import.meta.env.VITE_DATA_MODE === 'live' ? 'live' : 'demo'

export function getDataMode(): DataMode {
  return MODE
}

export function getApiUrl(): string {
  if (MODE === 'demo') return ''
  const configured = import.meta.env.VITE_API_URL
  // An empty value uses the page origin. Vite's dev server proxies /api, /auth, and /health.
  if (configured === '') return ''
  if (typeof configured === 'string' && configured.length > 0) {
    return configured.replace(/\/$/, '')
  }
  return 'http://127.0.0.1:8000'
}
