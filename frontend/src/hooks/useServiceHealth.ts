import { useEffect, useState } from 'react'
import { getDataMode } from '../services/config.ts'
import { fetchServiceHealth } from '../services/api.ts'

export type ServiceHealthState = 'local' | 'loading' | 'demo' | 'live' | 'down'

export function useServiceHealth(): ServiceHealthState {
  const frontend = getDataMode()
  const [state, setState] = useState<ServiceHealthState>(
    frontend === 'demo' ? 'local' : 'loading',
  )

  useEffect(() => {
    if (frontend === 'demo') return
    let cancelled = false
    fetchServiceHealth()
      .then((health) => {
        if (!cancelled) setState(health.mode === 'live' ? 'live' : 'demo')
      })
      .catch(() => {
        if (!cancelled) setState('down')
      })
    return () => {
      cancelled = true
    }
  }, [frontend])

  return state
}
