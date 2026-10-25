import { useEffect, useState } from 'react'
import { ApiError, apiGet } from '../services/api.ts'
import type { OverviewData } from '../types/overview.ts'

export const OVERVIEW_PATH = '/overview'

type OverviewState = {
  data: OverviewData | null
  loading: boolean
  error: string | null
  reload: () => void
}

function messageFrom(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error && error.message.length > 0) return error.message
  return 'The overview request failed.'
}

export function useOverview(): OverviewState {
  const [data, setData] = useState<OverviewData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    apiGet<OverviewData>(OVERVIEW_PATH)
      .then((result) => {
        if (cancelled) return
        setData(result)
        setError(null)
        setLoading(false)
      })
      .catch((caught: unknown) => {
        if (cancelled) return
        setData(null)
        setError(messageFrom(caught))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [attempt])

  return {
    data,
    loading,
    error,
    reload: () => {
      setLoading(true)
      setError(null)
      setAttempt((current) => current + 1)
    },
  }
}
