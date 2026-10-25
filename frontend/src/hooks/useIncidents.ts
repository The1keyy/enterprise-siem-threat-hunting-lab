import { useEffect, useState } from 'react'
import type { IncidentFilters } from '../lib/incidentFilters.ts'
import { ApiError, listIncidents } from '../services/api.ts'
import type { Incident } from '../types/incident.ts'

type IncidentsState = {
  data: Incident[] | null
  loading: boolean
  error: string | null
  reload: () => void
}

function messageFrom(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error && error.message.length > 0) return error.message
  return 'The incidents request failed.'
}

export function useIncidents(filters: IncidentFilters): IncidentsState {
  const [data, setData] = useState<Incident[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const filterKey = JSON.stringify(filters)

  useEffect(() => {
    let cancelled = false
    const parsed = JSON.parse(filterKey) as IncidentFilters
    listIncidents(parsed)
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
  }, [filterKey, attempt])

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
