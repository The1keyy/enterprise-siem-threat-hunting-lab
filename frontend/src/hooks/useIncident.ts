import { useCallback, useEffect, useState } from 'react'
import {
  addNote,
  ApiError,
  getIncident,
  logResponseDryRun,
  saveAnalyst,
  setChecklistItem,
  updateIncident,
} from '../services/api.ts'
import type {
  AnalystPatch,
  IncidentDetail,
  ResponseActionName,
} from '../types/incident.ts'
import type { IncidentStatus } from '../types/domain.ts'

type IncidentState = {
  data: IncidentDetail | null
  loading: boolean
  error: string | null
  notFound: boolean
  reload: () => void
  setStatus: (status: IncidentStatus) => Promise<void>
  setOwner: (owner: string) => Promise<void>
  addAnalystNote: (text: string) => Promise<void>
  saveAnalystFields: (patch: AnalystPatch) => Promise<void>
  confirmDryRun: (action: ResponseActionName, target: string) => Promise<void>
  setChecklist: (itemId: string, checked: boolean) => Promise<void>
}

function messageFrom(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error && error.message.length > 0) return error.message
  return 'The incident request failed.'
}

export function useIncident(id: string): IncidentState {
  const [data, setData] = useState<IncidentDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    getIncident(id)
      .then((result) => {
        if (cancelled) return
        setData(result)
        setError(null)
        setNotFound(false)
        setLoading(false)
      })
      .catch((caught: unknown) => {
        if (cancelled) return
        setData(null)
        setNotFound(caught instanceof ApiError && caught.status === 404)
        setError(messageFrom(caught))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [id, attempt])

  const apply = useCallback(async (task: Promise<IncidentDetail>) => {
    try {
      const next = await task
      setData(next)
      setError(null)
    } catch (caught: unknown) {
      setError(messageFrom(caught))
    }
  }, [])

  return {
    data,
    loading,
    error,
    notFound,
    reload: () => {
      setLoading(true)
      setError(null)
      setAttempt((current) => current + 1)
    },
    setStatus: (status) => apply(updateIncident(id, { status })),
    setOwner: (owner) => apply(updateIncident(id, { owner })),
    addAnalystNote: (text) => apply(addNote(id, text)),
    saveAnalystFields: (patch) => apply(saveAnalyst(id, patch)),
    confirmDryRun: (action, target) =>
      apply(logResponseDryRun(id, action, target)),
    setChecklist: (itemId, checked) =>
      apply(setChecklistItem(id, itemId, checked)),
  }
}
