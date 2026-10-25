import { useEffect, useState } from 'react'
import { ApiError, listHunts, promoteHunt, runHunt } from '../services/api.ts'
import type { Severity } from '../types/domain.ts'
import type {
  Hunt,
  HuntFilters,
  HuntHit,
  HuntRunResult,
} from '../types/hunt.ts'
import type { IncidentDetail, TimelineEvent } from '../types/incident.ts'

function messageFrom(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error && error.message.length > 0) return error.message
  return 'The hunt request failed.'
}

export function useHunts() {
  const [data, setData] = useState<Hunt[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    listHunts()
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

export function useHuntRun() {
  const [result, setResult] = useState<HuntRunResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function execute(id: string, filters: HuntFilters, query: string) {
    setLoading(true)
    setError(null)
    try {
      setResult(await runHunt(id, filters, query))
    } catch (caught: unknown) {
      setResult(null)
      setError(messageFrom(caught))
    } finally {
      setLoading(false)
    }
  }

  return { result, loading, error, execute }
}

export async function promoteHits(input: {
  title: string
  severity: Severity
  owner: string
  hits: HuntHit[]
}): Promise<IncidentDetail> {
  const events: TimelineEvent[] = input.hits.map((hit) => ({
    time: hit.time,
    title: hit.title,
    source: hit.source,
    host: hit.host,
    user: hit.user,
    eventId: hit.eventId,
    ruleId: hit.ruleId,
    severity: hit.severity,
    raw: hit.raw,
  }))
  return promoteHunt({
    title: input.title,
    severity: input.severity,
    owner: input.owner,
    events,
  })
}
