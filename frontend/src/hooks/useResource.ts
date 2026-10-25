import { useEffect, useState } from 'react'
import { ApiError } from '../services/api.ts'

function messageFrom(error: unknown, fallback: string): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error && error.message.length > 0) return error.message
  return fallback
}

export function useResource<T>(
  load: () => Promise<T>,
  key: string,
  fallback: string,
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    load()
      .then((result) => {
        if (cancelled) return
        setData(result)
        setNotFound(false)
        setError(null)
        setLoading(false)
      })
      .catch((caught: unknown) => {
        if (cancelled) return
        setData(null)
        setNotFound(caught instanceof ApiError && caught.status === 404)
        setError(messageFrom(caught, fallback))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [attempt, key, fallback, load])

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
  }
}
