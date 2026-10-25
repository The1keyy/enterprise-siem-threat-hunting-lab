import { useCallback, useEffect, useState } from 'react'
import {
  ApiError,
  getDetection,
  listDetections,
  setDetectionEnabled,
} from '../services/api.ts'
import type { Detection } from '../types/detection.ts'

function messageFrom(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error && error.message.length > 0) return error.message
  return 'The detections request failed.'
}

export function useDetections() {
  const [data, setData] = useState<Detection[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    listDetections()
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

  const toggleEnabled = useCallback(async (id: string, enabled: boolean) => {
    const next = await setDetectionEnabled(id, enabled)
    setData(
      (current) =>
        current?.map((item) => (item.id === id ? next : item)) ?? null,
    )
  }, [])

  return {
    data,
    loading,
    error,
    toggleEnabled,
    reload: () => {
      setLoading(true)
      setError(null)
      setAttempt((current) => current + 1)
    },
  }
}

export function useDetection(id: string) {
  const [data, setData] = useState<Detection | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    getDetection(id)
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
        setError(messageFrom(caught))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [id, attempt])

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
