import { useEffect, useState } from 'react'
import { subscribeToasts } from '../services/toasts.ts'

export function ToastViewport() {
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    let timer = 0
    const unsubscribe = subscribeToasts((next) => {
      setMessage(next)
      window.clearTimeout(timer)
      timer = window.setTimeout(() => setMessage(null), 2800)
    })
    return () => {
      unsubscribe()
      window.clearTimeout(timer)
    }
  }, [])

  if (!message) return null

  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-50">
      <p
        role="status"
        className="rounded-card border border-medium/40 bg-surface px-3 py-2 text-sm text-text shadow-card"
      >
        {message}
      </p>
    </div>
  )
}
