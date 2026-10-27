import { useState, type FormEvent } from 'react'
import { Navigate } from 'react-router'
import { useAuth } from '../hooks/useAuth.ts'
import { ApiError } from '../services/api.ts'
import { getDataMode } from '../services/config.ts'

export function LoginPage() {
  const auth = useAuth()
  const [username, setUsername] = useState('analyst')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (getDataMode() === 'demo' || auth.username) {
    return <Navigate to="/" replace />
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await auth.login(username.trim(), password)
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : 'Cannot reach the API.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg px-4 text-text">
      <form
        className="w-full max-w-sm rounded-card border border-border bg-surface p-6"
        onSubmit={(event) => void submit(event)}
      >
        <h1 className="text-lg font-semibold">SentinelForge</h1>
        <p className="mt-1 text-sm text-text-muted">
          Sign in to the lab console.
        </p>
        <label className="mt-4 block text-sm" htmlFor="username">
          Username
        </label>
        <input
          id="username"
          name="username"
          autoComplete="username"
          className="mt-1 w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
        />
        <label className="mt-3 block text-sm" htmlFor="password">
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          className="mt-1 w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        {error ? (
          <p className="mt-3 text-sm text-critical" role="alert">
            {error}
          </p>
        ) : null}
        <button
          type="submit"
          className="mt-4 w-full rounded-md border border-accent/40 bg-accent/15 px-3 py-2 text-sm text-accent disabled:opacity-50"
          disabled={busy || username.trim().length === 0 || password.length === 0}
        >
          {busy ? 'Signing in' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
