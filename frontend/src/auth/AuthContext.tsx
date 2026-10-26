import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Navigate, Outlet, useNavigate } from 'react-router'
import { ErrorState } from '../components/ErrorState.tsx'
import { LoadingState } from '../components/LoadingState.tsx'
import { useAuth } from '../hooks/useAuth.ts'
import {
  ApiError,
  currentUser,
  login as loginRequest,
  logout as logoutRequest,
} from '../services/api.ts'
import { getDataMode } from '../services/config.ts'
import { AuthContext, type AuthValue } from './context.ts'

export function AuthProvider({ children }: { children: ReactNode }) {
  const mode = getDataMode()
  const navigate = useNavigate()
  const [username, setUsername] = useState<string | null>(null)
  const [ready, setReady] = useState(mode === 'demo')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (mode === 'demo') return
    let cancelled = false
    currentUser()
      .then((session) => {
        if (cancelled) return
        setUsername(session?.username ?? null)
        setReady(true)
      })
      .catch((caught: unknown) => {
        if (cancelled) return
        setError(
          caught instanceof ApiError ? caught.message : 'Cannot reach the API.',
        )
        setReady(true)
      })
    return () => {
      cancelled = true
    }
  }, [mode])

  const value = useMemo<AuthValue>(
    () => ({
      username,
      ready,
      error,
      login: async (nextUser, password) => {
        const session = await loginRequest(nextUser, password)
        setUsername(session.username)
        setError(null)
      },
      logout: async () => {
        await logoutRequest()
        setUsername(null)
        navigate('/login', { replace: true })
      },
    }),
    [error, navigate, ready, username],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function RequireAuth() {
  const mode = getDataMode()
  const { username, ready, error } = useAuth()
  if (mode === 'demo') return <Outlet />
  if (!ready) return <LoadingState label="Checking session" />
  if (error && !username) {
    return <ErrorState title="API unavailable" message={error} />
  }
  if (!username) return <Navigate to="/login" replace />
  return <Outlet />
}
