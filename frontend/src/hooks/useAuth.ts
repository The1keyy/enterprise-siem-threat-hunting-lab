import { useContext } from 'react'
import { AuthContext, type AuthValue } from '../auth/context.ts'

const missing = new Error('AuthProvider is missing')

const guest: AuthValue = {
  username: null,
  ready: true,
  error: null,
  login: () => Promise.reject(missing),
  logout: () => Promise.reject(missing),
}

export function useAuth(): AuthValue {
  return useContext(AuthContext) ?? guest
}
