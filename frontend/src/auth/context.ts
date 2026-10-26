import { createContext } from 'react'

export type AuthValue = {
  username: string | null
  ready: boolean
  error: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthValue | null>(null)
