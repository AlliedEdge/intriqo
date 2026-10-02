import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { ApiError, clearAccessToken, getAccessToken, onUnauthorized, setAccessToken } from '@/api/client'
import { authApi } from '@/api'
import type { CurrentUser } from '@/types/api'

type AuthStatus = 'loading' | 'authenticated' | 'anonymous'

interface AuthContextValue {
  user: CurrentUser | null
  status: AuthStatus
  signIn: (username: string, password: string) => Promise<CurrentUser>
  signOut: () => void
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [status, setStatus] = useState<AuthStatus>('loading')

  useEffect(() => {
    let active = true
    const restoreSession = async () => {
      if (!getAccessToken()) {
        if (active) setStatus('anonymous')
        return
      }
      try {
        const currentUser = await authApi.me()
        if (active) {
          setUser(currentUser)
          setStatus('authenticated')
        }
      } catch {
        clearAccessToken()
        if (active) {
          setUser(null)
          setStatus('anonymous')
        }
      }
    }

    void restoreSession()
    return () => { active = false }
  }, [])

  useEffect(() => onUnauthorized(() => {
    setUser(null)
    setStatus('anonymous')
  }), [])

  const value = useMemo<AuthContextValue>(() => ({
    user,
    status,
    signIn: async (username, password) => {
      const token = await authApi.login(username, password)
      setAccessToken(token.access_token)
      try {
        const currentUser = await authApi.me()
        setUser(currentUser)
        setStatus('authenticated')
        return currentUser
      } catch (error) {
        clearAccessToken()
        setUser(null)
        setStatus('anonymous')
        if (error instanceof ApiError && error.status === 401) {
          throw new ApiError('The session could not be established. Please sign in again.', 401, 'SESSION_INVALID')
        }
        throw error
      }
    },
    signOut: () => {
      clearAccessToken()
      setUser(null)
      setStatus('anonymous')
    },
  }), [status, user])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside AuthProvider')
  return value
}
