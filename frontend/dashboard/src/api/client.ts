import type { ErrorEnvelope } from '@/types/api'

const configuredApiBase = import.meta.env.VITE_API_BASE_URL?.trim()
const API_BASE = (configuredApiBase || '/api/v1').replace(/\/$/, '')
const TOKEN_KEY = 'intriqo.access-token'
const AUTH_EVENT = 'intriqo:unauthorized'

export class ApiError extends Error {
  status: number
  code: string

  constructor(message: string, status: number, code = 'API_ERROR') {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

/** Session-only bearer storage matches the existing JWT API; never render or log it. */
export function getAccessToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY)
}

export function setAccessToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token)
}

export function clearAccessToken(): void {
  sessionStorage.removeItem(TOKEN_KEY)
}

export function onUnauthorized(callback: () => void): () => void {
  window.addEventListener(AUTH_EVENT, callback)
  return () => window.removeEventListener(AUTH_EVENT, callback)
}

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`
}

export function queryString(params: object = {}): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value))
  }
  const value = search.toString()
  return value ? `?${value}` : ''
}

type ApiOptions = Omit<RequestInit, 'body'> & { body?: unknown; authenticated?: boolean }

export async function request<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const { body, authenticated = true, ...rest } = options
  const headers = new Headers(rest.headers)
  headers.set('Accept', 'application/json')
  if (body !== undefined) headers.set('Content-Type', 'application/json')
  const token = authenticated ? getAccessToken() : null
  if (token) headers.set('Authorization', `Bearer ${token}`)

  let response: Response
  try {
    response = await fetch(apiUrl(path), {
      ...rest,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError('Unable to reach the control plane. Check your connection and try again.', 0, 'NETWORK_ERROR')
  }

  if (!response.ok) {
    let payload: ErrorEnvelope = {}
    try { payload = await response.json() as ErrorEnvelope } catch { /* Non-JSON proxy response. */ }
    if (response.status === 401 && authenticated) {
      clearAccessToken()
      window.dispatchEvent(new Event(AUTH_EVENT))
    }
    const fallback = response.status === 403
      ? 'Your role does not have access to this resource.'
      : `The request could not be completed (${response.status}).`
    throw new ApiError(payload.error?.message || payload.detail || fallback, response.status, payload.error?.code)
  }

  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const apiConfiguration = { baseUrl: API_BASE }
