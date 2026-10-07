import { queryString, request } from './client'
import type {
  AgentTask, AgentTaskCreate, AuditListParams, AuditLog, CurrentUser, EventListParams, Finding,
  FindingListParams, Incident, IncidentCreate, IncidentListParams, Paginated, SecurityEvent,
  IncidentStatus, MessageResponse, RegisterRequest, RegisteredUser, TaskListParams, TokenResponse,
} from '@/types/api'

export const authApi = {
  register: (payload: RegisterRequest) => request<RegisteredUser>('/auth/register', {
    method: 'POST', body: payload, authenticated: false,
  }),
  login: (username: string, password: string) => request<TokenResponse>('/auth/login', {
    method: 'POST', body: { username, password }, authenticated: false,
  }),
  verifyEmail: (token: string) => request<MessageResponse>('/auth/verify-email', {
    method: 'POST', body: { token }, authenticated: false,
  }),
  resendVerification: (email: string) => request<MessageResponse>('/auth/resend-verification', {
    method: 'POST', body: { email }, authenticated: false,
  }),
  forgotPassword: (email: string) => request<MessageResponse>('/auth/forgot-password', {
    method: 'POST', body: { email }, authenticated: false,
  }),
  resetPassword: (token: string, password: string) => request<MessageResponse>('/auth/reset-password', {
    method: 'POST', body: { token, new_password: password }, authenticated: false,
  }),
  me: () => request<CurrentUser>('/auth/me'),
}

export const eventsApi = {
  list: (params: EventListParams = {}, signal?: AbortSignal) => request<Paginated<SecurityEvent>>(`/events${queryString(params)}`, { signal }),
  get: (id: string, signal?: AbortSignal) => request<SecurityEvent>(`/events/${encodeURIComponent(id)}`, { signal }),
}

export const incidentsApi = {
  create: (payload: IncidentCreate) => request<Incident>('/incidents', { method: 'POST', body: payload }),
  list: (params: IncidentListParams = {}, signal?: AbortSignal) => request<Paginated<Incident>>(`/incidents${queryString(params)}`, { signal }),
  get: (id: string, signal?: AbortSignal) => request<Incident>(`/incidents/${encodeURIComponent(id)}`, { signal }),
  updateStatus: (id: string, status: IncidentStatus) => request<Incident>(`/incidents/${encodeURIComponent(id)}`, { method: 'PATCH', body: { status } }),
}

export const tasksApi = {
  create: (payload: AgentTaskCreate) => request<AgentTask>('/agent-tasks', { method: 'POST', body: payload }),
  list: (params: TaskListParams = {}, signal?: AbortSignal) => request<Paginated<AgentTask>>(`/agent-tasks${queryString(params)}`, { signal }),
  get: (id: string, signal?: AbortSignal) => request<AgentTask>(`/agent-tasks/${encodeURIComponent(id)}`, { signal }),
}

export const findingsApi = {
  list: (params: FindingListParams = {}, signal?: AbortSignal) => request<Paginated<Finding>>(`/findings${queryString(params)}`, { signal }),
  get: (id: string, signal?: AbortSignal) => request<Finding>(`/findings/${encodeURIComponent(id)}`, { signal }),
}

export const auditApi = {
  list: (params: AuditListParams = {}, signal?: AbortSignal) => request<Paginated<AuditLog>>(`/audit${queryString(params)}`, { signal }),
}
