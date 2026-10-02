import { queryString, request } from './client'
import type {
  AgentTask, AuditListParams, AuditLog, CurrentUser, EventListParams, Finding,
  FindingListParams, Incident, IncidentListParams, Paginated, SecurityEvent,
  TaskListParams, TokenResponse,
} from '@/types/api'

export const authApi = {
  login: (username: string, password: string) => request<TokenResponse>('/auth/login', {
    method: 'POST', body: { username, password }, authenticated: false,
  }),
  me: () => request<CurrentUser>('/auth/me'),
}

export const eventsApi = {
  list: (params: EventListParams = {}, signal?: AbortSignal) => request<Paginated<SecurityEvent>>(`/events${queryString(params)}`, { signal }),
  get: (id: string, signal?: AbortSignal) => request<SecurityEvent>(`/events/${encodeURIComponent(id)}`, { signal }),
}

export const incidentsApi = {
  list: (params: IncidentListParams = {}, signal?: AbortSignal) => request<Paginated<Incident>>(`/incidents${queryString(params)}`, { signal }),
  get: (id: string, signal?: AbortSignal) => request<Incident>(`/incidents/${encodeURIComponent(id)}`, { signal }),
  updateStatus: (id: string, status: string) => request<Incident>(`/incidents/${encodeURIComponent(id)}`, { method: 'PATCH', body: { status } }),
}

export const tasksApi = {
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
