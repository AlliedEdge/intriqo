export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type IncidentStatus =
  | 'OPEN'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
  | 'FALSE_POSITIVE'

export type AgentTaskStatus =
  | 'PENDING'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'

export interface Paginated<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  has_next: boolean
}

export interface SecurityEvent {
  event_id: string
  event_type: string
  severity: Severity
  timestamp: string
  source_address: string
  destination_address: string
  description: string | null
  details: Record<string, unknown>
  ingested_at: string
}

export interface Incident {
  incident_id: string
  title: string
  description: string
  status: IncidentStatus | string
  severity: Severity | string
  created_at: string
  updated_at: string
  resolved_at: string | null
  incident_metadata: Record<string, unknown>
  linked_event_ids: string[]
}

export interface AgentTask {
  task_id: string
  task_type: string
  description: string
  priority: string
  status: AgentTaskStatus | string
  event_id: string | null
  incident_id: string | null
  context: Record<string, unknown>
  created_at: string
  updated_at: string
  completed_at: string | null
}

export interface Finding {
  finding_id: string
  task_id: string
  agent_name: string
  status: string
  confidence: number
  summary: string | null
  findings: string[]
  evidence: Array<Record<string, unknown>>
  finding_metadata: Record<string, unknown>
  error: Record<string, unknown> | null
  created_at: string
}

export interface AuditLog {
  id: string
  actor: string
  action: string
  resource_type: string
  resource_id: string
  outcome: string
  detail: string | null
  extra: Record<string, unknown>
  created_at: string
}

export interface CurrentUser {
  user_id: string
  username: string
  role: string
}

export interface RegisterRequest {
  username?: string
  email: string
  password: string
  full_name?: string
}

export interface RegisteredUser {
  id: string
  username: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
  is_email_verified: boolean
}

export interface MessageResponse {
  message: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

export interface HealthResponse {
  status: string
  service: string
  version: string
  checks?: Record<string, string>
}

export interface ErrorEnvelope {
  error?: {
    code?: string
    message?: string
    details?: unknown
  }
  detail?: string
}

export interface EventListParams {
  severity?: string
  event_type?: string
  source_address?: string
  destination_address?: string
  from_time?: string
  to_time?: string
  page?: number
  page_size?: number
}

export interface IncidentListParams {
  status?: string
  severity?: string
  page?: number
  page_size?: number
}

export interface TaskListParams {
  status?: string
  priority?: string
  task_type?: string
  event_id?: string
  incident_id?: string
  page?: number
  page_size?: number
}

export interface FindingListParams {
  status?: string
  task_id?: string
  agent_name?: string
  page?: number
  page_size?: number
}

export interface AuditListParams {
  action?: string
  resource_type?: string
  resource_id?: string
  outcome?: string
  page?: number
  page_size?: number
}
