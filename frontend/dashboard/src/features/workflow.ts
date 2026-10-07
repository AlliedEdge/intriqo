import { auditApi, incidentsApi, tasksApi } from '@/api'
import type { AgentTask, AuditLog, Incident, SecurityEvent } from '@/types/api'

export function canMutateWorkflow(role: string | undefined): boolean {
  return role === 'ANALYST' || role === 'ADMIN'
}

export function investigationBlocker(event: SecurityEvent | undefined, incident: Incident | undefined): string | null {
  if (!incident?.incident_id) return 'A readable linked incident is required before an investigation task can be created.'
  if (!event?.event_id) return 'Select a readable source event linked to this incident.'
  if (!incident.linked_event_ids.includes(event.event_id)) return 'The selected event is not linked to this incident.'
  return null
}

export async function createInvestigationTask(event: SecurityEvent | undefined, incident: Incident | undefined, description: string): Promise<AgentTask> {
  const blocker = investigationBlocker(event, incident)
  if (blocker || !event || !incident) throw new Error(blocker || 'Both a source event and incident are required.')
  return tasksApi.create({
    task_type: 'INVESTIGATION', description, priority: 'MEDIUM',
    event_id: event.event_id, incident_id: incident.incident_id,
  })
}

export async function promoteMlAnomaly(event: SecurityEvent): Promise<Incident> {
  if (!event.event_id || event.event_type !== 'ML_ANOMALY') throw new Error('Only a real ML_ANOMALY event can be promoted here.')
  const response = await incidentsApi.create({
    title: `ML anomaly review · ${event.event_id.slice(0, 12)}`,
    description: event.description || `Analyst review for SecurityEvent ${event.event_id}.`,
    severity: event.severity, event_ids: [event.event_id],
  })
  // Read the durable incident: POST may reuse an existing correlated incident.
  const incident = await incidentsApi.get(response.incident_id)
  const blocker = investigationBlocker(event, incident)
  if (blocker) throw new Error(blocker)
  return incident
}

export interface WorkflowAudit {
  items: AuditLog[]
  unavailable: number
  truncated: boolean
}

export const WORKFLOW_AUDIT_LIMITS = { resources: 100, perResource: 50, entries: 200 } as const

/** Bounded, resource-filtered reads; keep inaccessible history visibly partial. */
export async function loadWorkflowAudit(incidentId: string, eventIds: string[], taskIds: string[], findingIds: string[], signal: AbortSignal): Promise<WorkflowAudit> {
  const resources = [
    { resource_type: 'incident', resource_id: incidentId },
    ...eventIds.map((resource_id) => ({ resource_type: 'security_event', resource_id })),
    ...taskIds.map((resource_id) => ({ resource_type: 'agent_task', resource_id })),
    ...findingIds.map((resource_id) => ({ resource_type: 'finding', resource_id })),
  ].filter((resource) => Boolean(resource.resource_id))
  const uniqueResources = Array.from(new Map(resources.map((resource) => [`${resource.resource_type}:${resource.resource_id}`, resource])).values())
  const responses = await Promise.all(uniqueResources.slice(0, WORKFLOW_AUDIT_LIMITS.resources).map(async (resource) => {
    try { return await auditApi.list({ ...resource, page: 1, page_size: WORKFLOW_AUDIT_LIMITS.perResource }, signal) }
    catch (error) { if (signal.aborted) throw error; return null }
  }))
  const entries = Array.from(new Map(responses.flatMap((response) => response?.items || []).map((entry) => [entry.id, entry])).values())
    .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))
  return {
    items: entries.slice(0, WORKFLOW_AUDIT_LIMITS.entries),
    unavailable: responses.filter((response) => response === null).length,
    truncated: uniqueResources.length > WORKFLOW_AUDIT_LIMITS.resources || entries.length > WORKFLOW_AUDIT_LIMITS.entries || responses.some((response) => response?.has_next),
  }
}
