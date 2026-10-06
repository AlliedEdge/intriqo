import type { AgentTask, Finding, SecurityEvent } from '@/types/api'

export interface RelationshipIds {
  incidentIds: string[]
  taskIds: string[]
  findingIds: string[]
}

function ids(value: string[] | undefined): string[] {
  return Array.from(new Set((value || []).filter((item): item is string => Boolean(item))))
}

/** Read additive relationship fields without making older API payloads invalid. */
export function eventRelationshipIds(event: SecurityEvent): RelationshipIds {
  return {
    incidentIds: ids(event.linked_incident_ids),
    taskIds: ids(event.linked_task_ids),
    findingIds: ids(event.linked_finding_ids),
  }
}

export function incidentRelationshipIds(incident: { linked_task_ids?: string[]; linked_finding_ids?: string[] }): Pick<RelationshipIds, 'taskIds' | 'findingIds'> {
  return {
    taskIds: ids(incident.linked_task_ids),
    findingIds: ids(incident.linked_finding_ids),
  }
}

export function taskFindingIds(task: AgentTask): string[] {
  return ids(task.finding_ids)
}

function detailString(details: Record<string, unknown> | undefined, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = details?.[key]
    if (typeof value === 'string' && value.trim()) return value
  }
  return null
}

/** The event contract keeps detector provenance in details; preserve it verbatim. */
export function eventDetectionSource(event: SecurityEvent): string | null {
  const explicit = detailString(event.details, 'detection_source', 'source')
  if (explicit) return explicit
  if (event.event_type === 'PORT_SCAN' || event.event_type === 'SYN_FLOOD') return 'DETERMINISTIC'
  return null
}

export function eventDetector(event: SecurityEvent): string | null {
  const direct = detailString(event.details, 'detector', 'detector_name')
  if (direct) return direct
  const result = event.details.result
  if (result && typeof result === 'object' && !Array.isArray(result)) {
    return detailString(result as Record<string, unknown>, 'detector', 'detector_name')
  }
  return null
}

export function findingEventType(finding: Finding): string | null {
  const value = finding.provenance?.event_type
  return typeof value === 'string' && value ? value : null
}

export function findingDetectionSource(finding: Finding): string | null {
  const explicit = finding.source || finding.provenance?.source || finding.provenance?.detection_source
  return typeof explicit === 'string' && explicit ? explicit : null
}

export function findingDetector(finding: Finding): string | null {
  const value = finding.provenance?.detector
  return typeof value === 'string' && value ? value : null
}

export type InvestigationState = 'NOT_STARTED' | 'IN_PROGRESS' | 'COMPLETED' | 'BLOCKED'

/** Investigation completion is derived from task execution, independent of incident response state. */
export function investigationState(tasks: AgentTask[]): InvestigationState {
  if (tasks.length === 0) return 'NOT_STARTED'
  if (tasks.some((task) => task.status === 'FAILED' || task.status === 'CANCELLED')) return 'BLOCKED'
  if (tasks.every((task) => task.status === 'COMPLETED')) return 'COMPLETED'
  return 'IN_PROGRESS'
}
