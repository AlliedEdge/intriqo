import { describe, expect, it } from 'vitest'
import type { AgentTask, SecurityEvent } from '@/types/api'
import { eventDetectionSource, eventDetector, eventRelationshipIds, investigationState, taskFindingIds } from './soc'

const event = (overrides: Partial<SecurityEvent> = {}): SecurityEvent => ({
  event_id: 'event-1',
  event_type: 'ML_ANOMALY',
  severity: 'HIGH',
  timestamp: '2026-10-01T12:00:00Z',
  source_address: '203.0.113.10',
  destination_address: '198.51.100.20',
  description: null,
  details: { detection_source: 'ML', detector: 'isolation_forest_v2' },
  ingested_at: '2026-10-01T12:00:01Z',
  ...overrides,
})

const task = (status: AgentTask['status'], findingIds?: string[]): AgentTask => ({
  task_id: `task-${status}`,
  task_type: 'INVESTIGATION',
  description: 'Investigate event',
  priority: 'HIGH',
  status,
  event_id: 'event-1',
  incident_id: 'incident-1',
  context: {},
  created_at: '2026-10-01T12:00:00Z',
  updated_at: '2026-10-01T12:00:00Z',
  completed_at: null,
  finding_ids: findingIds,
})

describe('SOC relationship and provenance helpers', () => {
  it('normalizes additive relationship IDs and removes duplicates', () => {
    expect(eventRelationshipIds(event({ linked_incident_ids: ['i-1', 'i-1'], linked_task_ids: ['t-1'], linked_finding_ids: [] }))).toEqual({
      incidentIds: ['i-1'], taskIds: ['t-1'], findingIds: [],
    })
    expect(taskFindingIds(task('COMPLETED', ['f-1', 'f-1']))).toEqual(['f-1'])
  })

  it('shows detector provenance from event details without inventing ML fields', () => {
    expect(eventDetectionSource(event())).toBe('ML')
    expect(eventDetector(event())).toBe('isolation_forest_v2')
    expect(eventDetectionSource(event({ event_type: 'PORT_SCAN', details: {} }))).toBe('DETERMINISTIC')
    expect(eventDetectionSource(event({ event_type: 'FUTURE_DETECTOR', details: {} }))).toBeNull()
  })

  it('keeps investigation completion independent from response lifecycle', () => {
    expect(investigationState([])).toBe('NOT_STARTED')
    expect(investigationState([task('IN_PROGRESS')])).toBe('IN_PROGRESS')
    expect(investigationState([task('COMPLETED')])).toBe('COMPLETED')
    expect(investigationState([task('FAILED')])).toBe('BLOCKED')
  })
})
