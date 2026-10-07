import { afterEach, describe, expect, it, vi } from 'vitest'
import { incidentsApi, tasksApi } from './index'
import type { Incident, SecurityEvent } from '@/types/api'
import { canMutateWorkflow, investigationBlocker } from '@/features/workflow'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('typed SOC workflow API methods', () => {
  it('creates an investigation task with its real event and incident links', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ task_id: 'task-1' }),
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('sessionStorage', { getItem: () => null })

    await tasksApi.create({
      task_type: 'INVESTIGATION',
      description: 'Investigate PORT_SCAN event',
      priority: 'MEDIUM',
      event_id: 'event-1',
      incident_id: 'incident-1',
    })

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/agent-tasks', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        task_type: 'INVESTIGATION',
        description: 'Investigate PORT_SCAN event',
        priority: 'MEDIUM',
        event_id: 'event-1',
        incident_id: 'incident-1',
      }),
    }))
  })

  it('requires both a readable linked event and incident before task creation', () => {
    const event = { event_id: 'event-1' } as SecurityEvent
    const incident = { incident_id: 'incident-1', linked_event_ids: ['event-1'] } as Incident
    expect(investigationBlocker(undefined, incident)).toContain('source event')
    expect(investigationBlocker(event, undefined)).toContain('linked incident')
    expect(investigationBlocker(event, incident)).toBeNull()
    expect(canMutateWorkflow('ANALYST')).toBe(true)
    expect(canMutateWorkflow('ADMIN')).toBe(true)
    expect(canMutateWorkflow('AGENT')).toBe(false)
  })

  it('patches incident status through the existing lifecycle endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ incident_id: 'incident-1', status: 'INVESTIGATING' }),
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('sessionStorage', { getItem: () => null })

    await incidentsApi.updateStatus('incident-1', 'INVESTIGATING')

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/incidents/incident-1', expect.objectContaining({
      method: 'PATCH',
      body: JSON.stringify({ status: 'INVESTIGATING' }),
    }))
  })

  it('promotes a real event through the typed incident-create contract', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ incident_id: 'incident-1' }),
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('sessionStorage', { getItem: () => null })

    await incidentsApi.create({
      title: 'ML anomaly review · event-1',
      description: 'Review this persisted anomaly.',
      severity: 'HIGH',
      event_ids: ['event-1'],
    })

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/incidents', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        title: 'ML anomaly review · event-1',
        description: 'Review this persisted anomaly.',
        severity: 'HIGH',
        event_ids: ['event-1'],
      }),
    }))
  })
})
