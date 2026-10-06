import { describe, expect, it } from 'vitest'
import { findingSeverity, shortId, toIsoDateTime, truncate } from './format'

describe('format helpers', () => {
  it('shortens identifiers without changing short values', () => {
    expect(shortId('event-123', 20)).toBe('event-123')
    expect(shortId('1234567890', 6)).toBe('123456…')
  })

  it('truncates long operator-facing copy', () => {
    expect(truncate('abcdefghij', 7)).toBe('abcdef…')
    expect(truncate(null)).toBe('—')
  })

  it('reads optional finding severity without inventing one', () => {
    const finding = {
      finding_metadata: { severity: 'HIGH' },
    } as never
    const withoutSeverity = { finding_metadata: {} } as never
    expect(findingSeverity(finding)).toBe('HIGH')
    expect(findingSeverity(withoutSeverity)).toBeNull()
  })

  it('prefers the additive finding severity field when present', () => {
    const finding = { severity: 'CRITICAL', finding_metadata: { severity: 'LOW' } } as never
    expect(findingSeverity(finding)).toBe('CRITICAL')
  })

  it('normalizes local filter dates to ISO only when valid', () => {
    expect(toIsoDateTime('2026-10-01T12:00:00Z')).toBe('2026-10-01T12:00:00.000Z')
    expect(toIsoDateTime('not-a-date')).toBeUndefined()
  })
})
