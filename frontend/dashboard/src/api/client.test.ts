import { describe, expect, it } from 'vitest'
import { queryString } from './client'

describe('API query construction', () => {
  it('omits empty optional parameters and preserves pagination', () => {
    expect(queryString({ severity: 'HIGH', source_address: '', page: 2, page_size: 20 })).toBe('?severity=HIGH&page=2&page_size=20')
  })

  it('returns an empty suffix when no filters are set', () => {
    expect(queryString({ severity: undefined, event_type: null, page: 1 })).toBe('?page=1')
    expect(queryString()).toBe('')
  })
})
