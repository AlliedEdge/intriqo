import { describe, expect, it } from 'vitest'
import { deriveUsername, isValidAccountToken, passwordStrength, validateEmail, validatePassword } from './auth'

describe('auth helpers', () => {
  it('derives a conservative username from a display name', () => {
    expect(deriveUsername('Ada Lovelace')).toBe('ada_lovelace')
    expect(deriveUsername(' Zoë  O\'Connor ')).toBe('zoe_o_connor')
    expect(deriveUsername('A')).toBe('a_user')
    expect(deriveUsername('')).toBe('operator')
  })

  it('reports password strength and the API boundary requirements', () => {
    expect(passwordStrength('').score).toBe(0)
    expect(passwordStrength('short').checks.length).toBe(false)
    expect(passwordStrength('LongerPass123!').score).toBe(4)
    expect(validatePassword('short', 'short')).toContain('at least 8')
    expect(validatePassword('LongerPass123!', 'Different123!')).toContain('do not match')
    expect(validatePassword('LongerPass123!', 'LongerPass123!')).toBeNull()
  })

  it('validates email and account-token input before making a request', () => {
    expect(validateEmail('')).toBeTruthy()
    expect(validateEmail('operator@example.com')).toBeNull()
    expect(isValidAccountToken('too-short')).toBe(false)
    expect(isValidAccountToken('a'.repeat(20))).toBe(true)
    expect(isValidAccountToken(`${'a'.repeat(19)} `)).toBe(false)
  })
})
