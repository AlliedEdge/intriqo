import { afterEach, describe, expect, it, vi } from 'vitest'
import { authApi } from './index'

afterEach(() => { vi.restoreAllMocks() })

describe('typed auth API methods', () => {
  it('sends registration and verification payloads without a session token', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({ id: '1' }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ message: 'Email verified successfully.' }) })
    vi.stubGlobal('fetch', fetchMock)

    await authApi.register({ username: 'ada_lovelace', email: 'ada@example.com', password: 'LongerPass123!' })
    await authApi.verifyEmail('a'.repeat(32))

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/auth/register', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ username: 'ada_lovelace', email: 'ada@example.com', password: 'LongerPass123!' }),
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/auth/verify-email', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ token: 'a'.repeat(32) }),
    }))
  })

  it('uses the generic recovery endpoints and explicit new_password contract', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({ message: 'If an account exists...' }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ message: 'Password reset successfully.' }) })
    vi.stubGlobal('fetch', fetchMock)

    await authApi.forgotPassword('ada@example.com')
    await authApi.resetPassword('a'.repeat(32), 'NewerPass123!')

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/auth/forgot-password', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ email: 'ada@example.com' }),
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/auth/reset-password', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ token: 'a'.repeat(32), new_password: 'NewerPass123!' }),
    }))
  })
})
