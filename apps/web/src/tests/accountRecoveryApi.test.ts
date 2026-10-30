import { accountRecoveryApi, AccountRecoveryApiError } from '../api/accountRecovery'

describe('accountRecoveryApi', () => {
  it('requests recovery through the public username-only contract', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        data: {
          code: 'account_recovery_request_accepted',
          accepted_at: '2026-07-23T10:00:00.123456789Z',
        },
      }), { status: 202, headers: { 'Content-Type': 'application/json' } }),
    )

    await expect(accountRecoveryApi.request({ username: 'jason' }, 'request-key')).resolves.toEqual({
      data: {
        code: 'account_recovery_request_accepted',
        accepted_at: '2026-07-23T10:00:00.123456789Z',
      },
    })

    expect(fetchSpy).toHaveBeenCalledWith('/v1/account-recovery/requests', {
      method: 'POST',
      credentials: 'omit',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': 'request-key',
      },
      body: JSON.stringify({ username: 'jason' }),
    })
    const body = JSON.parse(String(fetchSpy.mock.calls[0]?.[1]?.body))
    expect(body).not.toHaveProperty('tenant_id')
    expect(body).not.toHaveProperty('scope_id')
    expect(body).not.toHaveProperty('email')
    expect(body).not.toHaveProperty('phone')
  })

  it('passes opaque link material to the confirmation contract without interpreting it', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(null, { status: 204, headers: { 'Idempotency-Replayed': 'true' } }),
    )

    await expect(accountRecoveryApi.confirm({
      token: 'opaque-token',
      recovery_context: 'opaque-context',
      new_password: 'correct-horse-battery',
      confirm_password: 'correct-horse-battery',
    }, 'confirm-key')).resolves.toBeUndefined()

    expect(fetchSpy).toHaveBeenCalledWith('/v1/account-recovery/confirmations', {
      method: 'POST',
      credentials: 'omit',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': 'confirm-key',
      },
      body: JSON.stringify({
        token: 'opaque-token',
        recovery_context: 'opaque-context',
        new_password: 'correct-horse-battery',
        confirm_password: 'correct-horse-battery',
      }),
    })
  })

  it.each([
    ['a non-202 success', new Response(JSON.stringify({ data: {} }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    })],
    ['a malformed 202 envelope', new Response(JSON.stringify({ data: {
      code: 'account_recovery_request_accepted', accepted_at: 'not-a-date',
    } }), { status: 202, headers: { 'Content-Type': 'application/json' } })],
    ['a date-only accepted_at', new Response(JSON.stringify({ data: {
      code: 'account_recovery_request_accepted', accepted_at: '2026-07-23',
    } }), { status: 202, headers: { 'Content-Type': 'application/json' } })],
    ['an impossible RFC3339 date', new Response(JSON.stringify({ data: {
      code: 'account_recovery_request_accepted', accepted_at: '2026-02-31T10:00:00Z',
    } }), { status: 202, headers: { 'Content-Type': 'application/json' } })],
    ['a non-JSON 202 response', new Response('<html>accepted</html>', {
      status: 202, headers: { 'Content-Type': 'text/html' },
    })],
  ])('rejects %s as an unknown result', async (_, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)

    await expect(accountRecoveryApi.request({ username: 'jason' }, 'request-key'))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('rejects a non-204 confirmation success as an unknown result', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 200 }))

    await expect(accountRecoveryApi.confirm({
      token: 'opaque-token', recovery_context: 'opaque-context',
      new_password: 'correct-horse-battery', confirm_password: 'correct-horse-battery',
    }, 'confirm-key')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('carries a bounded Retry-After delay on rate limiting', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'account_recovery_rate_limited', request_id: 'request-recovery-1' },
    }), { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '120' } }))

    const error = await accountRecoveryApi.request({ username: 'jason' }, 'request-key')
      .catch((reason: unknown) => reason)

    expect(error).toBeInstanceOf(AccountRecoveryApiError)
    expect(error).toMatchObject({
      status: 429,
      code: 'account_recovery_rate_limited',
      retryAfterSeconds: 120,
    })
  })
})
