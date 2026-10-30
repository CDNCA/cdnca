import { ApiError } from './auth'
import {
  createIdentitySessionRevokeAttempt,
  identitySessionsApi,
  type IdentitySessionFamily,
} from './identitySessions'

const familyID = '11111111-1111-4111-8111-111111111111'
const requestID = '22222222-2222-4222-8222-222222222222'
const family: IdentitySessionFamily = {
  family_id: familyID,
  device_label: 'Chrome on macOS',
  ip_prefix: '203.0.113.0/24',
  created_at: '2026-08-08T08:00:00Z',
  last_used_at: '2026-08-08T09:00:00Z',
  expires_at: '2026-08-09T08:00:00Z',
  current: false,
  active: true,
  session_count: 2,
  revision: 3,
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('identitySessionsApi', () => {
  afterEach(() => vi.restoreAllMocks())

  it('lists a strict redacted page with a UUID request identity and abort signal', async () => {
    const controller = new AbortController()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [family], next_cursor: 'opaque-next',
    }))

    await expect(identitySessionsApi.list('session-token', {
      limit: 25, cursor: 'opaque-current',
    }, controller.signal)).resolves.toEqual({ items: [family], next_cursor: 'opaque-next' })

    expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/identity/sessions?limit=25&cursor=opaque-current',
      expect.objectContaining({ credentials: 'include', signal: controller.signal }),
    )
    const headers = new Headers(fetchSpy.mock.calls[0]?.[1]?.headers)
    expect(headers.get('Authorization')).toBe('Bearer session-token')
    expect(headers.get('X-Request-ID')).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(JSON.stringify(fetchSpy.mock.calls[0])).not.toContain('refresh-token')
  })

  it('rejects invalid list input and responses that expose uncontracted or unmasked data', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [{ ...family, raw_user_agent: 'Mozilla/5.0 secret' }] }))
      .mockResolvedValueOnce(json({ items: [{ ...family, ip_prefix: '203.0.113.47' }] }))
      .mockResolvedValueOnce(json({ items: [{ ...family, device_label: '' }] }))

    await expect(identitySessionsApi.list('token', { limit: 0 }))
      .rejects.toMatchObject({ status: 400, code: 'identity_session_validation_error' })
    await expect(identitySessionsApi.list('token', { cursor: '' }))
      .rejects.toMatchObject({ status: 400, code: 'identity_session_validation_error' })
    for (let index = 0; index < 3; index += 1) {
      await expect(identitySessionsApi.list('token'))
        .rejects.toMatchObject({ status: 502, code: 'identity_session_invalid_response' })
    }
    expect(fetchSpy).toHaveBeenCalledTimes(3)
  })

  it('revokes with an immutable strong-CAS attempt and accepts only its exact result', async () => {
    vi.spyOn(globalThis.crypto, 'randomUUID')
      .mockReturnValueOnce('33333333-3333-4333-8333-333333333333')
      .mockReturnValueOnce(requestID)
    const attempt = createIdentitySessionRevokeAttempt(familyID, 3)
    const result = {
      family_id: familyID,
      revision: 4,
      revoked_at: '2026-08-08T10:00:00Z',
      current: false,
      replayed: false,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(result))

    await expect(identitySessionsApi.revoke('session-token', attempt)).resolves.toEqual(result)
    expect(Object.isFrozen(attempt)).toBe(true)
    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/identity/session-families/${familyID}`,
      expect.objectContaining({ method: 'DELETE', credentials: 'include' }),
    )
    const init = fetchSpy.mock.calls[0]?.[1]
    const headers = new Headers(init?.headers)
    expect(init?.body).toBeUndefined()
    expect(headers.get('If-Match')).toBe('"3"')
    expect(headers.get('Idempotency-Key')).toBe('33333333-3333-4333-8333-333333333333')
    expect(headers.get('X-Request-ID')).toBe(requestID)
  })

  it('rejects malformed attempts/results and maps stable errors without raw messages', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...family, revision: 4, revoked_at: family.expires_at }))
      .mockResolvedValueOnce(json({ error: {
        code: 'identity_session_revision_conflict',
        message: 'private database details', request_id: requestID,
      } }, 409))

    await expect(identitySessionsApi.revoke('token', {
      familyID: 'not-a-uuid', revision: 0, idempotencyKey: 'bad key', requestID: 'bad',
    })).rejects.toMatchObject({ status: 400, code: 'identity_session_validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()

    const attempt = {
      familyID, revision: 3, idempotencyKey: 'revoke-key-1', requestID,
    } as const
    await expect(identitySessionsApi.revoke('token', attempt))
      .rejects.toMatchObject({ status: 502, code: 'identity_session_invalid_response' })
    const error = await identitySessionsApi.revoke('token', attempt).catch((reason) => reason)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 409, code: 'identity_session_revision_conflict', requestId: requestID,
      message: 'API request failed',
    })
    expect(String(error)).not.toContain('private database')
  })
})
