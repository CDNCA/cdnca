import { ApiError } from './auth'
import {
  createOriginAuthCredentialWriteMetadata,
  originAuthCredentialsApi,
  type OriginAuthCredential,
  type OriginAuthCredentialSecret,
} from './originAuthCredentials'

const scopeID = '11111111-1111-4111-8111-111111111111'
const credentialID = '22222222-2222-4222-8222-222222222222'
const credential: OriginAuthCredential = {
  id: credentialID,
  tenant_scope_id: scopeID,
  provider: 's3',
  name: 'primary-origin',
  status: 'pending',
  revision: 3,
  revision_ref: '33333333-3333-4333-8333-333333333333',
  not_before: '2026-08-07T08:00:00Z',
  expires_at: '2026-09-07T08:00:00Z',
  created_at: '2026-08-07T08:00:00Z',
  updated_at: '2026-08-07T08:05:00Z',
}
const secret: OriginAuthCredentialSecret = {
  access_key_id: 'AKIA-CURRENT',
  secret_access_key: 'request-only-secret',
  session_token: 'request-only-session',
  not_before: '2026-08-07T08:00:00Z',
  expires_at: '2026-09-07T08:00:00Z',
}
const metadata = { idempotencyKey: 'origin-auth-write-1' }

function json(value: unknown, status = 200, revision?: number): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...(revision ? { ETag: `"${revision}"` } : {}),
    },
  })
}

describe('originAuthCredentialsApi', () => {
  it('uses the exact tenant routes, filters, CAS, idempotency, and request-only secrets', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ items: [credential], next_cursor: 'next-page' }))
      .mockResolvedValueOnce(json(credential, 200, 3))
      .mockResolvedValueOnce(json(credential, 201, 3))
      .mockResolvedValueOnce(json({ ...credential, revision: 4 }, 200, 4))
      .mockResolvedValueOnce(json({ ...credential, revision: 4 }, 200, 4))
      .mockResolvedValueOnce(json({ ...credential, revision: 4 }, 200, 4))
      .mockResolvedValueOnce(json({ ...credential, revision: 4 }, 200, 4))

    await originAuthCredentialsApi.list('token', scopeID, {
      provider: 's3', status: 'pending', limit: 20, cursor: 'current-page',
    })
    await originAuthCredentialsApi.get('token', scopeID, credentialID)
    await originAuthCredentialsApi.create('token', scopeID, {
      provider: 's3', name: credential.name, secret,
    }, metadata)
    await originAuthCredentialsApi.replace('token', scopeID, credentialID, 3, { secret }, metadata)
    await originAuthCredentialsApi.verify('token', scopeID, credentialID, 3, metadata)
    await originAuthCredentialsApi.disable('token', scopeID, credentialID, 3, metadata)
    await originAuthCredentialsApi.delete('token', scopeID, credentialID, 3, metadata)

    const base = `/v1/tenant-scopes/${scopeID}/origin-auth/credentials`
    expect(fetchSpy.mock.calls.map(([url]) => url)).toEqual([
      `${base}?provider=s3&status=pending&limit=20&cursor=current-page`,
      `${base}/${credentialID}`,
      base,
      `${base}/${credentialID}/replace`,
      `${base}/${credentialID}/verify`,
      `${base}/${credentialID}/disable`,
      `${base}/${credentialID}`,
    ])
    expect(fetchSpy.mock.calls.map(([, init]) => init?.method ?? 'GET'))
      .toEqual(['GET', 'GET', 'POST', 'POST', 'POST', 'POST', 'DELETE'])
    for (const [, init] of fetchSpy.mock.calls) {
      expect(init?.credentials).toBe('include')
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
    }
    for (const call of fetchSpy.mock.calls.slice(2)) {
      expect(new Headers(call[1]?.headers).get('Idempotency-Key')).toBe(metadata.idempotencyKey)
    }
    for (const call of fetchSpy.mock.calls.slice(3)) {
      expect(new Headers(call[1]?.headers).get('If-Match')).toBe('"3"')
    }
    expect(fetchSpy.mock.calls[2]![1]?.body).toBe(JSON.stringify({
      provider: 's3', name: credential.name, secret,
    }))
    expect(fetchSpy.mock.calls[3]![1]?.body).toBe(JSON.stringify({ secret }))
    expect(fetchSpy.mock.calls.slice(4).map(([, init]) => init?.body)).toEqual(['{}', '{}', '{}'])
    expect(fetchSpy.mock.calls.every(([url]) => !String(url).includes(secret.secret_access_key))).toBe(true)
  })

  it.each([
    ['unknown credential field', { ...credential, encrypted_secret: 'private' }],
    ['wrong tenant', { ...credential, tenant_scope_id: credentialID }],
    ['invalid provider', { ...credential, provider: 'aws' }],
    ['invalid status', { ...credential, status: 'active' }],
    ['invalid revision', { ...credential, revision: 0 }],
    ['invalid timestamp order', { ...credential, expires_at: '2026-08-06T08:00:00Z' }],
  ])('rejects malformed successful response: %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [item] }))
    await expect(originAuthCredentialsApi.list('token', scopeID))
      .rejects.toMatchObject({ status: 502, code: 'origin_auth_invalid_response' })
  })

  it.each([
    ['invalid scope', () => originAuthCredentialsApi.list('token', 'INVALID')],
    ['whitespace token', () => originAuthCredentialsApi.list('bad token', scopeID)],
    ['invalid cursor', () => originAuthCredentialsApi.list('token', scopeID, { cursor: '' })],
    ['invalid credential', () => originAuthCredentialsApi.get('token', scopeID, 'INVALID')],
    ['invalid secret interval', () => originAuthCredentialsApi.create('token', scopeID, {
      provider: 's3', name: 'name', secret: { ...secret, expires_at: secret.not_before },
    }, metadata)],
    ['invalid revision', () => originAuthCredentialsApi.disable('token', scopeID, credentialID, 0, metadata)],
    ['invalid metadata', () => originAuthCredentialsApi.verify('token', scopeID, credentialID, 3, { idempotencyKey: '' })],
  ])('rejects %s locally with zero requests', async (_name, request) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(request()).rejects.toMatchObject({ status: 400, code: 'origin_auth_validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('requires exact response status, JSON, and matching ETag for writes', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(credential, 200, 3))
      .mockResolvedValueOnce(new Response('{}', { status: 201, headers: { 'Content-Type': 'text/plain', ETag: '"3"' } }))
      .mockResolvedValueOnce(json(credential, 201, 4))

    await expect(originAuthCredentialsApi.create('token', scopeID, {
      provider: 's3', name: credential.name, secret,
    }, metadata)).rejects.toMatchObject({ code: 'origin_auth_invalid_response' })
    await expect(originAuthCredentialsApi.create('token', scopeID, {
      provider: 's3', name: credential.name, secret,
    }, metadata)).rejects.toMatchObject({ code: 'origin_auth_invalid_response' })
    await expect(originAuthCredentialsApi.create('token', scopeID, {
      provider: 's3', name: credential.name, secret,
    }, metadata)).rejects.toMatchObject({ code: 'origin_auth_invalid_response' })
  })

  it('preserves stable errors without raw server or network details', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: {
        code: 'origin_auth_permission_denied', message: 'raw topology', request_id: 'safe-1', trace_id: 'trace-1',
      } }, 403))
      .mockRejectedValueOnce(new TypeError('private socket'))

    const denied = await originAuthCredentialsApi.list('token', scopeID).catch((error: unknown) => error)
    expect(denied).toBeInstanceOf(ApiError)
    expect(denied).toMatchObject({ status: 403, code: 'origin_auth_permission_denied', requestId: 'safe-1' })
    expect(String(denied)).not.toContain('raw topology')
    await expect(originAuthCredentialsApi.list('token', scopeID))
      .rejects.toMatchObject({ status: 0, code: 'network_error', message: 'Network request failed' })
  })

  it('generates bounded non-secret idempotency metadata', () => {
    const first = createOriginAuthCredentialWriteMetadata()
    const second = createOriginAuthCredentialWriteMetadata()
    expect(first.idempotencyKey).toMatch(/^origin-auth-credential-[A-Za-z0-9._:-]+$/)
    expect(first.idempotencyKey.length).toBeLessThanOrEqual(128)
    expect(second.idempotencyKey).not.toBe(first.idempotencyKey)
  })
})
