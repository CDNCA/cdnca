import { ApiError } from '../api/auth'
import {
  createMfaWriteMetadata,
  mfaApi,
  parseStepUpProof,
  type MfaWriteMetadata,
} from '../api/mfa'

const credentialID = '11111111-1111-4111-8111-111111111111'
const secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const provisioningURI = `otpauth://totp/CDNCA%3Ajason?algorithm=SHA1&digits=6&issuer=CDNCA&period=30&secret=${secret}`
const recoveryCodes = Array.from(
  { length: 10 },
  (_, index) => `ABCDEFGH-ABCDEFGH-ABCDEFGH-ABCDEFG${String.fromCharCode(65 + index)}`,
)
const metadata: MfaWriteMetadata = {
  requestId: 'mfa-request-1',
  idempotencyKey: 'mfa-write-1',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
}

const stepUpInput = {
  tenant_id: '22222222-2222-4222-8222-222222222222',
  audience: 'billing.grant',
  action: 'grant.create',
  authentication: { method: 'totp' as const, code: '123456' },
  ttl_seconds: 60,
  max_uses: 2,
}
const stepUpToken = 'abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE'

function json(body: unknown, status = 200, contentType = 'application/json'): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': contentType } })
}

function error(status: number, code: string): Response {
  return json({ error: { code, message: 'private server detail', request_id: 'mfa-request-error' } }, status)
}

describe('mfaApi', () => {
  it('reads each exact non-sensitive status with bearer correlation metadata', async () => {
    const responses = [
      { status: 'inactive' },
      {
        status: 'enrollment_pending',
        credential_id: credentialID,
        method: 'totp',
        enrollment_expires_at: '2026-08-02T10:00:00Z',
      },
      { status: 'active', credential_id: credentialID, method: 'totp' },
    ]
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    for (const response of responses) {
      fetchSpy.mockResolvedValueOnce(json(response))
      await expect(mfaApi.getStatus('memory-token')).resolves.toEqual(response)
    }

    expect(fetchSpy).toHaveBeenCalledTimes(3)
    for (const [url, init] of fetchSpy.mock.calls) {
      expect(url).toBe('/v1/account/mfa')
      expect(init).toMatchObject({
        method: 'GET',
        credentials: 'include',
        headers: expect.objectContaining({
          Authorization: 'Bearer memory-token',
          'X-Request-ID': expect.stringMatching(/^mfa-status-/),
          Traceparent: expect.stringMatching(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/),
        }),
      })
    }
  })

  it.each([
    ['unknown status', { status: 'disabled' }],
    ['extra inactive field', { status: 'inactive', credential_id: credentialID }],
    ['missing pending field', { status: 'enrollment_pending', credential_id: credentialID, method: 'totp' }],
    ['null pending field', { status: 'enrollment_pending', credential_id: credentialID, method: 'totp', enrollment_expires_at: null }],
    ['wrong active method', { status: 'active', credential_id: credentialID, method: 'webauthn' }],
    ['wrong active credential', { status: 'active', credential_id: 'not-a-uuid', method: 'totp' }],
  ])('rejects a status with %s', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))
    await expect(mfaApi.getStatus('memory-token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    ['a content-type parameter', json({ status: 'inactive' }, 200, 'application/json; charset=utf-8')],
    ['a missing content type', new Response(JSON.stringify({ status: 'inactive' }), { status: 200 })],
    ['a malformed document', new Response('{', { status: 200, headers: { 'Content-Type': 'application/json' } })],
  ])('rejects %s on a JSON success', async (_name, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)
    await expect(mfaApi.getStatus('memory-token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('begins enrollment with the exact body/key and accepts the one-time or replay shape by status', async () => {
    const created = {
      credential_id: credentialID,
      secret,
      provisioning_uri: provisioningURI,
      expires_at: '2026-08-02T10:00:00Z',
      replayed: false,
    } as const
    const replayed = {
      credential_id: credentialID,
      expires_at: '2026-08-02T10:00:00Z',
      replayed: true,
    } as const
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(created, 201))
      .mockResolvedValueOnce(json(replayed, 200))

    await expect(mfaApi.beginEnrollment('memory-token', { account_label: 'jason' }, metadata))
      .resolves.toEqual(created)
    await expect(mfaApi.beginEnrollment('memory-token', { account_label: 'jason' }, metadata))
      .resolves.toEqual(replayed)

    expect(fetchSpy.mock.calls[0]).toEqual(fetchSpy.mock.calls[1])
    expect(fetchSpy).toHaveBeenCalledWith('/v1/account/mfa/enrollments', {
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: 'Bearer memory-token',
        'Content-Type': 'application/json',
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
        Traceparent: metadata.traceparent,
      },
      body: JSON.stringify({ account_label: 'jason' }),
    })
  })

  it.each([
    ['201 replay', 201, { credential_id: credentialID, expires_at: '2026-08-02T10:00:00Z', replayed: true }],
    ['200 secret recovery', 200, { credential_id: credentialID, secret: 'ABCDEFGHIJKLMNOP', provisioning_uri: 'otpauth://totp/a?secret=x', expires_at: '2026-08-02T10:00:00Z', replayed: true }],
    ['missing secret', 201, { credential_id: credentialID, provisioning_uri: 'otpauth://totp/a?secret=x', expires_at: '2026-08-02T10:00:00Z', replayed: false }],
    ['null URI', 201, { credential_id: credentialID, secret: 'ABCDEFGHIJKLMNOP', provisioning_uri: null, expires_at: '2026-08-02T10:00:00Z', replayed: false }],
    ['extra field', 201, { credential_id: credentialID, secret: 'ABCDEFGHIJKLMNOP', provisioning_uri: 'otpauth://totp/a?secret=x', expires_at: '2026-08-02T10:00:00Z', replayed: false, account_label: 'jason' }],
  ])('rejects enrollment response %s', async (_name, status, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body, status))
    await expect(mfaApi.beginEnrollment('memory-token', { account_label: 'jason' }, metadata))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    ['an HOTP URI', secret, provisioningURI.replace('otpauth://totp/', 'otpauth://hotp/')],
    ['a URI missing issuer', secret, `otpauth://totp/CDNCA%3Ajason?algorithm=SHA1&digits=6&period=30&secret=${secret}`],
    ['a URI with a different secret', secret, `${provisioningURI.slice(0, -secret.length)}QRSTUVWXYZ234567`],
    ['a URI with a different account label', secret, provisioningURI.replace('jason', 'other')],
    ['an issuer containing a colon', secret, provisioningURI.replace('CDNCA%3Ajason', 'CDN%3AFly%3Ajason').replace('issuer=CDNCA', 'issuer=CDN%3AFly')],
    ['an account label containing a colon', secret, provisioningURI.replace('jason', 'jason%3Aother')],
    ['an extra label path', secret, provisioningURI.replace('jason', 'jason/other')],
    ['an encoded slash in the label', secret, provisioningURI.replace('jason', 'jason%2Fother')],
    ['a lowercase secret', secret.toLowerCase(), provisioningURI.replaceAll(secret, secret.toLowerCase())],
    ['a short secret', secret.slice(1), provisioningURI.replaceAll(secret, secret.slice(1))],
    ['a long secret', `${secret}A`, provisioningURI.replaceAll(secret, `${secret}A`)],
    ['an internally spaced secret', `${secret.slice(0, 16)} ${secret.slice(16)}`, provisioningURI.replaceAll(secret, `${secret.slice(0, 16)}%20${secret.slice(16)}`)],
    ['a control-bearing secret', `${secret.slice(0, 16)}\n${secret.slice(16)}`, provisioningURI.replaceAll(secret, `${secret.slice(0, 16)}%0A${secret.slice(16)}`)],
    ['a whitespace-only account label', secret, provisioningURI.replace('CDNCA%3Ajason', 'CDNCA%3A%20%20')],
  ])('rejects enrollment with %s', async (_name, responseSecret, responseURI) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      credential_id: credentialID,
      secret: responseSecret,
      provisioning_uri: responseURI,
      expires_at: '2026-08-02T10:00:00Z',
      replayed: false,
    }, 201))

    await expect(mfaApi.beginEnrollment('memory-token', { account_label: 'jason' }, metadata))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    '',
    '   ',
    ' jason',
    'jason ',
    'jason:other',
    'jason/other',
    'jason\nother',
  ])('rejects ambiguous account label %j before enrollment fetch', async (accountLabel) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    await expect(mfaApi.beginEnrollment('memory-token', { account_label: accountLabel }, metadata))
      .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('activates enrollment and never reconstructs recovery codes on replay', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({
        credential_id: credentialID,
        recovery_codes: recoveryCodes,
        activated_at: '2026-08-02T09:00:00Z',
        replayed: false,
      }, 201))
      .mockResolvedValueOnce(json({
        credential_id: credentialID,
        activated_at: '2026-08-02T09:00:00Z',
        replayed: true,
      }, 200))

    await expect(mfaApi.activateEnrollment('memory-token', credentialID, { code: '123456' }, metadata))
      .resolves.toMatchObject({ replayed: false, recovery_codes: recoveryCodes })
    await expect(mfaApi.activateEnrollment('memory-token', credentialID, { code: '123456' }, metadata))
      .resolves.toEqual({
        credential_id: credentialID,
        activated_at: '2026-08-02T09:00:00Z',
        replayed: true,
      })
    expect(fetchSpy.mock.calls[0]).toEqual(fetchSpy.mock.calls[1])
  })

  it.each(['12345', '1234567', 'ABCDEF', ' 123456', '123456\n'])(
    'rejects non-canonical activation code %j before fetch',
    async (code) => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
      await expect(mfaApi.activateEnrollment('memory-token', credentialID, { code }, metadata))
        .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
      expect(fetchSpy).not.toHaveBeenCalled()
    },
  )

  it.each([
    ['wrong recovery count', 201, { credential_id: credentialID, recovery_codes: ['one'], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['null recovery codes', 201, { credential_id: credentialID, recovery_codes: null, activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['codes on replay', 200, { credential_id: credentialID, recovery_codes: Array(10).fill('code'), activated_at: '2026-08-02T09:00:00Z', replayed: true }],
    ['missing replay flag', 201, { credential_id: credentialID, recovery_codes: Array(10).fill('code'), activated_at: '2026-08-02T09:00:00Z' }],
    ['blank recovery code', 201, { credential_id: credentialID, recovery_codes: ['   ', ...recoveryCodes.slice(1)], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['duplicate recovery code', 201, { credential_id: credentialID, recovery_codes: Array(10).fill(recoveryCodes[0]), activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['lowercase recovery code', 201, { credential_id: credentialID, recovery_codes: [recoveryCodes[0].toLowerCase(), ...recoveryCodes.slice(1)], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['wrong recovery character', 201, { credential_id: credentialID, recovery_codes: [`${recoveryCodes[0].slice(0, -1)}!`, ...recoveryCodes.slice(1)], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['internal recovery whitespace', 201, { credential_id: credentialID, recovery_codes: [`${recoveryCodes[0].slice(0, 8)} ${recoveryCodes[0].slice(9)}`, ...recoveryCodes.slice(1)], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['recovery CRLF', 201, { credential_id: credentialID, recovery_codes: [`${recoveryCodes[0].slice(0, 8)}\r\n${recoveryCodes[0].slice(9)}`, ...recoveryCodes.slice(1)], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['recovery control', 201, { credential_id: credentialID, recovery_codes: [`${recoveryCodes[0].slice(0, 8)}\u0000${recoveryCodes[0].slice(9)}`, ...recoveryCodes.slice(1)], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
    ['overlong recovery code', 201, { credential_id: credentialID, recovery_codes: [`${recoveryCodes[0]}A`, ...recoveryCodes.slice(1)], activated_at: '2026-08-02T09:00:00Z', replayed: false }],
  ])('rejects activation response %s', async (_name, status, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body, status))
    await expect(mfaApi.activateEnrollment('memory-token', credentialID, { code: '123456' }, metadata))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each(['disable', 'reset'] as const)('sends an exact %s terminal request and requires an empty 204', async (action) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))
    const input = {
      authentication: { method: 'recovery_code' as const, code: recoveryCodes[0] },
      reason: 'user request',
    }

    await expect(mfaApi[action]('memory-token', input, metadata)).resolves.toBeUndefined()
    expect(fetchSpy).toHaveBeenCalledWith(`/v1/account/mfa/${action}`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: 'Bearer memory-token',
        'Content-Type': 'application/json',
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
        Traceparent: metadata.traceparent,
      },
      body: JSON.stringify(input),
    })
  })

  it.each([
    ['totp', '12345'],
    ['totp', '1234567'],
    ['totp', 'ABCDEF'],
    ['totp', '123 456'],
    ['recovery_code', recoveryCodes[0].toLowerCase()],
    ['recovery_code', recoveryCodes[0].replaceAll('-', ':')],
    ['recovery_code', `${recoveryCodes[0]}A`],
    ['recovery_code', `${recoveryCodes[0]}\r\n`],
  ] as const)('rejects non-canonical %s terminal code %j before fetch', async (method, code) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    await expect(mfaApi.disable('memory-token', {
      authentication: { method, code }, reason: 'user request',
    }, metadata)).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['wrong success status', new Response(null, { status: 200 })],
    ['unexpected content type', new Response(null, { status: 204, headers: { 'Content-Type': 'application/json' } })],
  ])('rejects a terminal response with %s', async (_name, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)
    await expect(mfaApi.disable('memory-token', {
      authentication: { method: 'totp', code: '123456' }, reason: 'user request',
    }, metadata)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('preserves a strict stable 401 code and rejects malformed error envelopes', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(error(401, 'mfa_unauthenticated'))
      .mockResolvedValueOnce(json({ error: { code: 'mfa_unauthenticated', message: 'private' } }, 401))

    const unauthorized = await mfaApi.getStatus('expired-token').catch((reason: unknown) => reason)
    expect(unauthorized).toBeInstanceOf(ApiError)
    expect(unauthorized).toMatchObject({ status: 401, code: 'mfa_unauthenticated' })
    await expect(mfaApi.getStatus('expired-token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it.each([
    [401, new Response('<html>login</html>', { status: 401, headers: { 'Content-Type': 'text/html' } })],
    [403, json({ error: { code: 'mfa_principal_changed', message: 'private' } }, 403)],
  ])('preserves authentication status %s for a malformed error envelope', async (status, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)

    await expect(mfaApi.getStatus('expired-token')).rejects.toMatchObject({
      status,
      code: 'invalid_response',
    })
  })

  it('creates canonical fresh write metadata', () => {
    const first = createMfaWriteMetadata('enroll')
    const second = createMfaWriteMetadata('enroll')
    expect(first).not.toEqual(second)
    expect(first).toMatchObject({
      requestId: expect.stringMatching(/^mfa-enroll-/),
      idempotencyKey: expect.stringMatching(/^mfa-enroll-/),
      traceparent: expect.stringMatching(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/),
    })
  })

  it('creates a bound step-up proof and never reconstructs its token on replay', async () => {
    const created = {
      proof_id: credentialID,
      token: stepUpToken,
      method: 'totp',
      issued_at: '2026-08-02T09:00:00Z',
      expires_at: '2026-08-02T10:00:00Z',
      max_uses: 2,
      replayed: false,
    } as const
    const replayed = {
      proof_id: credentialID,
      method: 'totp',
      issued_at: '2026-08-02T09:00:00Z',
      expires_at: '2026-08-02T10:00:00Z',
      max_uses: 2,
      replayed: true,
    } as const
    const stepUpMetadata = createMfaWriteMetadata('step-up')
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(created, 201))
      .mockResolvedValueOnce(json(replayed, 200))

    expect(parseStepUpProof(created, 201)).toEqual(created)
    expect(parseStepUpProof(replayed, 200)).toEqual(replayed)
    await expect(mfaApi.createStepUpProof('memory-token', stepUpInput, stepUpMetadata))
      .resolves.toEqual(created)
    await expect(mfaApi.createStepUpProof('memory-token', stepUpInput, stepUpMetadata))
      .resolves.toEqual(replayed)
    expect(fetchSpy.mock.calls[0]).toEqual(fetchSpy.mock.calls[1])
    expect(fetchSpy.mock.calls[0]).toEqual(['/v1/account/mfa/step-up-proofs', {
      method: 'POST',
      credentials: 'include',
      headers: {
        Authorization: 'Bearer memory-token',
        'Content-Type': 'application/json',
        'Idempotency-Key': stepUpMetadata.idempotencyKey,
        'X-Request-ID': stepUpMetadata.requestId,
        Traceparent: stepUpMetadata.traceparent,
      },
      body: JSON.stringify(stepUpInput),
    }])
  })

  it.each([
    ['wrong token length', { ...stepUpInput }, { token: 'short' }],
    ['token on replay', { ...stepUpInput }, { token: stepUpToken, replayed: true }],
    ['wrong proof id', { ...stepUpInput }, { proof_id: 'not-a-uuid' }],
    ['invalid max uses', { ...stepUpInput }, { max_uses: 6 }],
  ])('rejects an invalid step-up response: %s', async (_name, _input, overrides) => {
    const body = {
      proof_id: credentialID,
      token: stepUpToken,
      method: 'totp',
      issued_at: '2026-08-02T09:00:00Z',
      expires_at: '2026-08-02T10:00:00Z',
      max_uses: 2,
      replayed: false,
      ...overrides,
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body, 201))
    await expect(mfaApi.createStepUpProof('memory-token', stepUpInput, metadata))
      .rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects malformed step-up input before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(mfaApi.createStepUpProof('memory-token', {
      ...stepUpInput,
      audience: ' ',
    }, metadata)).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    await expect(mfaApi.createStepUpProof('memory-token', {
      ...stepUpInput,
      authentication: { method: 'recovery_code', code: '123456' },
    }, metadata)).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fails closed without Web Crypto and never falls back to Math.random or fetch', async () => {
    const randomSpy = vi.spyOn(Math, 'random')
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    vi.stubGlobal('crypto', undefined)

    try {
      expect(() => createMfaWriteMetadata('enroll')).toThrow(expect.objectContaining({
        status: 400,
        code: 'crypto_unavailable',
      }))
      expect(randomSpy).not.toHaveBeenCalled()
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it.each([
    '00-00000000000000000000000000000000-2222222222222222-01',
    '00-11111111111111111111111111111111-0000000000000000-01',
  ])('rejects an all-zero trace or span ID before sending a write', async (invalidTraceparent) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    await expect(mfaApi.beginEnrollment('memory-token', { account_label: 'jason' }, {
      ...metadata,
      traceparent: invalidTraceparent,
    })).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
