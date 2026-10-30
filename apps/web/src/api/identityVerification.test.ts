import { ApiError } from './auth'
import {
  createIdentityVerificationWriteMetadata,
  identityVerificationApi,
  type IdentityVerificationCase,
  type IdentityVerificationProviderSession,
  type IdentityVerificationProviderUpload,
} from './identityVerification'

const caseID = '11111111-1111-4111-8111-111111111111'
const applicantID = '22222222-2222-4222-8222-222222222222'
const materialID = '33333333-3333-4333-8333-333333333333'
const evidenceToken = 'evidence-token-abcdefghijklmnopqrstuvwxyz'
const providerSessionID = '44444444-4444-4444-8444-444444444444'
const providerUploadID = '55555555-5555-4555-8555-555555555555'

const draft: IdentityVerificationCase = {
  id: caseID,
  applicant_user_id: applicantID,
  kind: 'personal_initial',
  status: 'draft',
  revision: 1,
  created_at: '2026-08-06T08:09:10Z',
  state_changed_at: '2026-08-06T08:09:10Z',
  retention: {
    eligible: false,
    eligible_at: '2032-08-04T08:09:10Z',
    reason_code: 'case_not_terminal',
  },
  materials: [{
    id: materialID,
    kind: 'identity_document',
    encrypted_envelope_present: true,
    mime_type: 'image/jpeg',
    size_bytes: 1024,
    created_at: '2026-08-06T08:09:10Z',
  }],
  replayed: false,
}

function json(body: unknown, status = 200, revision = 1): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ETag: `"${revision}"` },
  })
}

function providerJSON(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'provider-response-1' },
  })
}

describe('identityVerificationApi', () => {
  it('creates a sanitized draft using only the formal self contract', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(draft, 201))
    const metadata = { requestId: 'identity-create-request', idempotencyKey: 'identity-create-key' }

    await expect(identityVerificationApi.createDraft('memory-token', {
      kind: 'personal_initial',
      evidence_token: evidenceToken,
    }, metadata)).resolves.toEqual(draft)

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [input, init] = fetchSpy.mock.calls[0]!
    expect(String(input)).toBe('/v1/identity-verification/cases')
    expect(String(input)).not.toContain(evidenceToken)
    expect(init?.method).toBe('POST')
    expect(init?.credentials).toBe('include')
    expect(new Headers(init?.headers)).toMatchObject(expect.any(Headers))
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer memory-token')
    expect(new Headers(init?.headers).get('Content-Type')).toBe('application/json')
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(metadata.idempotencyKey)
    expect(new Headers(init?.headers).get('X-Request-ID')).toBe(metadata.requestId)
    expect(JSON.parse(String(init?.body))).toEqual({
      kind: 'personal_initial', evidence_token: evidenceToken,
    })
  })

  it('gets, submits, withdraws, and expires an owned case with exact methods and CAS headers', async () => {
    const submitted = { ...draft, status: 'submitted' as const, revision: 2 }
    const withdrawn = { ...submitted, status: 'withdrawn' as const, revision: 3 }
    const expired = { ...submitted, status: 'expired' as const, revision: 3 }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(draft))
      .mockResolvedValueOnce(json(submitted, 200, 2))
      .mockResolvedValueOnce(json(withdrawn, 200, 3))
      .mockResolvedValueOnce(json(expired, 200, 3))
    const metadata = { requestId: 'identity-mutation-request', idempotencyKey: 'identity-mutation-key' }

    await expect(identityVerificationApi.getCase('token', caseID)).resolves.toEqual(draft)
    await expect(identityVerificationApi.submit('token', caseID, 1, metadata)).resolves.toEqual(submitted)
    await expect(identityVerificationApi.withdraw('token', caseID, 2, metadata)).resolves.toEqual(withdrawn)
    await expect(identityVerificationApi.expire('token', caseID, 2, metadata)).resolves.toEqual(expired)

    expect(fetchSpy.mock.calls.map(([input]) => String(input))).toEqual([
      `/v1/identity-verification/cases/${caseID}`,
      `/v1/identity-verification/cases/${caseID}/submit`,
      `/v1/identity-verification/cases/${caseID}/withdraw`,
      `/v1/identity-verification/cases/${caseID}/expire`,
    ])
    expect(fetchSpy.mock.calls[0]?.[1]?.method).toBe('GET')
    for (const [, init] of fetchSpy.mock.calls.slice(1)) {
      expect(init?.method).toBe('POST')
      expect(init?.body).toBeUndefined()
      expect(new Headers(init?.headers).get('Content-Type')).toBeNull()
      expect(new Headers(init?.headers).get('If-Match')).toMatch(/^"[12]"$/)
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(metadata.idempotencyKey)
    }
  })

  it('reads the own status with a GET and rejects badges inconsistent with their facts', async () => {
    const latest = {
      id: caseID, kind: 'personal_initial', status: 'rejected', decision_reason_code: 'evidence_unreadable',
      revision: 4, created_at: '2026-08-06T08:09:10Z', state_changed_at: '2026-08-06T09:09:10Z',
      submitted_at: '2026-08-06T08:19:10Z',
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(providerJSON({ status: 'rejected', latest_case: latest }))

    await expect(identityVerificationApi.getStatus('memory-token')).resolves.toEqual({ status: 'rejected', latest_case: latest })
    expect(fetchSpy).toHaveBeenCalledWith('/v1/identity-verification/status', expect.objectContaining({
      method: 'GET', credentials: 'include', headers: { Authorization: 'Bearer memory-token' },
    }))

    for (const body of [
      { status: 'verified' },
      { status: 'unverified', verified_at: '2026-08-06T08:09:10Z' },
      { status: 'pending', latest_case: { ...latest, status: 'draft', decision_reason_code: undefined } },
      { status: 'rejected' },
      { status: 'unverified', latest_case: { ...latest, status: 'submitted', decision_reason_code: undefined } },
      { status: 'rejected', latest_case: { ...latest, subject_fingerprint_hint: 'abc' } },
      { status: 'rejected', latest_case: latest, applicant_user_id: applicantID },
      { status: 'approved' },
    ]) {
      fetchSpy.mockResolvedValueOnce(providerJSON(JSON.parse(JSON.stringify(body))))
      await expect(identityVerificationApi.getStatus('memory-token')).rejects.toMatchObject({ code: 'invalid_response' })
    }
    fetchSpy.mockResolvedValueOnce(providerJSON({ status: 'verified', verified_at: '2026-08-06T08:09:10Z',
      latest_case: { ...latest, status: 'draft', decision_reason_code: undefined } }))
    await expect(identityVerificationApi.getStatus('memory-token')).resolves.toMatchObject({ status: 'verified' })
  })

  it('accepts only status-bound stable decision reasons', async () => {
    const approved: IdentityVerificationCase = {
      ...draft, status: 'approved', decision_reason_code: 'evidence_verified', revision: 4,
    }
    const rejected: IdentityVerificationCase = {
      ...draft, status: 'rejected', decision_reason_code: 'identity_mismatch', revision: 5,
    }
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(approved, 200, 4))
      .mockResolvedValueOnce(json(rejected, 200, 5))

    await expect(identityVerificationApi.getCase('token', caseID)).resolves.toEqual(approved)
    await expect(identityVerificationApi.getCase('token', caseID)).resolves.toEqual(rejected)
  })

  it('rejects invalid identifiers, revisions, evidence, and metadata before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const metadata = { requestId: 'request-1', idempotencyKey: 'key-1' }

    await expect(identityVerificationApi.getCase('token', 'not-a-uuid'))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    await expect(identityVerificationApi.createDraft('token', {
      kind: 'enterprise', evidence_token: 'short',
    }, metadata)).rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    await expect(identityVerificationApi.submit('token', caseID, 0, metadata))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    await expect(identityVerificationApi.withdraw('token', caseID, 1, {
      ...metadata, idempotencyKey: 'bad key',
    })).rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['an extra sensitive field', { ...draft, subject_fingerprint: 'private' }, 1],
    ['an extra material reference', { ...draft, materials: [{ ...draft.materials[0], object_reference: 's3://private' }] }, 1],
    ['a malformed timestamp', { ...draft, created_at: '2026-02-31T08:09:10Z' }, 1],
    ['a non-canonical id', { ...draft, id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, 1],
    ['a different case identity', { ...draft, id: '44444444-4444-4444-8444-444444444444' }, 1],
    ['an approved case without a reason', { ...draft, status: 'approved' }, 1],
    ['a rejected case with the approval reason', { ...draft, status: 'rejected', decision_reason_code: 'evidence_verified' }, 1],
    ['a draft with a terminal reason', { ...draft, decision_reason_code: 'identity_mismatch' }, 1],
    ['an ETag mismatch', draft, 2],
  ])('rejects %s in a successful response', async (_case, body, revision) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body, 200, revision))

    await expect(identityVerificationApi.getCase('token', caseID))
      .rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('maps network and stable service errors without exposing server messages', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('private network topology'))
      .mockResolvedValueOnce(json({ error: {
        code: 'identity_verification_unavailable',
        message: 'postgres private topology',
        request_id: 'identity-request-2',
      } }, 503))

    await expect(identityVerificationApi.getCase('token', caseID))
      .rejects.toMatchObject({ code: 'network_error', message: 'Network request failed' })
    const error = await identityVerificationApi.getCase('token', caseID).catch((reason) => reason)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 503,
      code: 'identity_verification_unavailable',
      requestId: 'identity-request-2',
      message: 'API request failed',
    })
    expect(String(error)).not.toContain('postgres private topology')
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('creates bounded metadata without embedding evidence or access tokens', () => {
    const metadata = createIdentityVerificationWriteMetadata('submit')
    expect(metadata.requestId).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    expect(metadata.idempotencyKey).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    expect(JSON.stringify(metadata)).not.toMatch(/evidence|access.?token/i)
  })

  it('starts and exactly retries a durable provider session without putting secrets in request identity', async () => {
    const session: IdentityVerificationProviderSession = {
      id: providerSessionID,
      kind: 'enterprise',
      provider: 'trusted_kyc',
      state: 'unknown',
      revision: 1,
      expires_at: '2026-08-09T08:09:10Z',
      updated_at: '2026-08-08T08:09:10Z',
      replayed: false,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(providerJSON(session, 201))
      .mockResolvedValueOnce(providerJSON({
        ...session,
        state: 'succeeded',
        revision: 2,
        evidence_token: evidenceToken,
        replayed: true,
      }))
    const metadata = createIdentityVerificationWriteMetadata('provider-session')
    const input = { kind: 'enterprise' as const, provider: 'trusted_kyc' }

    await identityVerificationApi.startProviderSession('old-token', input, metadata)
    await identityVerificationApi.startProviderSession('new-token', input, metadata)

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      '/v1/identity-verification/provider-sessions',
      '/v1/identity-verification/provider-sessions',
    ])
    expect(fetchSpy.mock.calls.map(([, init]) => init?.body)).toEqual([
      JSON.stringify(input), JSON.stringify(input),
    ])
    const firstHeaders = new Headers(fetchSpy.mock.calls[0]?.[1]?.headers)
    const secondHeaders = new Headers(fetchSpy.mock.calls[1]?.[1]?.headers)
    expect(secondHeaders.get('Idempotency-Key')).toBe(firstHeaders.get('Idempotency-Key'))
    expect(secondHeaders.get('X-Request-ID')).toBe(firstHeaders.get('X-Request-ID'))
    expect(firstHeaders.get('Authorization')).toBe('Bearer old-token')
    expect(secondHeaders.get('Authorization')).toBe('Bearer new-token')
    expect(JSON.stringify(metadata)).not.toMatch(/token|secret|evidence/i)
  })

  it('binds private upload creation, object PUT, and finalize to exact immutable facts', async () => {
    const bytes = new TextEncoder().encode('private identity bytes')
    const file = new File([bytes], 'identity.png', { type: 'image/png' })
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
      .map((value) => value.toString(16).padStart(2, '0')).join('')
    const input = {
      material_kind: 'identity_document' as const,
      content_type: 'image/png' as const,
      size_bytes: file.size,
      sha256: digest,
    }
    const issued: IdentityVerificationProviderUpload = {
      id: providerUploadID,
      session_id: providerSessionID,
      material_kind: 'identity_document',
      state: 'issued',
      revision: 1,
      upload_url: 'https://private-objects.example/upload-once',
      required_headers: {
        'Content-Type': 'image/png',
        'x-amz-meta-sha256': digest,
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': 'opaque-kms-key',
        'x-amz-meta-object-version': 'immutable-version-1',
      },
      expires_at: '2026-08-08T09:09:10Z',
      replayed: false,
    }
    const finalized: IdentityVerificationProviderUpload = {
      id: providerUploadID,
      session_id: providerSessionID,
      material_kind: 'identity_document',
      state: 'finalized',
      revision: 2,
      expires_at: '2026-08-08T09:09:10Z',
      replayed: false,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(providerJSON(issued, 201))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(providerJSON(finalized))
    const createMetadata = createIdentityVerificationWriteMetadata('provider-upload')
    const finalizeMetadata = createIdentityVerificationWriteMetadata('provider-finalize')

    const upload = await identityVerificationApi.createProviderUpload(
      'token', providerSessionID, input, createMetadata,
    )
    await identityVerificationApi.putProviderUpload(upload, input, file)
    await expect(identityVerificationApi.finalizeProviderUpload(
      'token', providerSessionID, providerUploadID, 1, finalizeMetadata,
    )).resolves.toEqual(finalized)

    expect(fetchSpy.mock.calls[0]?.[1]?.body).toBe(JSON.stringify(input))
    expect(String(fetchSpy.mock.calls[0]?.[1]?.body)).not.toMatch(/kms|object|version/i)
    expect(fetchSpy.mock.calls[1]?.[0]).toBe(issued.upload_url)
    expect(fetchSpy.mock.calls[1]?.[1]).toMatchObject({
      method: 'PUT', credentials: 'omit', redirect: 'error', body: file,
    })
    expect(Object.fromEntries(new Headers(fetchSpy.mock.calls[1]?.[1]?.headers))).toEqual(
      Object.fromEntries(new Headers(issued.required_headers)),
    )
    expect(fetchSpy.mock.calls[2]?.[0]).toBe(
      `/v1/identity-verification/provider-sessions/${providerSessionID}/uploads/${providerUploadID}/finalize`,
    )
    const finalizeHeaders = new Headers(fetchSpy.mock.calls[2]?.[1]?.headers)
    expect(finalizeHeaders.get('If-Match')).toBe('"1"')
    expect(finalizeHeaders.get('Idempotency-Key')).toBe(finalizeMetadata.idempotencyKey)
  })

  it.each([
    ['session secret field', { id: providerSessionID, kind: 'personal_initial', provider: 'trusted_kyc', state: 'pending', revision: 1, expires_at: '2026-08-09T08:09:10Z', updated_at: '2026-08-08T08:09:10Z', replayed: false, private_key: 'secret' }],
    ['upload wrong owner', { id: providerUploadID, session_id: caseID, material_kind: 'identity_document', state: 'issued', revision: 1, upload_url: 'https://private-objects.example/upload-once', required_headers: { 'Content-Type': 'image/png' }, expires_at: '2026-08-08T09:09:10Z', replayed: false }],
    ['upload unsafe authorization header', { id: providerUploadID, session_id: providerSessionID, material_kind: 'identity_document', state: 'issued', revision: 1, upload_url: 'https://private-objects.example/upload-once', required_headers: { Authorization: 'secret' }, expires_at: '2026-08-08T09:09:10Z', replayed: false }],
  ])('rejects malformed provider response: %s', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(providerJSON(body, 201))
    const metadata = createIdentityVerificationWriteMetadata('provider-session')

    await expect(identityVerificationApi.startProviderSession('token', {
      kind: 'personal_initial', provider: 'trusted_kyc',
    }, metadata)).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })
})
