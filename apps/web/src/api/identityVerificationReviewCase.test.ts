import { ApiError } from './auth'
import {
  createIdentityVerificationReviewWriteMetadata,
  identityVerificationReviewCaseApi,
  type IdentityVerificationReviewCase,
} from './identityVerificationReviewCase'

const caseID = '11111111-1111-4111-8111-111111111111'
const applicantID = '22222222-2222-4222-8222-222222222222'
const materialID = '33333333-3333-4333-8333-333333333333'

const submitted: IdentityVerificationReviewCase = {
  id: caseID,
  applicant_user_id: applicantID,
  kind: 'enterprise',
  status: 'submitted',
  agent_relationship: 'authorized_representative',
  revision: 3,
  created_at: '2026-08-06T08:09:10Z',
  state_changed_at: '2026-08-06T09:09:10Z',
  submitted_at: '2026-08-06T09:09:10Z',
  expires_at: '2026-08-07T09:09:10Z',
  retention: {
    eligible: false,
    eligible_at: '2032-08-04T09:09:10Z',
    reason_code: 'case_not_terminal',
  },
  materials: [{
    id: materialID,
    kind: 'business_license',
    encrypted_envelope_present: true,
    mime_type: 'application/pdf',
    size_bytes: 2048,
    created_at: '2026-08-06T08:10:10Z',
  }],
  replayed: false,
}

function json(body: unknown, status = 200, revision = 3): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ETag: `"${revision}"` },
  })
}

describe('identityVerificationReviewCaseApi', () => {
  it('gets and claims a reviewer case with the exact mounted contract and frozen write metadata', async () => {
    const claimed = {
      ...submitted,
      status: 'reviewing' as const,
      reviewer_user_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      revision: 4,
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(submitted))
      .mockResolvedValueOnce(json(claimed, 200, 4))
    const metadata = { requestId: 'identity-review-claim-request', idempotencyKey: 'identity-review-claim-key' }

    await expect(identityVerificationReviewCaseApi.getCase('review-token', caseID))
      .resolves.toEqual(submitted)
    await expect(identityVerificationReviewCaseApi.claim('review-token', caseID, 3, metadata))
      .resolves.toEqual(claimed)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect(fetchSpy.mock.calls.map(([input]) => String(input))).toEqual([
      `/v1/identity-verification/reviewer/cases/${caseID}`,
      `/v1/identity-verification/reviewer/cases/${caseID}/claim`,
    ])
    const getInit = fetchSpy.mock.calls[0]?.[1]
    expect(getInit?.method).toBe('GET')
    expect(getInit?.credentials).toBe('include')
    expect(new Headers(getInit?.headers).get('Authorization')).toBe('Bearer review-token')
    const claimInit = fetchSpy.mock.calls[1]?.[1]
    expect(claimInit?.method).toBe('POST')
    expect(claimInit?.body).toBeUndefined()
    expect(new Headers(claimInit?.headers).get('Authorization')).toBe('Bearer review-token')
    expect(new Headers(claimInit?.headers).get('If-Match')).toBe('"3"')
    expect(new Headers(claimInit?.headers).get('Idempotency-Key')).toBe(metadata.idempotencyKey)
    expect(new Headers(claimInit?.headers).get('X-Request-ID')).toBe(metadata.requestId)
  })

  it('rejects invalid tokens, identifiers, revisions, and metadata before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const metadata = { requestId: 'request-1', idempotencyKey: 'key-1' }

    await expect(identityVerificationReviewCaseApi.getCase('bad token', caseID))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    await expect(identityVerificationReviewCaseApi.getCase('token', 'not-a-uuid'))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    await expect(identityVerificationReviewCaseApi.claim('token', caseID, 0, metadata))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    await expect(identityVerificationReviewCaseApi.claim('token', caseID, 3, {
      ...metadata, idempotencyKey: 'bad key',
    })).rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['an extra sensitive case field', { ...submitted, subject_fingerprint: 'private' }, 3],
    ['material secret content', { ...submitted, materials: [{ ...submitted.materials[0], object_reference: 's3://private' }] }, 3],
    ['a malformed timestamp', { ...submitted, created_at: '2026-02-31T08:09:10Z' }, 3],
    ['a non-canonical identifier', { ...submitted, id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, 3],
    ['a different case identity', { ...submitted, id: '44444444-4444-4444-8444-444444444444' }, 3],
    ['an ETag mismatch', submitted, 4],
  ])('rejects %s in a successful CaseView response', async (_name, body, revision) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body, 200, revision))

    await expect(identityVerificationReviewCaseApi.getCase('token', caseID))
      .rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('accepts only spec status/code pairs and never exposes raw service messages', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('private network topology'))
      .mockResolvedValueOnce(json({ error: {
        code: 'identity_verification_revision_conflict',
        message: 'private database revision',
        request_id: 'review-request-2',
      } }, 409))
      .mockResolvedValueOnce(json({ error: {
        code: 'identity_verification_permission_denied',
        message: 'private IAM detail',
        request_id: 'review-request-3',
      } }, 503))

    await expect(identityVerificationReviewCaseApi.getCase('token', caseID))
      .rejects.toMatchObject({ code: 'network_error', message: 'Network request failed' })
    const conflict = await identityVerificationReviewCaseApi.claim(
      'token', caseID, 3, { requestId: 'request-2', idempotencyKey: 'key-2' },
    ).catch((reason) => reason)
    expect(conflict).toBeInstanceOf(ApiError)
    expect(conflict).toMatchObject({
      status: 409,
      code: 'identity_verification_revision_conflict',
      requestId: 'review-request-2',
      message: 'API request failed',
    })
    expect(String(conflict)).not.toContain('private database revision')
    await expect(identityVerificationReviewCaseApi.getCase('token', caseID))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    expect(fetchSpy).toHaveBeenCalledTimes(3)
  })

  it('creates bounded metadata without embedding case or access-token data', () => {
    const metadata = createIdentityVerificationReviewWriteMetadata()
    expect(metadata.requestId).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    expect(metadata.idempotencyKey).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    expect(JSON.stringify(metadata)).not.toMatch(/11111111|access.?token/i)
  })
})
