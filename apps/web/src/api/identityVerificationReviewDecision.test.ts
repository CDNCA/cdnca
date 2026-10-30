import { ApiError } from './auth'
import {
  createIdentityVerificationReviewDecisionMetadata,
  identityVerificationReviewDecisionApi,
  type IdentityVerificationReviewCase,
} from './identityVerificationReviewDecision'

const caseID = '11111111-1111-4111-8111-111111111111'
const reviewing: IdentityVerificationReviewCase = {
  id: caseID,
  applicant_user_id: '22222222-2222-4222-8222-222222222222',
  kind: 'personal_initial',
  status: 'reviewing',
  reviewer_user_id: '33333333-3333-4333-8333-333333333333',
  revision: 2,
  created_at: '2026-08-06T08:09:10Z',
  state_changed_at: '2026-08-06T08:10:10Z',
  submitted_at: '2026-08-06T08:09:40Z',
  retention: {
    eligible: false,
    eligible_at: '2032-08-04T08:09:10Z',
    reason_code: 'case_not_terminal',
  },
  materials: [],
  replayed: false,
}

function json(body: unknown, status = 200, revision = reviewing.revision) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ETag: `"${revision}"` },
  })
}

describe('identityVerificationReviewDecisionApi', () => {
  afterEach(() => vi.restoreAllMocks())

  it('gets a sanitized reviewer case and posts an exact decision contract', async () => {
    const decided = { ...reviewing, status: 'rejected' as const, revision: 3 }
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(reviewing))
      .mockResolvedValueOnce(json(decided, 200, 3))
    const metadata = { requestId: 'review-request-1', idempotencyKey: 'review-key-1' }

    await expect(identityVerificationReviewDecisionApi.getCase('session-token', caseID))
      .resolves.toEqual(reviewing)
    await expect(identityVerificationReviewDecisionApi.decide(
      'session-token', caseID, 2,
      { decision: 'rejected', reason_code: 'evidence_incomplete' }, metadata,
    )).resolves.toEqual(decided)

    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual([
      `/v1/identity-verification/reviewer/cases/${caseID}`,
      `/v1/identity-verification/reviewer/cases/${caseID}/decision`,
    ])
    const init = fetchSpy.mock.calls[1]?.[1]
    const headers = new Headers(init?.headers)
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      decision: 'rejected', reason_code: 'evidence_incomplete',
    })
    expect(headers.get('Authorization')).toBe('Bearer session-token')
    expect(headers.get('If-Match')).toBe('"2"')
    expect(headers.get('Idempotency-Key')).toBe(metadata.idempotencyKey)
    expect(headers.get('X-Request-ID')).toBe(metadata.requestId)
    expect(headers.get('Content-Type')).toBe('application/json')
  })

  it.each([
    [{ decision: 'approved', reason_code: 'suspected_fraud' }],
    [{ decision: 'rejected', reason_code: 'evidence_verified' }],
    [{ decision: 'pending', reason_code: 'evidence_incomplete' }],
    [{ decision: 'rejected', reason_code: 'free text with a document number' }],
  ])('rejects invalid decision/reason combinations before fetch', async (input) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await expect(identityVerificationReviewDecisionApi.decide(
      'session-token', caseID, 2, input as never,
      { requestId: 'request-1', idempotencyKey: 'key-1' },
    )).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects malformed identifiers, revisions, metadata, and sensitive response fields', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...reviewing, subject_fingerprint: 'private' }))
      .mockResolvedValueOnce(json(reviewing, 200, 3))
      .mockResolvedValueOnce(json({
        ...reviewing, id: '44444444-4444-4444-8444-444444444444',
      }))

    await expect(identityVerificationReviewDecisionApi.getCase('session-token', 'not-a-uuid'))
      .rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    await expect(identityVerificationReviewDecisionApi.decide(
      'session-token', caseID, 0,
      { decision: 'approved', reason_code: 'evidence_verified' },
      { requestId: 'bad request', idempotencyKey: 'key-1' },
    )).rejects.toMatchObject({ status: 400, code: 'invalid_request' })
    await expect(identityVerificationReviewDecisionApi.getCase('session-token', caseID))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    await expect(identityVerificationReviewDecisionApi.getCase('session-token', caseID))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    await expect(identityVerificationReviewDecisionApi.getCase('session-token', caseID))
      .rejects.toMatchObject({ status: 502, code: 'invalid_response' })
    expect(fetchSpy).toHaveBeenCalledTimes(3)
  })

  it('maps network and stable errors without exposing raw server messages', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('private network topology'))
      .mockResolvedValueOnce(json({ error: {
        code: 'identity_verification_revision_conflict',
        message: 'postgres row and private subject data',
        request_id: 'review-request-2',
      } }, 409))

    await expect(identityVerificationReviewDecisionApi.getCase('session-token', caseID))
      .rejects.toMatchObject({ status: 0, code: 'network_error', message: 'Network request failed' })
    const error = await identityVerificationReviewDecisionApi.getCase('session-token', caseID)
      .catch((reason) => reason)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 409,
      code: 'identity_verification_revision_conflict',
      requestId: 'review-request-2',
      message: 'API request failed',
    })
    expect(String(error)).not.toContain('postgres')
  })

  it('creates bounded metadata without tokens or case identifiers', () => {
    const metadata = createIdentityVerificationReviewDecisionMetadata()
    expect(metadata.requestId).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    expect(metadata.idempotencyKey).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
    expect(JSON.stringify(metadata)).not.toMatch(/token|case|evidence/i)
  })
})
