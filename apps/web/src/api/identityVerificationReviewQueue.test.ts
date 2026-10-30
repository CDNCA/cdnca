import { ApiError } from './auth'
import {
  identityVerificationReviewQueueApi,
  type IdentityVerificationReviewCase,
} from './identityVerificationReviewQueue'

const caseID = '11111111-1111-4111-8111-111111111111'
const reviewCase: IdentityVerificationReviewCase = {
  id: caseID,
  applicant_user_id: '22222222-2222-4222-8222-222222222222',
  kind: 'enterprise',
  status: 'reviewing',
  reviewer_user_id: '33333333-3333-4333-8333-333333333333',
  revision: 3,
  created_at: '2026-08-06T08:00:00Z',
  state_changed_at: '2026-08-06T08:30:00Z',
  submitted_at: '2026-08-06T08:10:00Z',
  expires_at: '2026-08-07T08:10:00Z',
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('identityVerificationReviewQueueApi', () => {
  it('uses the exact mounted reviewer list route and supported filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      items: [reviewCase],
      next_cursor: 'next-page',
    }))

    await expect(identityVerificationReviewQueueApi.list('review-token', {
      kind: 'enterprise',
      status: 'reviewing',
      limit: 50,
      cursor: 'current-page',
    })).resolves.toEqual({ items: [reviewCase], next_cursor: 'next-page' })

    expect(fetchSpy).toHaveBeenCalledOnce()
    const [url, init] = fetchSpy.mock.calls[0]!
    expect(url).toBe('/v1/identity-verification/reviewer/cases?kind=enterprise&status=reviewing&limit=50&cursor=current-page')
    expect(init?.credentials).toBe('include')
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer review-token')
    expect(new Headers(init?.headers).has('Content-Type')).toBe(false)
  })

  it.each([
    ['unknown item field', { ...reviewCase, evidence_token: 'private' }],
    ['missing required field', { ...reviewCase, revision: undefined }],
    ['noncanonical UUID', { ...reviewCase, id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }],
    ['unknown kind', { ...reviewCase, kind: 'passport' }],
    ['unknown status', { ...reviewCase, status: 'queued' }],
    ['unsafe revision', { ...reviewCase, revision: Number.MAX_SAFE_INTEGER + 1 }],
    ['invalid timestamp', { ...reviewCase, state_changed_at: '2026-02-30T00:00:00Z' }],
  ])('rejects a successful payload with %s', async (_name, item) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [item] }))

    await expect(identityVerificationReviewQueueApi.list('token'))
      .rejects.toMatchObject({ status: 502, code: 'identity_verification_invalid_response' })
  })

  it.each([
    ['unknown page field', { items: [], count: 0 }],
    ['non-array items', { items: {} }],
    ['too many items', { items: Array.from({ length: 101 }, () => reviewCase) }],
    ['empty next cursor', { items: [], next_cursor: '' }],
    ['oversized next cursor', { items: [], next_cursor: 'x'.repeat(4097) }],
  ])('rejects malformed page shape: %s', async (_name, body) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(body))

    await expect(identityVerificationReviewQueueApi.list('token'))
      .rejects.toMatchObject({ status: 502, code: 'identity_verification_invalid_response' })
  })

  it.each([
    ['bad token', 'token with spaces', {}],
    ['unsupported limit', 'token', { limit: 21 }],
    ['empty cursor', 'token', { cursor: '' }],
    ['oversized cursor', 'token', { cursor: 'x'.repeat(4097) }],
    ['invalid kind', 'token', { kind: 'passport' }],
    ['invalid status', 'token', { status: 'queued' }],
  ])('rejects %s locally without a request', async (_name, token, params) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    await expect(identityVerificationReviewQueueApi.list(token, params as never))
      .rejects.toMatchObject({ status: 400, code: 'identity_verification_validation_error' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('strictly parses errors and never exposes server or network messages', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: {
        code: 'identity_verification_permission_denied',
        message: 'raw tenant membership topology',
        request_id: 'review-safe-1',
      } }, 403))
      .mockResolvedValueOnce(json({ error: {
        code: 'permission_denied',
        message: 'raw private detail',
        request_id: 'review-safe-2',
        trace: 'private',
      } }, 403))
      .mockRejectedValueOnce(new TypeError('private socket address'))

    const denied = await identityVerificationReviewQueueApi.list('token')
      .catch((error: unknown) => error)
    expect(denied).toBeInstanceOf(ApiError)
    expect(denied).toMatchObject({
      status: 403,
      code: 'identity_verification_permission_denied',
      requestId: 'review-safe-1',
    })
    expect(String(denied)).not.toContain('raw tenant membership topology')

    await expect(identityVerificationReviewQueueApi.list('token'))
      .rejects.toMatchObject({ status: 403, code: 'request_failed', requestId: undefined })
    await expect(identityVerificationReviewQueueApi.list('token'))
      .rejects.toMatchObject({ status: 0, code: 'network_error', message: 'Network request failed' })
  })
})
