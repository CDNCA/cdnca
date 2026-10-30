import { ApiError } from './auth'
import {
  AccountRegistrationApiError,
  accountRegistrationApi,
  type AccountRegistrationChallengeRequest,
  type AccountRegistrationChallengeVerificationRequest,
  type AccountRegistrationRequest,
  type AccountRegistrationRequestMetadata,
} from './accountRegistration'

const registration: AccountRegistrationRequest = {
  username: 'alice',
  password: 'correct-horse-battery-staple',
  display_name: 'Alice',
  email: 'alice@example.com',
  phone: '+8613812345678',
  terms_accepted: true,
  terms_version: 'terms-2026-08',
  verification_channel: 'email',
}

const challenge: AccountRegistrationChallengeRequest = {
  username: registration.username,
  email: registration.email,
  phone: registration.phone,
  verification_channel: registration.verification_channel,
  human_token: 'turnstile-human-token-1234567890',
}

const verification: AccountRegistrationChallengeVerificationRequest = {
  challenge_id: '11111111-1111-4111-8111-111111111111',
  username: registration.username,
  email: registration.email,
  phone: registration.phone,
  verification_channel: registration.verification_channel,
  otp: '123456',
}

const metadata: AccountRegistrationRequestMetadata = {
  idempotencyKey: 'registration-11111111-1111-4111-8111-111111111111',
  requestId: 'registration-22222222-2222-4222-8222-222222222222',
}

function json(body: unknown, status: number, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers)
  responseHeaders.set('Content-Type', 'application/json')
  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders,
  })
}

function expectAnonymousPost(
  call: Parameters<typeof fetch>,
  path: string,
  body: unknown,
) {
  const [url, init] = call
  const headers = new Headers(init?.headers)
  expect(url).toBe(path)
  expect(init).toMatchObject({ method: 'POST', credentials: 'include' })
  expect(headers.get('Content-Type')).toBe('application/json')
  expect(headers.get('Idempotency-Key')).toBe(metadata.idempotencyKey)
  expect(headers.get('X-Request-ID')).toBe(metadata.requestId)
  expect(headers.has('Authorization')).toBe(false)
  expect(JSON.parse(String(init?.body))).toEqual(body)
}

describe('accountRegistrationApi', () => {
  it('creates a challenge with the exact frozen anonymous contract', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ data: {
      accepted: true,
      challenge_id: verification.challenge_id,
      expires_at: '2026-08-08T09:10:00Z',
      replayed: false,
    } }, 202))

    await expect(accountRegistrationApi.createChallenge(challenge, metadata)).resolves.toEqual({
      accepted: true,
      challenge_id: verification.challenge_id,
      expires_at: '2026-08-08T09:10:00Z',
      replayed: false,
    })

    expect(fetchSpy).toHaveBeenCalledOnce()
    expectAnonymousPost(fetchSpy.mock.calls[0], '/v1/auth/registration-challenges', challenge)
  })

  it('verifies the OTP through a cookie-bearing 204 request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, {
      status: 204,
      headers: { 'Set-Cookie': '__Host-cdnca_registration_proof=private; Secure; HttpOnly' },
    }))

    await expect(accountRegistrationApi.verifyChallenge(verification, metadata)).resolves.toBeUndefined()

    expect(fetchSpy).toHaveBeenCalledOnce()
    expectAnonymousPost(
      fetchSpy.mock.calls[0],
      '/v1/auth/registration-challenge-verifications',
      verification,
    )
  })

  it('submits the frozen registration body with the proof cookie but no proof field', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      accepted: true,
      replayed: false,
    }, 202))

    await expect(accountRegistrationApi.register(registration, metadata)).resolves.toEqual({
      accepted: true,
      replayed: false,
    })

    expect(fetchSpy).toHaveBeenCalledOnce()
    expectAnonymousPost(fetchSpy.mock.calls[0], '/v1/auth/register', registration)
    const body = JSON.parse(String(fetchSpy.mock.calls[0][1]?.body)) as Record<string, unknown>
    expect(Object.keys(body).sort()).toEqual([
      'display_name', 'email', 'password', 'phone', 'terms_accepted', 'terms_version',
      'username', 'verification_channel',
    ])
    expect(Object.keys(body).join(',')).not.toMatch(/proof|token/i)
  })

  it.each([
    ['wrong status', json({ data: { accepted: true, challenge_id: verification.challenge_id, expires_at: '2026-08-08T09:10:00Z', replayed: false } }, 200)],
    ['missing envelope', json({ accepted: true, challenge_id: verification.challenge_id, expires_at: '2026-08-08T09:10:00Z', replayed: false }, 202)],
    ['invalid uuid', json({ data: { accepted: true, challenge_id: 'private', expires_at: '2026-08-08T09:10:00Z', replayed: false } }, 202)],
    ['invalid time', json({ data: { accepted: true, challenge_id: verification.challenge_id, expires_at: 'tomorrow', replayed: false } }, 202)],
    ['extra field', json({ data: { accepted: true, challenge_id: verification.challenge_id, expires_at: '2026-08-08T09:10:00Z', replayed: false, destination: 'private' } }, 202)],
  ])('rejects an invalid challenge receipt: %s', async (_case, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)
    await expect(accountRegistrationApi.createChallenge(challenge, metadata)).rejects.toEqual(
      expect.objectContaining({ code: 'invalid_response', status: 502 }),
    )
  })

  it.each([
    ['wrong verify status', () => accountRegistrationApi.verifyChallenge(verification, metadata), new Response(null, { status: 202 })],
    ['wrong register status', () => accountRegistrationApi.register(registration, metadata), json({ accepted: true, replayed: false }, 200)],
    ['invalid register receipt', () => accountRegistrationApi.register(registration, metadata), json({ accepted: false, replayed: false }, 202)],
  ])('rejects an invalid success response: %s', async (_case, request, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)
    await expect(request()).rejects.toEqual(expect.objectContaining({ code: 'invalid_response', status: 502 }))
  })

  it.each([
    ['account_registration_challenge_invalid', 422],
    ['account_registration_challenge_rate_limited', 429],
    ['account_registration_challenge_conflict', 409],
    ['account_registration_challenge_unavailable', 503],
  ])('preserves stable challenge error %s and bounded Retry-After without server detail', async (code, status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code, message: `private ${code} detail`, request_id: 'registration-request-1' },
    }, status, { 'Retry-After': '45' }))

    const error = await accountRegistrationApi.createChallenge(challenge, metadata).catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(AccountRegistrationApiError)
    expect(error).toEqual(expect.objectContaining({
      code,
      status,
      requestId: 'registration-request-1',
      retryAfterSeconds: status === 429 ? 45 : null,
    }))
    expect((error as Error).message).not.toContain('private')
  })

  it.each([
    ['account_registration_invalid_input', 422],
    ['account_registration_terms_required', 422],
    ['account_registration_rate_limited', 429],
    ['account_registration_idempotency_conflict', 409],
    ['account_registration_unavailable', 503],
  ])('preserves stable registration error %s without server detail', async (code, status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code, message: `private ${code} detail`, request_id: 'registration-request-1' },
    }, status))

    const error = await accountRegistrationApi.register(registration, metadata).catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toEqual(expect.objectContaining({ code, status, requestId: 'registration-request-1' }))
    expect((error as Error).message).not.toContain('private')
  })
})
