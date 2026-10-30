import { authApi } from '../api/auth'
import { passwordLoginMetadata, sendPasswordLoginChallenge } from '../api/passwordLoginChallenge'

const scope = '11111111-1111-4111-8111-111111111111'
const challenge = '22222222-2222-4222-8222-222222222222'
const input = { username: 'member', password: 'component-secret', scope_id: scope }
const metadata = { idempotencyKey: 'request-retry-key', requestId: 'request-trace-id' }
const receipt = { accepted: true, challenge_id: challenge, expires_at: '2099-09-28T12:00:00Z', replayed: false }
const response = (body: unknown, status = 202) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

it('uses secure request metadata and only serializes the password flow whitelist', async () => {
  const first = passwordLoginMetadata(), second = passwordLoginMetadata()
  expect(first.idempotencyKey).toMatch(/^password-login-[a-f0-9]{32}$/)
  expect(first.requestId).toMatch(/^[a-f0-9]{32}$/)
  expect(first.requestId).not.toBe(first.idempotencyKey.slice('password-login-'.length))
  expect(first).not.toEqual(second)
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response({ data: receipt }))
  await expect(sendPasswordLoginChallenge({ ...input, channel: 'sms', identifier: 'private-contact', human_token: 'human-token' } as typeof input, metadata)).resolves.toEqual(receipt)
  const options = fetchSpy.mock.calls[0][1]
  expect(options?.credentials).toBe('omit')
  expect(options?.cache).toBe('no-store')
  expect(JSON.parse(String(options?.body))).toEqual({ ...input, human_token: 'human-token' })
})

it.each([
  [{ data: receipt }, 200],
  [{ data: { ...receipt, private_contact: 'private' } }, 202],
  [{ data: { ...receipt, challenge_id: 'not-a-uuid' } }, 202],
  [{ data: { ...receipt, expires_at: '2099-09-28T12:00:00+00:00' } }, 202],
  [{ data: { ...receipt, accepted: false } }, 202],
  [{ data: { ...receipt, replayed: null } }, 202],
  [{ data: receipt, private: 'detail' }, 202],
  [null, 202],
])('rejects malformed or non-contract challenge receipts', async (body, status) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response(body, status as number))
  await expect(sendPasswordLoginChallenge(input, metadata)).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
})

it.each([['120', 120], ['0', 60], ['-1', 60], ['86401', 60], ['1e2', 60], ['1.5', 60], ['', 60]])('bounds integer Retry-After %s', async (value, seconds) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'account_login_rate_limited', message: 'private' } }), {
    status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': String(value) },
  }))
  await expect(sendPasswordLoginChallenge(input, metadata)).rejects.toMatchObject({ code: 'account_login_rate_limited', retryAfterSeconds: seconds, message: 'API request failed' })
})

it('rejects invalid proof or missing idempotency metadata before any login request', () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
  expect(() => authApi.login({ ...input, login_challenge: { challenge_id: challenge, otp: '123456' } })).toThrow()
  expect(() => authApi.login({ ...input, login_challenge: { challenge_id: challenge, otp: 'no' } }, metadata.idempotencyKey)).toThrow()
  expect(fetchSpy).not.toHaveBeenCalled()
})
