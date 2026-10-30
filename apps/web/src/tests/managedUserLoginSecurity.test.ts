import { createUserWriteMetadata, usersApi } from '../api/users'

const userID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const scopeID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const policy = {
  user_id: userID, tenant_scope_id: scopeID, revision: 0,
  login_verification: 'none', login_allowlist: [],
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
})

it('reads the independent policy for the exact selected user and tenant scope', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(policy))
  expect(await usersApi.getLoginSecurity('session-token', userID, scopeID)).toEqual(policy)
  expect(fetchSpy).toHaveBeenCalledWith(
    `/v1/admin/users/${userID}/login-security?tenant_scope_id=${scopeID}`,
    expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer session-token' }) }),
  )
})

it('replaces all policy fields using its own revision and write receipt', async () => {
  const updated = { ...policy, revision: 1, login_verification: 'email', login_allowlist: ['192.0.2.1'] }
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(updated))
  const metadata = createUserWriteMetadata('login-security')
  const input = { expected_revision: 0, login_verification: 'email' as const, login_allowlist: ['192.0.2.1'] }
  expect(await usersApi.updateLoginSecurity('session-token', userID, scopeID, input, metadata)).toEqual(updated)
  expect(fetchSpy).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({
    method: 'PUT', body: JSON.stringify(input),
    headers: expect.objectContaining({ 'Idempotency-Key': metadata.idempotencyKey }),
  }))
})

it.each([
  { ...policy, user_id: scopeID },
  { ...policy, tenant_scope_id: userID },
  { ...policy, revision: -1 },
  { ...policy, login_verification: 'unsupported' },
  { ...policy, login_verification: ['none'] },
  { ...policy, login_allowlist: null },
  { ...policy, extra: true },
])('rejects malformed or mismatched policy responses', async (response) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
  await expect(usersApi.getLoginSecurity('session-token', userID, scopeID)).rejects.toMatchObject({ code: 'invalid_response' })
})

it('does not send an invalid target or policy body', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
  expect(() => usersApi.getLoginSecurity('session-token', 'invalid', scopeID)).toThrow()
  expect(() => usersApi.updateLoginSecurity('session-token', userID, scopeID, {
    expected_revision: 0, login_verification: 'none', login_allowlist: Array(33).fill('192.0.2.1'),
  }, createUserWriteMetadata('login-security'))).toThrow()
  expect(fetchSpy).not.toHaveBeenCalled()
})
