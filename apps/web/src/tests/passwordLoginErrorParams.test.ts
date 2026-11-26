import { responseApiError } from '../api/auth'

const scopeID = '11111111-1111-4111-8111-111111111111'
const response = (params: unknown, status = 401, code = 'login_verification_required') => new Response(JSON.stringify({ error: { code, message: 'private detail', request_id: 'safe-request', params } }), { status, headers: { 'Content-Type': 'application/json' } })
it('preserves only safe typed login requirement parameters without raw server details', async () => {
  const error = await responseApiError(response({ channel: 'sms', scope_id: scopeID }))
  expect(error).toMatchObject({ status: 401, code: 'login_verification_required', requestId: 'safe-request', params: { channel: 'sms', scope_id: scopeID } })
  expect(error.message).toBe('API request failed')
})
it.each([
  [{ channel: 'email', scope_id: scopeID }, 403, 'login_verification_required'],
  [{ channel: 'email', scope_id: scopeID }, 401, 'invalid_credentials'],
  [{ channel: 'private-channel', scope_id: scopeID }, 401, 'login_verification_required'],
  [{ channel: 'email', scope_id: 'raw-private-secret' }, 401, 'login_verification_required'],
  [{ channel: 'email', scope_id: scopeID, secret: 'raw-private-secret' }, 401, 'login_verification_required'],
  [null, 401, 'login_verification_required'],
])('discards untrusted or unrelated parameters: %j', async (params, status, code) => {
  const error = await responseApiError(response(params, status as number, code as string))
  expect(error).not.toHaveProperty('params')
  expect(JSON.stringify(error)).not.toContain('raw-private-secret')
})

// 403 entitlement_feature_denied 的 details.required_feature 读成 requiredFeature。
it.each([
  [{ required_feature: 'packages.manage' }, 'packages.manage'],
  [{ required_feature: 'Packages Manage' }, undefined],
  [undefined, undefined],
])('reads the required license feature of an entitlement refusal: %j', async (details, feature) => {
  const error = await responseApiError(new Response(JSON.stringify({ error: {
    code: 'entitlement_feature_denied', message: 'private detail', request_id: 'safe-request', details,
  } }), { status: 403, headers: { 'Content-Type': 'application/json' } }))
  expect(error.code).toBe('entitlement_feature_denied')
  expect(error.requiredFeature).toBe(feature)
})
