import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { LoginPage } from '../pages/LoginPage'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import i18n, { changeLocale } from '../i18n'

vi.mock('../pages/registration/TurnstileWidget', () => ({
  TurnstileWidget: ({ onToken, label }: { onToken: (token: string) => void; label: string }) =>
    <button type="button" onClick={() => onToken('human-token-only-in-memory')}>{label}</button>,
}))
vi.mock('../pages/login/ExternalCaptchaWidget', () => ({
  ExternalCaptchaWidget: ({ onToken, config }: { onToken: (token: string) => void; config: { provider: string; appId: string } }) =>
    <button type="button" onClick={() => onToken('{"ticket":"t-1","randstr":"r-1"}')}>{`external ${config.provider} ${config.appId}`}</button>,
}))

const scopeID = '11111111-1111-4111-8111-111111111111'
const challengeID = '22222222-2222-4222-8222-222222222222'
const password = 'private-password-only-in-component'
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const required = (channel = 'email') => json({ error: { code: 'login_verification_required', message: 'private policy detail', params: { channel, scope_id: scopeID } } }, 401)
const methods = (mode: string, provider = '', appId = '') => json({ data: {
  email_enabled: true, sms_enabled: true, email_anti_abuse_mode: mode, sms_anti_abuse_mode: 'native',
  captcha_provider: provider, captcha_app_id: appId,
} })
const accepted = () => json({ data: { accepted: true, challenge_id: challengeID, expires_at: '2099-09-28T12:00:00Z', replayed: false } }, 202)
function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const view = render(<ConfigProvider button={{ autoInsertSpace: false }}><App><QueryClientProvider client={client}><MemoryRouter initialEntries={['/login']}><Routes>
    <Route path="/login" element={<LoginPage />} /><Route path="/home" element={<div>signed in</div>} /><Route path="/forgot-password" element={<div>recovery</div>} />
  </Routes></MemoryRouter></QueryClientProvider></App></ConfigProvider>)
  return { ...view, client, user: userEvent.setup() }
}
async function enterCredentials(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('用户名、手机或邮箱'), 'jason')
  await user.type(screen.getByLabelText('密码'), password)
  await user.click(screen.getByRole('button', { name: '登录' }))
}

it.each(['email', 'sms'])('requires explicit code sending and binds %s proof to the validated scope without a mutation cache', async (channel) => {
  const actor = principal({ scope_id: scopeID })
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required(channel)).mockResolvedValueOnce(accepted())
    .mockResolvedValueOnce(json(authResponse(actor))).mockResolvedValueOnce(json(actor))
  const { user, client } = setup()
  await enterCredentials(user)
  await screen.findByRole('button', { name: '发送验证码' })
  expect(fetchSpy).toHaveBeenCalledTimes(1)
  expect(screen.queryByText('private policy detail')).not.toBeInTheDocument()
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  await user.click(screen.getByRole('button', { name: '发送验证码' }))
  await screen.findByText('验证码已发送')
  const send = fetchSpy.mock.calls[1]
  expect(JSON.parse(String(send[1]?.body))).toEqual({ username: 'jason', password, scope_id: scopeID })
  expect(new Headers(send[1]?.headers).get('Idempotency-Key')).toBeTruthy()
  expect(new Headers(send[1]?.headers).get('X-Request-ID')).toBeTruthy()
  await user.type(screen.getByLabelText('登录验证码'), '654321')
  await user.click(screen.getByRole('button', { name: '登录' }))
  expect(await screen.findByText('signed in')).toBeInTheDocument()
  const final = fetchSpy.mock.calls[2]
  expect(JSON.parse(String(final[1]?.body))).toEqual({ username: 'jason', password, scope_id: scopeID, login_challenge: { challenge_id: challengeID, otp: '654321' } })
  expect(new Headers(final[1]?.headers).get('Idempotency-Key')).toBeTruthy()
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(JSON.stringify([localStorage, sessionStorage])).not.toMatch(/private-password-only-in-component|654321/)
})

it('keeps pending password requests out of caches and ignores successful login after navigation', async () => {
  let resolve!: (response: Response) => void
  let loginSignal: AbortSignal | undefined
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementationOnce((_input, init) => {
    loginSignal = init?.signal as AbortSignal
    return new Promise<Response>(done => { resolve = done })
  })
  const { user, client } = setup()
  await enterCredentials(user)
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  await user.click(screen.getByRole('link', { name: '忘记密码？' }))
  await screen.findByText('recovery')
  await waitFor(() => expect(loginSignal?.aborted).toBe(true))
  await act(async () => resolve(json(authResponse(principal()))))
  expect(fetchSpy).toHaveBeenCalledTimes(1)
  expect(useSessionStore.getState().principal).toBeNull()
})

it('discards old challenge and pending send after credentials change', async () => {
  let resolve!: (response: Response) => void
  let sendSignal: AbortSignal | undefined
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required()).mockImplementationOnce((_input, init) => {
    sendSignal = init?.signal as AbortSignal
    return new Promise<Response>(done => { resolve = done })
  })
  const { user } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await user.clear(screen.getByLabelText('用户名、手机或邮箱'))
  await user.type(screen.getByLabelText('用户名、手机或邮箱'), 'other-user')
  await waitFor(() => expect(sendSignal?.aborted).toBe(true))
  await act(async () => resolve(accepted()))
  await waitFor(() => expect(screen.queryByLabelText('登录验证码')).not.toBeInTheDocument())
  expect(screen.queryByText('验证码已发送')).not.toBeInTheDocument()
  expect(fetchSpy).toHaveBeenCalledTimes(2)
})

it('retries an uncertain send with the exact body and metadata and keeps pending credentials out of caches', async () => {
  let resolve!: (response: Response) => void
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required()).mockRejectedValueOnce(new TypeError('offline'))
    .mockImplementationOnce(() => new Promise<Response>(done => { resolve = done }))
  const { user, client } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await user.click(await screen.findByRole('button', { name: '使用同一请求重试发送' }))
  await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
  expect(fetchSpy.mock.calls[2]).toEqual(fetchSpy.mock.calls[1])
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(JSON.stringify([localStorage, sessionStorage])).not.toContain(password)
  await act(async () => resolve(accepted()))
  expect(await screen.findByText('验证码已发送')).toBeInTheDocument()
})

it('locks an uncertain login proof and retries exactly even after its receipt expires', async () => {
  const actor = principal({ scope_id: scopeID })
  const clock = Date.now()
  const receipt = { data: { accepted: true, challenge_id: challengeID, expires_at: new Date(clock + 60_000).toISOString(), replayed: false } }
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required()).mockResolvedValueOnce(json(receipt, 202))
    .mockRejectedValueOnce(new TypeError('offline')).mockResolvedValueOnce(json(authResponse(actor))).mockResolvedValueOnce(json(actor))
  const { user, client } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await user.type(await screen.findByLabelText('登录验证码'), '654321')
  await user.click(screen.getByRole('button', { name: '登录' }))
  await waitFor(() => expect(screen.getByLabelText('登录验证码')).toBeDisabled())
  expect(screen.getByRole('button', { name: '发送验证码' })).toBeDisabled()
  vi.spyOn(Date, 'now').mockReturnValue(clock + 120_000)
  await user.click(screen.getByRole('button', { name: '重试登录验证' }))
  expect(await screen.findByText('signed in')).toBeInTheDocument()
  expect(fetchSpy.mock.calls[3]).toEqual(fetchSpy.mock.calls[2])
  expect(client.getMutationCache().getAll()).toHaveLength(0)
})

it('retains a successful login response in component memory and retries /me without consuming OTP twice', async () => {
  const actor = principal({ scope_id: scopeID })
  const loginResponse = json(authResponse(actor))
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required()).mockResolvedValueOnce(accepted())
    .mockResolvedValueOnce(loginResponse).mockRejectedValueOnce(new TypeError('offline'))
    .mockResolvedValueOnce(json(actor))
  const { user, client } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await user.type(await screen.findByLabelText('登录验证码'), '654321')
  await user.click(screen.getByRole('button', { name: '登录' }))
  expect(screen.getByLabelText('登录验证码')).toBeDisabled()
  await user.click(await screen.findByRole('button', { name: '重试登录验证' }))
  expect(await screen.findByText('signed in')).toBeInTheDocument()
  expect(fetchSpy).toHaveBeenCalledTimes(5)
  expect(new URL(typeof fetchSpy.mock.calls[4][0] === 'string' ? fetchSpy.mock.calls[4][0] : String(fetchSpy.mock.calls[4][0]), 'https://cdnca.invalid').pathname).toBe('/v1/auth/me')
  expect(client.getMutationCache().getAll()).toHaveLength(0)
})

it('allows a fresh challenge after invalid OTP and uses a new idempotency key', async () => {
  const actor = principal({ scope_id: scopeID })
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required()).mockResolvedValueOnce(accepted())
    .mockResolvedValueOnce(json({ error: { code: 'account_login_verification_invalid', message: 'private OTP detail' } }, 401))
    .mockResolvedValueOnce(accepted())
    .mockResolvedValueOnce(json(authResponse(actor))).mockResolvedValueOnce(json(actor))
  const { user } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await user.type(await screen.findByLabelText('登录验证码'), '654321')
  await user.click(screen.getByRole('button', { name: '登录' }))
  await screen.findByText('验证码无效或已过期，请重新输入或发送。')
  expect(screen.queryByText('private OTP detail')).not.toBeInTheDocument()
  expect(screen.getByLabelText('登录验证码')).toBeDisabled()
  await user.click(screen.getByRole('button', { name: '发送验证码' }))
  await user.type(await screen.findByLabelText('登录验证码'), '123456')
  await user.click(screen.getByRole('button', { name: '登录' }))
  expect(await screen.findByText('signed in')).toBeInTheDocument()
  const before = fetchSpy.mock.calls[2][1], after = fetchSpy.mock.calls[4][1]
  expect(JSON.parse(String(after?.body)).login_challenge.otp).toBe('123456')
  expect(new Headers(after?.headers).get('Idempotency-Key')).not.toBe(new Headers(before?.headers).get('Idempotency-Key'))
})

it('never includes a hidden OTP or stale scope in password-only login after changing credentials', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required()).mockResolvedValueOnce(accepted()).mockResolvedValueOnce(required())
  const { user } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await user.type(await screen.findByLabelText('登录验证码'), '654321')
  await user.type(screen.getByLabelText('密码'), '-changed')
  expect(screen.queryByLabelText('登录验证码')).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '登录' }))
  await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
  expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toEqual({ username: 'jason', password: password + '-changed' })
  expect(new Headers(fetchSpy.mock.calls[2][1]?.headers).has('Idempotency-Key')).toBe(false)
})

it('invalidates pending sends on session epoch change and permits a fresh login attempt', async () => {
  let resolve!: (response: Response) => void
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required())
    .mockImplementationOnce(() => new Promise<Response>(done => { resolve = done })).mockResolvedValueOnce(required())
  const { user } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await act(async () => useSessionStore.getState().clearSession())
  expect(screen.getByLabelText('密码')).toHaveValue('')
  expect(screen.queryByLabelText('登录验证码')).not.toBeInTheDocument()
  await enterCredentials(user)
  await screen.findByRole('button', { name: '发送验证码' })
  await act(async () => resolve(accepted()))
  expect(screen.queryByText('验证码已发送')).not.toBeInTheDocument()
  expect(screen.getByLabelText('登录验证码')).toBeDisabled()
  expect(fetchSpy).toHaveBeenCalledTimes(3)
})

it('does not apply a late /me response after navigation', async () => {
  let resolve!: (response: Response) => void
  const actor = principal()
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(authResponse(actor)))
    .mockImplementationOnce(() => new Promise<Response>(done => { resolve = done }))
  const { user } = setup()
  await enterCredentials(user)
  await waitFor(() => expect(resolve).toBeTypeOf('function'))
  await user.click(screen.getByRole('link', { name: '忘记密码？' }))
  await act(async () => resolve(json(actor)))
  expect(useSessionStore.getState().principal).toBeNull()
  expect(screen.getByText('recovery')).toBeInTheDocument()
})

it('honors Retry-After and only sends a human token after the server requires verification', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required())
    .mockResolvedValueOnce(json({ error: { code: 'account_login_human_verification_required' } }, 422))
    .mockResolvedValueOnce(methods('native'))
    .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'account_login_rate_limited' } }), {
      status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '30' },
    }))
  const { user } = setup()
  await enterCredentials(user)
  expect(screen.queryByRole('button', { name: '请完成人机验证' })).not.toBeInTheDocument()
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await screen.findByText('请完成人机验证后发送验证码。')
  expect(screen.getByRole('button', { name: '发送验证码' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: '请完成人机验证' }))
  await user.click(screen.getByRole('button', { name: '发送验证码' }))
  expect(await screen.findByRole('button', { name: '30 秒后可重试' })).toBeDisabled()
  expect(String(fetchSpy.mock.calls[2][0])).toMatch(/\/v1\/auth\/login-methods$/)
  expect(JSON.parse(String(fetchSpy.mock.calls[3][1]?.body))).toEqual({ username: 'jason', password, scope_id: scopeID, human_token: 'human-token-only-in-memory' })
  expect(JSON.stringify([localStorage, sessionStorage])).not.toContain('human-token-only-in-memory')
})

it('uses the Tencent CAPTCHA widget when the challenge channel is protected by it (FX55)', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required('email'))
    .mockResolvedValueOnce(json({ error: { code: 'account_login_human_verification_required' } }, 422))
    .mockResolvedValueOnce(methods('tencent', 'tencent', '190000001'))
    .mockResolvedValueOnce(accepted())
  const { user } = setup()
  await enterCredentials(user)
  await user.click(await screen.findByRole('button', { name: '发送验证码' }))
  await user.click(await screen.findByRole('button', { name: 'external tencent 190000001' }))
  expect(screen.queryByRole('button', { name: '请完成人机验证' })).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '发送验证码' }))
  await screen.findByText('验证码已发送')
  expect(JSON.parse(String(fetchSpy.mock.calls[3][1]?.body))).toEqual({
    username: 'jason', password, scope_id: scopeID, human_token: '{"ticket":"t-1","randstr":"r-1"}',
  })
})

it.each(['zh-CN', 'zh-TW', 'en-US', 'qps-ploc'] as const)('renders localized challenge and failure text for %s', async locale => {
  await changeLocale(locale)
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(required()).mockResolvedValueOnce(json({ error: { code: 'login_source_denied', message: 'private source detail' } }, 403))
  const { user } = setup()
  await user.type(screen.getByLabelText(i18n.t('auth:username')), 'jason')
  await user.type(screen.getByLabelText(i18n.t('auth:password')), password)
  await user.click(screen.getByRole('button', { name: i18n.t('auth:login') }))
  await user.click(await screen.findByRole('button', { name: i18n.t('passwordLoginChallenge:send') }))
  expect(await screen.findByText(i18n.t('passwordLoginChallenge:errors.login_source_denied'))).toBeInTheDocument()
  expect(screen.queryByText('private source detail')).not.toBeInTheDocument()
})
