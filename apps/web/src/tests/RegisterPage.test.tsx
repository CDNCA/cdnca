import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import i18n, { changeLocale } from '../i18n'
import { RegisterPage } from '../pages/RegisterPage'
import type {
  TurnstileAdapter,
  TurnstileMountOptions,
} from '../pages/registration/turnstileAdapter'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const challengeID = '11111111-1111-4111-8111-111111111111'
const futureExpiry = '2099-08-08T09:10:00Z'

function json(body: unknown, status: number, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers)
  responseHeaders.set('Content-Type', 'application/json')
  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders,
  })
}

function challengeResponse(expiresAt = futureExpiry, replayed = false): Response {
  return json({ data: {
    accepted: true,
    challenge_id: challengeID,
    expires_at: expiresAt,
    replayed,
  } }, 202)
}

function LocationProbe() {
  const location = useLocation()
  return <div data-testid="registration-location">{location.pathname}</div>
}

function fakeTurnstile() {
  let options: TurnstileMountOptions | null = null
  let mounts = 0
  const adapter: TurnstileAdapter = {
    async mount(_container, next) {
      mounts += 1
      options = next
      return () => {
        if (options === next) options = null
      }
    },
  }
  return {
    adapter,
    get mounts() { return mounts },
    async solve(token = 'turnstile-human-token-1234567890') {
      await waitFor(() => expect(options).not.toBeNull())
      act(() => options?.onToken(token))
    },
  }
}

function renderRegistration(turnstile = fakeTurnstile()) {
  renderWithProviders(
    <RegisterPage turnstileAdapter={turnstile.adapter} turnstileSiteKey="test-site-key" />,
    ['/register'],
  )
  return turnstile
}

async function fillRegistration(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('用户名'), 'alice')
  await user.type(screen.getByLabelText('显示名称'), 'Alice')
  await user.type(screen.getByLabelText('密码'), 'correct-horse-battery-staple')
  await user.type(screen.getByLabelText('邮箱'), 'alice@example.com')
  await user.type(screen.getByLabelText('手机号'), '+8613812345678')
  await user.click(screen.getByRole('checkbox', { name: /我已阅读并同意/ }))
}

function headersAt(call: Parameters<typeof fetch>): Headers {
  return new Headers(call[1]?.headers)
}

describe('RegisterPage', () => {
  beforeEach(async () => {
    useSessionStore.getState().clearSession()
    await changeLocale('zh-CN')
  })

  it('shows the shared password strength popover under the field while it has focus', async () => {
    const user = userEvent.setup()
    renderRegistration()
    const password = screen.getByLabelText('密码')
    await user.click(password)
    expect(await screen.findByText('请至少输入 8 个字符。')).toBeInTheDocument()
    expect(screen.getByText('请不要使用容易被猜到的密码。')).toBeInTheDocument()
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuetext', '弱')
    await user.type(password, 'Abcdefgh1234')
    await waitFor(() => expect(screen.getByRole('meter')).toHaveAttribute('aria-valuetext', '强'))
  })

  it('requires both bound contacts, terms, and a real human token before requesting an OTP', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const user = userEvent.setup()
    renderRegistration()

    await user.click(screen.getByRole('button', { name: '发送验证码' }))

    expect(await screen.findByText('用户名须为 3 至 128 位小写字母、数字、点、下划线或连字符')).toBeInTheDocument()
    expect(await screen.findByText('请输入显示名称')).toBeInTheDocument()
    expect(await screen.findByText('密码长度须为 8–1024 位')).toBeInTheDocument()
    expect(await screen.findByText('请输入有效邮箱')).toBeInTheDocument()
    expect(await screen.findByText('请输入 6 至 20 位有效手机号')).toBeInTheDocument()
    expect(await screen.findByText('请阅读并同意服务条款')).toBeInTheDocument()
    expect(await screen.findByText('请先完成人机验证')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('runs challenge, OTP verification, and registration without leaking a destination or logging in', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(challengeResponse())
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json({ accepted: true, replayed: false }, 202))
    const user = userEvent.setup()
    const turnstile = renderRegistration()

    await fillRegistration(user)
    await turnstile.solve()
    await user.click(screen.getByRole('button', { name: '发送验证码' }))

    expect(await screen.findByText('验证码已提交发送，请查看所选验证渠道。')).toBeInTheDocument()
    expect(screen.getByText(/验证码有效期及重新获取冷却剩余/)).toBeInTheDocument()
    expect(screen.getByText('本页面剩余验证次数：5')).toBeInTheDocument()
    expect(screen.queryByText('alice@example.com')).not.toBeInTheDocument()
    expect(screen.queryByText('+8613812345678')).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '验证并注册' }))

    expect(await screen.findByRole('status')).toHaveTextContent('注册请求已受理')
    expect(useSessionStore.getState().status).not.toBe('authenticated')
    expect(fetchSpy).toHaveBeenCalledTimes(3)
    expect(fetchSpy.mock.calls.map((call) => call[0])).toEqual([
      '/v1/auth/registration-challenges',
      '/v1/auth/registration-challenge-verifications',
      '/v1/auth/register',
    ])
    expect(JSON.parse(String(fetchSpy.mock.calls[0]?.[1]?.body))).toEqual({
      username: 'alice',
      email: 'alice@example.com',
      phone: '+8613812345678',
      verification_channel: 'email',
      human_token: 'turnstile-human-token-1234567890',
    })
    expect(JSON.parse(String(fetchSpy.mock.calls[1]?.[1]?.body))).toEqual({
      challenge_id: challengeID,
      username: 'alice',
      email: 'alice@example.com',
      phone: '+8613812345678',
      verification_channel: 'email',
      otp: '123456',
    })
    const registration = JSON.parse(String(fetchSpy.mock.calls[2]?.[1]?.body)) as Record<string, unknown>
    expect(registration).toEqual({
      username: 'alice',
      password: 'correct-horse-battery-staple',
      display_name: 'Alice',
      email: 'alice@example.com',
      phone: '+8613812345678',
      terms_accepted: true,
      terms_version: 'terms-2026-08',
      verification_channel: 'email',
    })
    expect(Object.keys(registration).join(',')).not.toMatch(/proof|token/i)
    for (let index = 0; index < 3; index += 1) {
      expect(fetchSpy.mock.calls[index]?.[1]).toMatchObject({ credentials: 'include' })
    }
  })

  it('retries unknown challenge, verification, and registration writes with each exact original identity', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('private challenge transport failure'))
      .mockResolvedValueOnce(challengeResponse(futureExpiry, true))
      .mockRejectedValueOnce(new TypeError('private verification transport failure'))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockRejectedValueOnce(new TypeError('private registration transport failure'))
      .mockResolvedValueOnce(json({ accepted: true, replayed: true }, 202))
    const user = userEvent.setup()
    const turnstile = renderRegistration()

    await fillRegistration(user)
    await turnstile.solve()
    await user.click(screen.getByRole('button', { name: '发送验证码' }))
    expect(await screen.findByText('验证码请求结果尚未确认，请使用原请求重试或重新开始。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用原请求重试' }))
    expect(await screen.findByText('验证码已提交发送，请查看所选验证渠道。')).toBeInTheDocument()

    await user.type(screen.getByLabelText('验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '验证并注册' }))
    expect(await screen.findByText('验证结果尚未确认，请使用原请求重试或重新开始。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用原请求重试' }))
    expect(await screen.findByText('注册结果尚未确认，请使用原请求重试或重新开始。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用原请求重试' }))

    expect(await screen.findByRole('status')).toHaveTextContent('原注册请求已确认受理')
    expect(fetchSpy).toHaveBeenCalledTimes(6)
    for (const [first, retry] of [[0, 1], [2, 3], [4, 5]] as const) {
      expect(fetchSpy.mock.calls[retry]?.[1]?.body).toBe(fetchSpy.mock.calls[first]?.[1]?.body)
      expect(headersAt(fetchSpy.mock.calls[retry]).get('Idempotency-Key')).toBe(headersAt(fetchSpy.mock.calls[first]).get('Idempotency-Key'))
      expect(headersAt(fetchSpy.mock.calls[retry]).get('X-Request-ID')).toBe(headersAt(fetchSpy.mock.calls[first]).get('X-Request-ID'))
    }
  })

  it('decrements the page safety limit on an explicit invalid OTP without exposing server text', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(challengeResponse())
      .mockResolvedValueOnce(json({ error: {
        code: 'account_registration_challenge_invalid',
        message: 'private OTP detail',
        request_id: 'challenge-request-1',
      } }, 422))
    const user = userEvent.setup()
    const turnstile = renderRegistration()

    await fillRegistration(user)
    await turnstile.solve()
    await user.click(screen.getByRole('button', { name: '发送验证码' }))
    await user.type(await screen.findByLabelText('验证码'), '123456')
    await user.click(screen.getByRole('button', { name: '验证并注册' }))

    expect(await screen.findByText('验证码不正确或已失效，请重试。')).toBeInTheDocument()
    expect(screen.getByText('本页面剩余验证次数：4')).toBeInTheDocument()
    expect(screen.queryByText('private OTP detail')).not.toBeInTheDocument()
  })

  it('localizes rate limiting and its Retry-After cooldown without exposing server text', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ error: {
      code: 'account_registration_challenge_rate_limited',
      message: 'private throttle detail',
      request_id: 'challenge-request-1',
    } }, 429, { 'Retry-After': '45' }))
    const user = userEvent.setup()
    const turnstile = renderRegistration()

    await fillRegistration(user)
    await turnstile.solve()
    await user.click(screen.getByRole('button', { name: '发送验证码' }))

    expect(await screen.findByText('验证码请求过于频繁，请在 45 秒后重试。')).toBeInTheDocument()
    expect(screen.queryByText('private throttle detail')).not.toBeInTheDocument()
  })

  it('marks an already expired challenge and does not issue a verification request', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(challengeResponse('2000-01-01T00:00:00Z'))
    const user = userEvent.setup()
    const turnstile = renderRegistration()

    await fillRegistration(user)
    await turnstile.solve()
    await user.click(screen.getByRole('button', { name: '发送验证码' }))

    expect(await screen.findByText('验证码已过期，请重新开始。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '验证并注册' })).toBeDisabled()
    expect(fetchSpy).toHaveBeenCalledOnce()
  })

  it('clears a solved human challenge when the bound target or channel changes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const user = userEvent.setup()
    const turnstile = renderRegistration()

    await fillRegistration(user)
    await turnstile.solve()
    expect(screen.getByRole('button', { name: '发送验证码' })).toBeEnabled()
    await user.click(screen.getByText('短信验证'))

    expect(screen.getByRole('button', { name: '发送验证码' })).toBeDisabled()
    await waitFor(() => expect(turnstile.mounts).toBeGreaterThan(1))
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['en-US', 'Create account', 'Send verification code'],
    ['qps-ploc', i18n.getFixedT('qps-ploc', 'accountRegistration')('title'), i18n.getFixedT('qps-ploc', 'accountRegistration')('actions.sendCode')],
  ] as const)('renders the complete public form in %s', async (locale, title, sendCode) => {
    await changeLocale(locale)
    renderRegistration()
    expect(screen.getByRole('form', { name: title })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: sendCode })).toBeInTheDocument()
  })

  it('mounts anonymously at /register and redirects an authenticated principal', async () => {
    const anonymous = renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/register'])
    expect(await screen.findByRole('form', { name: '注册账号' })).toBeInTheDocument()
    expect(screen.getByTestId('registration-location')).toHaveTextContent('/register')
    anonymous.unmount()

    const actor = principal()
    act(() => useSessionStore.getState().setSession(authResponse(actor), actor))
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/register'])
    await waitFor(() => expect(screen.getByTestId('registration-location')).toHaveTextContent('/home'))
    expect(screen.queryByRole('form', { name: '注册账号' })).not.toBeInTheDocument()
  })
})
