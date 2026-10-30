import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { LoginPage } from '../pages/LoginPage'
import { authResponse, principal } from '../test/fixtures'
import '../i18n'

const captchaA = '33333333-3333-4333-8333-333333333333'
const captchaB = '44444444-4444-4444-8444-444444444444'
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
const captcha = (id: string) => json({ id, image: 'data:image/png;base64,iVBORw0KGgo=', expires_at: '2099-01-01T00:00:00Z' }, 201)

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<ConfigProvider button={{ autoInsertSpace: false }}><App><QueryClientProvider client={client}><MemoryRouter initialEntries={['/login']}><Routes>
    <Route path="/login" element={<LoginPage />} /><Route path="/home" element={<div>signed in</div>} />
  </Routes></MemoryRouter></QueryClientProvider></App></ConfigProvider>)
  return userEvent.setup()
}

it('shows the image CAPTCHA after login_captcha_required, sends it once and refreshes it after a wrong answer', async () => {
  const actor = principal()
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ error: { code: 'login_captcha_required' } }, 401))
    .mockResolvedValueOnce(captcha(captchaA))
    .mockResolvedValueOnce(json({ error: { code: 'login_captcha_invalid' } }, 401))
    .mockResolvedValueOnce(captcha(captchaB))
    .mockResolvedValueOnce(json(authResponse(actor)))
    .mockResolvedValueOnce(json(actor))
  const user = setup()
  await user.type(screen.getByLabelText('用户名、手机或邮箱'), 'jason')
  await user.type(screen.getByLabelText('密码'), 'secret-password')
  await user.click(screen.getByRole('button', { name: '登录' }))
  expect(await screen.findByText('登录失败次数较多，请输入图形验证码后重试。')).toBeInTheDocument()
  expect(await screen.findByRole('img', { name: '图形验证码图片' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '登录' })).toBeDisabled()
  await user.type(screen.getByLabelText('图形验证码'), 'ab-c12')
  await user.click(screen.getByRole('button', { name: '登录' }))
  expect(JSON.parse(String(fetchSpy.mock.calls[2][1]?.body))).toEqual({
    username: 'jason', password: 'secret-password', captcha: { id: captchaA, answer: 'abc12' },
  })
  expect(await screen.findByText('图形验证码错误或已过期，请重新输入。')).toBeInTheDocument()
  // A new image is fetched and the old answer is cleared.
  await screen.findByRole('img', { name: '图形验证码图片' })
  expect(String(fetchSpy.mock.calls[3][0])).toMatch(/\/v1\/auth\/login-captchas$/)
  expect(screen.getByLabelText('图形验证码')).toHaveValue('')
  await user.type(screen.getByLabelText('图形验证码'), 'XYZ23')
  await user.click(screen.getByRole('button', { name: '登录' }))
  expect(await screen.findByText('signed in')).toBeInTheDocument()
  expect(JSON.parse(String(fetchSpy.mock.calls[4][1]?.body)).captcha).toEqual({ id: captchaB, answer: 'XYZ23' })
})

it('tells the user how long the account is locked from Retry-After', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({ error: { code: 'login_throttled' } }, 429, { 'Retry-After': '1500' }))
  const user = setup()
  await user.type(screen.getByLabelText('用户名、手机或邮箱'), 'jason')
  await user.type(screen.getByLabelText('密码'), 'secret-password')
  await user.click(screen.getByRole('button', { name: '登录' }))
  expect(await screen.findByText('登录失败次数过多，请 25 分钟后再试，或换一个网络登录。')).toBeInTheDocument()
})
