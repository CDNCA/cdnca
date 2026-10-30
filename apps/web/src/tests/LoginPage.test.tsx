import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App, ConfigProvider } from 'antd'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi } from 'vitest'

import { LoginPage } from '../pages/LoginPage'
import { renderWithProviders } from '../test/render'
import { authResponse, principal } from '../test/fixtures'

function renderLoginWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <App>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/login']}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/home" element={<div>home</div>} />
              <Route path="/admin-home" element={<div>admin home</div>} />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </App>
    </ConfigProvider>,
  )
}

function serializedMutationCache(queryClient: QueryClient): string {
  return JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state))
}

describe('LoginPage', () => {
  it('links to the canonical public recovery request route', () => {
    renderWithProviders(<LoginPage />, ['/login'])

    expect(screen.getByRole('link', { name: '忘记密码？' })).toHaveAttribute(
      'href',
      '/forgot-password',
    )
  })

  it('rejects missing credentials without calling the API', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const user = userEvent.setup()
    renderWithProviders(<LoginPage />, ['/login'])

    await user.click(screen.getByRole('button', { name: '登录' }))

    expect(await screen.findByText('请输入用户名、手机或邮箱')).toBeInTheDocument()
    expect(await screen.findByText('请输入密码')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['invalid credentials', 'invalid_credentials', 401, '用户名或密码错误'],
    ['a disabled account', 'account_disabled', 403, '账号已被禁用'],
    ['an invalid session after login', 'invalid_session', 401, '会话刷新失败，请重新登录'],
  ])('shows a stable localized error for %s without exposing the server message', async (_case, code, status, expected) => {
    const rawMessage = `private ${code} server detail`
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: {
            code,
            message: rawMessage,
            request_id: 'request-1',
          },
        }),
        { status, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    const user = userEvent.setup()
    renderWithProviders(<LoginPage />, ['/login'])

    await user.type(screen.getByLabelText('用户名、手机或邮箱'), 'jason')
    await user.type(screen.getByLabelText('密码'), 'wrong-password')
    await user.click(screen.getByRole('button', { name: '登录' }))

    await waitFor(() => expect(screen.getByText(expected)).toBeInTheDocument())
    expect(screen.queryByText(rawMessage)).not.toBeInTheDocument()
  })

  it('scrubs failed login credentials from the mutation cache', async () => {
    const password = 'failed-login-password-sentinel'
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({
      error: { code: 'invalid_credentials', message: 'raw server error' },
    }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderLoginWithQueryClient(queryClient)

    await user.type(screen.getByLabelText('用户名、手机或邮箱'), 'jason')
    await user.type(screen.getByLabelText('密码'), password)
    await user.click(screen.getByRole('button', { name: '登录' }))

    await waitFor(() => expect(screen.getByText('用户名或密码错误')).toBeInTheDocument())
    await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0))
    expect(serializedMutationCache(queryClient)).not.toContain(password)
    expect(screen.queryByText('raw server error')).not.toBeInTheDocument()
  })

  it('scrubs successful login credentials while preserving principal navigation', async () => {
    const actor = principal()
    const password = 'successful-login-password-sentinel'
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(authResponse(actor)), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify(actor), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const user = userEvent.setup()
    renderLoginWithQueryClient(queryClient)

    await user.type(screen.getByLabelText('用户名、手机或邮箱'), actor.username)
    await user.type(screen.getByLabelText('密码'), password)
    await user.click(screen.getByRole('button', { name: '登录' }))

    expect(await screen.findByText('home')).toBeInTheDocument()
    await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0))
    expect(serializedMutationCache(queryClient)).not.toContain(password)
  })
})
