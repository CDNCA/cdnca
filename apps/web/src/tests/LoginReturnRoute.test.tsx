import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { MemoryRouter, useLocation, type InitialEntry } from 'react-router-dom'
import { vi } from 'vitest'

import { AppRoutes } from '../App'
import { useSessionStore, type AppRole } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'

vi.mock('../pages/SiteListPage', () => ({ default: () => <h1>site-list-page</h1> }))
vi.mock('../pages/UserListPage', () => ({ default: () => <h1>user-list-page</h1> }))
vi.mock('../pages/AdminHomePage', () => ({ AdminHomePage: () => <h1>admin-home-page</h1> }))
vi.mock('../pages/UserHomePage', () => ({ UserHomePage: () => <h1>user-home-page</h1> }))

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="login-return-location">{`${location.pathname}${location.search}${location.hash}`}</output>
}

function renderRoutes(initialEntry: InitialEntry) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[initialEntry]}>
            <AppRoutes />
            <LocationProbe />
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function actorFor(role: AppRole) {
  return role === 'admin'
    ? principal({
        scope_kind: 'platform',
        tenant_id: null,
        username: 'admin',
        display_name: 'admin',
        roles: ['platform_admin'],
        permissions: ['platform.admin'],
      })
    : principal({ permissions: ['identity.self.read', 'sites.read'] })
}

function mockLogin(role: AppRole) {
  const actor = actorFor(role)
  vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    const target = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const path = new URL(target, 'https://cdnca.invalid').pathname
    if (path === '/v1/auth/login') {
      return Promise.resolve(new Response(JSON.stringify(authResponse(actor)), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    }
    if (path === '/v1/auth/me') {
      return Promise.resolve(new Response(JSON.stringify(actor), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    }
    return Promise.reject(new Error(`unexpected request: ${path}`))
  })
  return actor
}

describe('protected login return navigation', () => {
  it.each([
    ['user', '/site/list?status=active#site-row', 'site-list-page'],
    ['admin', '/sys/user?status=active#user-row', 'user-list-page'],
  ] as const)('returns a %s login to the original protected path', async (role, returnTo, heading) => {
    const actor = mockLogin(role)
    const user = userEvent.setup()
    renderRoutes(returnTo)

    expect(await screen.findByRole('button', { name: '登录' })).toBeInTheDocument()
    await user.type(screen.getByLabelText('用户名、手机或邮箱'), actor.username)
    await user.type(screen.getByLabelText('密码'), 'correct-password')
    await user.click(screen.getByRole('button', { name: '登录' }))

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(screen.getByTestId('login-return-location')).toHaveTextContent(returnTo)
  })

  it.each([
    ['user', '//attacker.example/steal', '/home', 'user-home-page'],
    ['admin', '', '/admin-home', 'admin-home-page'],
    ['user', '/login?returnTo=/site/list', '/home', 'user-home-page'],
    ['admin', 'https://attacker.example/steal', '/admin-home', 'admin-home-page'],
  ] as const)('sends an authenticated %s with an invalid return target to its role home', async (role, returnTo, home, heading) => {
    const actor = actorFor(role)
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderRoutes({ pathname: '/login', state: { returnTo } })

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(screen.getByTestId('login-return-location')).toHaveTextContent(home)
  })

  // fp-role ID-01：另一角色首页的旧书签登录后落到自己的首页，不再弹「需要普通用户/管理员权限」。
  it.each([
    ['admin', '/home?tab=1#top', '/admin-home', 'admin-home-page'],
    ['user', '/admin-home', '/home', 'user-home-page'],
  ] as const)('lands a %s login from the other role home %s on its own home without a role warning', async (role, returnTo, home, heading) => {
    const actor = mockLogin(role)
    const user = userEvent.setup()
    renderRoutes(returnTo)

    expect(await screen.findByRole('button', { name: '登录' })).toBeInTheDocument()
    await user.type(screen.getByLabelText('用户名、手机或邮箱'), actor.username)
    await user.type(screen.getByLabelText('密码'), 'correct-password')
    await user.click(screen.getByRole('button', { name: '登录' }))

    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument()
    expect(screen.getByTestId('login-return-location')).toHaveTextContent(new RegExp(`^${home}$`))
    expect(screen.queryByText(/需要(普通用户|管理员)权限|属于管理员端|当前账号为管理员/)).not.toBeInTheDocument()
  })

  it('lets an authenticated public-only route consume a valid internal return target', async () => {
    const actor = actorFor('admin')
    useSessionStore.getState().setSession(authResponse(actor), actor)

    renderRoutes({ pathname: '/login', state: { returnTo: '/sys/user?status=active#user-row' } })

    expect(await screen.findByRole('heading', { name: 'user-list-page' })).toBeInTheDocument()
    expect(screen.getByTestId('login-return-location')).toHaveTextContent('/sys/user?status=active#user-row')
  })

  it('preserves passwordChanged by showing login and clearing the old session instead of consuming returnTo', async () => {
    const actor = mockLogin('admin')
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const user = userEvent.setup()

    renderRoutes({ pathname: '/login', state: { passwordChanged: true, returnTo: '/sys/user' } })

    expect(await screen.findByText('密码修改成功，请重新登录')).toBeInTheDocument()
    await waitFor(() => expect(useSessionStore.getState().status).toBe('anonymous'))
    expect(screen.getByTestId('login-return-location')).toHaveTextContent('/login')
    expect(screen.queryByRole('heading', { name: 'user-list-page' })).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('用户名、手机或邮箱'), actor.username)
    await user.type(screen.getByLabelText('密码'), 'new-password')
    await user.click(screen.getByRole('button', { name: '登录' }))

    expect(await screen.findByRole('heading', { name: 'admin-home-page' })).toBeInTheDocument()
    expect(screen.getByTestId('login-return-location')).toHaveTextContent('/admin-home')
    expect(screen.queryByRole('heading', { name: 'user-list-page' })).not.toBeInTheDocument()
  })
})
