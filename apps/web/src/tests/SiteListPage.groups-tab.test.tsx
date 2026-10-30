import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { useLocation } from 'react-router-dom'

import { useSessionStore } from '../auth/session'
import SiteListPage from '../pages/SiteListPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

vi.mock('../pages/SiteGroupsPage', () => ({
  default: () => <div data-testid="embedded-groups">groups</div>,
}))

function CurrentPath() {
  return <output data-testid="current-path">{useLocation().pathname}</output>
}

describe('website list group tab', function siteGroupsStayOnList() {
  beforeEach(() => {
    sessionStorage.clear()
    const actor = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['sites.read', 'sites.manage', 'users.read'], roles: ['platform_owner'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ items: [], total: 0, page: 1, limit: 10 }), { status: 200 }))
  })

  it('opens the group view inside the list and returns to the list without changing route', async () => {
    renderWithProviders(<><SiteListPage /><CurrentPath /></>, ['/site/list'])
    await screen.findByText('共 0 条')
    fireEvent.click(screen.getByRole('button', { name: '分组管理' }))
    expect(screen.getByTestId('embedded-groups')).toBeInTheDocument()
    expect(screen.getByTestId('current-path')).toHaveTextContent('/site/list')
    expect(screen.queryByRole('button', { name: '添加网站' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '分组管理' })).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(screen.getByRole('button', { name: '网站列表' }))
    expect(screen.queryByTestId('embedded-groups')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '添加网站' })).toBeInTheDocument()
    expect(screen.getByTestId('current-path')).toHaveTextContent('/site/list')
  })

  it('opens the group tab of the one site settings shell from the route state (SITE-CURRENT-07)', async () => {
    renderWithProviders(<><SiteListPage /><CurrentPath /></>, [{ pathname: '/site/list', state: { siteSubnav: 'groups' } }])
    expect(await screen.findByTestId('embedded-groups')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '分组管理' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('unmounts the group view immediately when site read permission is revoked', async () => {
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await screen.findByText('共 0 条')
    fireEvent.click(screen.getByRole('button', { name: '分组管理' }))
    expect(screen.getByTestId('embedded-groups')).toBeInTheDocument()
    act(() => useSessionStore.setState({ principal: { ...useSessionStore.getState().principal!, permissions: [] } }))
    expect(screen.queryByTestId('embedded-groups')).not.toBeInTheDocument()
  })

  it('does not bypass a server-side list permission rejection through the group tab', async () => {
    vi.mocked(fetch).mockImplementation(async () => new Response(JSON.stringify({ error: { code: 'permission_denied', message: 'denied' } }), { status: 403 }))
    renderWithProviders(<SiteListPage />, ['/site/list'])
    await waitFor(() => expect(document.querySelector('.ant-result-403')).not.toBeNull())
    fireEvent.click(screen.getByRole('button', { name: '分组管理' }))
    expect(screen.queryByTestId('embedded-groups')).not.toBeInTheDocument()
  })

  it('removes the embedded view when an already pending list read is denied', async () => {
    let complete!: (response: Response) => void
    vi.mocked(fetch).mockImplementation(() => new Promise((resolve) => { complete = resolve }))
    renderWithProviders(<SiteListPage />, ['/site/list'])
    fireEvent.click(screen.getByRole('button', { name: '分组管理' }))
    expect(screen.getByTestId('embedded-groups')).toBeInTheDocument()
    await act(async () => complete(new Response(JSON.stringify({ error: { code: 'permission_denied', message: 'denied' } }), { status: 403 })))
    await waitFor(() => expect(screen.queryByTestId('embedded-groups')).not.toBeInTheDocument())
    expect(document.querySelector('.ant-result-403')).not.toBeNull()
  })
})
