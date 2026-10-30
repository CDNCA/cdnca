import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import { openrestySecurityApi, type OpenRestySecurityDocument } from '../api/openrestySecurity'
import { useSessionStore } from '../auth/session'
import FirewallPoliciesPage from '../pages/FirewallPoliciesPage'
import firewallCSS from '../pages/FirewallPoliciesPage.css?raw'

vi.mock('../api/openrestySecurity', async () => {
  const actual = await vi.importActual<typeof import('../api/openrestySecurity')>('../api/openrestySecurity')
  return {
    ...actual,
    openrestySecurityApi: {
      ...actual.openrestySecurityApi,
      getGlobal: vi.fn(),
      listRuleGroups: vi.fn(),
      listOverrides: vi.fn(),
    },
  }
})

const globalDocument: OpenRestySecurityDocument = {
  id: '11111111-1111-4111-8111-111111111111',
  scope_type: 'global',
  scope_id: 'platform',
  revision: 7,
  key_configured: true,
  updated_at: '2026-09-14T00:00:00Z',
  config: { cc_enable: true, default_page_rule: '10003' },
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={['/config/waf']}>
      <QueryClientProvider client={client}><FirewallPoliciesPage /></QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('FirewallPoliciesPage visual baseline', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useSessionStore.setState({
      accessToken: 'token',
      sessionEpoch: 1,
      principal: {
        user_id: '44444444-4444-4444-8444-444444444444',
        scope_id: 'platform',
        scope_kind: 'platform',
        tenant_id: null,
        username: 'admin',
        display_name: 'Administrator',
        roles: ['platform_admin'],
        permissions: ['openresty_security.read', 'openresty_security.manage'],
      },
    })
    vi.mocked(openrestySecurityApi.getGlobal).mockResolvedValue(globalDocument)
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue([
      { id: '10003', name: '旋转图片', enabled: true },
      { id: '10004', name: '点击验证', enabled: true },
    ])
    vi.mocked(openrestySecurityApi.listOverrides).mockResolvedValue({ items: [], page: 1, page_size: 20, total: 0 })
  })

  it('keeps the observed tabs, compact cards, and scoped rule-group select', async () => {
    const view = renderPage()

    expect(await screen.findByRole('tab', { name: 'CC全局配置' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: 'WAF全局配置' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '区域及节点配置' })).toBeInTheDocument()
    expect(view.container.querySelector('.firewall-card-grid')).toBeInTheDocument()
    expect(view.container.querySelector('.firewall-setting-card--wide')).toBeInTheDocument()
    expect(view.container.querySelector('.firewall-select-field .ant-select')).toBeInTheDocument()
    expect(view.container.querySelector('button[aria-label="向前查看更多页签"]')).toBeInTheDocument()
    expect(view.container.querySelector('button[aria-label="向后查看更多页签"]')).toBeInTheDocument()
    expect(firewallCSS).toMatch(/\.firewall-tabs-scroll--previous::before\s*\{[\s\S]*content:\s*'\\f115';/)
    expect(firewallCSS).toMatch(/\.firewall-tabs-scroll--next::before\s*\{[\s\S]*content:\s*'\\f11f';/)
    expect(firewallCSS).toMatch(/\.firewall-reference-tabs > \.ant-tabs-nav \.ant-tabs-nav-operations\s*\{[\s\S]*display:\s*none !important;/)
  })

  it('scrolls the mobile tab track with the competitor-style arrow controls', async () => {
    const view = renderPage()

    await screen.findByRole('tab', { name: 'CC全局配置' })
    const wrap = view.container.querySelector<HTMLElement>('.firewall-reference-tabs .ant-tabs-nav-wrap')!
    const previous = view.container.querySelector<HTMLButtonElement>('button[aria-label="向前查看更多页签"]')!
    const next = view.container.querySelector<HTMLButtonElement>('button[aria-label="向后查看更多页签"]')!
    const scrollBy = vi.fn()
    Object.defineProperty(wrap, 'scrollBy', { configurable: true, value: scrollBy })

    fireEvent.click(next)
    expect(scrollBy).toHaveBeenCalledWith({ left: 116, behavior: 'smooth' })
    fireEvent.click(previous)
    expect(scrollBy).toHaveBeenLastCalledWith({ left: -116, behavior: 'smooth' })
  })

  it('opens the rule-group menu with the reference-specific popup surface', async () => {
    const user = userEvent.setup()
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    await user.click(select)

    expect(await screen.findByRole('option', { name: '点击验证' })).toBeInTheDocument()
    expect(document.querySelector('.firewall-rule-group-dropdown')).toBeInTheDocument()
  })
})
