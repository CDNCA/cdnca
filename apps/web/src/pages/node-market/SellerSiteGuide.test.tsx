import { screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { SellerSiteGuide, sellerSiteOrigin } from './SellerSiteGuide'

// fix-sellersite: the controller points at the seller site for what only it
// does; the button follows the seller site address the market answered with.

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: [], permissions: ['marketplace.browse', 'marketplace.sell'] })

function member(body: Record<string, unknown>) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ id: 'm', display_name: 'me', status: 'active', features: [],
    offers_quota: 3, ...body }), { status: 200, headers: { 'Content-Type': 'application/json' } })))
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'market-token' }, admin)
})
afterEach(() => vi.unstubAllGlobals())

describe('卖家站指路', () => {
  it('已开通供货：说明卖家站管收入、提现、团队等，按钮去卖家站结算页', async () => {
    member({ supplier: { status: 'active', can_sell: true }, seller_site_url: 'https://developer.example.test' })
    renderWithProviders(<SellerSiteGuide scope="node" />)
    expect(await screen.findByText('收入、提现与团队在卖家站')).toBeInTheDocument()
    expect(screen.getByText(/节点的增减只能在这里设置/)).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: '去卖家站' })).toHaveAttribute('href', 'https://developer.example.test/finance')
  })

  it('未入驻：显示申请成为节点供应商，按钮去入驻页', async () => {
    member({ supplier: { status: 'none', can_sell: false, apply_url: 'https://developer.example.test/onboarding?role=node_supplier' },
      seller_site_url: 'https://developer.example.test' })
    renderWithProviders(<SellerSiteGuide scope="node" />)
    expect(await screen.findByRole('link', { name: '申请成为节点供应商' }))
      .toHaveAttribute('href', 'https://developer.example.test/onboarding?role=node_supplier')
  })

  it('市场未配置卖家站：只留文字，不显示按钮', async () => {
    member({ supplier: { status: 'active', can_sell: true } })
    renderWithProviders(<SellerSiteGuide scope="plugin" />)
    expect(await screen.findByText('发布插件在卖家站')).toBeInTheDocument()
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })

  it('地址只取 http(s) 源，旧市场回落到 apply_url 的源', () => {
    expect(sellerSiteOrigin({ id: 'm', display_name: '', status: 'active', features: [], offers_quota: 0,
      supplier: { status: 'none', can_sell: false, apply_url: 'https://old.example.test/onboarding?role=node_supplier' } })).toBe('https://old.example.test')
    expect(sellerSiteOrigin({ id: 'm', display_name: '', status: 'active', features: [], offers_quota: 0, seller_site_url: 'javascript:alert(1)' })).toBeNull()
  })
})
