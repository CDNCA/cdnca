import { render, screen, within } from '@testing-library/react'
import { renderToString } from 'react-dom/server'
import { App } from '../App'
import { offerPrice, type PublicOffer } from '../content/marketApi'
import { MARKET_PUBLIC_API } from '../site'

const offer: PublicOffer = {
  id: 'o1', name: '华东 BGP', seller_name: '某供货方', regions: ['cn-east'], carriers: ['telecom'], line_class: 'BGP',
  billing_model: 'daily_bundle', pricing: { currency: 'CNY', daily_minor: 1200, min_days: 1, max_days: 30 },
  trial_days: 3, serving_nodes: '6-20', quality_tier: 'high',
}
const plugin = {
  id: 'p1', plugin_id: 'io.cdnca.autodefense', title: '智能自动防御', summary: '学习、观察、告警', kind: 'module',
  publisher_kind: 'official', categories: [], latest_version: '1.0.0', price_models: ['free'],
}

function ok(items: unknown[], more = false) {
  return new Response(JSON.stringify({ items, page: 1, has_more: more }), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

describe('/market', () => {
  it('预渲染只出骨架，不把数据写进 HTML', () => {
    const html = renderToString(<App pathname="/market" />)
    expect(html).toContain('正在加载公开数据')
    expect(html).not.toContain('华东 BGP')
  })

  it('请求公开接口（不带凭据）并渲染报价与插件卡', async () => {
    const fetchMock = vi.fn((url: string) => Promise.resolve(url.endsWith('/node-offers') ? ok([offer], true) : ok([plugin])))
    vi.stubGlobal('fetch', fetchMock)
    render(<App pathname="/market" />)
    expect(await screen.findByRole('heading', { level: 3, name: '华东 BGP' })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { level: 3, name: '智能自动防御' })).toBeInTheDocument()
    // 同源路径：线上 CSP connect-src 只有 'self'（install-site.sh），跨域地址会被浏览器拦截。
    expect(MARKET_PUBLIC_API).toBe('/public/v1')
    expect(fetchMock).toHaveBeenCalledWith(`${MARKET_PUBLIC_API}/node-offers`, expect.objectContaining({ credentials: 'omit' }))
    expect(fetchMock).toHaveBeenCalledWith(`${MARKET_PUBLIC_API}/plugins`, expect.objectContaining({ credentials: 'omit' }))
    const nodes = screen.getByRole('list', { name: '节点市场' })
    expect(within(nodes).getByText('12 CNY / 天')).toBeInTheDocument()
    expect(within(nodes).getByText('质量高')).toBeInTheDocument()
    // C04/MARKET-01：订阅在客户自己的主控里办，按钮指向订阅说明，不再落到授权门户登录根。
    expect(within(nodes).getByRole('link', { name: '在主控中订阅：华东 BGP' })).toHaveAttribute('href', '/docs/market-subscriber#browse')
    expect(screen.getByText('更多条目请登录后查看。')).toBeInTheDocument()
    const plugins = screen.getByRole('list', { name: '插件市场' })
    expect(within(plugins).getByText('官方')).toBeInTheDocument()
    // C04/MARKET-02：官方免费模块不写“购买”。
    expect(within(plugins).getByRole('link', { name: '新装主控已内置：智能自动防御' })).toHaveAttribute('href', '/docs/plugins#official')
    expect(within(plugins).queryByText(/购买/)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/抽成|抽点|佣金|手续费/)
  })

  it('接口不可用时降级为“暂无公开数据”与授权门户链接', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))))
    render(<App pathname="/market" />)
    const msgs = await screen.findAllByText('暂无公开数据（市场接口暂时不可用）。')
    expect(msgs).toHaveLength(2)
    const guides = screen.getAllByRole('link', { name: '查看操作说明' })
    expect(guides.map((a) => a.getAttribute('href'))).toEqual(['/docs/market-subscriber#browse', '/docs/plugins#admin'])
    // 其他导航不受影响
    expect(screen.getByRole('navigation', { name: '主导航' })).toBeInTheDocument()
  })

  it('非 2xx 或格式不对同样降级；空列表显示暂无公开数据', async () => {
    vi.stubGlobal('fetch', vi.fn((url: string) => Promise.resolve(url.endsWith('/node-offers')
      ? new Response('{"error":"unavailable"}', { status: 503 })
      : new Response('{"nope":1}', { status: 200 }))))
    render(<App pathname="/en/market" />)
    expect(await screen.findAllByText('No public listings right now (the market API is unavailable).')).toHaveLength(2)
  })

  it('空列表', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok([]))))
    render(<App pathname="/market" />)
    expect(await screen.findAllByText('暂无公开数据。')).toHaveLength(2)
  })

  it('报价按供货方填写原样格式化', () => {
    expect(offerPrice({ ...offer, billing_model: 'traffic', pricing: { currency: 'CNY', tiers: [{ up_to_gb: 0, price_per_gb_minor: 15 }] } }, 'zh')).toBe('0.15 CNY / GB 起')
    expect(offerPrice({ ...offer, billing_model: 'bandwidth_95', pricing: { currency: 'USD', per_mbps_month_minor: 300 } }, 'en')).toBe('3 USD / Mbps·month')
    expect(offerPrice({ ...offer, billing_model: 'committed_plus_overage' }, 'zh')).toBe('—')
  })

  it('插件按价格给动作：第三方免费“获取”、收费“购买”，英文页带 /en 前缀', async () => {
    const items = [
      { ...plugin, id: 'p2', plugin_id: 'io.example.free', title: '免费工具', publisher_kind: 'third_party', price_models: ['free'] },
      { ...plugin, id: 'p3', plugin_id: 'io.example.paid', title: '收费工具', publisher_kind: 'certified', price_models: ['free', 'subscription_month'] },
    ]
    vi.stubGlobal('fetch', vi.fn((url: string) => Promise.resolve(url.endsWith('/node-offers') ? ok([]) : ok(items))))
    render(<App pathname="/market" />)
    const list = await screen.findByRole('list', { name: '插件市场' })
    expect(within(list).getByRole('link', { name: '在主控中获取：免费工具' })).toHaveAttribute('href', '/docs/plugins#admin')
    expect(within(list).getByRole('link', { name: '在主控中购买：收费工具' })).toHaveAttribute('href', '/docs/plugins#admin')
  })

  it('英文页说明链接带语言前缀', async () => {
    vi.stubGlobal('fetch', vi.fn((url: string) => Promise.resolve(url.endsWith('/node-offers') ? ok([offer]) : ok([]))))
    render(<App pathname="/en/market" />)
    expect(await screen.findByRole('link', { name: 'Subscribe in your control plane：华东 BGP' })).toHaveAttribute('href', '/en/docs/market-subscriber#browse')
  })
})
