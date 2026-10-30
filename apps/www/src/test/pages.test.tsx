import { render, screen, within } from '@testing-library/react'
import { renderToString } from 'react-dom/server'
import { App } from '../App'
import { FEATURES } from '../content/features'
import { CONTROL_INSTALL_COMMAND, LINKS } from '../site'

const FIGURES = ['fig-a', 'fig-b', 'fig-c', 'fig-d', 'fig-e', 'fig-f', 'fig-g']

describe('首页', () => {
  it('中文：大字、主控免费徽标、CTA 指向注册与安装文档', () => {
    render(<App pathname="/" />)
    expect(screen.getByRole('heading', { level: 1, name: '一个主控，就能当 CDN 老板' })).toBeInTheDocument()
    expect(screen.getByText('主控免费，直接可用')).toBeInTheDocument()
    const main = screen.getByRole('main')
    for (const a of within(main).getAllByRole('link', { name: '免费使用' })) expect(a).toHaveAttribute('href', LINKS.register)
    expect(within(main).getAllByRole('link', { name: '查看安装文档' })[0]).toHaveAttribute('href', '/docs/install-control')
    expect(within(main).getByRole('link', { name: '查看更新日志' })).toHaveAttribute('href', '/changelog')
    expect(within(main).getByRole('link', { name: '了解开发者平台' })).toHaveAttribute('href', '/developers')
  })

  it('六张王牌卡都链到对应功能页', () => {
    render(<App pathname="/" />)
    for (const f of FEATURES) {
      expect(screen.getByRole('link', { name: `了解更多：${f.name.zh}` })).toHaveAttribute('href', `/features/${f.slug}`)
    }
  })

  it('英文首页文案与链接', () => {
    render(<App pathname="/en/" />)
    expect(screen.getByRole('heading', { level: 1, name: 'One control plane. Your own CDN business.' })).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'Get started free' })[0]).toHaveAttribute('href', LINKS.register)
    expect(screen.getByRole('link', { name: 'Learn more：Dynamic routing' })).toHaveAttribute('href', '/en/features/dynamic-routing')
  })

  it('安装命令与授权门户生成规则一致，可复制', async () => {
    render(<App pathname="/" />)
    expect(screen.getByText(CONTROL_INSTALL_COMMAND)).toBeInTheDocument()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    screen.getAllByRole('button', { name: '复制' })[0].click()
    expect(writeText).toHaveBeenCalledWith(CONTROL_INSTALL_COMMAND)
    expect(await screen.findByRole('button', { name: '已复制' })).toBeInTheDocument()
  })

  it('FAQ 可展开且含“主控真的免费吗”', () => {
    render(<App pathname="/" />)
    expect(screen.getByText('主控真的免费吗？').closest('details')).not.toHaveAttribute('open')
  })

  it('FAQ 含“忘记管理员密码”，直达随包 root 恢复手册（卡 41）', () => {
    render(<App pathname="/" />)
    const item = screen.getByText('忘记管理员密码怎么办？').closest('details')!
    expect(within(item).getByRole('link', { name: '主控 root 恢复手册' })).toHaveAttribute('href', 'https://auth.cdnca.com/downloads/platform-admin-recovery.md')
    expect(item.textContent).toContain('/data/cdnca-native-root/cdnca/current/docs/platform-admin-recovery.md')
  })

  it('不出现价格页与平台抽成字样', () => {
    const html = renderToString(<App pathname="/" />) + renderToString(<App pathname="/features" />)
    expect(html).not.toMatch(/抽成|抽点|佣金|价格页|commission/i)
    expect(html).not.toContain('href="/pricing"')
  })
})

describe('功能页', () => {
  it('总览页列出六项核心能力与五组全量能力', () => {
    render(<App pathname="/features" />)
    for (const f of FEATURES) expect(screen.getByRole('heading', { level: 3, name: f.name.zh })).toBeInTheDocument()
    for (const g of ['接入', '加速', '安全', '运营', '运维']) expect(screen.getByRole('heading', { level: 3, name: g })).toBeInTheDocument()
  })

  it.each(FEATURES.map((f) => f.slug))('/features/%s 有标语、原理图与注册 CTA', (slug) => {
    const f = FEATURES.find((x) => x.slug === slug)!
    render(<App pathname={`/features/${slug}`} />)
    expect(screen.getByRole('heading', { level: 1, name: f.tagline.zh })).toBeInTheDocument()
    expect(screen.getByRole('img')).toHaveAccessibleName()
    expect(screen.getAllByRole('link', { name: '免费使用' })[0]).toHaveAttribute('href', LINKS.register)
    expect(screen.getByRole('link', { name: '← 返回功能总览' })).toHaveAttribute('href', '/features')
  })

  it('已合入的直结与保证金出现在节点订阅页（availability.ts，merge-batch10）', () => {
    const html = renderToString(<App pathname="/features/node-market" />)
    expect(html).toContain('结算只走直结')
    expect(html).toContain('防跑路保障')
    expect(html).not.toContain('交付中')
  })
})

describe('插图可访问性', () => {
  it('所有 SVG 插图都有可访问名称与描述，中英文各自成文', () => {
    const html = ['/', '/features', ...FEATURES.map((f) => `/features/${f.slug}`)].map((p) => renderToString(<App pathname={p} />)).join('')
    for (const id of FIGURES) expect(html).toContain(`data-figure="${id}"`)
    document.body.innerHTML = html
    const imgs = document.querySelectorAll('svg[role="img"]')
    expect(imgs.length).toBeGreaterThan(0)
    for (const svg of imgs) {
      const ids = svg.getAttribute('aria-labelledby')!.split(' ')
      expect(ids).toHaveLength(2)
      for (const id of ids) expect(svg.querySelector(`[id="${id}"]`)?.textContent?.length ?? 0).toBeGreaterThan(4)
    }
    const en = renderToString(<App pathname="/en/features/waf" />)
    expect(en).toContain('WAF rule-intelligence loop')
  })
})
