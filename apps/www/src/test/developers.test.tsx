import { render, screen, within } from '@testing-library/react'
import { App } from '../App'
import { getCatalog, getGroupDetail } from '../content/apiCatalog'
import { urls } from '../entry-server'
import { LINKS } from '../site'

describe('可开发类目与市场实际支持一致', () => {
  it('类目页逐行标明官方专属', () => {
    render(<App pathname="/developers/categories" />)
    const row = screen.getByRole('row', { name: /聚合边缘适配器/ })
    expect(within(row).getByText('官方专属')).toBeInTheDocument()
    expect(within(screen.getByRole('row', { name: /^主题/ })).getByText('认证开发者')).toBeInTheDocument()
    expect(screen.getAllByText('官方专属')).toHaveLength(4)
  })
})

describe('开发者平台页', () => {
  it('CTA 指向卖家站登录与接口目录，介绍三种对接方式', () => {
    render(<App pathname="/developers" />)
    expect(screen.getByRole('heading', { level: 1, name: '写插件，在每一个 cdnca 主控里售卖' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '进入开发者平台' })).toHaveAttribute('href', LINKS.developerLogin)
    expect(LINKS.developerLogin).toBe('https://developer.cdnca.com/login')
    expect(screen.getByRole('link', { name: '查看开放接口' })).toHaveAttribute('href', '/developers/api')
    for (const h of ['开放 API', '事件 Webhook', '插件']) expect(screen.getByRole('heading', { level: 3, name: h })).toBeInTheDocument()
  })

  it('收入页不出现平台抽成，节点市场直结（已合入）说明钱进供货方商户号', () => {
    const { container } = render(<App pathname="/developers/earn" />)
    expect(container.textContent).not.toMatch(/抽成|抽点|佣金|手续费/)
    expect(container.textContent).toContain('商户号')
    expect(container.querySelector('[data-figure="fig-i"]')).not.toBeNull()
  })
})

describe('开放接口目录', () => {
  const c = getCatalog()!

  it('目录来自生成文件：有 API Key 接口，不含内部接口', () => {
    expect(c.sources).toEqual(['api/openapi/v1/control.yaml', 'api/openapi/v1/sites.yaml', 'api/openapi/v1/dns-acme.yaml'])
    expect(c.api_key_count).toBeGreaterThan(0)
    expect(c.groups.flatMap((g) => g.operations).some((o) => o.path.startsWith('/v1/internal/'))).toBe(false)
  })

  it('索引页列出全部分组并链到分组页', () => {
    render(<App pathname="/developers/api" />)
    const nav = screen.getByRole('navigation', { name: '接口分组' })
    expect(within(nav).getAllByRole('link')).toHaveLength(c.groups.length)
    const sites = c.groups.find((g) => g.prefix === '/v1/sites')!
    expect(within(nav).getByRole('link', { name: new RegExp(`^/v1/sites ${sites.count} 个接口`) })).toHaveAttribute('href', '/developers/api/sites')
  })

  it('分组页列出方法、路径、认证徽标；每个分组都预渲染中英文', () => {
    const g = c.groups.find((x) => x.api_key_count > 0)!
    render(<App pathname={`/en/developers/api/${g.id}`} />)
    expect(within(document.querySelector<HTMLElement>('table.api-table')!).getAllByRole('row')).toHaveLength(g.count + 1)
    expect(screen.getAllByText('API key').length).toBeGreaterThanOrEqual(g.api_key_count)
    expect(screen.getByRole('link', { name: '← All groups' })).toHaveAttribute('href', '/en/developers/api')
    const all = urls()
    for (const x of c.groups) {
      expect(all).toContain(`/developers/api/${x.id}`)
      expect(all).toContain(`/en/developers/api/${x.id}`)
    }
  })

  it('“N 个接口支持 API Key”：N 由目录自动计算，等于各分组之和与带 apiKey 认证的接口数', () => {
    const n = c.groups.flatMap((g) => g.operations).filter((o) => o.auth.includes('apiKey')).length
    expect(c.api_key_count).toBe(n)
    expect(c.groups.reduce((a, g) => a + g.api_key_count, 0)).toBe(n)
    const { container } = render(<App pathname="/developers/api" />)
    expect(container.querySelector('main .hero')!.textContent).toContain(`${n} 个接口支持 API Key`)
    expect(container.textContent).not.toContain('个可用 API Key')
  })

  it('每个分组都有详情文件，详情与索引一一对应（operationId、方法、路径、认证）', () => {
    for (const g of c.groups) {
      const d = getGroupDetail(g.id)!
      expect(d, g.id).toBeTruthy()
      expect(d.operations.map((o) => [o.operation_id, o.method, o.path, o.auth.join()])).toEqual(g.operations.map((o) => [o.operation_id, o.method, o.path, o.auth.join()]))
    }
  })

  it('详情取自契约：listSecurityPolicies 的认证、权限、参数与响应字段', () => {
    const op = getGroupDetail('security-policies')!.operations.find((o) => o.operation_id === 'listSecurityPolicies')!
    expect(op.auth).toEqual(['apiKey', 'bearer'])
    expect(op.description).toContain('Requires security_policies.read')
    expect(op.params!.map((p) => p.name)).toEqual(expect.arrayContaining(['page', 'limit']))
    expect(op.responses!.find((r) => r.status === '200')!.fields!.map((f) => f.name)).toEqual(['items', 'total', 'page', 'limit'])
    const webhook = getGroupDetail('tenant-scopes')!.operations.find((o) => o.operation_id === 'createPluginWebhookSubscription')!
    expect(webhook.permissions).toEqual(['plugin_webhooks.manage'])
    expect(webhook.params!.find((p) => p.name === 'Idempotency-Key')).toMatchObject({ in: 'header', required: true })
  })

  it('分组页渲染每个接口的详情锚点：认证说明、权限、参数表、响应表与失败下一步', () => {
    render(<App pathname="/developers/api/security-policies" />)
    const g = c.groups.find((x) => x.id === 'security-policies')!
    for (const o of g.operations) expect(document.getElementById(o.operation_id), o.operation_id).not.toBeNull()
    const op = document.getElementById('listSecurityPolicies')!
    expect(within(op).getByRole('heading', { level: 3 })).toHaveTextContent('GET /v1/security-policies')
    expect(op.textContent).toContain('Authorization: CdncaKey <key_id>.<secret>')
    expect(within(op).getByRole('table', { name: 'listSecurityPolicies 参数' })).toBeInTheDocument()
    expect(within(op).getByRole('table', { name: 'listSecurityPolicies 响应' })).toBeInTheDocument()
    expect(op.textContent).toContain('失败时怎么办')
    expect(screen.getAllByRole('link', { name: '/v1/security-policies' })[0]).toHaveAttribute('href', '#listSecurityPolicies')
  })

  // DOC-API-01：权限取自契约结构化扩展；kind 与服务端一致含 waf；中文正文随契约生成，中文页优先显示。
  it('listSecurityPolicies：结构化权限、kind 含 waf、scope 说明只用于 WAF，中英正文都来自契约', () => {
    const ops = getGroupDetail('security-policies')!.operations
    const op = ops.find((o) => o.operation_id === 'listSecurityPolicies')!
    expect(op.permissions).toEqual(['security_policies.read'])
    expect(op.params!.find((p) => p.name === 'kind')!.type).toBe('string: waf / cc / acl')
    const scope = op.params!.find((p) => p.name === 'scope')!
    expect(scope.description).toContain('requires kind=waf')
    expect(scope.description_zh).toContain('必须同时传 kind=waf')
    expect(op.summary).toContain('WAF')
    expect(op.summary_zh).toBe('列出 WAF 规则库、CC 与访问控制策略')
    expect(op.responses!.find((r) => r.status === '403')!.description_zh).toBe('当前身份没有执行该操作的权限。')
    // 本组每个接口都有结构化权限与中文摘要（与服务端 handler 的权限码一致）。
    for (const o of ops) {
      expect(o.permissions, o.operation_id).toHaveLength(1)
      expect(o.permissions![0], o.operation_id).toMatch(o.method === 'GET' || o.operation_id === 'evaluateSecurityPolicy' ? /^security_policies\.read$/ : /^security_policies\.manage$/)
      expect(o.summary_zh, o.operation_id).toBeTruthy()
    }
    expect(JSON.stringify(ops)).not.toContain('SEC-ACCOUNT')
  })

  it('中文页显示契约中文正文与权限，英文原文折叠；英文页仍显示英文', () => {
    render(<App pathname="/developers/api/security-policies" />)
    const op = document.getElementById('listSecurityPolicies')!
    expect(op.textContent).toContain('列出 WAF 规则库、CC 与访问控制策略')
    expect(within(op).getByText(/租户身份只看到当前作用域内的策略/)).toBeInTheDocument()
    expect(within(op).getByText('security_policies.read')).toBeInTheDocument()
    expect(op.textContent).not.toContain('契约没有单独标注权限码')
    expect(within(op).getByText(/必须同时传 kind=waf/)).toBeInTheDocument()
    expect(op.querySelector('details p[lang="en"]')).toHaveTextContent('Requires security_policies.read')
  })

  it('英文页显示英文摘要', () => {
    render(<App pathname="/en/developers/api/security-policies" />)
    const op = document.getElementById('listSecurityPolicies')!
    expect(op.textContent).toContain('List tenant WAF, CC and ACL policies')
    expect(op.textContent).not.toContain('列出 WAF 规则库')
  })

  it('公开详情不含内部编号与源码路径', () => {
    const text = JSON.stringify(c.groups.map((g) => getGroupDetail(g.id)))
    expect(text).not.toMatch(/\bADR[ -]?\d{4}\b|\b(?:PA|RS|AD|GW|ML)-\d+\b|(?:libs|services|apps)\/[\w./-]+\.go/)
  })

  it('未知分组返回 404 页', () => {
    render(<App pathname="/developers/api/no-such-group" />)
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('页面不存在')
  })
})
