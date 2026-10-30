import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { dnsProviderSplitsCarrierLines, dnsProviderWritesWeights } from '../api/dns'
import { dnsConfigCredentials, validTTL } from '../pages/dns/dnsProviderSpecs'
import NodeDnsPage from '../pages/NodeDnsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const platformScope = '11111111-1111-4111-8111-111111111111'
const at = '2026-10-14T00:00:00Z'
const emptyConfig = { identifiers: {}, secret_saved: false, ttl: 600, ip_weight: false, weight_supported: false, version: 1,
  sync: { tenants: 0 }, last_error: null }
const savedConfig = { ...emptyConfig, provider_type: 'dnspod_cn', identifiers: { dp_id: '269638' }, secret_saved: true,
  weight_supported: true, version: 2, sync: { tenants: 2 } }
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status,
  headers: { 'Content-Type': 'application/json' } }))

function authenticate(permissions = ['dns.read', 'dns.manage']) {
  const actor = principal({ scope_kind: 'platform', scope_id: platformScope, tenant_id: undefined, permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function mockAPI(state: { config: Record<string, unknown>; saveError?: string; connection?: unknown; connectionError?: string }) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = new URL(String(input), 'https://test.invalid')
    const method = init?.method ?? 'GET'
    if (url.pathname === '/v1/dns/platform-config' && method === 'PUT') {
      if (state.saveError) return json({ error: { code: state.saveError, message: 'rejected' } }, 422)
      const body = JSON.parse(String(init!.body))
      state.config = { ...state.config, ...body, secret_saved: true, version: Number(state.config.version) + 1 }
      return json(state.config)
    }
    if (url.pathname === '/v1/dns/platform-config') return json(state.config)
    if (url.pathname === '/v1/dns/platform-config/connection-test') {
      if (state.connectionError) return json({ error: { code: state.connectionError, message: 'rejected' } }, 422)
      return json(state.connection ?? { provider_type: 'dnspod_cn', zones: [] })
    }
    if (url.pathname.startsWith('/v1/dns/platform-config/')) {
      return json({ operations: [{ id: 'd0000000-0000-4000-8000-0000000000a1', kind: 'dns.repair.v1', subject: 'DNS记录修复', state: 'queued',
        progress: { total: 1, completed: 0, succeeded: 0, failed: 0 } }], replayed: false }, 202)
    }
    if (url.pathname === '/v1/dns/platform-zones') return json({ items: [], total: 0 })
    return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
  })
}

const calls = (fetchMock: ReturnType<typeof mockAPI>, path: string, method: string) =>
  fetchMock.mock.calls.filter(([input, init]) => String(input).endsWith(path) && (init?.method ?? 'GET') === method)

afterEach(() => { vi.restoreAllMocks() })

describe('节点管理 DNS配置 tab', () => {
  // RB-U01（审测卡 11）：配置没读到时“DNS错误”显示未读取，不显示“没有错误”。
  it('shows the DNS error as not read when the configuration failed to load', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ error: { code: 'service_unavailable', message: 'down' } }, 503))
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByText(/未读取/)).toBeInTheDocument()
    expect(screen.queryByText('没有错误')).not.toBeInTheDocument()
  })

  it('shows the competitor tabs, fields and buttons with DNSPod labels', async () => {
    authenticate()
    mockAPI({ config: savedConfig })
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByDisplayValue('269638')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'DNS配置', selected: true })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'CNAME域名' })).toBeInTheDocument()
    expect(screen.getByLabelText('Token')).toHaveAttribute('placeholder', '已保存，不修改请留空')
    // NET-UX-1: the secret is masked like the shared ProviderEditor.
    expect(screen.getByLabelText('Token')).toHaveAttribute('type', 'password')
    expect(screen.getByLabelText('TTL')).toHaveValue('600')
    expect(screen.getByText('秒')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '开启IP权重' })).not.toBeChecked()
    expect(screen.getByRole('status')).toHaveTextContent('没有错误')
    const buttons = screen.getAllByRole('button').map((button) => button.textContent)
    expect(buttons).toEqual(expect.arrayContaining(['保存配置', '记录修复', '清除CDN无关解析']))
  })

  it('switches the ID/Token labels per provider, hides the ID for Cloudflare and disables DNSPod国际版', async () => {
    authenticate()
    mockAPI({ config: emptyConfig })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByLabelText('AccessKey ID')).toHaveAttribute('placeholder', '请输入AccessKey ID')
    expect(screen.getByLabelText('AccessKey Secret')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'DNS提供商' }))
    await screen.findAllByRole('option')
    const options = [...document.querySelectorAll('.ant-select-item-option-content')]
    expect(options.map((option) => option.textContent)).toEqual(['阿里云 (aliyun.com, alibabacloud.com)', '华为云 (huaweicloud.com)',
      'DNSLA (dns.la)', 'DNSPod (dnspod.cn)', 'DNSPod国际版 (dnspod.com)', '帝恩思 (51dns.com)', 'Cloudflare (cloudflare.com)',
      'Name.com (name.com)', '自定义 HTTP 接口'])
    await user.click(screen.getByText('Cloudflare (cloudflare.com)', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByLabelText('API Token')).toBeInTheDocument()
    expect(screen.queryByLabelText('ID')).not.toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'DNS提供商' }))
    await user.click(screen.getByText('华为云 (huaweicloud.com)', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByLabelText('Access Key Id')).toBeInTheDocument()
    expect(screen.getByLabelText('项目ID')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'DNS提供商' }))
    await user.click(screen.getByText('DNSPod国际版 (dnspod.com)', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText(/DNSPod国际版已迁移到腾讯云国际站/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /保存配置/ })).toBeDisabled()
    await user.click(screen.getByRole('combobox', { name: 'DNS提供商' }))
    await user.click(screen.getByText('自定义 HTTP 接口', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByLabelText('接口地址')).toBeInTheDocument()
    expect(screen.getByLabelText('签名密钥')).toBeInTheDocument()
    expect(screen.getByText(/拒绝内网地址/)).toBeInTheDocument()
  })

  it('shows per provider whether DNS lines (三网/境外) are supported', async () => {
    authenticate()
    mockAPI({ config: emptyConfig })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByText('支持分线路：默认、电信、联通、移动、境外')).toBeInTheDocument()
    const pick = async (label: string) => {
      await user.click(screen.getByRole('combobox', { name: 'DNS提供商' }))
      await user.click(screen.getByText(label, { selector: '.ant-select-item-option-content' }))
    }
    await pick('华为云 (huaweicloud.com)')
    expect(await screen.findByText('支持分线路：默认、电信、联通、移动、境外')).toBeInTheDocument()
    await pick('DNSLA (dns.la)')
    expect(await screen.findByText('支持分线路：默认、电信、联通、移动、境外')).toBeInTheDocument()
    await pick('DNSPod (dnspod.cn)')
    expect(await screen.findByText('支持分线路：默认、电信、联通、移动、境外')).toBeInTheDocument()
    // Cloudflare writes the default line only (dnsproviderremote matrix, NET-03).
    await pick('Cloudflare (cloudflare.com)')
    expect(await screen.findByRole('note')).toHaveTextContent('该服务商不支持按运营商分线路')
    // DNS.COM opens lines by the plan tier chosen below (default free).
    await pick('帝恩思 (51dns.com)')
    expect(await screen.findByText('按套餐开放线路：免费版支持默认、电信、联通、移动；境外需旗舰版')).toBeInTheDocument()
    expect(screen.getByText(/该线路标为“套餐不支持”，访客按默认线路解析/)).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '套餐档位' }))
    await user.click(screen.getByText('旗舰版', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText('按套餐开放线路：旗舰版支持默认、电信、联通、移动、境外')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '套餐档位' }))
    await user.click(screen.getByText('企业版', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByText(/企业版支持默认、电信、联通、移动，另有拓展（教育网等）、区域（华南等）、大洲线路/)).toBeInTheDocument()
  })

  it('saves credentials, TTL and IP weight and shows 保存成功', async () => {
    authenticate()
    const state = { config: emptyConfig as Record<string, unknown> }
    const fetchMock = mockAPI(state)
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('combobox', { name: 'DNS提供商' }))
    await user.click(screen.getByText('DNSPod (dnspod.cn)', { selector: '.ant-select-item-option-content' }))
    await user.type(await screen.findByLabelText('ID'), '269638')
    await user.type(screen.getByLabelText('Token'), 'secret-token')
    await user.clear(screen.getByLabelText('TTL'))
    await user.type(screen.getByLabelText('TTL'), '300')
    await user.click(screen.getByRole('switch', { name: '开启IP权重' }))
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    expect(await screen.findByText('保存成功')).toBeInTheDocument()
    const [save] = calls(fetchMock, '/v1/dns/platform-config', 'PUT')
    expect(JSON.parse(String(save[1]!.body))).toEqual({ provider_type: 'dnspod_cn',
      credentials: { dp_id: '269638', dp_key: 'secret-token' }, ttl: 300, ip_weight: true })
    expect(new Headers(save[1]!.headers).get('If-Match')).toBe('"1"')
  })

  it('validates before saving and shows the provider error after a rejected save', async () => {
    authenticate()
    const state = { config: savedConfig as Record<string, unknown>, saveError: 'provider_credentials_rejected' }
    const fetchMock = mockAPI(state)
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await screen.findByDisplayValue('269638')
    const ttl = screen.getByLabelText('TTL')
    await user.clear(ttl)
    await user.type(ttl, '0')
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    expect(await screen.findByText('TTL 须为 1-86400 的整数')).toBeInTheDocument()
    await user.clear(ttl)
    await user.type(ttl, '900')
    await user.clear(screen.getByLabelText('ID'))
    await user.type(screen.getByLabelText('ID'), '1000')
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    expect(await screen.findByText('修改密钥或切换DNS提供商时请重新输入Token')).toBeInTheDocument()
    expect(calls(fetchMock, '/v1/dns/platform-config', 'PUT')).toHaveLength(0)
    await user.type(screen.getByLabelText('Token'), 'bad')
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    expect(await screen.findByText('DNS提供商拒绝了该密钥')).toBeInTheDocument()
  })

  // DNS维护原 P2-1（审测卡 10）：维护动作只用已保存配置；有草稿时先“保存后执行 / 放弃后执行 / 取消”，
  // 保存失败不执行；迟到的连接测试结果不贴到新输入。
  it('asks before repairing with unsaved changes and never runs after a failed save', async () => {
    authenticate()
    const state: { config: Record<string, unknown>; saveError?: string } = { config: savedConfig, saveError: 'validation_error' }
    const fetchMock = mockAPI(state)
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await screen.findByDisplayValue('269638')
    const ttl = screen.getByLabelText('TTL')
    expect(screen.getByText('连接测试使用当前输入；记录修复和清除使用已保存的配置。')).toBeInTheDocument()
    await user.clear(ttl)
    await user.type(ttl, '900')
    expect(screen.getByText(/有未保存的修改/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /记录修复/ }))
    expect(await screen.findByText(/记录修复和清除只按已保存的配置执行/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '取消' }))
    expect(calls(fetchMock, '/v1/dns/platform-config/repair', 'POST')).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: /记录修复/ }))
    await user.click(await screen.findByRole('button', { name: '保存后执行' }))
    await waitFor(() => expect(calls(fetchMock, '/v1/dns/platform-config', 'PUT')).toHaveLength(1))
    expect(calls(fetchMock, '/v1/dns/platform-config/repair', 'POST')).toHaveLength(0)
    state.saveError = undefined
    await user.click(screen.getByRole('button', { name: /记录修复/ }))
    await user.click(await screen.findByRole('button', { name: '保存后执行' }))
    await waitFor(() => expect(calls(fetchMock, '/v1/dns/platform-config/repair', 'POST')).toHaveLength(1))
    expect(JSON.parse(String(calls(fetchMock, '/v1/dns/platform-config', 'PUT')[1][1]!.body))).toMatchObject({ ttl: 900 })
  })

  it('discards the draft before repairing with the saved configuration', async () => {
    authenticate()
    const fetchMock = mockAPI({ config: savedConfig })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await screen.findByDisplayValue('269638')
    const ttl = screen.getByLabelText('TTL')
    await user.clear(ttl)
    await user.type(ttl, '900')
    await user.click(screen.getByRole('button', { name: /记录修复/ }))
    await user.click(await screen.findByRole('button', { name: '放弃修改后执行' }))
    await waitFor(() => expect(calls(fetchMock, '/v1/dns/platform-config/repair', 'POST')).toHaveLength(1))
    expect(calls(fetchMock, '/v1/dns/platform-config', 'PUT')).toHaveLength(0)
    expect(screen.getByLabelText('TTL')).toHaveValue('600')
  })

  it('drops a connection test result that arrives after the input changed', async () => {
    authenticate()
    let release: (() => void) | undefined
    const fetchMock = mockAPI({ config: savedConfig })
    const base = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation((input, init) => {
      if (String(input).endsWith('/v1/dns/platform-config/connection-test')) {
        return new Promise((resolve) => { release = () => resolve(base(input, init) as unknown as Response) })
      }
      return base(input, init)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await screen.findByDisplayValue('269638')
    await user.click(screen.getByRole('button', { name: /连接测试/ }))
    await waitFor(() => expect(release).toBeDefined())
    expect(screen.getByRole('button', { name: /记录修复/ })).toBeDisabled()
    release!()
    await waitFor(() => expect(screen.getByRole('button', { name: /记录修复/ })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: /连接测试/ }))
    await waitFor(() => expect(calls(fetchMock, '/v1/dns/platform-config/connection-test', 'POST')).toHaveLength(2))
    await user.clear(screen.getByLabelText('TTL'))
    release!()
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(screen.queryByText(/已连接/)).not.toBeInTheDocument()
  })

  it('submits 记录修复 at once and 清除CDN无关解析 after confirmation', async () => {
    authenticate()
    const fetchMock = mockAPI({ config: savedConfig })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('button', { name: /记录修复/ }))
    expect(await screen.findByText('已提交记录修复任务，可在 系统管理 > 后台任务 查看结果')).toBeInTheDocument()
    expect(calls(fetchMock, '/v1/dns/platform-config/repair', 'POST')).toHaveLength(1)
    // NET-UX-2 / fz-x2b: a single queued task deep-links to that exact task.
    expect(screen.getByText('已提交 1 个「DNS记录修复」任务，任务 ID：d0000000-0000-4000-8000-0000000000a1')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '查看本次任务' }))
      .toHaveAttribute('href', '/sys/task?task_id=d0000000-0000-4000-8000-0000000000a1')
    await user.click(screen.getByRole('button', { name: /清除CDN无关解析/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/根域名、NS、MX、TXT 等不受影响/)).toBeInTheDocument()
    expect(calls(fetchMock, '/v1/dns/platform-config/cleanup', 'POST')).toHaveLength(0)
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(calls(fetchMock, '/v1/dns/platform-config/cleanup', 'POST')).toHaveLength(1))
    expect(await screen.findByText('已提交清除任务，可在 系统管理 > 后台任务 查看结果')).toBeInTheDocument()
  })

  it('shows the last DNS write failure in red', async () => {
    authenticate()
    mockAPI({ config: { ...savedConfig, last_error: { source: 'dns_repair', code: 'item_failed',
      message: '修复记录 a.cdn.example.com A 192.0.2.1 (dns_reconcile_failed)', at } } })
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    const status = await screen.findByText(/记录修复失败：部分记录失败/)
    expect(status).toHaveClass('is-error')
    expect(status).toHaveTextContent('域名 a.cdn.example.com：服务商写入解析失败，请稍后重新点“记录修复”')
  })

  // The failed item reads as which domain, why
  // and what to do, not as the raw item id and error code.
  it('explains a failed repair item in plain words', async () => {
    authenticate()
    mockAPI({ config: { ...savedConfig, last_error: { source: 'dns_repair', code: 'all_items_failed',
      message: '修复记录 1qsl2olo.868yun.com (dns_no_serving_endpoint)', at } } })
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    const status = await screen.findByText(/记录修复失败：全部记录失败/)
    expect(status).toHaveTextContent('域名 1qsl2olo.868yun.com：线路分组没有可用节点，请检查该网站所用线路分组是否有在线节点')
    expect(status).not.toHaveTextContent('dns_no_serving_endpoint')
  })

  it('tests the connection with the saved or entered keys without saving', async () => {
    authenticate()
    const user = userEvent.setup()
    const state = { config: savedConfig as Record<string, unknown>, connection: { provider_type: 'dnspod_cn',
      zones: [{ name: 'cdn.868yun.com', status: 'hosted', apex: '868yun.com' }] } as unknown, connectionError: undefined as string | undefined }
    const fetchMock = mockAPI(state)
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await screen.findByDisplayValue('269638')
    await user.click(screen.getByRole('button', { name: /连接测试/ }))
    expect(await screen.findByText('已连接：CNAME 域名 cdn.868yun.com 都在该账号下')).toHaveClass('is-ok')
    expect(JSON.parse(String(calls(fetchMock, '/v1/dns/platform-config/connection-test', 'POST')[0][1]!.body)))
      .toEqual({ provider_type: 'dnspod_cn' })
    state.connection = { provider_type: 'dnspod_cn', zones: [{ name: 'cdn.868yun.com', status: 'not_hosted' }] }
    await user.type(screen.getByLabelText('Token'), 'new-token')
    await user.click(screen.getByRole('button', { name: /连接测试/ }))
    expect(await screen.findByText(/不在该 DNS 账号下（无该域名权限）：cdn.868yun.com/)).toHaveClass('is-error')
    expect(JSON.parse(String(calls(fetchMock, '/v1/dns/platform-config/connection-test', 'POST')[1][1]!.body)))
      .toEqual({ provider_type: 'dnspod_cn', credentials: { dp_id: '269638', dp_key: 'new-token' } })
    state.connectionError = 'provider_credentials_rejected'
    await user.click(screen.getByRole('button', { name: /连接测试/ }))
    expect(await screen.findByText('未连接：DNS提供商拒绝了该密钥')).toHaveClass('is-error')
    expect(calls(fetchMock, '/v1/dns/platform-config', 'PUT')).toHaveLength(0)
  })

  // C11/X13-b: a failed first read leaves nothing to save against; the
  // aliyun default is not the saved provider. Retrying unlocks the form.
  it('keeps the form locked until the configuration was read once', async () => {
    authenticate()
    let fail = true
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config' && (init?.method ?? 'GET') === 'GET') {
        return fail ? json({ error: { code: 'internal', message: 'boom' } }, 500) : json(savedConfig)
      }
      return json({ items: [], total: 0 })
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByText(/DNS配置读取失败：未读到当前配置前不能修改/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /保存配置/ })).toBeDisabled()
    expect(screen.getByLabelText('TTL')).toBeDisabled()
    fail = false
    await user.click(screen.getByRole('button', { name: /重\s*试/ }))
    await waitFor(() => expect(screen.getByRole('button', { name: /保存配置/ })).toBeEnabled())
    expect(screen.queryByText(/DNS配置读取失败/)).not.toBeInTheDocument()
  })

  it('is read-only without dns.manage', async () => {
    authenticate(['dns.read'])
    mockAPI({ config: savedConfig })
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByText('当前账号没有 DNS 写权限。')).toBeInTheDocument()
    expect(await screen.findByDisplayValue('269638')).toBeDisabled()
    expect(screen.getByRole('button', { name: /记录修复/ })).toBeDisabled()
    expect(screen.getByLabelText('ID')).toBeDisabled()
  })

  it('maps credentials and TTL ranges per provider', () => {
    const form = { identifier: ' id ', secret: 'secret', region: 'cn-north-4', projectID: 'a'.repeat(32) }
    expect(dnsConfigCredentials('cloudflare', { ...form, identifier: '' })).toEqual({ api_token: 'secret' })
    expect(dnsConfigCredentials('huawei', form)).toEqual({ access_key: 'id', secret_key: 'secret', region: 'cn-north-4', project_id: 'a'.repeat(32) })
    expect(dnsConfigCredentials('dns_com', form)).toEqual({ api_key: 'id', api_secret: 'secret', plan: 'free' })
    expect(dnsConfigCredentials('dns_com', { ...form, plan: 'flagship' })).toEqual({ api_key: 'id', api_secret: 'secret', plan: 'flagship' })
    expect(dnsConfigCredentials('dns_com', { ...form, plan: 'custom' })).toEqual({ api_key: 'id', api_secret: 'secret', plan: 'free' })
    expect(dnsConfigCredentials('dnspod_intl', form)).toBeNull()
    expect(dnsConfigCredentials('aliyun', { ...form, secret: ' ' })).toBeNull()
    expect(validTTL('cloudflare', '30')).toBe(false)
    expect(validTTL('cloudflare', '60')).toBe(true)
    expect(validTTL('aliyun', '1')).toBe(true)
    expect(validTTL('aliyun', '86401')).toBe(false)
    expect(dnsConfigCredentials('namecom', form)).toEqual({ username: 'id', api_token: 'secret' })
    expect(validTTL('namecom', '60')).toBe(false)
    expect(validTTL('namecom', '300')).toBe(true)
  })

  it('shows Name.com without carrier lines, disables IP weight and saves username + API token at TTL >= 300', async () => {
    authenticate()
    const state = { config: { ...emptyConfig, ip_weight: true } as Record<string, unknown> }
    const fetchMock = mockAPI(state)
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('combobox', { name: 'DNS提供商' }))
    await user.click(screen.getByText('Name.com (name.com)', { selector: '.ant-select-item-option-content' }))
    expect(await screen.findByRole('note')).toHaveTextContent('该服务商不支持按运营商分线路')
    expect(screen.queryByText('支持分线路：默认、电信、联通、移动、境外')).not.toBeInTheDocument()
    const weight = screen.getByRole('switch', { name: '开启IP权重' })
    expect(weight).toBeDisabled()
    expect(weight).not.toBeChecked()
    expect(screen.getByText(/TTL 最低 300 秒/)).toBeInTheDocument()
    await user.type(screen.getByLabelText('Username'), 'fixture-user')
    await user.type(screen.getByLabelText('API Token'), 'fixture-token')
    await user.clear(screen.getByLabelText('TTL'))
    await user.type(screen.getByLabelText('TTL'), '60')
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    expect(await screen.findByText('TTL 须为 300-86400 的整数')).toBeInTheDocument()
    expect(calls(fetchMock, '/v1/dns/platform-config', 'PUT')).toHaveLength(0)
    // TTL 报错走反馈弹窗，进场动画结束才抢焦点；负载高时会落在下面改 TTL 之后把按键吞掉，先等它拿到焦点。
    await waitFor(() => expect(document.activeElement?.closest('.cdnca-feedback')).not.toBeNull())
    await user.clear(screen.getByLabelText('TTL'))
    await user.type(screen.getByLabelText('TTL'), '300')
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    await waitFor(() => expect(calls(fetchMock, '/v1/dns/platform-config', 'PUT')).toHaveLength(1))
    const body = JSON.parse(String(calls(fetchMock, '/v1/dns/platform-config', 'PUT')[0][1]!.body))
    expect(body).toEqual({ provider_type: 'namecom', credentials: { username: 'fixture-user', api_token: 'fixture-token' },
      ttl: 300, ip_weight: false })
  })
})

describe('节点管理 DNS配置 third-party DNS plugins (PA-22)', () => {
  const plugins = [
    { plugin_id: 'com.example.dnsplus', version: '1.2.0', base_url: 'https://dns.dnsplus.example', kinds: ['dns'], status: 'active',
      contract_status: 'passed', enabled: true, usable: true, updated_at: at },
    { plugin_id: 'com.example.pending', version: '1.0.0', base_url: 'https://dns.pending.example', kinds: ['dns'], status: 'active',
      contract_status: 'pending', enabled: false, usable: false, updated_at: at },
    { plugin_id: 'com.example.sms', version: '1.0.0', base_url: 'https://sms.example.com', kinds: ['sms'], status: 'active',
      contract_status: 'passed', enabled: true, usable: true, updated_at: at },
  ]

  it('offers only contract-passed, enabled DNS plugins and saves provider_type plugin with the plugin id', async () => {
    authenticate()
    const state: { config: Record<string, unknown> } = { config: emptyConfig }
    const base = mockAPI(state)
    const fallback = base.getMockImplementation()!
    base.mockImplementation((input, init) => new URL(String(input), 'https://test.invalid').pathname === '/v1/admin/plugin-providers'
      ? json({ items: plugins }) : fallback(input, init))
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await screen.findByLabelText('AccessKey ID')
    await user.click(screen.getByRole('combobox', { name: 'DNS提供商' }))
    await screen.findByText('第三方插件（已通过契约测试）')
    const options = [...document.querySelectorAll('.ant-select-item-option-content')].map((option) => option.textContent)
    expect(options).toContain('第三方插件 com.example.dnsplus（v1.2.0）')
    expect(options.some((option) => option?.includes('com.example.pending'))).toBe(false)
    expect(options.some((option) => option?.includes('com.example.sms'))).toBe(false)
    await user.click(screen.getByText('第三方插件 com.example.dnsplus（v1.2.0）', { selector: '.ant-select-item-option-content' }))
    expect(screen.queryByLabelText('AccessKey Secret')).not.toBeInTheDocument()
    expect(screen.getByText(/解析记录由该第三方插件写入/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '保存配置' }))
    await waitFor(() => expect(calls(base, '/v1/dns/platform-config', 'PUT'), document.querySelector('.ant-message')?.textContent ?? '').toHaveLength(1))
    const body = JSON.parse(String(calls(base, '/v1/dns/platform-config', 'PUT')[0][1]!.body))
    expect(body).toMatchObject({ provider_type: 'plugin', credentials: { plugin_id: 'com.example.dnsplus' } })
  })

  it('saves the DNS.COM plan with the keys and shows 套餐不支持 line errors', async () => {
    authenticate()
    const state = { config: { ...emptyConfig, last_error: { source: 'cname_line', code: 'dns_line_not_in_plan', message: 'overseas', at } } as Record<string, unknown> }
    const fetchMock = mockAPI(state)
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByText('分线路解析：套餐不支持该线路，已按默认线路解析：overseas')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'DNS提供商' }))
    await user.click(screen.getByText('帝恩思 (51dns.com)', { selector: '.ant-select-item-option-content' }))
    await user.type(await screen.findByLabelText('API Key'), 'dnscom-key')
    await user.type(screen.getByLabelText('API Secret'), 'dnscom-secret')
    await user.click(screen.getByRole('combobox', { name: '套餐档位' }))
    await user.click(screen.getByText('旗舰版', { selector: '.ant-select-item-option-content' }))
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    expect(await screen.findByText('保存成功')).toBeInTheDocument()
    const put = calls(fetchMock, '/v1/dns/platform-config', 'PUT')
    expect(put).toHaveLength(1)
    expect(JSON.parse(String(put[0][1]!.body))).toMatchObject({ provider_type: 'dns_com',
      credentials: { api_key: 'dnscom-key', api_secret: 'dnscom-secret', plan: 'flagship' } })
  })
})

describe('DNS provider capabilities (NET-03/NET-04)', () => {
  it('splits carrier lines only for providers whose adapter writes them; unknown or unloaded is no', () => {
    for (const type of ['aliyun', 'huawei', 'dnspod_cn', 'dns_com', 'dns_la', 'custom_http', 'plugin']) {
      expect(dnsProviderSplitsCarrierLines(type)).toBe(true)
    }
    for (const type of ['cloudflare', 'namecom', 'dnspod_intl', 'dnsdun', undefined]) {
      expect(dnsProviderSplitsCarrierLines(type)).toBe(false)
    }
    expect(['aliyun', 'huawei', 'dnspod_cn', 'dns_com', 'dns_la', 'cloudflare', 'namecom', 'custom_http', 'plugin', undefined]
      .filter((type) => dnsProviderWritesWeights(type))).toEqual(['dnspod_cn'])
  })

  it('disables IP weight for a provider without record weights and never saves it on', async () => {
    authenticate()
    const state = { config: { ...savedConfig, provider_type: 'aliyun', identifiers: { access_key_id: 'ak' }, ip_weight: true,
      weight_supported: false } as Record<string, unknown> }
    const fetchMock = mockAPI(state)
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    const weight = await screen.findByRole('switch', { name: '开启IP权重' })
    await waitFor(() => expect(weight).toBeDisabled())
    expect(weight).not.toBeChecked()
    expect(screen.getByText('当前服务商的接口不支持记录权重，不能开启（仅 DNSPod 支持）')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /保存配置/ }))
    expect(await screen.findByText('保存成功')).toBeInTheDocument()
    expect(JSON.parse(String(calls(fetchMock, '/v1/dns/platform-config', 'PUT')[0][1]!.body))).toMatchObject({ ip_weight: false })
  })
})

describe('节点管理 CNAME域名 (NET-05/NET-06)', () => {
  const zone = (id: string, name: string) => ({ id, display_id: Number(id.slice(-1)), name, remark: '', in_use: false, version: 1,
    created_at: at, updated_at: at })
  const zoneA = zone('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', 'a.example.com')
  const zoneB = zone('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2', 'b.example.com')

  it('clears a selection hidden by a search and lists every domain before a batch delete', async () => {
    authenticate()
    const deletes: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config') return json(savedConfig)
      if (init?.method === 'DELETE') { deletes.push(url.pathname); return Promise.resolve(new Response(null, { status: 204 })) }
      if (url.pathname === '/v1/dns/platform-zones') {
        const search = url.searchParams.get('search') ?? ''
        const items = [zoneA, zoneB].filter((item) => item.name.includes(search))
        return json({ items, total: items.length })
      }
      return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('tab', { name: 'CNAME域名' }))
    const rowA = (await screen.findByText('a.example.com')).closest('tr')!
    await user.click(within(rowA).getByRole('checkbox'))
    await user.type(screen.getByLabelText('输入域名搜索'), 'b.example{Enter}')
    await waitFor(() => expect(screen.queryByText('a.example.com')).not.toBeInTheDocument())
    await user.click(screen.getAllByRole('button', { name: /删除/ })[0])
    // Nothing visible is selected: the hidden a.example.com is not deleted.
    expect(await screen.findByText('请先选择要删除的域名')).toBeInTheDocument()
    expect(deletes).toEqual([])
  })

  it('shows a failed read with retry instead of an empty list and blocks deletion', async () => {
    authenticate()
    let fail = true
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config') return json(savedConfig)
      if (url.pathname === '/v1/dns/platform-zones') {
        return fail ? json({ error: { code: 'internal_error', message: 'boom' } }, 500) : json({ items: [zoneA], total: 1 })
      }
      return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('tab', { name: 'CNAME域名' }))
    expect((await screen.findAllByText(/CNAME 域名读取失败/)).length).toBeGreaterThan(0)
    expect(screen.queryByText('暂无数据')).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /删除/ })[0]).toBeDisabled()
    fail = false
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('a.example.com')).toBeInTheDocument()
  })

  // C11: a refusal about the domain shows on the domain field, not as a toast.
  it('shows domain refusals on the domain field and clears them on edit', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config') return json(savedConfig)
      if (url.pathname === '/v1/dns/platform-zones' && init?.method === 'POST') {
        return json({ error: { code: 'dns_zone_not_hosted', message: 'not hosted' } }, 422)
      }
      if (url.pathname === '/v1/dns/platform-zones') return json({ items: [zoneA], total: 1 })
      return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('tab', { name: 'CNAME域名' }))
    await screen.findByText('a.example.com')
    await user.click(screen.getByRole('button', { name: /新增域名/ }))
    let dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('域名'), 'bad')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    expect(within(dialog).getByText('请输入正确的域名')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('域名')).toHaveAttribute('aria-invalid', 'true')
    await user.clear(within(dialog).getByLabelText('域名'))
    expect(within(dialog).queryByText('请输入正确的域名')).not.toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('域名'), 'cdn.other.com')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('该域名不在所选 DNS 账号下')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('域名')).toHaveAttribute('aria-invalid', 'true')
  })

  // C11: deleting the only row of the last page goes back to the page before.
  it('goes back a page after deleting the last row of the last page', async () => {
    authenticate()
    const zones = Array.from({ length: 11 }, (_, index) => zone(`aaaaaaaa-aaaa-4aaa-8aaa-${String(index).padStart(12, '0')}`, `z${index}.example.com`))
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config') return json(savedConfig)
      if (init?.method === 'DELETE') {
        const id = url.pathname.split('/').at(-1)
        zones.splice(zones.findIndex((item) => item.id === id), 1)
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      if (url.pathname === '/v1/dns/platform-zones') {
        const page = Number(url.searchParams.get('page') ?? '1')
        const limit = Number(url.searchParams.get('limit') ?? '10')
        return json({ items: zones.slice((page - 1) * limit, page * limit), total: zones.length })
      }
      return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('tab', { name: 'CNAME域名' }))
    await screen.findByText('z0.example.com')
    await user.click(screen.getByTitle('2'))
    const row = (await screen.findByText('z10.example.com')).closest('tr')!
    await user.click(within(row).getByText('删除'))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: /确\s*定/ }))
    expect(await screen.findByText('z0.example.com')).toBeInTheDocument()
    expect(screen.queryByText('z10.example.com')).not.toBeInTheDocument()
    expect(screen.getByTitle('1').closest('li')).toHaveClass('ant-pagination-item-active')
  })

  it('names every selected domain in the batch delete confirmation', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config') return json(savedConfig)
      if (url.pathname === '/v1/dns/platform-zones') return json({ items: [zoneA, zoneB], total: 2 })
      return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    await user.click(await screen.findByRole('tab', { name: 'CNAME域名' }))
    for (const name of ['a.example.com', 'b.example.com']) {
      await user.click(within((await screen.findByText(name)).closest('tr')!).getByRole('checkbox'))
    }
    await user.click(screen.getAllByRole('button', { name: /删除/ })[0])
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('确定删除选中的 2 个域名吗？')
    expect(within(dialog).getByText('a.example.com')).toBeInTheDocument()
    expect(within(dialog).getByText('b.example.com')).toBeInTheDocument()
  })
})

// A save refusal naming a field is shown under that field
// (TTL, credentials -> the secret box), not in a dialog; editing it clears it.
describe('DNS配置 save field errors', () => {
  it('marks a refused TTL under the TTL box without a dialog, and clears it on edit', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config' && init?.method === 'PUT') {
        return json({ error: { code: 'validation_error', message: 'invalid', request_id: 'r', details: { field: 'ttl', reason: 'out_of_range' } } }, 400)
      }
      if (url.pathname === '/v1/dns/platform-config') return json(savedConfig)
      if (url.pathname === '/v1/dns/platform-zones') return json({ items: [], total: 0 })
      return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByDisplayValue('269638')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /保存配置/ }))

    const item = screen.getByLabelText('TTL').closest('.ant-form-item')!
    await waitFor(() => expect(item).toHaveClass('ant-form-item-has-error'))
    expect(within(item as HTMLElement).getByText('超出允许的范围')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('TTL'), '0')
    expect(item).not.toHaveClass('ant-form-item-has-error')
  })

  it('marks refused credentials under the secret box', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/dns/platform-config' && init?.method === 'PUT') {
        return json({ error: { code: 'validation_error', message: 'invalid', request_id: 'r', details: { field: 'credentials', reason: 'invalid' } } }, 400)
      }
      if (url.pathname === '/v1/dns/platform-config') return json(savedConfig)
      if (url.pathname === '/v1/dns/platform-zones') return json({ items: [], total: 0 })
      return json({ error: { code: 'not_found', message: 'unexpected' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeDnsPage />, ['/node/dns'])
    expect(await screen.findByDisplayValue('269638')).toBeInTheDocument()
    await user.type(screen.getByLabelText('Token'), 'new-token')
    await user.click(screen.getByRole('button', { name: /保存配置/ }))

    const item = screen.getByLabelText('Token').closest('.ant-form-item')!
    await waitFor(() => expect(item).toHaveClass('ant-form-item-has-error'))
    expect(within(item as HTMLElement).getByText('填写的内容不符合要求')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
