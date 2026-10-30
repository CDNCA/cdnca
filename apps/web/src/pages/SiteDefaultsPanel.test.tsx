import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { siteDefaultSettingNames, siteDefaultSwitches, type SiteUserDefault } from '../api/siteDefaults'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import SiteDefaultsPanel from './SiteDefaultsPanel'
import { CacheRulesDefaultEditor, CondOriginDefaultEditor } from './SiteDefaultDocumentEditors'
import { siteDefaultValueError } from './siteDefaultValue'

// fp-site SITE-CURRENT-03/04/05/06/08（网站列表 > 默认设置）。

const scope = '019a03a3-735b-7ee2-bf40-8c6f92c26c77'
const userID = '019a03a3-735c-7b8c-9cc2-8543d041c822'

function row(index: number, patch: Partial<SiteUserDefault> = {}): SiteUserDefault {
  return {
    id: `019a1b00-0000-7000-8000-00000000000${index}`, display_id: String(index), scope_id: scope, owner_user_id: userID,
    setting_name: 'websocket_enable', setting_value: '1', scope_name: 'global', group_id: null, group_name: null,
    enabled: true, version: 1, created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z', ...patch,
  }
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function signIn(permissions = ['sites.read', 'sites.manage']) {
  useSessionStore.setState({ accessToken: 'access-token', sessionEpoch: 1, status: 'authenticated',
    principal: principal({ scope_id: scope, user_id: userID, permissions }) })
}

const dialogs = () => screen.queryAllByRole('dialog').filter((element) => !element.classList.contains('cdnca-feedback'))

describe('SiteDefaultsPanel', () => {
  beforeEach(async () => {
    await changeLocale('zh-CN')
    signIn()
  })

  it('validates ports and timeouts with the server rules (SITE-CURRENT-08)', () => {
    expect(siteDefaultValueError('http_listen_port', '80 8080')).toBeNull()
    expect(siteDefaultValueError('http_listen_port', '80,8080')).toBeNull()
    for (const value of ['0', '65536', '80 80', 'abc', '']) expect(siteDefaultValueError('http_listen_port', value)).toBe('ports')
    expect(siteDefaultValueError('backend_https_port', '443')).toBeNull()
    expect(siteDefaultValueError('backend_https_port', '443 8443')).toBe('port')
    for (const value of ['1', '300']) expect(siteDefaultValueError('ups_keepalive_timeout', value)).toBeNull()
    for (const value of ['0', '301', '1.5', '']) expect(siteDefaultValueError('ups_keepalive_timeout', value)).toBe('timeout')
    expect(siteDefaultValueError('hsts', '1')).toBeNull()
  })

  // fp-site3（36 项第二批）：与后端 normalizeSiteDefaultValue 同规则
  it('validates the TLS and origin defaults with the server rules', () => {
    for (const value of ['TLSv1.2 TLSv1.3', 'TLSv1.3', 'TLSv1 TLSv1.1 TLSv1.2']) expect(siteDefaultValueError('ssl_protocols', value)).toBeNull()
    for (const value of ['TLSv1 TLSv1.3', 'SSLv3', 'TLSv1.3 TLSv1.3', '']) expect(siteDefaultValueError('ssl_protocols', value)).toBe('protocols')
    expect(siteDefaultValueError('backend_http_port', '8080')).toBeNull()
    expect(siteDefaultValueError('backend_http_port', '0')).toBe('port')
    expect(siteDefaultValueError('origin_connect_timeout', '30')).toBeNull()
    expect(siteDefaultValueError('origin_connect_timeout', '31')).toBe('connectTimeout')
    expect(siteDefaultValueError('origin_read_timeout', '300')).toBeNull()
    expect(siteDefaultValueError('origin_read_timeout', '301')).toBe('timeout')
  })

  // fp-site4（36 项第三批）
  it('validates the CC durations and DNS API defaults with the server rules', () => {
    expect(siteDefaultValueError('cc_ban_seconds', '3600')).toBeNull()
    for (const value of ['0', '86401', '1.5']) expect(siteDefaultValueError('cc_ban_seconds', value)).toBe('banSeconds')
    expect(siteDefaultValueError('cc_pass_seconds', '604800')).toBeNull()
    expect(siteDefaultValueError('cc_pass_seconds', '59')).toBe('passSeconds')
    expect(siteDefaultValueError('dns_provider', '0190b1d6-3c8e-7a51-9f00-000000000001')).toBeNull()
    expect(siteDefaultValueError('dns_provider', 'aliyun')).toBe('dnsProvider')
    expect(siteDefaultValueError('gzip_enable', '1')).toBeNull()
  })

  // fp-site5b：规则库 ID、上传限制、源站请求头与后端同规则
  it('validates the rule library, upload and origin header defaults', () => {
    expect(siteDefaultValueError('waf_policy', '0190b1d6-3c8e-7a51-9f00-000000000001')).toBeNull()
    expect(siteDefaultValueError('acl_policy', '默认黑名单')).toBe('policy')
    expect(siteDefaultValueError('post_size_limit', '1024')).toBeNull()
    for (const value of ['0', '1025', '1.5']) expect(siteDefaultValueError('post_size_limit', value)).toBe('postSize')
    expect(siteDefaultValueError('req_header', 'X-From: cdn\nX-Port: $remote_port')).toBeNull()
    for (const value of ['no colon', 'X-A: 1\nx-a: 2', 'bad name: 1']) expect(siteDefaultValueError('req_header', value)).toBe('reqHeader')
    expect(siteDefaultValueError('block_proxy', '1')).toBeNull()
  })

  it('shows a rule library default by its name and states how proxies are identified', async () => {
    signIn(['sites.read', 'sites.manage', 'security_policies.read'])
    const library = '0190b1d6-3c8e-7a51-9f00-0000000000a1'
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).includes('/v1/security-policies')
      ? json({ items: new URL(String(input), 'http://x').searchParams.get('kind') === 'waf' ? [{ id: library, scope_id: scope, kind: 'waf',
          name: '默认 WAF 库', description: '', enabled: true, default_action: 'allow', rules: [], version: 1, origin: 'custom',
          protected: false, created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z' }] : [], total: 1, page: 1, limit: 100 })
      : json({ items: [row(1, { setting_name: 'waf_policy', setting_value: library }), row(2, { setting_name: 'block_proxy', setting_value: '1' })],
          total: 2, page: 1, limit: 10 }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteDefaultsPanel />)
    expect(await screen.findByText('默认 WAF 库')).toBeInTheDocument()
    expect(screen.getByText('屏蔽透明代理')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '编辑 屏蔽透明代理' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑设置' })
    expect(within(dialog).getByText(/按代理请求头识别，可能误伤经企业代理访问的用户/)).toBeInTheDocument()
  })

  // fp-site5a：HTTP2 / HTTP3 / ssl_prefer_server_ciphers 是 1/0 开关
  it('treats the HTTPS protocol defaults as switches', () => {
    for (const name of ['http2', 'http3', 'ssl_prefer_server_ciphers'] as const) {
      expect(siteDefaultSettingNames).toContain(name)
      expect(siteDefaultSwitches.has(name)).toBe(true)
    }
  })

  // fp-site6：网站缓存 / 条件源站是 JSON 规则文档；条件源站只写条件，源站池用占位 @default
  it('validates the cache and conditional origin rule documents', () => {
    expect(siteDefaultSettingNames).toContain('proxy_cache')
    expect(siteDefaultSettingNames).toContain('cond_origin')
    expect(siteDefaultValueError('proxy_cache', '{"mode":"override","rules":[{"order":1,"extensions":[".css"],"ttl_seconds":60}]}')).toBeNull()
    expect(siteDefaultValueError('proxy_cache', 'not json')).toBe('document')
    expect(siteDefaultValueError('proxy_cache', '{"mode":"override","rules":[]}')).toBe('document')
    expect(siteDefaultValueError('cond_origin', '{"routes":[{"id":"api","priority":0,"path_prefix":"/api/","pool_id":"@default"}]}')).toBeNull()
    for (const value of ['{"routes":[]}', '{"routes":[{"id":"a","path_prefix":"/a/","pool_id":"backup"}]}',
      '{"routes":[{"id":"a","path_prefix":"/a/","pool_id":"@default","fallback_pool_id":"x"}]}',
      '{"routes":[{"id":"a","path_prefix":"/a/","pool_id":"@default"}],"pools":[]}']) {
      expect(siteDefaultValueError('cond_origin', value)).toBe('document')
    }
  })

  it('lists a rule document default by its rule count', async () => {
    signIn(['sites.read', 'sites.manage'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [
      row(1, { setting_name: 'cond_origin', setting_value: '{"routes":[{"id":"a","priority":0,"path_prefix":"/a/","pool_id":"@default"},{"id":"b","priority":0,"path_prefix":"/b/","pool_id":"@default"}]}' }),
    ], total: 1, page: 1, limit: 10 }))
    renderWithProviders(<SiteDefaultsPanel />)
    expect(await screen.findByText('2 条规则')).toBeInTheDocument()
    expect(screen.getByText('条件源站')).toBeInTheDocument()
  })

  it('shows the default DNS API by the account name', async () => {
    signIn(['sites.read', 'sites.manage', 'dns.read'])
    const provider = '0190b1d6-3c8e-7a51-9f00-000000000001'
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).includes('/v1/dns/')
      ? json({ items: [{ id: provider, scope_id: scope, name: '阿里云主账号', provider_type: 'aliyun', credentials_configured: true,
          status: 'verified', version: 1, created_at: '2026-10-25T00:00:00Z', updated_at: '2026-10-25T00:00:00Z' }], total: 1, page: 1, limit: 100 })
      : json({ items: [row(1, { setting_name: 'dns_provider', setting_value: provider })], total: 1, page: 1, limit: 10 }))
    renderWithProviders(<SiteDefaultsPanel />)
    expect(await screen.findByText('阿里云主账号')).toBeInTheDocument()
    expect(screen.getByText('DNS API（自动添加记录）')).toBeInTheDocument()
  })

  it('shows choice defaults by their labels', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [
      row(1, { setting_name: 'origin_protocol', setting_value: 'follow' }),
      row(2, { setting_name: 'ssl_cipher_preset', setting_value: 'compatible' }),
      row(3, { setting_name: 'balance_way', setting_value: 'ip_hash' }),
    ], total: 3, page: 1, limit: 10 }))
    renderWithProviders(<SiteDefaultsPanel />)
    expect(await screen.findByText('跟随访问协议')).toBeInTheDocument()
    expect(screen.getByText('回源协议')).toBeInTheDocument()
    expect(screen.getByText('兼容')).toBeInTheDocument()
    expect(screen.getByText('定源（IP Hash）')).toBeInTheDocument()
  })

  it('locks a batch while it runs and retries an unknown item with its original key; later items wait (SITE-CURRENT-03)', async () => {
    const items = [row(1), row(2), row(3)]
    const keys: string[] = []
    let second = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'PATCH') {
        const key = String((init.headers as Record<string, string>)['Idempotency-Key'])
        keys.push(`${url.split('/').pop()}:${key}`)
        if (url.endsWith(items[1].id) && second++ === 0) throw new TypeError('network down')
        return json({ ...items.find((item) => url.endsWith(item.id)), enabled: false, version: 2 })
      }
      return json({ items, total: 3, page: 1, limit: 10 })
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteDefaultsPanel />)
    await screen.findByText('3')
    await user.click(screen.getAllByRole('checkbox')[0]) // select all on this page
    const disable = screen.getByRole('button', { name: /禁用/ })
    fireEvent.click(disable)
    fireEvent.click(disable)
    expect(await screen.findByText(/有一项结果未知/)).toBeInTheDocument()
    expect(keys.filter((value) => value.startsWith(items[0].id))).toHaveLength(1)
    expect(keys.filter((value) => value.startsWith(items[2].id))).toHaveLength(0)
    expect(screen.getByText(/（3）：未执行/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新增设置/ })).toBeDisabled()
    const firstKey = keys.find((value) => value.startsWith(items[1].id))!
    await user.click(screen.getByRole('button', { name: '用原请求重试' }))
    await waitFor(() => expect(keys.filter((value) => value.startsWith(items[2].id))).toHaveLength(1))
    expect(keys.filter((value) => value.startsWith(items[1].id))).toEqual([firstKey, firstKey])
    expect(keys.filter((value) => value.startsWith(items[0].id))).toHaveLength(1)
  })

  it('clears the selection on another page so a batch never runs with zero requests (SITE-CURRENT-05)', async () => {
    const pages = [Array.from({ length: 10 }, (_, index) => row(index)), [row(11, { id: '019a1b00-0000-7000-8000-000000000011' })]]
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const page = new URL(String(input), 'http://x').searchParams.get('page') === '2' ? 1 : 0
      return json({ items: pages[page], total: 11, page: page + 1, limit: 10 })
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteDefaultsPanel />)
    await screen.findByText('9')
    await user.click(screen.getAllByRole('checkbox')[1])
    expect(screen.getByRole('button', { name: /禁用/ })).toBeEnabled()
    await user.click(screen.getByTitle('2'))
    await screen.findByText('11')
    expect(screen.getByRole('button', { name: /禁用/ })).toBeDisabled()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(false)
  })

  it('keeps the editor open on X/Esc while the outcome is unknown (SITE-CURRENT-04)', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') throw new TypeError('network down')
      return json({ items: [], total: 0, page: 1, limit: 10 })
    })
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteDefaultsPanel />)
    await user.click(await screen.findByRole('button', { name: /新增设置/ }))
    const dialog = dialogs()[0]
    await user.type(within(dialog).getByRole('textbox', { name: '设置值' }), '8080')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByRole('button', { name: '重试' })).toBeInTheDocument()
    expect(dialog.querySelector('.ant-modal-close')).toBeNull()
    fireEvent.keyDown(dialog, { key: 'Escape', code: 'Escape', keyCode: 27 })
    expect(within(dialog).getByRole('button', { name: '重试' })).toBeInTheDocument()
  })

  // fp-site7 #4/#31：区域屏蔽预设按取值单选，列表按文案显示
  it('offers the region blocking presets and lists them by label', async () => {
    expect(siteDefaultSettingNames).toContain('block_region')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [row(1, { setting_name: 'block_region', setting_value: 'abrord_no_inc' })],
      total: 1, page: 1, limit: 10 }))
    renderWithProviders(<SiteDefaultsPanel />)
    expect(await screen.findByText('屏蔽境外（不含港澳台）')).toBeInTheDocument()
    expect(screen.getByText('区域屏蔽')).toBeInTheDocument()
  })

  // tls-custom #11：TLS 密码套件可选「自定义」，自定义套件列出时显示为冒号串
  it('offers the custom cipher preset and the custom cipher suites default', async () => {
    expect(siteDefaultSettingNames).toContain('ssl_cipher_suites')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [
      row(1, { setting_name: 'ssl_cipher_preset', setting_value: 'custom' }),
      row(2, { setting_name: 'ssl_cipher_suites', setting_value: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256' }),
    ], total: 2, page: 1, limit: 10 }))
    renderWithProviders(<SiteDefaultsPanel />)
    expect(await screen.findByText('自定义')).toBeInTheDocument()
    expect(screen.getByText('自定义套件')).toBeInTheDocument()
    expect(screen.getByText('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256')).toBeInTheDocument()
  })

  // fp-site7 #3：网站缓存默认用站点缓存页同一弹窗编辑规则，值仍为缓存策略 JSON（override）
  it('edits cache rule defaults with the site cache rule dialog', async () => {
    const values: string[] = []
    const user = userEvent.setup({ delay: null })
    const view = renderWithProviders(<CacheRulesDefaultEditor value={JSON.stringify({ mode: 'override', rules: [], query_mode: 'preserve',
      query_names: [], vary_headers: [], disk_quota_bytes: 1_073_741_824 })} onChange={(value) => values.push(value)} />)
    await user.click(screen.getByRole('button', { name: '添加规则' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByText('后缀'))
    await user.type(within(dialog).getByRole('textbox', { name: /后缀，用/ }), 'css|js')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    const saved = JSON.parse(values.at(-1)!) as { mode: string; disk_quota_bytes: number; rules: Array<{ order: number; extensions: string[]; ttl_seconds: number }> }
    expect(saved.mode).toBe('override')
    expect(saved.disk_quota_bytes).toBe(1_073_741_824)
    expect(saved.rules).toHaveLength(1)
    expect(saved.rules[0]).toMatchObject({ order: 1, extensions: ['.css', '.js'], ttl_seconds: 86_400 })
    view.rerender(<CacheRulesDefaultEditor value={values.at(-1)} onChange={(value) => values.push(value)} />)
    expect(screen.getByText(/后缀 css\|js/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '删除规则' }))
    expect((JSON.parse(values.at(-1)!) as { rules: unknown[] }).rules).toHaveLength(0)
  })

  // fp-site7 #30：条件源站默认用站点条件源站页同一弹窗，回源池固定为 @default，不提供备用池
  it('edits conditional origin defaults with the site route dialog, always to @default', async () => {
    const values: string[] = []
    const user = userEvent.setup({ delay: null })
    const view = renderWithProviders(<CondOriginDefaultEditor value='{"routes":[]}' onChange={(value) => values.push(value)} />)
    await user.click(screen.getByRole('button', { name: '添加条件规则' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByLabelText('备用回源池')).toBeNull()
    await user.type(within(dialog).getByRole('textbox', { name: '规则 ID' }), 'api')
    await user.type(within(dialog).getByRole('textbox', { name: '路径前缀' }), '/api/')
    await user.click(within(dialog).getByRole('button', { name: '应用规则' }))
    await waitFor(() => expect(values).toHaveLength(1))
    expect(JSON.parse(values[0]!)).toEqual({ routes: [{ id: 'api', priority: 0, path_prefix: '/api/', pool_id: '@default' }] })
    expect(siteDefaultValueError('cond_origin', values[0]!)).toBeNull()
    view.rerender(<CondOriginDefaultEditor value={values[0]} onChange={(value) => values.push(value)} />)
    await user.click(screen.getByRole('button', { name: '添加条件规则' }))
    const second = await screen.findByRole('dialog')
    await user.type(within(second).getByRole('textbox', { name: '规则 ID' }), 'api')
    await user.type(within(second).getByRole('textbox', { name: '路径前缀' }), '/b/')
    await user.click(within(second).getByRole('button', { name: '应用规则' }))
    expect(await within(second).findByText(/已存在|重复/)).toBeInTheDocument()
    expect(values).toHaveLength(1)
  })

  it('rejects an invalid port in the field before any write (SITE-CURRENT-08)', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [], total: 0, page: 1, limit: 10 }))
    const user = userEvent.setup({ delay: null })
    renderWithProviders(<SiteDefaultsPanel />)
    await user.click(await screen.findByRole('button', { name: /新增设置/ }))
    const dialog = dialogs()[0]
    await user.type(within(dialog).getByRole('textbox', { name: '设置值' }), '65536')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText(/端口须为 1–65535 的整数/)).toBeInTheDocument()
    expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })
})
