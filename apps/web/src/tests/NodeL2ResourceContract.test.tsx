import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import NodeL2TopologyPage from '../pages/NodeL2TopologyPage'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const scopeID = '22222222-2222-4222-8222-222222222222'
const regionPage = { count: 1, data: [{
  id: '1', name: 'cn-east', code: 'cn-east', country_code: '', province_code: '', description: '', l2_check_port: 443, sort: 1, revision: 1,
  created_at: '2026-10-09T00:00:00Z', updated_at: '2026-10-09T00:00:00Z',
}] }

beforeEach(() => {
  sessionStorage.clear()
  useSessionStore.setState({
    accessToken: 'l2-test-access', sessionEpoch: 7, status: 'authenticated',
    principal: principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null, permissions: ['platform.admin'] }),
  })
})

describe('L2 real resource contract', () => {
  it.each(['zh-CN', 'qps-ploc'])('creates and reads back the default empty region on a fresh control (%s)', async (locale) => {
    await i18n.changeLanguage(locale)
    const t = (key: string) => i18n.t(`nodeL2Topology:${key}`)
    let saved: Record<string, unknown> | null = null
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'POST') {
        saved = { ...JSON.parse(String(init.body)), id: '11111111-1111-4111-8111-111111111111', display_id: '1', tenant_scope_id: scopeID, revision: 1 }
        return new Response(JSON.stringify(saved))
      }
      return new Response(JSON.stringify(String(url).startsWith('/v1/regions')
        ? { data: [], count: 0 } : { items: saved ? [saved] : [] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: t('actions.create') }))
    const dialog = await screen.findByRole('dialog')
    const region = within(dialog).getByRole('combobox', { name: t('create.region') })
    expect(region.closest('.ant-select')).toHaveTextContent(t('values.defaultRegion'))
    await user.click(region)
    const option = await screen.findByText(t('values.defaultRegion'), { selector: '.ant-select-item-option-content' })
    expect(option.closest('.ant-select-item-option')).not.toHaveClass('ant-select-item-option-disabled')
    await user.click(option)
    await user.type(within(dialog).getByRole('textbox', { name: t('create.name') }), '默认区域配置')
    await user.click(within(dialog).getByRole('button', { name: t('actions.confirm') }))
    expect(await screen.findByText(t('notices.saved'))).toBeInTheDocument()
    const row = (await screen.findByRole('cell', { name: '默认区域配置' })).closest('tr')!
    expect(within(row).getByRole('cell', { name: t('values.defaultRegion') })).toBeInTheDocument()
    const writes = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(writes).toHaveLength(1)
    expect(String(writes[0]![0])).toBe('/v1/l2-configs')
    expect(JSON.parse(String(writes[0]![1]?.body))).toEqual({ name: '默认区域配置', region: '', remark: '', mode: 'cache', load_method: 'rr' })
    expect(new Headers(writes[0]![1]?.headers).get('If-Match')).toBe('"0"')
    expect(new Headers(writes[0]![1]?.headers).get('Idempotency-Key')).toBeTruthy()
    await act(async () => { await i18n.changeLanguage('zh-CN') })
  })

  it('uses regions.read independently of nodes.read for the real region directory', async () => {
    useSessionStore.setState({ principal: principal({ permissions: ['node_scheduling.read', 'node_scheduling.manage', 'regions.read'] }) })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
      new Response(JSON.stringify(String(url).startsWith('/v1/regions') ? regionPage : { items: [] })))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => String(url).startsWith('/v1/regions'))).toBe(true))
    await user.click(within(await screen.findByRole('dialog')).getByRole('combobox', { name: '区域' }))
    expect(await screen.findByText('cn-east', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
  })

  it('does not use nodes.read to load a forbidden directory, but still saves the default region', async () => {
    useSessionStore.setState({ principal: principal({ permissions: ['node_scheduling.read', 'node_scheduling.manage', 'nodes.read'] }) })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => new Response(JSON.stringify(
      String(url).startsWith('/v1/regions') ? regionPage : init?.method === 'POST'
        ? { ...JSON.parse(String(init.body)), id: '11111111-1111-4111-8111-111111111111', display_id: '1', tenant_scope_id: scopeID, revision: 1 }
        : { items: [] },
    )))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '无需目录的默认配置')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/regions'))).toHaveLength(0)
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(JSON.parse(String(write[1]?.body)).region).toBe('')
  })

  it('keeps a denied region directory closed while allowing an explicit default configuration', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).startsWith('/v1/regions')) return new Response(JSON.stringify({ error: { code: 'forbidden', message: 'private region error' } }), { status: 403 })
      return new Response(JSON.stringify(init?.method === 'POST'
        ? { ...JSON.parse(String(init.body)), id: '11111111-1111-4111-8111-111111111111', display_id: '1', tenant_scope_id: scopeID, revision: 1 }
        : { items: [] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/regions'))).toHaveLength(1))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '取消' }))
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '目录拒绝时的默认配置')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/regions'))).toHaveLength(1)
    expect(screen.queryByText('private region error')).not.toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(JSON.parse(String(write[1]?.body)).region).toBe('')
  })

  it('keeps an unknown existing region read-only without making it a new configuration candidate', async () => {
    let config = { id: '11111111-1111-4111-8111-111111111111', display_id: '1', tenant_scope_id: scopeID, revision: 4,
      name: '已有配置', region: 'retired-region', remark: '', mode: 'cache', load_method: 'rr' }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'PUT') {
        config = { ...config, ...JSON.parse(String(init.body)), revision: 5 }
        return new Response(JSON.stringify(config))
      }
      return new Response(JSON.stringify(String(url).startsWith('/v1/regions') ? regionPage : { items: [config] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    const row = (await screen.findByRole('cell', { name: '已有配置' })).closest('tr')!
    await user.click(within(row).getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('combobox', { name: '区域' })).toBeDisabled()
    expect(within(dialog).getByRole('textbox', { name: '名称' })).toBeEnabled()
    await user.clear(within(dialog).getByRole('textbox', { name: '名称' }))
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '更新名称')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'PUT')!
    expect(JSON.parse(String(write[1]?.body))).toEqual({ name: '更新名称', region: 'retired-region', remark: '', mode: 'cache', load_method: 'rr' })
    expect(new Headers(write[1]?.headers).get('If-Match')).toBe('"4"')
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('combobox', { name: '区域' }))
    expect(await screen.findByText('cn-east', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.queryByText('retired-region', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
  })

  it('does not save a new nonempty region after region read permission is revoked', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => new Response(JSON.stringify(
      String(url).startsWith('/v1/regions') ? regionPage : { items: [] },
    )))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('combobox', { name: '区域' }))
    await user.click(await screen.findByText('cn-east', { selector: '.ant-select-item-option-content' }))
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '权限改变')
    act(() => useSessionStore.setState({ principal: principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null,
      permissions: ['node_scheduling.read', 'node_scheduling.manage'] }) }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('请选择默认区域或当前可用的区域。')).toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('keeps a new-region unknown retry locked when only region read permission is revoked', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'POST') throw new TypeError('unknown result')
      return new Response(JSON.stringify(String(url).startsWith('/v1/regions') ? regionPage : { items: [] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('combobox', { name: '区域' }))
    await user.click(await screen.findByText('cn-east', { selector: '.ant-select-item-option-content' }))
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '区域权限重试')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('操作结果待确认', OUTCOME_BAR)
    const record = sessionStorage.getItem(sessionStorage.key(0)!)
    act(() => useSessionStore.setState({ principal: principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null,
      permissions: ['node_scheduling.read', 'node_scheduling.manage'] }) }))
    const retry = screen.getByRole('button', { name: '使用同一请求重试' })
    expect(retry).toBeDisabled()
    await user.click(retry)
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    expect(sessionStorage.getItem(sessionStorage.key(0)!)).toBe(record)
    expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    act(() => useSessionStore.setState({ principal: principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null,
      permissions: ['node_scheduling.read', 'node_scheduling.manage', 'regions.read'] }) }))
    await waitFor(() => expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(2))
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    expect(new Headers(calls[1]![1]?.headers).get('Idempotency-Key')).toBe(new Headers(calls[0]![1]?.headers).get('Idempotency-Key'))
    expect(sessionStorage.getItem(sessionStorage.key(0)!)).toBe(record)
  })

  it('discards a late region page when the session owner changes and never reads its next page', async () => {
    let resolveRegions!: (response: Response) => void
    const regionResponse = new Promise<Response>((resolve) => { resolveRegions = resolve })
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
      String(url).startsWith('/v1/regions') ? regionResponse : new Response(JSON.stringify({ items: [] })))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    await waitFor(() => expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/regions'))).toHaveLength(1))
    act(() => useSessionStore.setState({ principal: principal({ user_id: '99999999-9999-4999-8999-999999999999',
      permissions: ['node_scheduling.read', 'node_scheduling.manage'] }), sessionEpoch: 8, accessToken: 'new-owner-token' }))
    await act(async () => resolveRegions(new Response(JSON.stringify({ ...regionPage, count: 301 }))))
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog')
    const region = within(dialog).getByRole('combobox', { name: '区域' })
    expect(region.closest('.ant-select')).toHaveTextContent('默认')
    await user.click(region)
    expect(screen.queryByText('cn-east', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/regions'))).toHaveLength(1)
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0)
  })

  it('restores a default-region unknown write across a fresh QueryClient without leaking it to another owner', async () => {
    let writes = 0
    let saved: Record<string, unknown> | null = null
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') {
        if (++writes === 1) throw new TypeError('lost response')
        saved = { ...JSON.parse(String(init.body)), id: '11111111-1111-4111-8111-111111111111', display_id: '1', tenant_scope_id: scopeID, revision: 1 }
        return new Response(JSON.stringify(saved))
      }
      return new Response(JSON.stringify({ items: saved ? [saved] : [] }))
    })
    const owner = principal({ permissions: ['node_scheduling.read', 'node_scheduling.manage'] })
    useSessionStore.setState({ principal: owner })
    const user = userEvent.setup()
    const first = renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '默认重试')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await screen.findByText('操作结果待确认', OUTCOME_BAR)
    const record = sessionStorage.getItem(sessionStorage.key(0)!)!
    expect(record).not.toContain('l2-test-access')
    expect(JSON.parse(record).attempt.input.region).toBe('')
    first.unmount()
    useSessionStore.setState({ principal: { ...owner, user_id: '99999999-9999-4999-8999-999999999999' }, sessionEpoch: 8 })
    const foreign = renderWithProviders(<NodeL2TopologyPage />)
    expect(await screen.findByRole('button', { name: '新增配置' })).toBeEnabled()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(writes).toBe(1)
    foreign.unmount()
    useSessionStore.setState({ principal: owner, sessionEpoch: 9, accessToken: 'new-token' })
    renderWithProviders(<NodeL2TopologyPage />)
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(writes).toBe(1)
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    const calls = fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')
    expect(calls).toHaveLength(2)
    expect(calls[1]![1]?.body).toBe(calls[0]![1]?.body)
    for (const header of ['If-Match', 'Idempotency-Key', 'X-Request-ID'])
      expect(new Headers(calls[1]![1]?.headers).get(header)).toBe(new Headers(calls[0]![1]?.headers).get(header))
    expect(new Headers(calls[1]![1]?.headers).get('Authorization')).toBe('Bearer new-token')
    expect(fetchSpy.mock.calls.filter(([url]) => String(url).startsWith('/v1/regions'))).toHaveLength(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('reads the own-control L2 resource without a tenant UUID prompt', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] })))
    renderWithProviders(<NodeL2TopologyPage />)
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    expect(String(fetchSpy.mock.calls[0]![0])).toBe('/v1/l2-configs')
    expect(screen.queryByRole('button', { name: '读取租户' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新增配置' })).toBeEnabled()
  })

  it('creates an L2 configuration in a real region without UUID or endpoint fields', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => new Response(JSON.stringify(
      String(url).startsWith('/v1/regions') ? regionPage : init?.method === 'POST' ? {
        ...JSON.parse(String(init.body)), id: '11111111-1111-4111-8111-111111111111',
        display_id: '1', tenant_scope_id: scopeID, revision: 1,
      } : { items: [] },
    )))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog', { name: '新增L2配置' })
    expect(within(dialog).queryByLabelText(/UUID|节点 ID|作用域/)).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('combobox', { name: '区域' }))
    await user.click(await screen.findByText('cn-east', { selector: '.ant-select-item-option-content' }))
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '验收L2')
    await user.click(within(dialog).getByRole('radio', { name: '全局' }).closest('label')!)
    await user.click(within(dialog).getByRole('radio', { name: 'URL哈希' }).closest('label')!)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await waitFor(() => expect(fetchSpy.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(true))
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(String(write[0])).toBe('/v1/l2-configs')
    expect(JSON.parse(String(write[1]?.body))).toEqual({ name: '验收L2', region: 'cn-east', remark: '', mode: 'global', load_method: 'url_hash' })
    expect(new Headers(write[1]?.headers).get('If-Match')).toBe('"0"')
    expect(new Headers(write[1]?.headers).get('Idempotency-Key')).toBeTruthy()
  })

  it('opens real editable condition rules instead of a disabled conditions tab', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] })))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('tab', { name: 'L2条件' }))
    await user.click(screen.getByRole('button', { name: '新增条件' }))
    // The coarse fetch mock also fails the scheduling-settings read, which opens a feedback
    // dialog; antd gives every dialog the same test-id label, so find the editor by its title.
    const dialog = (await screen.findByText('新增条件', { selector: '.ant-modal-title' })).closest('[role="dialog"]') as HTMLElement
    expect(within(dialog).getByRole('combobox', { name: '匹配项' })).toBeEnabled()
    expect(within(dialog).getByRole('combobox', { name: '操作符' })).toBeEnabled()
    expect(within(dialog).getByRole('textbox', { name: '匹配值' })).toBeEnabled()
    expect(fetchSpy.mock.calls.some(([url]) => String(url) === '/v1/l2-conds')).toBe(true)
  })

  it('saves field/operator rules and reads the saved condition back', async () => {
    let saved: Record<string, unknown> | null = null
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'POST') {
        saved = { ...JSON.parse(String(init.body)), id: '11111111-1111-4111-8111-111111111111', display_id: '1', tenant_scope_id: scopeID, revision: 1 }
        return new Response(JSON.stringify(saved))
      }
      return new Response(JSON.stringify({ items: String(url) === '/v1/l2-conds' && saved ? [saved] : [] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('tab', { name: 'L2条件' }))
    await user.click(screen.getByRole('button', { name: '新增条件' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '缓存请求')
    await user.click(within(dialog).getByRole('combobox', { name: '匹配项' }))
    await user.click(screen.getByText('请求URI', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('combobox', { name: '操作符' }))
    await user.click(screen.getByText('前缀匹配', { selector: '.ant-select-item-option-content' }))
    await user.type(within(dialog).getByRole('textbox', { name: '匹配值' }), '/cache/')
    await user.click(within(dialog).getByRole('button', { name: '添加' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('L2 配置已保存')).toBeInTheDocument()
    expect(await screen.findByText('缓存请求', { selector: 'td' })).toBeInTheDocument()
    const write = fetchSpy.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(String(write[0])).toBe('/v1/l2-conds')
    expect(JSON.parse(String(write[1]?.body))).toEqual({ name: '缓存请求', remark: '', rules: [{ field: 'request_uri', operator: 'prefix', value: '/cache/' }] })
    expect(new Headers(write[1]?.headers).get('If-Match')).toBe('"0"')
  })

  it('refuses an invalid regex rule before it reaches the rule table (L2-REGEX-01)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] })))
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('tab', { name: 'L2条件' }))
    await user.click(screen.getByRole('button', { name: '新增条件' }))
    const dialog = (await screen.findByText('新增条件', { selector: '.ant-modal-title' })).closest('[role="dialog"]') as HTMLElement
    await user.click(within(dialog).getByRole('combobox', { name: '匹配项' }))
    await user.click(screen.getByText('域名', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('combobox', { name: '操作符' }))
    await user.click(screen.getByText('正则匹配', { selector: '.ant-select-item-option-content' }))
    const value = within(dialog).getByRole('textbox', { name: '匹配值' })
    await user.type(value, '[[')
    await user.click(within(dialog).getByRole('button', { name: '添加' }))
    expect(within(dialog).getByRole('alert')).toHaveTextContent('正则表达式无效')
    expect(value).toHaveValue('[')
    await user.clear(value)
    await user.type(value, '^www\\.example\\.com$')
    await user.click(within(dialog).getByRole('button', { name: '添加' }))
    expect(within(dialog).queryByText('正则表达式无效', { exact: false })).not.toBeInTheDocument()
  })

  it('keeps a frozen request but denies retry after live manage permission is removed', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'POST') throw new TypeError('connection reset')
      return new Response(JSON.stringify(String(url).startsWith('/v1/regions') ? regionPage : { items: [] }))
    })
    const user = userEvent.setup()
    renderWithProviders(<NodeL2TopologyPage />)
    await user.click(screen.getByRole('button', { name: '新增配置' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('combobox', { name: '区域' }))
    await user.click(await screen.findByText('cn-east', { selector: '.ant-select-item-option-content' }))
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '权限测试')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await screen.findByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    act(() => useSessionStore.setState({ principal: principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null, permissions: ['node_scheduling.read'] }) }))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    expect(fetchSpy.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
    expect(screen.getByText('操作结果待确认', OUTCOME_BAR)).toBeInTheDocument()
  })
})
