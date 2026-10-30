import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import {
  openrestySecurityApi,
  type OpenRestySecurityDocument,
  type OpenRestySecurityRuleGroup,
} from '../api/openrestySecurity'
import { useSessionStore } from '../auth/session'
import FirewallPoliciesPage from '../pages/FirewallPoliciesPage'

vi.mock('../api/openrestySecurity', async () => {
  const actual = await vi.importActual<typeof import('../api/openrestySecurity')>('../api/openrestySecurity')
  return {
    ...actual,
    openrestySecurityApi: {
      ...actual.openrestySecurityApi,
      getGlobal: vi.fn(),
      patchGlobal: vi.fn(),
      listOverrides: vi.fn(),
      createOverride: vi.fn(),
      patchOverride: vi.fn(),
      deleteOverride: vi.fn(),
      searchTargets: vi.fn(),
      getEffective: vi.fn(),
      listRuleGroups: vi.fn(),
      queueCCImageDownload: vi.fn(),
    },
  }
})

const globalDocument: OpenRestySecurityDocument = {
  id: '11111111-1111-4111-8111-111111111111',
  scope_type: 'global',
  scope_id: 'platform',
  revision: 7,
  key_configured: true,
  updated_at: '2026-09-15T00:00:00Z',
  config: {
    cc_enable: true,
    block_time: 3600,
    white_time: 21600,
    default_block_way: 'exit',
    ipset_auto_enable: true,
    site_block_qps: 200,
    block_page_num_limit: 200,
    block_page_not_counted: true,
    tmp_white_total_limit: 400,
    tmp_white_per_limit: 50,
    custom_white: '',
    custom_black: '',
    ssl_handshake_limit: 1,
    default_page_refuse: false,
    force_default_page_cc: 'auto',
    auto_default_page_cc_qps: 100,
    default_page_rule: '10003',
    icmp_drop: false,
    auto_delete_access_log: 0,
    auto_switch: { enable: false, qps_50x: 50, qps_total: 1000, rule: '10003', seconds: 300 },
    cc_img_url_type: 'system',
    cc_img_url: '',
    at_hour: 0,
    slider_html: '<html></html>',
    captcha_html: '',
    click_html: '',
    delay_jump_html: '',
    rotate_html: '',
    easy_click_html: '',
    easy_slider_html: '',
    log: { log_level: 'info', debug_ip: '' },
    well_known_auto_protect_count: 600,
    internal_qps: 50,
    internal_res_block_time: 3600,
    internal_rule: [{ period: 120, reqs: 20 }, { period: 0, reqs: 0 }, { period: 0, reqs: 0 }],
    waf_enable: false,
    waf_resource_limits: {
      candidate_per_param: 2048,
      candidate_per_request: 4096,
      ffi_per_request: 8192,
      json_max_leaves: 2048,
      json_max_nodes: 9216,
      json_max_depth: 64,
      json_max_string_bytes: 262144,
      json_body_bytes: 1048576,
      multipart_max_parts: 128,
      body_scan_bytes: 16777216,
    },
  },
}

const ruleGroups: OpenRestySecurityRuleGroup[] = [
  { id: 'cc.system.00007', system_rule_id: '10003', system_rule_key: 'cc.system.00007', name: '旋转图片', enabled: true, kind: 'system', system_rule: true },
  { id: 'cc.system.00005', system_rule_id: '2', system_rule_key: 'cc.system.00005', name: '滑块验证', enabled: true, kind: 'system', system_rule: true },
  { id: 'custom-default-rule', name: '自定义默认规则', enabled: true, kind: 'custom', system_rule: false },
]

function setPrincipal(permissions = ['openresty_security.read', 'openresty_security.manage']) {
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
      permissions,
    },
  })
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <CdncaProvider>
      <MemoryRouter initialEntries={['/config/waf']}>
        <QueryClientProvider client={client}>
          <FirewallPoliciesPage />
        </QueryClientProvider>
      </MemoryRouter>
    </CdncaProvider>,
  )
}

describe('FirewallPoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setPrincipal()
    vi.mocked(openrestySecurityApi.getGlobal).mockResolvedValue(globalDocument)
    vi.mocked(openrestySecurityApi.patchGlobal).mockResolvedValue(globalDocument)
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue([
      { id: '10003', name: '旋转图片', enabled: true },
    ])
    vi.mocked(openrestySecurityApi.listOverrides).mockResolvedValue({
      items: [], page: 1, page_size: 20, total: 0,
    })
    vi.mocked(openrestySecurityApi.searchTargets).mockResolvedValue({
      items: [{ value: 'node-a', label: '节点A', description: '192.0.2.41' }],
      page: 1,
      page_size: 20,
      total: 1,
    })
    vi.mocked(openrestySecurityApi.createOverride).mockResolvedValue({
      ...globalDocument,
      id: '22222222-2222-4222-8222-222222222222',
      scope_type: 'node',
      scope_id: 'node-a',
      scope_label: '节点A',
      revision: 1,
      config: { block_time: 7200 },
    })
  })

  it('renders the three observed top-level tabs and compact card-grid structure', async () => {
    const view = renderPage()

    expect(await screen.findByText('CC 防护策略')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'CC全局配置' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'WAF全局配置' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: '区域及节点配置' })).toBeInTheDocument()
    expect(view.container.querySelector('.firewall-settings-page')).not.toBeNull()
    expect(view.container.querySelector('.firewall-tab-panel')).not.toBeNull()
    expect(view.container.querySelector('.firewall-card-grid')).not.toBeNull()
    expect(view.container.querySelector('.firewall-setting-card--wide')).not.toBeNull()
  })

  it('patches the CC switch with the current revision and write identity', async () => {
    const user = userEvent.setup()
    vi.mocked(openrestySecurityApi.patchGlobal).mockResolvedValue({
      ...globalDocument,
      revision: 8,
      config: { ...globalDocument.config, cc_enable: false },
    })
    renderPage()

    const toggle = await screen.findByRole('switch', { name: 'CC 防护开关' })
    await user.click(toggle)
    const dialog = await screen.findByRole('dialog', { name: '确认关闭「CC 防护开关」？' })
    expect(dialog).toHaveTextContent('立即下发到所有节点')
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: '确认' }))

    await waitFor(() => expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledWith(
      'token',
      7,
      { cc_enable: false },
      expect.objectContaining({
        requestId: expect.stringMatching(/^openresty-global-/),
        idempotencyKey: expect.stringMatching(/^openresty-global-/),
      }),
    ))
  })

  it('does not save a global switch when its confirmation is cancelled (W4)', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('switch', { name: '禁止PING' }))
    const dialog = await screen.findByRole('dialog', { name: '确认开启「禁止PING」？' })
    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByRole('switch', { name: '禁止PING' })).not.toBeChecked()
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
  })

  it('confirms before restoring the recommended WAF limits (W4)', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(await screen.findByRole('tab', { name: 'WAF全局配置' }))
    await user.click(await screen.findByRole('button', { name: '恢复推荐值' }))
    const dialog = await screen.findByRole('dialog', { name: '确认恢复 WAF 推荐值？' })
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledWith(
      'token', 7, { waf_resource_limits: expect.any(Object) }, expect.any(Object)))
  })

  it.each([
    ['numeric system alias', '10003', '旋转图片'],
    ['stable system key', 'cc.system.00007', '旋转图片'],
    ['custom rule ID', 'custom-default-rule', '自定义默认规则'],
  ])('shows the label for a %s without rewriting its stored value', async (_, value, label) => {
    vi.mocked(openrestySecurityApi.getGlobal).mockResolvedValue({
      ...globalDocument, config: { ...globalDocument.config, default_page_rule: value },
    })
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue(ruleGroups)
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    expect(await within(select.closest('.ant-select')!).findByText(label, { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    expect(select).toBeEnabled()
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
  })

  it('prefers an exact custom ID over a system alias', async () => {
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue([
      ...ruleGroups, { id: '10003', name: '精确自定义规则', enabled: true, kind: 'custom', system_rule: false },
    ])
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    expect(await within(select.closest('.ant-select')!).findByText('精确自定义规则', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
  })

  it('resolves a stored stable key against a legacy numeric catalog ID', async () => {
    vi.mocked(openrestySecurityApi.getGlobal).mockResolvedValue({
      ...globalDocument, config: { ...globalDocument.config, default_page_rule: 'cc.system.00007' },
    })
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue(ruleGroups.map((group) => group.system_rule ? { ...group, id: group.system_rule_id! } : group))
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    expect(await within(select.closest('.ant-select')!).findByText('旋转图片', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
  })

  it('does not interpret custom metadata as a system alias', async () => {
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue([
      { ...ruleGroups[2], system_rule_id: '10003', system_rule_key: 'cc.system.00007' },
    ])
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    expect(within(select.closest('.ant-select')!).getByText('10003', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    await waitFor(() => expect(select).toBeDisabled())
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
  })

  it.each([
    ['stable key', 'cc.system.00005', ruleGroups],
    ['legacy numeric ID', '2', ruleGroups.map((group) => group.system_rule ? { ...group, id: group.system_rule_id! } : group)],
    ['custom ID', 'custom-default-rule', ruleGroups],
  ])('saves the original catalog ID when selecting a %s', async (_, value, groups) => {
    const user = userEvent.setup()
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue(groups)
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    await user.click(select)
    await user.click(await screen.findByRole('option', { name: value === 'custom-default-rule' ? '自定义默认规则' : '滑块验证' }))

    await waitFor(() => expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledWith(
      'token', 7, { default_page_rule: value },
      expect.objectContaining({ requestId: expect.stringMatching(/^openresty-global-/), idempotencyKey: expect.stringMatching(/^openresty-global-/) }),
    ))
    expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledTimes(1)
  })

  it('keeps an unknown stored rule read-only without changing it when another field is saved', async () => {
    const user = userEvent.setup()
    const document = { ...globalDocument, config: { ...globalDocument.config, default_page_rule: 'retired-rule' } }
    vi.mocked(openrestySecurityApi.getGlobal).mockResolvedValue(document)
    vi.mocked(openrestySecurityApi.patchGlobal).mockResolvedValue({ ...document, revision: 8, config: { ...document.config, cc_enable: false } })
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue(ruleGroups)
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    expect(within(select.closest('.ant-select')!).getByText('retired-rule', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    await waitFor(() => expect(select).toBeDisabled())
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
    await user.click(screen.getByRole('switch', { name: 'CC 防护开关' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledWith('token', 7, { cc_enable: false }, expect.any(Object)))
    expect(select).toBeDisabled()
    expect(within(select.closest('.ant-select')!).getByText('retired-rule', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
  })

  it.each(['loading', 'error'])('does not classify a rule as unknown while its catalog is %s', async (state) => {
    if (state === 'loading') vi.mocked(openrestySecurityApi.listRuleGroups).mockReturnValue(new Promise(() => {}))
    else vi.mocked(openrestySecurityApi.listRuleGroups).mockRejectedValue(new Error('network'))
    renderPage()

    const select = await screen.findByRole('combobox', { name: '规则组' })
    expect(within(select.closest('.ant-select')!).getByText('10003', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    expect(select).toBeEnabled()
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
  })

  it('keeps all write actions disabled for a read-only platform operator', async () => {
    setPrincipal(['openresty_security.read'])
    renderPage()

    expect(await screen.findByRole('switch', { name: 'CC 防护开关' })).toBeDisabled()
    expect(screen.getByRole('combobox', { name: '规则组' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /立即更新/ })).toBeDisabled()
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
  })

  it('loads the real override collection when the regional tab is opened', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('CC 防护策略')

    await user.click(screen.getByRole('tab', { name: '区域及节点配置' }))

    await waitFor(() => expect(openrestySecurityApi.listOverrides).toHaveBeenCalledWith(
      'token',
      { page: 1, pageSize: 20 },
    ))
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
  })

  it('shows a platform node\'s effective auto switch and the layer it comes from (fix-fwregion)', async () => {
    const user = userEvent.setup()
    vi.mocked(openrestySecurityApi.searchTargets).mockResolvedValue({
      items: [{ value: '55555555-5555-4555-8555-555555555555', label: '华东节点', description: '192.0.2.41' }],
      page: 1, page_size: 20, total: 1,
    })
    vi.mocked(openrestySecurityApi.getEffective).mockResolvedValue({
      ...globalDocument,
      scope_type: 'node',
      scope_id: '55555555-5555-4555-8555-555555555555',
      config: { ...globalDocument.config, auto_switch: { enable: true, qps_50x: 0, qps_total: 50, rule: '10003', seconds: 120 } },
      sources: { auto_switch: 'region', cc_enable: 'global' },
    })
    renderPage()
    await screen.findByText('CC 防护策略')
    await user.click(screen.getByRole('tab', { name: '区域及节点配置' }))
    const panel = (await screen.findByRole('heading', { name: '节点生效值' })).closest('section')!
    await user.click(within(panel).getByRole('combobox', { name: '查看节点' }))
    await user.click(await screen.findByTitle('192.0.2.41'))
    await waitFor(() => expect(openrestySecurityApi.getEffective).toHaveBeenCalledWith('token', '55555555-5555-4555-8555-555555555555'))
    expect(await within(panel).findByText('总请求达 50/秒时切换到规则组 10003，120 秒后恢复')).toBeInTheDocument()
    expect(within(panel).getByText('区域')).toBeInTheDocument()
  })

  it('adds one override field at a time, restores the placeholder, removes it, and submits the edited value', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('CC 防护策略')
    await user.click(screen.getByRole('tab', { name: '区域及节点配置' }))
    await user.click(await screen.findByRole('button', { name: '新增设置' }))
    const dialog = await screen.findByRole('dialog', { name: '新增设置' })

    expect(within(dialog).getByRole('button', { name: /确\s*定/ })).toBeEnabled()
    const target = within(dialog).getByRole('combobox', { name: '节点选择' })
    fireEvent.mouseDown(target)
    await user.click(await screen.findByText('节点A', { selector: '.ant-select-item-option-content' }))

    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '配置项' }))
    await user.click(await screen.findByText('黑名单时间', { selector: '.ant-select-item-option-content' }))
    expect(within(dialog).getByText('请选择配置项')).toBeInTheDocument()
    expect(within(dialog).getByRole('spinbutton', { name: '黑名单时间' })).toHaveValue('3600')

    await user.click(within(dialog).getByRole('button', { name: '删除黑名单时间配置项' }))
    expect(within(dialog).queryByRole('spinbutton', { name: '黑名单时间' })).not.toBeInTheDocument()
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '配置项' }))
    await user.click(await screen.findByText('黑名单时间', { selector: '.ant-select-item-option-content' }))
    const duration = within(dialog).getByRole('spinbutton', { name: '黑名单时间' })
    await user.clear(duration)
    await user.type(duration, '7200')
    await user.click(within(dialog).getByRole('button', { name: /确\s*定/ }))

    await waitFor(() => expect(openrestySecurityApi.createOverride).toHaveBeenCalledWith(
      'token',
      { scopeType: 'node', scopeId: 'node-a', config: { block_time: 7200 } },
    ))
  })

  it('shows a retryable error state instead of an empty configuration', async () => {
    vi.mocked(openrestySecurityApi.getGlobal).mockRejectedValueOnce(new Error('network'))
    renderPage()

    expect(await screen.findByText('防火墙配置加载失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /重\s*试/ })).toBeInTheDocument()
    expect(screen.queryByText('CC 防护策略')).not.toBeInTheDocument()
  })
})

describe('FirewallPoliciesPage global CC auto switch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setPrincipal()
    vi.mocked(openrestySecurityApi.getGlobal).mockResolvedValue({
      ...globalDocument, config: { ...globalDocument.config, auto_switch: { enable: true, qps_50x: 50, qps_total: 1000, rule: '10003', seconds: 0 } },
    })
    vi.mocked(openrestySecurityApi.patchGlobal).mockResolvedValue(globalDocument)
    vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue(ruleGroups)
  })

  it('chooses the system rule group sites switch to by its catalog ID; custom groups are not offered', async () => {
    const user = userEvent.setup()
    renderPage()
    const select = await screen.findByRole('combobox', { name: '切换到' })
    expect(await within(select.closest('.ant-select')!).findByText('旋转图片', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: '恢复时间' })).toHaveValue('300')
    await user.click(select)
    const dropdown = await waitFor(() => document.querySelector<HTMLElement>('.ant-select-dropdown:not(.ant-select-dropdown-hidden)')!)
    expect(within(dropdown).queryByTitle('自定义默认规则')).not.toBeInTheDocument()
    await user.click(within(dropdown).getByTitle('滑块验证'))
    await waitFor(() => expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledWith(
      'token', 7, { auto_switch: { enable: true, qps_50x: 50, qps_total: 1000, rule: '2', seconds: 0 } }, expect.anything()))
  })
})
