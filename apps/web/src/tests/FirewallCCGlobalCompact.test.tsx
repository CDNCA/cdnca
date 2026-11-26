import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CdncaProvider } from '@cdnca/ui'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import { openrestySecurityApi, type OpenRestySecurityConfig, type OpenRestySecurityDocument } from '../api/openrestySecurity'
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
      listRuleGroups: vi.fn(),
      queueCCImageDownload: vi.fn(),
    },
  }
})

const config: OpenRestySecurityConfig = {
  cc_enable: true, block_time: 3600, white_time: 21600, default_block_way: 'exit', ipset_auto_enable: true,
  site_block_qps: 200, block_page_num_limit: 200, block_page_not_counted: true, tmp_white_total_limit: 400,
  tmp_white_per_limit: 50, custom_white: '', custom_black: '', ssl_handshake_limit: 1, default_page_refuse: false,
  force_default_page_cc: 'auto', auto_default_page_cc_qps: 100, default_page_rule: '10003', icmp_drop: false,
  auto_delete_access_log: 0, auto_switch: { enable: false, qps_50x: 50, qps_total: 1000, rule: '10003', seconds: 300 },
  cc_img_url_type: 'system', cc_img_url: '', at_hour: 0, slider_html: '<html></html>', captcha_html: '', click_html: '',
  delay_jump_html: '', rotate_html: '', easy_click_html: '', easy_slider_html: '', log: { log_level: 'info', debug_ip: '' },
  well_known_auto_protect_count: 600, internal_qps: 50, internal_res_block_time: 3600,
  internal_rule: [{ period: 120, reqs: 20 }, { period: 0, reqs: 0 }, { period: 0, reqs: 0 }], waf_enable: false,
}

const baseDocument: OpenRestySecurityDocument = {
  id: '11111111-1111-4111-8111-111111111111', scope_type: 'global', scope_id: 'platform', revision: 7,
  key_configured: true, updated_at: '2026-11-24T00:00:00Z', config,
}

// The server echo: every successful patch merges into the stored document and bumps the revision.
let stored: OpenRestySecurityDocument

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <CdncaProvider>
      <MemoryRouter initialEntries={['/config/waf']}>
        <QueryClientProvider client={client}><FirewallPoliciesPage /></QueryClientProvider>
      </MemoryRouter>
    </CdncaProvider>,
  )
}

const patches = () => vi.mocked(openrestySecurityApi.patchGlobal).mock.calls.map(([, revision, patch]) => [revision, patch])

beforeEach(() => {
  vi.clearAllMocks()
  stored = structuredClone(baseDocument)
  useSessionStore.setState({
    accessToken: 'token', sessionEpoch: 1,
    principal: {
      user_id: '44444444-4444-4444-8444-444444444444', scope_id: 'platform', scope_kind: 'platform', tenant_id: null,
      username: 'admin', display_name: 'Administrator', roles: ['platform_admin'],
      permissions: ['openresty_security.read', 'openresty_security.manage'],
    },
  })
  vi.mocked(openrestySecurityApi.getGlobal).mockImplementation(async () => structuredClone(stored))
  vi.mocked(openrestySecurityApi.patchGlobal).mockImplementation(async (_token, _revision, patch) => {
    const { key: _key, ...rest } = patch
    stored = { ...stored, revision: stored.revision + 1, config: { ...stored.config, ...rest } }
    return structuredClone(stored)
  })
  vi.mocked(openrestySecurityApi.listRuleGroups).mockResolvedValue([{ id: '10003', name: '旋转图片', enabled: true }])
  vi.mocked(openrestySecurityApi.listOverrides).mockResolvedValue({ items: [], page: 1, page_size: 20, total: 0 })
})

type User = ReturnType<typeof userEvent.setup>

async function settled(count: number) {
  await waitFor(() => expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledTimes(count))
  await waitFor(() => expect(screen.getByRole('switch', { name: 'CC 防护开关' })).toBeEnabled())
}

async function toggle(user: User, name: string) {
  await user.click(screen.getByRole('switch', { name }))
  const dialog = await screen.findByRole('dialog')
  await user.click(within(dialog).getByRole('button', { name: '确认' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
}

async function setNumber(user: User, name: string, value: string) {
  const input = screen.getByRole('spinbutton', { name })
  await user.clear(input)
  await user.type(input, value)
  // Blur to the page, not into the next field: every number field also saves on blur.
  await user.click(document.body)
}

async function setText(user: User, element: HTMLElement, value: string) {
  await user.click(element)
  await user.type(element, value)
  await user.click(document.body)
}

describe('FirewallPoliciesPage CC global tab', () => {
  // The compact layout only moves controls: the same operations must send the same patches, in order, at the same revisions.
  it('sends the same patches for the same operations', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByRole('switch', { name: 'CC 防护开关' })
    let count = 0
    const step = async (action: () => Promise<void>) => { await action(); await settled(++count) }
    // A submission equal to the saved value is not written: no request, no new revision.
    const noop = async (action: () => Promise<void>) => {
      await action()
      await new Promise((resolve) => setTimeout(resolve, 30))
      expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledTimes(count)
    }

    await step(() => toggle(user, 'CC 防护开关'))
    await step(() => setNumber(user, '黑名单时间', '7200'))
    await noop(() => setNumber(user, '黑名单时间', '7200'))
    await noop(async () => { await user.click(screen.getByRole('spinbutton', { name: '临时白名单' })); await user.click(document.body) })
    await step(() => setNumber(user, '临时白名单', '900'))
    await step(() => setNumber(user, '网站每秒拉黑次数', '300'))
    await step(() => setNumber(user, '页面次数限制', '150'))
    await step(() => toggle(user, '页面不计流量'))
    await step(() => toggle(user, '自动切换'))
    await step(async () => { await user.click(screen.getByRole('radio', { name: 'ipset(全局)' })) })
    await step(() => setNumber(user, '总请求数', '500'))
    await step(() => setNumber(user, '同 URL 请求', '60'))
    await step(() => setText(user, screen.getByRole('textbox', { name: '白名单 IP' }), '192.0.2.1'))
    await noop(async () => { await user.click(screen.getByRole('textbox', { name: '白名单 IP' })); await user.click(document.body) })
    await step(() => setText(user, screen.getByRole('textbox', { name: '黑名单 IP' }), '198.51.100.0/24'))
    await step(() => toggle(user, '防止TLS握手攻击'))
    await step(() => toggle(user, '禁止节点IP及未绑定域名访问'))
    await step(() => setNumber(user, '自动开启阈值', '120'))
    await step(async () => { await user.click(screen.getByRole('radio', { name: '强制开启' })) })
    await step(() => toggle(user, '禁止PING'))
    await step(() => setText(user, screen.getByLabelText('密钥'), 'node-secret'))
    await step(async () => { await user.click(screen.getByRole('radio', { name: '同时清空访问日志和缓存' })) })
    await step(() => toggle(user, 'CC规则自动切换'))
    await step(() => setNumber(user, '总请求阈值', '2000'))
    await noop(() => setNumber(user, '50x 请求阈值', '50'))
    await step(() => setNumber(user, '恢复时间', '600'))
    await step(async () => { await user.click(screen.getByRole('radio', { name: '自定义' })) })
    await step(() => setText(user, screen.getByRole('textbox', { name: '自定义下载地址' }), 'https://img.example.com/cc.zip'))
    await step(() => setText(user, screen.getByRole('textbox', { name: '页面模板 HTML' }), '<p>x</p>'))
    await noop(async () => { await user.click(screen.getByRole('textbox', { name: '页面模板 HTML' })); await user.click(document.body) })
    await step(() => toggle(user, '诊断日志'))
    await step(() => setText(user, screen.getByRole('textbox', { name: '调试客户端 IP' }), '203.0.113.10'))
    await step(() => setNumber(user, '404 阈值', '700'))
    await step(() => setNumber(user, '触发阈值', '60'))
    await step(() => setNumber(user, '拉黑时长', '1800'))
    await noop(async () => { await user.click(screen.getByRole('button', { name: /保\s*存/ })) })
    await step(async () => {
      const period = screen.getByRole('spinbutton', { name: '统计时长(秒) 2' })
      await user.clear(period)
      await user.type(period, '60')
      await user.click(screen.getByRole('button', { name: /保\s*存/ }))
    })
    await step(() => toggle(user, '诊断日志'))

    expect(patches()).toEqual([
      [7, { cc_enable: false }],
      [8, { block_time: 7200 }],
      [9, { white_time: 900 }],
      [10, { site_block_qps: 300 }],
      [11, { block_page_num_limit: 150 }],
      [12, { block_page_not_counted: false }],
      [13, { ipset_auto_enable: false }],
      [14, { default_block_way: 'ipset' }],
      [15, { tmp_white_total_limit: 500 }],
      [16, { tmp_white_per_limit: 60 }],
      [17, { custom_white: '192.0.2.1' }],
      [18, { custom_black: '198.51.100.0/24' }],
      [19, { ssl_handshake_limit: 0 }],
      [20, { default_page_refuse: true }],
      [21, { auto_default_page_cc_qps: 120 }],
      [22, { force_default_page_cc: 'force' }],
      [23, { icmp_drop: true }],
      [24, { key: 'node-secret' }],
      [25, { auto_delete_access_log: 2 }],
      [26, { auto_switch: { enable: true, qps_50x: 50, qps_total: 1000, rule: '10003', seconds: 300 } }],
      [27, { auto_switch: { enable: true, qps_50x: 50, qps_total: 2000, rule: '10003', seconds: 300 } }],
      [28, { auto_switch: { enable: true, qps_50x: 50, qps_total: 2000, rule: '10003', seconds: 600 } }],
      [29, { cc_img_url_type: 'custom' }],
      [30, { cc_img_url: 'https://img.example.com/cc.zip' }],
      [31, { slider_html: '<html></html><p>x</p>' }],
      [32, { log: { log_level: 'debug', debug_ip: '' } }],
      [33, { log: { log_level: 'debug', debug_ip: '203.0.113.10' } }],
      [34, { well_known_auto_protect_count: 700 }],
      [35, { internal_qps: 60 }],
      [36, { internal_res_block_time: 1800 }],
      [37, { internal_rule: [{ period: 120, reqs: 20 }, { period: 60, reqs: 0 }, { period: 0, reqs: 0 }] }],
      [38, { log: { log_level: 'info', debug_ip: '' } }],
    ])
  }, 60_000)
  it('keeps group titles, fields and units without restating each title, and keeps the decision constraints', async () => {
    const view = renderPage()
    await screen.findByRole('switch', { name: 'CC 防护开关' })
    for (const restated of [
      '控制全局拦截方式、黑白名单时长和临时白名单阈值。', '控制全局 CC 防护是否启用。', '设置黑名单拦截时长和临时白名单放行时长。',
      '选择默认拦截动作，并在非 ipset 模式下配置高攻击量切换策略。', '开启后访问拉黑页面不计流量。', '达到阈值后进入临时白名单，降低误拦截概率。',
      '一行一个，支持 # 作为注释。', '保护节点入口、默认页和自动清理策略，减少误开放风险。', '限制异常 TLS 握手占用，降低节点握手洪泛风险。',
      '阻断直接访问节点 IP 或未绑定域名的请求。', '配置默认页触发 CC 防护的方式，并选择命中的规则组。', '关闭节点 ICMP 回应，减少暴露面。',
      '节点磁盘不足时的访问日志和缓存清理策略。', '按 QPS 自动切换规则组，并管理防 CC 图片资源更新。', '按错误请求和总 QPS 自动切换到指定规则组。',
      '选择图片资源地址，并主动通知节点刷新资源。', '维护各类验证页 HTML，当前选择切换时只展示对应模板。', '模板保存后通过不可变配置版本下发到节点。',
      '开启诊断日志，保护证书验证路径和防 CC 页静态资源。', '开启后只记录指定客户端 IP 的调试日志。', '保护证书验证路径，避免异常 404 请求持续回源主控。',
    ]) expect(screen.queryByText(restated)).not.toBeInTheDocument()
    for (const constraint of [
      '临时白名单时间不能小于 600 秒。',
      'ipset 几乎不消耗带宽和 CPU；断开连接、返回页面会有额外消耗。建议默认使用非 ipset，并在攻击量升高时自动切换为 ipset。',
      '当网站每秒拉黑次数超过以上值时，自动切换 ipset 方式拉黑。',
      '超过阈值后 300 秒内仅允许已验证通过的 IP 回源，仍可正常申请证书。',
      '强烈建议自己搭建生成图片的服务器，并选择自定义填入自己的图片下载地址。',
      '留空或填 0 的行不启用。',
    ]) expect(screen.getByText(constraint)).toBeInTheDocument()
    // Scope is in the option names; the cleanup consequences are the options themselves.
    for (const option of ['ipset(全局)', '断开连接 (网站级别)', '返回页面 (网站级别)', '节点空间不足时，清空访问日志', '同时清空访问日志和缓存']) {
      expect(screen.getByRole('radio', { name: option })).toBeInTheDocument()
    }
    // List format lives in the input example; term explanations behind the help icon next to the title.
    expect(screen.getByRole('textbox', { name: '白名单 IP' })).toHaveAttribute('placeholder', '一行一个，支持 # 注释，如：\n192.168.1.10\n192.168.1.0/25')
    expect(screen.getByRole('textbox', { name: '黑名单 IP' })).toHaveAttribute('placeholder', '一行一个，支持 # 注释，如：\n192.168.1.10\n192.168.1.0/25')
    expect(screen.getByRole('img', { name: '内置资源指防 CC 页面里的图片、JS 等静态资源。' })).toBeInTheDocument()
    expect(screen.getByRole('img', { name: '节点侧 OpenResty 配置通信使用的共享密钥。' })).toBeInTheDocument()
    // Layout: full-width panel, content-height cards, no spacer cards for a lone switch.
    expect(view.container.querySelector('.firewall-cc-panel')).not.toBeNull()
    expect(view.container.querySelectorAll('.firewall-cc-grid').length).toBe(4)
    expect(view.container.querySelector('.firewall-cc-panel .firewall-card-spacer')).toBeNull()
    expect(view.container.querySelector('.firewall-section-heading p')).toBeNull()
  })

  it('names every switch after its visible field label', async () => {
    renderPage()
    await screen.findByRole('switch', { name: 'CC 防护开关' })
    for (const name of ['CC 防护开关', '防止TLS握手攻击', '禁止节点IP及未绑定域名访问', '禁止PING']) {
      const control = screen.getByRole('switch', { name })
      expect(control.closest('.firewall-cc-switch')).toHaveTextContent(name)
    }
    for (const name of ['自动切换', '页面不计流量', 'CC规则自动切换', '诊断日志']) expect(screen.getByRole('switch', { name })).toBeInTheDocument()
    expect(screen.getAllByRole('switch')).toHaveLength(8)
  })

  it('shows a dependent field only while its switch or option is on, keeping the value and writing nothing', async () => {
    const user = userEvent.setup()
    stored = { ...stored, config: {
      ...config, ipset_auto_enable: false, site_block_qps: 321, force_default_page_cc: 'force', auto_default_page_cc_qps: 140,
      auto_switch: { enable: false, qps_50x: 70, qps_total: 1500, rule: '10003', seconds: 900 },
    } }
    renderPage()
    await screen.findByRole('switch', { name: 'CC 防护开关' })
    expect(screen.queryByRole('spinbutton', { name: '网站每秒拉黑次数' })).not.toBeInTheDocument()
    expect(screen.queryByText('当网站每秒拉黑次数超过以上值时，自动切换 ipset 方式拉黑。')).not.toBeInTheDocument()
    expect(screen.queryByRole('spinbutton', { name: '自动开启阈值' })).not.toBeInTheDocument()
    expect(screen.queryByRole('spinbutton', { name: '总请求阈值' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: '调试客户端 IP' })).not.toBeInTheDocument()
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()

    // Cancelling the confirmation keeps the field hidden and writes nothing.
    await user.click(screen.getByRole('switch', { name: '自动切换' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '取消' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.queryByRole('spinbutton', { name: '网站每秒拉黑次数' })).not.toBeInTheDocument()
    expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()

    await toggle(user, '自动切换')
    await settled(1)
    expect(screen.getByRole('spinbutton', { name: '网站每秒拉黑次数' })).toHaveValue('321')
    expect(screen.getByText('当网站每秒拉黑次数超过以上值时，自动切换 ipset 方式拉黑。')).toBeInTheDocument()

    await user.click(screen.getByRole('radio', { name: '自动开启' }))
    await settled(2)
    expect(screen.getByRole('spinbutton', { name: '自动开启阈值' })).toHaveValue('140')

    await toggle(user, 'CC规则自动切换')
    await settled(3)
    expect(screen.getByRole('spinbutton', { name: '总请求阈值' })).toHaveValue('1500')
    expect(screen.getByRole('spinbutton', { name: '恢复时间' })).toHaveValue('900')

    await toggle(user, '自动切换')
    await settled(4)
    expect(screen.queryByRole('spinbutton', { name: '网站每秒拉黑次数' })).not.toBeInTheDocument()
    expect(patches()).toEqual([
      [7, { ipset_auto_enable: true }],
      [8, { force_default_page_cc: 'auto' }],
      [9, { auto_switch: { enable: true, qps_50x: 70, qps_total: 1500, rule: '10003', seconds: 900 } }],
      [10, { ipset_auto_enable: false }],
    ])
    expect(stored.config.site_block_qps).toBe(321)
  }, 30_000)
  it('writes nothing when a field is submitted with its saved value', async () => {
    const user = userEvent.setup()
    stored = { ...stored, config: { ...config, auto_switch: { enable: true, qps_50x: 50, qps_total: 1000, rule: '10003', seconds: 0 } } }
    renderPage()
    const blockTime = await screen.findByRole('spinbutton', { name: '黑名单时间' })
    const idle = async () => {
      await new Promise((resolve) => setTimeout(resolve, 30))
      expect(openrestySecurityApi.patchGlobal).not.toHaveBeenCalled()
    }

    // Focus and leave without typing.
    await user.click(blockTime)
    await user.click(document.body)
    await idle()
    // Edit, then type the saved value back before leaving.
    await user.clear(blockTime)
    await user.type(blockTime, '7200')
    await user.clear(blockTime)
    await user.type(blockTime, '3600')
    await user.click(document.body)
    await idle()
    // Text fields and the recovery time shown as 300 for a stored 0 (the server default).
    await user.click(screen.getByRole('textbox', { name: '黑名单 IP' }))
    await user.click(document.body)
    await user.click(screen.getByRole('spinbutton', { name: '恢复时间' }))
    await user.click(document.body)
    await idle()

    // A real change is written once, with the same body as before.
    await user.clear(blockTime)
    await user.type(blockTime, '7200')
    await user.click(document.body)
    await settled(1)
    expect(patches()).toEqual([[7, { block_time: 7200 }]])
    // Leaving again with the now-saved 7200 writes nothing more.
    await user.click(blockTime)
    await user.click(document.body)
    await new Promise((resolve) => setTimeout(resolve, 30))
    expect(openrestySecurityApi.patchGlobal).toHaveBeenCalledTimes(1)
  })
})
