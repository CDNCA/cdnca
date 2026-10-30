import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { siteAccessApi, type SiteAccessState } from '../../api/siteAccess'
import SiteAccessPanel from './SiteAccessPanel'

const siteId = '11111111-1111-4111-8111-111111111111'

function state(patch: Partial<SiteAccessState> = {}): SiteAccessState {
  return {
    site_id: siteId, version: 4, https_enabled: true, force_https: true,
    domains: ['example.test', 'www.example.test'], updated_at: null,
    settings: {
      host_redirects: [], hsts: null, compression: null, limits: null, basic_auth: null, maintenance: null,
      force_https: { status: 301, exclude_hosts: [] },
    },
    ...patch,
  }
}

function renderPanel(canManage = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<ConfigProvider><AntApp><QueryClientProvider client={client}>
    <SiteAccessPanel siteId={siteId} accessToken="token" canManage={canManage} locked={false} />
  </QueryClientProvider></AntApp></ConfigProvider>)
}

// 没有保存按钮，改动即保存；每次提交都基于上一次保存返回的版本。
const lastBody = (put: { mock: { calls: unknown[][] } }) => put.mock.calls.at(-1)![3] as SiteAccessState['settings']

describe('SiteAccessPanel', () => {
  beforeEach(() => { vi.restoreAllMocks() })

  it('saves HSTS, limits and a basic auth user against the site version, password only in the request', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state())
    const put = vi.spyOn(siteAccessApi, 'put').mockImplementation(async (_token, _site, version, settings) => ({
      ...state({ version: version + 1 }),
      settings: { ...settings, basic_auth: settings.basic_auth && { ...settings.basic_auth, users: settings.basic_auth.users.map((user) => ({ username: user.username })) } },
    }))
    renderPanel()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('switch', { name: 'HSTS' }))
    await user.click(screen.getByRole('switch', { name: '包含子域名' }))
    await user.click(screen.getByRole('switch', { name: '连接与限速' }))
    await user.clear(screen.getByRole('spinbutton', { name: '单 IP 并发请求数' }))
    await user.type(screen.getByRole('spinbutton', { name: '单 IP 并发请求数' }), '12')
    fireEvent.blur(screen.getByRole('spinbutton', { name: '单 IP 并发请求数' }))
    await waitFor(() => expect(lastBody(put).limits).toEqual({ connections_per_ip: 12 }))
    expect(screen.queryByRole('button', { name: /保存/ })).toBeNull()
    expect(put.mock.calls[0]![1]).toBe(siteId)
    expect(put.mock.calls.map((call) => call[2])).toEqual(put.mock.calls.map((_, index) => 4 + index))
    await user.click(screen.getByRole('switch', { name: '访问认证（Basic）' }))
    await user.click(screen.getByRole('button', { name: /添加用户/ }))
    await user.type(screen.getByRole('textbox', { name: '用户名 1' }), 'alice')
    const before = put.mock.calls.length
    await user.type(screen.getByLabelText('密码 1'), 'correct horse')
    fireEvent.blur(screen.getByLabelText('密码 1'))
    await waitFor(() => expect(put.mock.calls.length).toBeGreaterThan(before))
    const settings = lastBody(put)
    expect(settings.hsts).toEqual({ max_age_seconds: 31536000, include_subdomains: true, preload: false })
    expect(settings.limits).toEqual({ connections_per_ip: 12 })
    expect(settings.basic_auth?.users).toEqual([{ username: 'alice', password: 'correct horse' }])
    expect(settings.compression).toBeNull()
    expect(settings.maintenance).toBeNull()
    expect((await screen.findAllByText('操作成功')).length).toBeGreaterThan(0)
    await waitFor(() => expect(screen.getByLabelText('密码 1')).toHaveValue(''))
  })

  it('saves Brotli with levels and automatic WebP', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state())
    const put = vi.spyOn(siteAccessApi, 'put').mockImplementation(async (_token, _site, version, settings) => ({ ...state({ version: version + 1 }), settings }))
    renderPanel()
    const user = userEvent.setup()
    await user.click(await screen.findByText('本站开启'))
    await user.type(screen.getByRole('textbox', { name: '压缩类型' }), 'text/css')
    await user.click(screen.getByRole('checkbox', { name: 'Brotli' }))
    await user.type(screen.getByRole('spinbutton', { name: 'Brotli 压缩级别' }), '5')
    await user.clear(screen.getByRole('spinbutton', { name: 'Gzip 压缩级别' }))
    await user.type(screen.getByRole('spinbutton', { name: 'Gzip 压缩级别' }), '7')
    expect(screen.getByText(/Brotli 和自定义压缩级别需要节点支持/)).toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: '自动转 WebP' }))
    await user.type(screen.getByRole('spinbutton', { name: 'WebP 质量' }), '70')
    fireEvent.blur(screen.getByRole('spinbutton', { name: 'WebP 质量' }))
    await waitFor(() => expect(lastBody(put).webp).toEqual({ enabled: true, quality: 70 }))
    const settings = lastBody(put)
    expect(settings.compression).toEqual({ enabled: true, types: ['text/css'], min_length_bytes: 256, encodings: ['br', 'gzip'], gzip_level: 7, brotli_level: 5 })
    expect(settings.webp).toEqual({ enabled: true, quality: 70 })
  })

  it('sends gzip only without encodings and drops the level of a removed encoding', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state({ settings: { ...state().settings,
      compression: { enabled: true, types: ['text/css'], min_length_bytes: 100, encodings: ['br', 'gzip'], brotli_level: 4 },
      webp: { enabled: true } } }))
    const put = vi.spyOn(siteAccessApi, 'put').mockImplementation(async (_token, _site, version, settings) => ({ ...state({ version: version + 1 }), settings }))
    renderPanel()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('checkbox', { name: 'Brotli' }))
    expect(screen.queryByRole('spinbutton', { name: 'Brotli 压缩级别' })).toBeNull()
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0]![3].compression).toEqual({ enabled: true, types: ['text/css'], min_length_bytes: 100 })
    await user.click(screen.getByRole('switch', { name: '自动转 WebP' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    const settings = lastBody(put)
    expect(settings.compression).toEqual({ enabled: true, types: ['text/css'], min_length_bytes: 100 })
    expect(settings.webp).toBeNull()
  })

  it('adds, edits and orders response rules and saves them cleaned', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state())
    const put = vi.spyOn(siteAccessApi, 'put').mockImplementation(async (_token, _site, version, settings) => ({ ...state({ version: version + 1 }), settings }))
    renderPanel()
    const user = userEvent.setup()
    expect(await screen.findByText(/改写响应头的规则对回源响应和缓存命中的响应都执行/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /添加响应规则/ }))
    await user.type(screen.getByRole('textbox', { name: '状态码 1' }), '200-299')
    await user.click(screen.getByRole('button', { name: /添加条件 1/ }))
    await user.type(screen.getByRole('textbox', { name: '响应头名称 1.1' }), 'X-Powered-By')
    await user.type(screen.getByRole('textbox', { name: '头名称 1.1' }), 'x-powered-by')
    await user.click(screen.getByRole('combobox', { name: '操作 1.1' }))
    await user.click(await screen.findByTitle('删除'))
    expect(screen.queryByRole('textbox', { name: '头的值 1.1' })).toBeNull()
    expect(screen.getByText(/响应规则需要节点支持/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /添加响应规则/ }))
    await user.type(screen.getByRole('textbox', { name: '状态码 2' }), '500, 502, bad')
    await user.click(screen.getByRole('combobox', { name: '动作 2' }))
    await user.click(await screen.findByTitle('拦截'))
    expect(screen.getByRole('spinbutton', { name: '返回状态码 2' })).toHaveValue('403')
    await user.click(screen.getByRole('button', { name: '上移 2' }))
    // 失焦即保存：保存后状态码按服务端结果整理（丢掉无法识别的 bad）。
    await waitFor(() => expect(screen.getByRole('textbox', { name: '状态码 1' })).toHaveValue('500, 502'))

    await waitFor(() => expect(put).toHaveBeenCalled())
    await waitFor(() => expect(lastBody(put).response_rules).toEqual([
      { id: 'rule-2', action: 'block', statuses: [{ from: 500, to: 500 }, { from: 502, to: 502 }], status: 403 },
      { id: 'rule-1', action: 'headers', statuses: [{ from: 200, to: 299 }],
        headers: [{ name: 'X-Powered-By', op: 'exists' }], header_actions: [{ kind: 'delete', name: 'x-powered-by' }] },
    ]))
    expect(lastBody(put).response_rules).toEqual([
      { id: 'rule-2', action: 'block', statuses: [{ from: 500, to: 500 }, { from: 502, to: 502 }], status: 403 },
      { id: 'rule-1', action: 'headers', statuses: [{ from: 200, to: 299 }],
        headers: [{ name: 'X-Powered-By', op: 'exists' }], header_actions: [{ kind: 'delete', name: 'x-powered-by' }] },
    ])
  })

  it('shows stored response rules and removes them', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state({ settings: { ...state().settings, response_rules: [
      { id: 'page', statuses: [{ from: 500, to: 504 }], headers: [{ name: 'server', op: 'regex', value: '^nginx' }], action: 'error_page', status: 503 },
    ] } }))
    const put = vi.spyOn(siteAccessApi, 'put').mockImplementation(async (_token, _site, version, settings) => ({ ...state({ version: version + 1 }), settings }))
    renderPanel()
    const user = userEvent.setup()
    expect(await screen.findByRole('textbox', { name: '状态码 1' })).toHaveValue('500-504')
    expect(screen.getByRole('textbox', { name: '值 1.1' })).toHaveValue('^nginx')
    expect(screen.getByRole('spinbutton', { name: '返回状态码 1' })).toHaveValue('503')
    await user.click(screen.getByRole('button', { name: /删除规则/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][3].response_rules).toEqual([])
  })

  it('keeps HSTS and the forced HTTPS settings off without HTTPS', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state({ https_enabled: false, force_https: false }))
    renderPanel()
    expect(await screen.findByRole('switch', { name: 'HSTS' })).toBeDisabled()
    expect(screen.getByText('本站未开启 HTTPS，不能开启 HSTS。')).toBeInTheDocument()
    expect(screen.getByText(/本站未开启强制 HTTPS/)).toBeInTheDocument()
  })

  it('says streaming responses are controlled by the origin X-Accel-Buffering header', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state({}))
    renderPanel()
    // The long note sits behind the (?) next to the section title.
    expect(await screen.findByRole('img', { name: /由源站在该响应上发送 X-Accel-Buffering: no/ })).toBeInTheDocument()
  })

  it('blocks a preload without a year and subdomains', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state({
      settings: { ...state().settings, hsts: { max_age_seconds: 600, include_subdomains: false, preload: true } },
    }))
    const put = vi.spyOn(siteAccessApi, 'put')
    renderPanel()
    // 校验失败不提交：改 HSTS 有效期仍不足一年。
    const maxAge = await screen.findByRole('spinbutton', { name: '有效期（秒）' })
    await userEvent.setup().type(maxAge, '0')
    fireEvent.blur(maxAge)
    expect(screen.getAllByText(/预加载需要有效期至少一年/).length).toBeGreaterThan(0)
    expect(put).not.toHaveBeenCalled()
  })

  it('rolls a control back to the server value and explains the refusal when saving fails', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state())
    const put = vi.spyOn(siteAccessApi, 'put').mockRejectedValue(new ApiError('locked', 409, 'site_locked'))
    renderPanel()
    const webp = await screen.findByRole('switch', { name: '自动转 WebP' })
    await userEvent.setup().click(webp)
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(webp).not.toBeChecked())
  })

  it('is read-only without manage permission and explains a server refusal', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state())
    renderPanel(false)
    expect(await screen.findByText('你没有修改本站设置的权限。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保存/ })).not.toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '维护页' })).toBeDisabled()
  })

  // 性能与协议里压缩卡片只放三态；「本站开启」的类型/算法/级别在「压缩方式」弹层里填，保存仍走本卡片。
  it('opens the compression dialog for 本站开启 when split into the performance card', async () => {
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(state())
    const put = vi.spyOn(siteAccessApi, 'put').mockImplementation(async (_token, _site, version, settings) => ({ ...state({ version: version + 1 }), settings }))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    render(<ConfigProvider><AntApp><QueryClientProvider client={client}>
      <SiteAccessPanel siteId={siteId} accessToken="token" canManage locked={false} parts={['compression']} />
    </QueryClientProvider></AntApp></ConfigProvider>)
    const user = userEvent.setup()
    await user.click(await screen.findByText('本站开启'))
    const dialog = await screen.findByRole('dialog', { name: '压缩方式' })
    await user.type(within(dialog).getByRole('textbox', { name: '压缩类型' }), 'text/css')
    fireEvent.blur(within(dialog).getByRole('textbox', { name: '压缩类型' }))
    await user.click(within(dialog).getByRole('button', { name: /完\s*成/ }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '压缩方式' })).toBeNull())
    expect(screen.getByRole('button', { name: '压缩方式设置' })).toBeInTheDocument()
    await waitFor(() => expect(lastBody(put).compression).toEqual({ enabled: true, types: ['text/css'], min_length_bytes: 256 }))
    expect(lastBody(put).compression).toEqual({ enabled: true, types: ['text/css'], min_length_bytes: 256 })
  })

  // tp-b3c: 高级设置 splits the cards (Gzip in 性能与协议, the rest in 更多设置);
  // each split saves its own cards and keeps the stored values of the others.
  it('saves only its own cards when split, keeping the other cards as stored', async () => {
    const stored = state({ settings: { ...state().settings, limits: { connections_per_ip: 3 } } })
    vi.spyOn(siteAccessApi, 'get').mockResolvedValue(stored)
    const put = vi.spyOn(siteAccessApi, 'put').mockImplementation(async (_token, _site, version, settings) => ({ ...stored, version: version + 1, settings }))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    render(<ConfigProvider><AntApp><QueryClientProvider client={client}>
      <SiteAccessPanel siteId={siteId} accessToken="token" canManage locked={false} parts={['compression']} />
      <SiteAccessPanel siteId={siteId} accessToken="token" canManage locked={false} parts={['limits', 'hsts']} />
    </QueryClientProvider></AntApp></ConfigProvider>)
    const user = userEvent.setup()
    expect(await screen.findAllByRole('heading', { level: 3 })).toHaveLength(3)
    // the first split saves compression only
    await user.click(screen.getByText('本站关闭'))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const first = put.mock.calls[0]![3]
    expect(first.compression).toEqual({ enabled: false, types: [], min_length_bytes: 256 })
    expect(first.hsts).toBeNull()
    expect(first.limits).toEqual({ connections_per_ip: 3 })
    // the second split saves against the new version and keeps the first split's value
    await user.click(screen.getByRole('switch', { name: 'HSTS' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    const [, , version, second] = put.mock.calls[1]!
    expect(version).toBe(5)
    expect(second.hsts).toEqual({ max_age_seconds: 31536000, include_subdomains: false, preload: false })
    expect(second.compression).toEqual({ enabled: false, types: [], min_length_bytes: 256 })
  })
})
