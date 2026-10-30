// 全局配置 > Nginx配置 > 区域及节点配置 > 新增设置。
// 节点/区域来自本主控的节点清单与区域目录（不可手填），配置项中文名称+指令副标题，
// 前端校验与 services/control-api/internal/systemconfig/schema.go validateNginxCore 一致，
// 每个配置项都能选中、填写并写出服务端结构。
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { nodesApi, regionsApi, type NodeInventoryItem, type RegionRecord } from '../api/nodes'
import { securityPoliciesApi } from '../api/securityPolicies'
import { systemConfigurationApi, type NginxConfiguration, type SystemConfigurationDocument } from '../api/systemConfiguration'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import SystemSettingsPage from '../pages/SystemSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const nginx: NginxConfiguration = {
  worker: { worker_processes: 4, worker_connections: 4_096, worker_rlimit_nofile: 65_536, worker_shutdown_timeout_ms: 10_000, logs_dir: '/var/log/cdnca/nginx' },
  http: {
    gzip_comp_level: 5, gzip_http_version: '1.1', gzip_min_length_bytes: 1_024, gzip_vary: true, server_addr_outgoing: false,
    proxy_request_buffering: true, proxy_buffering: true, proxy_cache_min_free_bytes: 5_368_709_120, proxy_cache_max_size_bytes: 107_374_182_400,
    proxy_cache_methods: ['GET', 'HEAD'], proxy_http_version: '1.1', proxy_max_temp_file_size_bytes: 1_073_741_824,
    proxy_next_upstream: ['error', 'timeout'], proxy_connect_timeout_ms: 5_000, proxy_send_timeout_ms: 60_000, proxy_read_timeout_ms: 60_000,
    client_body_buffer_size_bytes: 16_384, server: 'CDNCA', client_max_body_size_bytes: 104_857_600, default_type: 'text/plain',
    keepalive_requests: 1_000, keepalive_timeout_ms: 75_000, log_not_found: false, server_tokens: false,
    large_client_header_buffers: { count: 4, size_bytes: 8_192 }, server_names_hash_max_size: 4_096, server_names_hash_bucket_size: 64,
  },
  stream: { proxy_connect_timeout_ms: 5_000, proxy_timeout_ms: 300_000 },
  overrides: [],
}

const nodeA = '11111111-1111-4111-8111-111111111111'
const nodeB = '22222222-2222-4222-8222-222222222222'

function nginxDocument(value: NginxConfiguration = nginx): SystemConfigurationDocument<'nginx'> {
  return {
    schema: 'cdnca.system-configuration/v2', category: 'nginx', head_revision: 2,
    active_revision: 1, revision: 2, status: 'draft', snapshot_sha256: 'a'.repeat(64), pending_categories: [], value,
  }
}

function node(id: string, name: string, ipv4: string, displayID: string, admin_state: NodeInventoryItem['admin_state'] = 'active'): NodeInventoryItem {
  return { id, display_id: displayID, name, ipv4, region: '华东', admin_state } as unknown as NodeInventoryItem
}

function region(id: string, name: string, sort: number): RegionRecord {
  return { id, name, code: `region-${id}`, country_code: '', province_code: '', description: '', l2_check_port: 80, sort, revision: 1, created_at: '', updated_at: '' }
}

function authenticate() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

async function openAddDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('tab', { name: '区域及节点配置' }))
  await user.click(screen.getByRole('button', { name: '新增设置' }))
  return screen.findByRole('dialog')
}

async function chooseSetting(dialog: HTMLElement, label: string) {
  fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '配置项' }))
  fireEvent.click(await screen.findByText(label, { selector: '.ant-select-item-option-content' }))
}

async function chooseNode(_user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement, label: string) {
  fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '节点选择' }))
  fireEvent.click(await screen.findByText(label, { selector: '.ant-select-item-option-content' }))
}

function settingRow(dialog: HTMLElement, label: string): HTMLElement {
  return dialog.querySelector(`.configuration-override-value-field [aria-label="${label}"]`)!.closest('.configuration-override-value-field') as HTMLElement
}

beforeEach(async () => {
  await changeLocale('zh-CN')
  vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [] } as never)
})

afterEach(() => {
  vi.restoreAllMocks()
  useSessionStore.getState().clearSession()
})

describe('Nginx 区域及节点配置 新增设置', () => {
  it('节点下拉只列本主控节点清单（服务端搜索/分页），不能手填任意文本', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 0, data: [] })
    const list = vi.spyOn(nodesApi, 'list').mockImplementation(async (_token, params) => {
      if (params.search === '10.0.0.2') return { items: [node(nodeB, 'edge-b', '10.0.0.2', '102')] }
      if (params.cursor === nodeA) return { items: [node(nodeB, 'edge-b', '10.0.0.2', '102')] }
      return {
        items: [node(nodeA, 'edge-a', '10.0.0.1', '101'), node('33333333-3333-4333-8333-333333333333', 'old', '10.0.0.9', '109', 'retired')],
        next_cursor: params.limit === 20 && !params.search ? nodeA : undefined,
      }
    })
    const user = userEvent.setup()
    renderWithProviders(<SystemSettingsPage />)
    const dialog = await openAddDialog(user)

    const target = within(dialog).getByRole('combobox', { name: '节点选择' })
    fireEvent.mouseDown(target)
    expect(await screen.findByText('edge-a (10.0.0.1) #101', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    // 已退役节点不出现
    expect(screen.queryByText(/^old /u, { selector: '.ant-select-item-option-content' })).toBeNull()
    expect(list).toHaveBeenCalledWith(expect.any(String), { limit: 20, search: undefined, cursor: undefined })

    // 加载更多走游标分页
    await user.click(await screen.findByRole('button', { name: '加载更多' }))
    expect(await screen.findByText('edge-b (10.0.0.2) #102', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(list).toHaveBeenCalledWith(expect.any(String), { limit: 20, search: undefined, cursor: nodeA })

    // 搜索交给服务端；输入的文字本身不会变成可选项
    await user.type(target, 'not-a-node')
    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.any(String), { limit: 20, search: 'not-a-node', cursor: undefined }))
    expect(screen.queryByText('not-a-node', { selector: '.ant-select-item-option-content' })).toBeNull()
    await user.clear(target)
    await user.type(target, '10.0.0.2')
    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.any(String), { limit: 20, search: '10.0.0.2', cursor: undefined }))
    await user.click(await screen.findByText('edge-b (10.0.0.2) #102', { selector: '.ant-select-item-option-content' }))

    await chooseSetting(dialog, '工作进程数（worker_processes）')
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(nginxDocument())
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    await user.click(await screen.findByRole('button', { name: '保存' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const written = put.mock.calls[0]?.[2] as NginxConfiguration
    expect(written.overrides).toEqual([expect.objectContaining({ scope: 'node', scope_id: nodeB, values: { worker: { worker_processes: 4 } } })])
  })

  it('区域选择是区域目录下拉，保存区域 ID，表格显示区域名称', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })
    const regions = vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 2, data: [region('7', '华东', 1), region('8', '华南', 2)] })
    const user = userEvent.setup()
    renderWithProviders(<SystemSettingsPage />)
    const dialog = await openAddDialog(user)

    fireEvent.click(within(dialog).getByRole('radio', { name: '区域' }))
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '区域选择' }))
    fireEvent.click(await screen.findByText('华南', { selector: '.ant-select-item-option-content' }))
    expect(regions).toHaveBeenCalledWith(expect.any(String), { page: 1, page_size: 20, search: undefined })
    await chooseSetting(dialog, '回源读取超时（proxy_read_timeout）')
    await user.clear(within(dialog).getByRole('textbox', { name: '回源读取超时（proxy_read_timeout）' }))
    await user.type(within(dialog).getByRole('textbox', { name: '回源读取超时（proxy_read_timeout）' }), '90s')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    const row = (await screen.findByText('华南')).closest('tr')!
    expect(within(row).getByText('回源读取超时（proxy_read_timeout）')).toBeInTheDocument()
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(nginxDocument())
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect((put.mock.calls[0]?.[2] as NginxConfiguration).overrides)
      .toEqual([expect.objectContaining({ scope: 'region', scope_id: '8', values: { http: { proxy_read_timeout_ms: 90_000 } } })])
  })

  it('全部 30 个配置项（日志目录与 Stream 超时不下发，已去掉）：中文名称、说明，逐个写入与服务端一致的结构', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 0, data: [] })
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node(nodeA, 'edge-a', '10.0.0.1', '101')] })
    const user = userEvent.setup()
    renderWithProviders(<SystemSettingsPage />)
    const dialog = await openAddDialog(user)
    await chooseNode(user, dialog, 'edge-a (10.0.0.1) #101')

    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '配置项' }))
    const labels = Array.from(document.querySelectorAll('.configuration-select-popup:not(.ant-select-dropdown-hidden) .ant-select-item-option-content'))
      .map((item) => item.textContent).filter((item) => item !== 'edge-a (10.0.0.1) #101')
    expect(labels).toHaveLength(30)
    expect(labels).not.toContain('日志目录')
    expect(labels.some((label) => label!.includes('（stream '))).toBe(false)
    // 名称都以中文开头（指令名只作括号里的副标题）
    for (const label of labels) expect(label).toMatch(/^[一-龥A-Z]/u)
    expect(labels.slice(0, 5)).toEqual([
      '最大打开文件数（worker_rlimit_nofile）', '优雅退出超时（worker_shutdown_timeout）', '单进程最大连接数（worker_connections）',
      '工作进程数（worker_processes）', 'Gzip 压缩级别（gzip_comp_level）',
    ])
    fireEvent.keyDown(within(dialog).getByRole('combobox', { name: '配置项' }), { key: 'Escape' })

    const edits: Array<[string, string | null]> = [
      ['最大打开文件数（worker_rlimit_nofile）', '100000'], ['优雅退出超时（worker_shutdown_timeout）', '30s'],
      ['单进程最大连接数（worker_connections）', '8192'], ['工作进程数（worker_processes）', 'auto'],
      ['Gzip 压缩级别（gzip_comp_level）', '6'], ['Gzip 最低 HTTP 版本（gzip_http_version）', null], ['Gzip 最小压缩长度（gzip_min_length）', '2k'],
      ['Gzip Vary 响应头（gzip_vary）', null], ['入口 IP 回源', null], ['缓冲客户端请求体（proxy_request_buffering）', null],
      ['缓冲源站响应（proxy_buffering）', null], ['缓存总容量（proxy_cache_max_size）', '200g'], ['缓存最小剩余空间（min_free）', '10g'],
      ['可缓存的请求方法（proxy_cache_methods）', null], ['回源 HTTP 版本（proxy_http_version）', null], ['回源临时文件上限（proxy_max_temp_file_size）', '0'],
      ['回源失败重试条件（proxy_next_upstream）', null], ['回源连接超时（proxy_connect_timeout）', '10s'], ['回源发送超时（proxy_send_timeout）', '2m'],
      ['回源读取超时（proxy_read_timeout）', '3m'], ['Server 响应头（server）', 'edge'], ['请求体大小上限（client_max_body_size）', '200m'],
      ['默认 MIME 类型（default_type）', 'application/octet-stream'], ['长连接最大请求数（keepalive_requests）', '500'], ['长连接超时（keepalive_timeout）', '30s'],
      ['记录文件不存在错误（log_not_found）', null], ['显示 Nginx 版本号（server_tokens）', null], ['大请求头缓冲区（large_client_header_buffers）', '8 16k'],
      ['域名哈希表大小（server_names_hash_max_size）', '8192'], ['域名哈希桶大小（server_names_hash_bucket_size）', '128'],
    ]
    for (const [label, value] of edits) {
      await chooseSetting(dialog, label)
      if (value !== null) {
        const box = within(dialog).getByRole('textbox', { name: label })
        await user.clear(box)
        if (value) await user.type(box, value)
      }
    }
    // 选完后配置项下拉不残留上一项名称；指令名作为副标题单独显示
    expect(within(dialog).getByRole('combobox', { name: '配置项' }).closest('.ant-select')!.querySelector('.ant-select-selection-item')).toBeNull()
    expect(dialog.querySelectorAll('.configuration-override-directive')).toHaveLength(29)
    // 每个配置项都有中文说明
    expect(dialog.querySelectorAll('.configuration-override-help')).toHaveLength(30)
    expect(within(dialog).getByText('填写 auto 按 CPU 核数自动设置，或填 1–256 的整数。')).toBeInTheDocument()
    // 单选/多选控件可操作
    await user.click(within(settingRow(dialog, 'Gzip 最低 HTTP 版本（gzip_http_version）')).getByRole('radio', { name: '1.0' }))
    await user.click(within(settingRow(dialog, '记录文件不存在错误（log_not_found）')).getByRole('radio', { name: '开启' }))
    await user.click(within(dialog).getByRole('checkbox', { name: 'HEAD' }))
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '回源失败重试条件（proxy_next_upstream）' }))
    await user.click(await screen.findByText('http_502', { selector: '.ant-select-item-option-content' }))

    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(screen.queryByText('设置值无效，请检查格式和范围。')).toBeNull()
    const put = vi.spyOn(systemConfigurationApi, 'put').mockResolvedValue(nginxDocument())
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [override] = (put.mock.calls[0]?.[2] as NginxConfiguration).overrides
    expect(override).toEqual(expect.objectContaining({ scope: 'node', scope_id: nodeA }))
    expect(override!.values).toEqual({
      worker: { worker_rlimit_nofile: 100_000, worker_shutdown_timeout_ms: 30_000, worker_connections: 8_192, worker_processes: 0 },
      http: {
        gzip_comp_level: 6, gzip_http_version: '1.0', gzip_min_length_bytes: 2_048, gzip_vary: true, server_addr_outgoing: false,
        proxy_request_buffering: true, proxy_buffering: true, proxy_cache_max_size_bytes: 200 * 2 ** 30, proxy_cache_min_free_bytes: 10 * 2 ** 30,
        proxy_cache_methods: ['GET'], proxy_http_version: '1.1', proxy_max_temp_file_size_bytes: 0,
        proxy_next_upstream: ['error', 'timeout', 'http_502'], proxy_connect_timeout_ms: 10_000, proxy_send_timeout_ms: 120_000,
        proxy_read_timeout_ms: 180_000, server: 'edge', client_max_body_size_bytes: 200 * 2 ** 20, default_type: 'application/octet-stream',
        keepalive_requests: 500, keepalive_timeout_ms: 30_000, log_not_found: true, server_tokens: false,
        large_client_header_buffers: { count: 8, size_bytes: 16_384 }, server_names_hash_max_size: 8_192, server_names_hash_bucket_size: 128,
      },
    })
  })

  it.each([
    ['域名哈希表大小（server_names_hash_max_size）', '5000'],
    ['域名哈希桶大小（server_names_hash_bucket_size）', '100'],
    ['大请求头缓冲区（large_client_header_buffers）', '64 8k'],
    ['大请求头缓冲区（large_client_header_buffers）', '4 512'],
    ['Server 响应头（server）', '<edge>'],
    ['默认 MIME 类型（default_type）', 'plain'],
    ['缓存最小剩余空间（min_free）', '1000k'],
  ])('与服务端一致地拒绝 %s = %s', async (label, value) => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 0, data: [] })
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node(nodeA, 'edge-a', '10.0.0.1', '101')] })
    const user = userEvent.setup()
    renderWithProviders(<SystemSettingsPage />)
    const dialog = await openAddDialog(user)
    await chooseNode(user, dialog, 'edge-a (10.0.0.1) #101')
    await chooseSetting(dialog, label)
    const box = within(dialog).getByRole('textbox', { name: label })
    await user.clear(box)
    await user.type(box, value)
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('设置值无效，请检查格式和范围。')).toBeInTheDocument()
  })

  it('off 不能与其它回源重试条件同时选择', async () => {
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 0, data: [] })
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node(nodeA, 'edge-a', '10.0.0.1', '101')] })
    const user = userEvent.setup()
    renderWithProviders(<SystemSettingsPage />)
    const dialog = await openAddDialog(user)
    await chooseNode(user, dialog, 'edge-a (10.0.0.1) #101')
    await chooseSetting(dialog, '回源失败重试条件（proxy_next_upstream）')
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: '回源失败重试条件（proxy_next_upstream）' }))
    await user.click(await screen.findByText('off', { selector: '.ant-select-item-option-content' }))
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('设置值无效，请检查格式和范围。')).toBeInTheDocument()
  })

  it('英文界面显示英文名称与说明', async () => {
    await changeLocale('en-US')
    authenticate()
    vi.spyOn(systemConfigurationApi, 'get').mockResolvedValue(nginxDocument())
    vi.spyOn(regionsApi, 'list').mockResolvedValue({ count: 0, data: [] })
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [] })
    const user = userEvent.setup()
    renderWithProviders(<SystemSettingsPage />)
    await user.click(await screen.findByRole('tab', { name: 'Regional and node configuration' }))
    await user.click(screen.getByRole('button', { name: 'Add setting' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(dialog).getByRole('combobox', { name: 'Configuration items' }))
    fireEvent.click(await screen.findByText('Worker processes (worker_processes)', { selector: '.ant-select-item-option-content' }))
    expect(within(dialog).getByText('Enter auto to match CPU cores, or an integer from 1 to 256.')).toBeInTheDocument()
  })
})
