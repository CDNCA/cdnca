import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { onlineManager } from '@tanstack/react-query'
import { useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { observabilityLogsApi, type ObservabilityLogFact } from '../api/observabilityLogs'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import AccountLogPage from './AccountLogPage'

const loginFacts: ObservabilityLogFact[] = [
  {
    event_id: 'login-2', occurred_at: '2026-10-24T18:37:44Z', kind: 'login', actor_user_id: '33333333-3333-4333-8333-333333333333',
    action: 'auth.login', reason_code: 'credentials_accepted', result_code: 'success', source_ip: '203.0.113.61',
    user_agent: 'Mozilla/5.0 (Macintosh) Chrome/141.0', geo_code: 'CN', geo_region: '山东省', geo_city: '潍坊市', geo_resolution: 'matched',
  },
  {
    event_id: 'login-1', occurred_at: '2026-10-24T10:00:00Z', kind: 'login', action: 'auth.login', reason_code: 'credentials_rejected',
    result_code: 'denied', source_ip: '127.0.0.1', user_agent: 'unknown', geo_code: 'unknown',
  },
]

const operationFacts: ObservabilityLogFact[] = [
  {
    event_id: 'op-1', occurred_at: '2026-10-24T12:44:30Z', kind: 'operation', actor_user_id: '33333333-3333-4333-8333-333333333333',
    action: 'site.update', reason_code: 'site.update', result_code: 'success', resource_type: 'site', resource_id: '1',
    source_ip: '111.201.0.113', geo_code: 'CN', geo_region: '北京市', geo_city: '北京市', category: 'site', change_summary: '{}',
    resource_name: 'www.example.com', user_agent: 'Mozilla/5.0 (Windows NT 10.0) Firefox/144.0',
  },
  {
    event_id: 'op-2', occurred_at: '2026-10-24T12:40:00Z', kind: 'operation', action: 'site.delete', reason_code: 'site.delete',
    result_code: 'success', resource_type: 'site', resource_id: '7f3c2a1b-0000-4000-8000-000000000001', resource_deleted: true,
    source_ip: '111.201.0.114', geo_code: 'unknown', category: 'site',
  },
  {
    event_id: 'op-3', occurred_at: '2026-10-24T12:30:00Z', kind: 'operation', action: 'package_product.update', reason_code: 'package_product.update',
    result_code: 'success', resource_type: 'package_product', resource_id: 'pkg-42', source_ip: '111.201.0.115', geo_code: 'unknown', category: 'package',
  },
]

function signIn() {
  const actor = principal({ permissions: ['identity.self.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

beforeEach(() => {
  vi.spyOn(observabilityLogsApi, 'list').mockImplementation(async (_token, filters) => ({
    items: filters.kinds?.[0] === 'operation' ? operationFacts : loginFacts,
    total_count: filters.kinds?.[0] === 'operation' ? operationFacts.length : loginFacts.length,
    snapshot_at: '2026-10-25T00:00:00Z',
  }))
})

describe('AccountLogPage', () => {
  it('shows the login log first with the expected columns, UA and 国家-省-市 location', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log'])

    const page = await screen.findByTestId('account-log-page')
    expect(within(page).getByRole('tab', { name: '登录日志' })).toHaveAttribute('aria-selected', 'true')
    expect(within(page).getByRole('tab', { name: '操作日志' })).toHaveAttribute('aria-selected', 'false')
    expect(await within(page).findByText('中国-山东省-潍坊市')).toBeInTheDocument()
    expect(within(page).getAllByRole('columnheader').map((header) => header.textContent)).toEqual(['IP地址', '地理位置', '浏览器UA', '登录时间', '登录状态'])
    expect(within(page).getByText('Mozilla/5.0 (Macintosh) Chrome/141.0')).toBeInTheDocument()
    // IP 库没命中：地区显示 —；UA 是 unknown 时也显示 —。
    const deniedRow = within(page).getByText('127.0.0.1').closest('tr')!
    expect(within(deniedRow).getAllByText('—')).toHaveLength(2)
    expect(within(deniedRow).getByText('失败')).toBeInTheDocument()
    expect(within(page).getByText('共 2 条')).toBeInTheDocument()
    expect(within(page).getByPlaceholderText('请输入IP地址')).toBeInTheDocument()
    expect(observabilityLogsApi.list).toHaveBeenCalledWith('memory-only-access-token', expect.objectContaining({ kinds: ['login'], limit: 10 }))
  })

  it('switches to the operation log with category/object, action, change, UA, IP/location and time columns', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    await screen.findByText('中国-山东省-潍坊市')

    fireEvent.click(screen.getByRole('tab', { name: '操作日志' }))

    expect(await screen.findByText('中国-北京市-北京市')).toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map((header) => header.textContent)).toEqual(['类别/对象', '动作', '变更内容', '浏览器UA', 'IP/位置', '操作时间'])
    expect(screen.getAllByText('网站配置')).toHaveLength(2)
    // 对象列：名称；已删除显示 ID 前 8 位；不可反查的类型显示原 ID。浏览器UA：真实值，缺失显示 —。
    const named = screen.getByText('111.201.0.113').closest('tr')!
    expect(within(named).getByText('www.example.com')).toBeInTheDocument()
    expect(within(named).getByText('Mozilla/5.0 (Windows NT 10.0) Firefox/144.0')).toBeInTheDocument()
    expect(within(named).getByText('无变更内容')).toBeInTheDocument()
    expect(within(named).getByText('更新')).toBeInTheDocument()
    const deleted = screen.getByText('111.201.0.114').closest('tr')!
    expect(within(deleted).getByText('已删除的对象（7f3c2a1b）')).toBeInTheDocument()
    expect(within(deleted).getAllByText('—').length).toBeGreaterThanOrEqual(2)
    expect(within(screen.getByText('111.201.0.115').closest('tr')!).getByText('pkg-42')).toBeInTheDocument()
    expect(screen.getByText('共 3 条')).toBeInTheDocument()
    expect(observabilityLogsApi.list).toHaveBeenLastCalledWith('memory-only-access-token', expect.objectContaining({ kinds: ['operation'] }))

    const list = vi.mocked(observabilityLogsApi.list)
    list.mockClear()
    // 1440 宽下查询/高级筛选与常显条件同一行——常显 时间、IP；动作、分类、对象、变更内容收进「高级筛选」。
    const panel = document.getElementById(screen.getByRole('button', { name: '高级筛选' }).getAttribute('aria-controls')!)!
    expect(panel).not.toContainElement(screen.getByLabelText('IP地址'))
    expect(panel).toContainElement(screen.getByRole('combobox', { name: '动作', hidden: true }))
    expect(panel).toContainElement(screen.getByLabelText('对象'))
    expect(screen.getByLabelText('对象')).not.toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: '高级筛选' }))
    fireEvent.change(screen.getByLabelText('对象'), { target: { value: 'example.com' } })
    // A4：改条件不发请求，点「查询」才发。
    expect(list).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({
      kinds: ['operation'], resourceId: 'example.com', cursor: undefined,
    })))
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()
    expect(screen.getByRole('list', { name: '已启用的高级条件' })).toHaveTextContent('对象：example.com')
    fireEvent.click(screen.getByRole('button', { name: '移除条件 对象' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ kinds: ['operation'], resourceId: undefined }))
    expect(screen.getByLabelText('对象')).toHaveValue('')

    // 动作在高级筛选里，选后查询带 actionVerb，标签 × 清除再查。
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '动作' }))
    fireEvent.click(await screen.findByText('删除', { selector: '.ant-select-item-option-content' }))
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ kinds: ['operation'], actionVerb: 'delete' }))
    expect(screen.getByRole('list', { name: '已启用的高级条件' })).toHaveTextContent('动作：删除')
    fireEvent.click(screen.getByRole('button', { name: '移除条件 动作' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ kinds: ['operation'], actionVerb: undefined }))
  })

  // A3：非法 IP 就地报错、不发请求；回车与点「查询」同义。
  it('A3: rejects an invalid IP next to the field without sending a request, Enter submits a valid one', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    await screen.findByText('中国-山东省-潍坊市')
    const list = vi.mocked(observabilityLogsApi.list)
    list.mockClear()

    const ip = screen.getByLabelText('IP地址')
    fireEvent.change(ip, { target: { value: 'not-an-ip' } })
    fireEvent.click(screen.getByRole('button', { name: '查询' }))
    expect(await screen.findByText('请输入正确的 IP 地址，例如 203.0.113.7')).toBeInTheDocument()
    expect(ip).toHaveAttribute('aria-invalid', 'true')
    expect(list).not.toHaveBeenCalled()

    fireEvent.change(ip, { target: { value: '198.18.0.1' } })
    expect(screen.queryByText('请输入正确的 IP 地址，例如 203.0.113.7')).not.toBeInTheDocument()
    fireEvent.keyDown(ip, { key: 'Enter', code: 'Enter', keyCode: 13 })
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ kinds: ['login'], sourceIp: '198.18.0.1' })))
  })

  // A3/A6：后端拒绝原因码翻成中文并带请求编号，不显示「请稍后重试」，空表不冒充「暂无日志」。
  it('A3: shows the backend refusal in Chinese with the request ID instead of a retry message', async () => {
    signIn()
    vi.mocked(observabilityLogsApi.list).mockRejectedValue(new ApiError('bad', 400, 'observability_logs_invalid_request', 'req-1'))
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    const alert = await screen.findAllByText('查询条件无效，请检查 IP 地址和时间范围（请求 ID：req-1）')
    expect(alert.length).toBeGreaterThan(0)
    expect(screen.queryByText('暂无日志')).not.toBeInTheDocument()
    expect(screen.queryByText('日志加载失败，请稍后重试。')).not.toBeInTheDocument()
  })

  it('returns 403 without identity.self.read', () => {
    const actor = principal({ permissions: [] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    expect(screen.getByText('403')).toBeInTheDocument()
    expect(observabilityLogsApi.list).not.toHaveBeenCalled()
  })

  // SEC-ACCOUNT-10: 「发信」标签；后端按本人限定，发信区分服务商已接受与已送达。「备份」标签的数据只来自已删的
  // 旧高危操作中心，该中心已删除。
  it('SEC-ACCOUNT-10: shows the notification tab scoped to its kind and no backup tab', async () => {
    signIn()
    vi.mocked(observabilityLogsApi.list).mockImplementation(async (_token, filters) => ({
      items: filters.kinds?.[0] === 'notification' ? [
        { event_id: 'n-1', occurred_at: '2026-10-24T12:00:00Z', kind: 'notification', action: 'notification.provider_accepted',
          reason_code: 'notification.provider_accepted', result_code: 'accepted', source_ip: 'unknown', geo_code: 'unknown' },
        { event_id: 'n-2', occurred_at: '2026-10-24T11:00:00Z', kind: 'notification', action: 'notification.delivered',
          reason_code: 'notification.delivered', result_code: 'delivered', source_ip: 'unknown', geo_code: 'unknown' },
      ] : [],
      total_count: filters.kinds?.[0] === 'notification' ? 2 : 0,
      snapshot_at: '2026-10-25T00:00:00Z',
    }))
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    expect(await screen.findByRole('tab', { name: '消息发送' })).toBeInTheDocument()
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual(['登录日志', '操作日志', '消息发送'])

    fireEvent.click(screen.getByRole('tab', { name: '消息发送' }))
    await waitFor(() => expect(observabilityLogsApi.list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ kinds: ['notification'] })))
    expect(await screen.findByText('服务商已接受')).toBeInTheDocument()
    expect(screen.getByText('已接受')).toBeInTheDocument()
    expect(screen.getByText('已送达')).toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map((header) => header.textContent)).toEqual(['操作', '结果', '对象', '时间'])
  })
  // 活动 tabpanel 内含对应表格，不另起外部表
  it('renders each log table inside its active tabpanel', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    const loginTab = await screen.findByRole('tab', { name: '登录日志' })
    const loginPanel = document.getElementById(loginTab.getAttribute('aria-controls')!)!
    expect(loginPanel).toHaveAttribute('role', 'tabpanel')
    expect(await within(loginPanel).findByText('中国-山东省-潍坊市')).toBeInTheDocument()
    expect(within(loginPanel).getByRole('table')).toBeInTheDocument()
    expect(screen.getAllByRole('table')).toHaveLength(1)

    fireEvent.click(screen.getByRole('tab', { name: '操作日志' }))
    const operationTab = screen.getByRole('tab', { name: '操作日志' })
    const operationPanel = document.getElementById(operationTab.getAttribute('aria-controls')!)!
    expect(operationPanel).toHaveAttribute('role', 'tabpanel')
    expect(await within(operationPanel).findByText('www.example.com')).toBeInTheDocument()
    expect(screen.getAllByRole('table')).toHaveLength(1)
    expect(document.querySelectorAll('[role="tabpanel"]').length).toBeGreaterThan(0)
    for (const panel of document.querySelectorAll('[role="tabpanel"]')) {
      if (panel !== operationPanel) expect(panel.querySelector('table')).toBeNull()
    }
  })

  // dispatching 显示「发送中」，accepted 不升级为已送达，未知码仍回退
  it('labels dispatching notifications as sending and keeps unknown codes unknown', async () => {
    signIn()
    vi.mocked(observabilityLogsApi.list).mockImplementation(async (_token, filters) => ({
      items: filters.kinds?.[0] === 'notification' ? [
        { event_id: 'n-1', occurred_at: '2026-10-24T12:00:00Z', kind: 'notification', action: 'notification.dispatch_started',
          reason_code: 'notification.dispatch_started', result_code: 'dispatching', source_ip: 'unknown', geo_code: 'unknown' },
        { event_id: 'n-2', occurred_at: '2026-10-24T11:00:00Z', kind: 'notification', action: 'notification.provider_accepted',
          reason_code: 'notification.provider_accepted', result_code: 'accepted', source_ip: 'unknown', geo_code: 'unknown' },
        { event_id: 'n-3', occurred_at: '2026-10-24T10:00:00Z', kind: 'notification', action: 'notification.provider_accepted',
          reason_code: 'notification.provider_accepted', result_code: 'brand_new_code', source_ip: 'unknown', geo_code: 'unknown' },
      ] : [],
      total_count: filters.kinds?.[0] === 'notification' ? 3 : 0,
      snapshot_at: '2026-10-25T00:00:00Z',
    }))
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    fireEvent.click(await screen.findByRole('tab', { name: '消息发送' }))
    const sending = await screen.findByText('发送中')
    expect(sending.closest('.ant-tag')).toHaveClass('ant-tag-processing')
    expect(screen.getByText('已接受').closest('.ant-tag')).toHaveClass('ant-tag-processing')
    expect(screen.queryByText('已送达')).not.toBeInTheDocument()
    expect(screen.getByText('未知结果').closest('.ant-tag')).toHaveClass('ant-tag-error')
  })
})

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.search}</output>
}

// 日志查询的默认范围、页签与范围进 URL、操作日志默认不列会话续期、即时筛选不显示「应用」、离线等待网络。
describe('AccountLogPage filters', () => {
  it('selects 近30天 for the default 30-day query', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    await screen.findByText('中国-山东省-潍坊市')
    expect(screen.getByRole('radio', { name: '近30天' })).toBeChecked()
    expect(screen.getByRole('radio', { name: '自定义' })).not.toBeChecked()
    const filters = vi.mocked(observabilityLogsApi.list).mock.calls[0]![1]
    expect(Date.now() - Date.parse(filters.from!)).toBeLessThanOrEqual(31 * 24 * 3600 * 1000)
    expect(screen.getByTestId('account-log-page')).toBeInTheDocument()
  })

  it('keeps the tab and the applied range in the URL and reads them back', async () => {
    signIn()
    const view = renderWithProviders(<><AccountLogPage /><LocationProbe /></>, ['/account/log?keep=1'])
    await screen.findByText('中国-山东省-潍坊市')
    expect(screen.getByTestId('location').textContent).toBe('?keep=1')
    fireEvent.click(screen.getByRole('tab', { name: '消息发送' }))
    await waitFor(() => expect(screen.getByTestId('location').textContent).toBe('?keep=1&tab=notification'))
    fireEvent.click(screen.getByRole('radio', { name: '近7天' }))
    await waitFor(() => expect(new URLSearchParams(screen.getByTestId('location').textContent!).get('range')).toBe('last7d'))
    const search = screen.getByTestId('location').textContent!
    view.unmount()

    vi.mocked(observabilityLogsApi.list).mockClear()
    renderWithProviders(<AccountLogPage />, [`/account/log${search}`])
    expect(await screen.findByRole('tab', { name: '消息发送' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('radio', { name: '近7天' })).toBeChecked()
    await waitFor(() => expect(observabilityLogsApi.list).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ kinds: ['notification'] })))
    view.unmount()
  })

  it('falls back to the login tab and the default range for unknown URL values', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log?tab=backup&range=last90d'])
    expect(await screen.findByRole('tab', { name: '登录日志' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('radio', { name: '近30天' })).toBeChecked()
  })

  it('hides session renewals by default, no 应用', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log?tab=operation'])
    await screen.findByText('中国-北京市-北京市')
    const list = vi.mocked(observabilityLogsApi.list)
    expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ kinds: ['operation'], hideSessionRefresh: true })
    const toggle = screen.getByRole('button', { name: '高级筛选' })
    if (toggle.getAttribute('aria-expanded') !== 'true') fireEvent.click(toggle)
    const panel = screen.getByRole('group', { name: '高级筛选' })
    expect(within(panel).queryByRole('button', { name: '应用' })).toBeNull()
    fireEvent.click(within(panel).getByRole('checkbox', { name: '显示会话续期' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ kinds: ['operation'], hideSessionRefresh: undefined }))
    expect(screen.getByRole('list', { name: '已启用的高级条件' })).toHaveTextContent('会话续期：显示')
    fireEvent.click(screen.getByRole('button', { name: '移除条件 会话续期' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ hideSessionRefresh: true }))
  })

  it('marks a paused search as waiting for the network', async () => {
    signIn()
    renderWithProviders(<AccountLogPage />, ['/account/log'])
    await screen.findByText('中国-山东省-潍坊市')
    try {
      act(() => onlineManager.setOnline(false))
      fireEvent.click(screen.getByRole('button', { name: '查询' }))
      expect(await screen.findByRole('status')).toHaveTextContent('等待网络连接，恢复后自动查询')
      act(() => onlineManager.setOnline(true))
      await waitFor(() => expect(screen.queryByText('等待网络连接，恢复后自动查询')).toBeNull())
    } finally {
      onlineManager.setOnline(true)
    }
  })
})
