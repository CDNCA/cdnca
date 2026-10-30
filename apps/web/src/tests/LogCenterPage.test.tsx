import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { auditLogQuery, auditLogsApi, type AuditLogItem } from '../api/auditLogs'
import { systemCleanupSettingsApi, type PlatformSystemCleanupDocument } from '../api/systemCleanupSettings'
import { useSessionStore } from '../auth/session'
import LogCenterPage from '../pages/LogCenterPage'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const item: AuditLogItem = {
  id: '01920000-0000-7000-8000-000000000001', occurred_at: '2026-10-18T01:00:00Z', time: '2026-10-18 09:00:00',
  category: 'security', category_label: '防御策略', action: 'firewall.policy.put', catalogued: true,
  actor: '管理员 root', actor_kind: 'user', source_ip: '203.0.113.7', scope_id: '01920000-0000-7000-8000-0000000000aa',
  resource_type: 'site', resource_id: 's1', resource: 'example.com', result: 'success', result_label: '成功',
  request_id: 'req-1', summary: '管理员 root 于 2026-10-18 09:00:00 从 203.0.113.7 修改网站 example.com 的防火墙策略：CC 防护从「关闭」改为「开启」',
  changes: [{ field: 'cc_enabled', label: 'CC 防护', before: '关闭', after: '开启' }], fields: [],
}

function signIn(kind: 'platform' | 'tenant') {
  const actor = principal(kind === 'platform'
    ? { scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['platform.admin', 'system_configuration.read', 'system_configuration.manage'] }
    : { permissions: ['identity.self.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

afterEach(() => vi.restoreAllMocks())

describe('LogCenterPage', () => {
  // TEL-UX-EXPORT-OWNER：导出迟到时已换账号，旧文件不下载、也不提示"已导出"。
  it('drops a late audit export after the account changed (TEL-UX-EXPORT-OWNER)', async () => {
    signIn('platform')
    vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [item] })
    let finish!: (blob: Blob) => void
    const exportSpy = vi.spyOn(auditLogsApi, 'export').mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const createURL = vi.fn(() => 'blob:x')
    Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: vi.fn() })
    const user = userEvent.setup()
    renderWithProviders(<LogCenterPage />)
    await user.click(await screen.findByRole('button', { name: '导出 CSV' }))
    await waitFor(() => expect(exportSpy).toHaveBeenCalled())
    expect(exportSpy.mock.calls[0]![2]?.signal).toBeInstanceOf(AbortSignal)
    const other = principal({ scope_kind: 'platform', tenant_id: null, user_id: '44444444-4444-4444-8444-444444444444', permissions: ['platform.admin'] })
    useSessionStore.getState().setSession(authResponse(other), other)
    finish(new Blob(['a,b'], { type: 'text/csv' }))
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(createURL).not.toHaveBeenCalled()
    expect(screen.queryByText('已导出')).not.toBeInTheDocument()
  })

  it('lists server-rendered sentences per category and opens the change detail', async () => {
    signIn('tenant')
    const list = vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [item] })
    renderWithProviders(<LogCenterPage />)
    expect(await screen.findByText(item.summary)).toBeInTheDocument()
    expect(list.mock.calls[0][1]).toMatchObject({ category: 'all', limit: 50 })
    expect(screen.queryByRole('textbox', { name: '租户范围 ID' })).not.toBeInTheDocument()

    const user = userEvent.setup()
    // log-merge: categories moved from tabs into the 操作 tab's category filter.
    await user.click(screen.getByRole('tab', { name: '登录与安全' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ category: 'auth' }))

    await user.click(screen.getAllByRole('button', { name: '查看' })[0])
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('CC 防护')).toBeInTheDocument()
    expect(within(drawer).getByText('开启')).toBeInTheDocument()
    expect(within(drawer).getByText('firewall.policy.put')).toBeInTheDocument()
    // W1: the object shows the resolved name, the raw ID stays as a hover hint.
    expect(within(drawer).getByText('site example.com')).toHaveAttribute('title', 's1')
    expect(within(drawer).queryByText('site s1')).not.toBeInTheDocument()
  })

  it('applies filters, offers the scope filter to platform admins and shows the attack and access logs in place', async () => {
    signIn('platform')
    const list = vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [], next_cursor: 'c2' })
    renderWithProviders(<LogCenterPage />)
    const user = userEvent.setup()
    // fix-advfilter4：1440 宽下查询/重置/高级筛选与常显条件同一行——常显只留 时间范围、操作人；来源 IP、结果、租户范围 ID 收进高级筛选。
    const toggle = await screen.findByRole('button', { name: '高级筛选' })
    const panel = document.getElementById(toggle.getAttribute('aria-controls')!)!
    expect(panel).not.toContainElement(screen.getByRole('textbox', { name: '操作人用户名' }))
    expect(panel).toContainElement(screen.getByRole('textbox', { name: '来源 IP', hidden: true }))
    expect(panel).toContainElement(screen.getByRole('combobox', { name: '结果', hidden: true }))
    await user.type(screen.getByRole('textbox', { name: '操作人用户名' }), 'root')
    await user.click(toggle)
    expect(screen.getByRole('textbox', { name: '租户范围 ID' })).toBeInTheDocument()
    await user.type(screen.getByRole('textbox', { name: '来源 IP' }), '203.0.113.7')
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ sourceIp: '203.0.113.7', actor: 'root' }))
    expect(screen.getByRole('list', { name: '已启用的高级条件' })).toHaveTextContent('来源 IP：203.0.113.7')

    await user.click(screen.getByRole('button', { name: '下一页' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ cursor: 'c2' }))

    const calls = list.mock.calls.length
    // fix-ui1026 #5: the attack / access logs render inside the log center (same components as their own pages), no links out.
    await user.click(screen.getByRole('tab', { name: '攻击日志' }))
    const attack = await screen.findByTestId('log-center-attack')
    expect(await within(attack).findByRole('tab', { name: '安全概览' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '打开攻击日志' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '访问日志' }))
    const access = await screen.findByTestId('log-center-access')
    expect(await within(access).findByRole('region', { name: '访问日志' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '打开访问日志' })).not.toBeInTheDocument()
    expect(list.mock.calls.length).toBe(calls)
  })

  // fix-rangepicker：共享时间范围组件；默认不限时间，快捷项在查询时按当前时间取窗口。
  it('queries a quick range from the shared time range filter', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: new Date(2026, 9, 28, 10, 20) })
    signIn('tenant')
    const list = vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<LogCenterPage />)
    const user = userEvent.setup()
    const range = await screen.findByRole('group', { name: '时间' })
    expect(within(range).getByRole('radio', { name: '自定义' })).toBeChecked()
    // fix-rangecompact：快捷项统一为今天/近7天/近30天。
    await user.click(within(range).getByText('近7天'))
    await user.click(screen.getByRole('button', { name: '查询' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({
      since: new Date(2026, 9, 21, 10, 20).toISOString(), until: new Date(2026, 9, 28, 10, 20).toISOString(),
    }))
    vi.useRealTimers()
  })

  it('refuses users without log permission', async () => {
    const actor = principal({ permissions: [] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    renderWithProviders(<LogCenterPage />)
    expect(await screen.findByText('没有查看日志的权限')).toBeInTheDocument()
  })

  // u1b: a failed read is reported in place (reason in Chinese + request ID), not as an empty table.
  it('reports a failed read in place with the reason and request ID instead of the empty state', async () => {
    signIn('tenant')
    vi.spyOn(auditLogsApi, 'list').mockRejectedValue(new ApiError('bad', 400, 'audit_log_invalid_request', 'req-9'))
    renderWithProviders(<LogCenterPage />)
    const alert = await screen.findByTestId('log-center-error')
    expect(alert).toHaveTextContent('查询条件无效，请检查时间范围、IP 地址和对象 ID')
    expect(alert).toHaveTextContent('req-9')
    expect(screen.queryByText('没有符合条件的日志')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('falls back to a generic reason for unknown failures and still shows the request ID', async () => {
    signIn('tenant')
    vi.spyOn(auditLogsApi, 'list').mockRejectedValue(new ApiError('boom', 503, 'audit_log_unavailable', 'req-10'))
    renderWithProviders(<LogCenterPage />)
    const alert = await screen.findByTestId('log-center-error')
    expect(alert).toHaveTextContent('日志服务暂不可用，请稍后重试')
    expect(alert).toHaveTextContent('req-10')
  })
})

describe('auditLogQuery', () => {
  it('encodes filters and rejects bad values before calling the API', () => {
    expect(auditLogQuery({ category: 'finance', result: 'denied', sourceIp: ' 1.2.3.4 ', limit: 20, lang: 'en' }))
      .toBe('?category=finance&source_ip=1.2.3.4&result=denied&limit=20&lang=en')
    expect(auditLogQuery({ category: 'all' })).toBe('')
    expect(() => auditLogQuery({ category: 'misc' as never })).toThrow()
    expect(() => auditLogQuery({ scopeId: 'not-a-uuid' })).toThrow()
    expect(() => auditLogQuery({ since: '2026-10-18T02:00:00Z', until: '2026-10-18T01:00:00Z' })).toThrow()
    expect(() => auditLogQuery({ resourceId: 'a\nb' })).toThrow()
  })
})

describe('per-category retention in the cleanup settings', () => {
  it('shows one retention field per category and saves the edited value', async () => {
    signIn('platform')
    const document: PlatformSystemCleanupDocument = {
      schema: 'cdnca.platform-system-cleanup-settings/v1', revision: 2,
      value: {
        cleanup_cache_days: 30, access_logs_days: 7, node_metrics_days: 7, bandwidth_history_days: 90, blacklist_history_days: 7,
        node_traffic_history_days: 45,
        audit_retention_days: { admin: 365, user: 180, auth: 90, site: 180, security: 180, rule: 180, finance: 1095, package: 365, plugin: 180, node: 90, dns: 180, cert: 180, system: 365, other: 180 },
      },
    }
    vi.spyOn(systemCleanupSettingsApi, 'get').mockResolvedValue(document)
    const put = vi.spyOn(systemCleanupSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({ ...document, revision: revision + 1, value }))
    renderWithProviders(<SystemGlobalSettingsPage initialTab="cleanup" />)
    const section = await screen.findByTestId('system-settings-audit-retention')
    const auth = within(section).getByRole('spinbutton', { name: '登录与安全' })
    expect(auth).toHaveValue('90')
    expect(within(section).getByRole('spinbutton', { name: '财务' })).toHaveValue('1095')
    const user = userEvent.setup()
    await user.clear(auth)
    await user.type(auth, '30')
    await user.click(screen.getByRole('button', { name: /保存/ }))
    await waitFor(() => expect(put).toHaveBeenCalled())
    expect(put.mock.calls[0][2].audit_retention_days).toMatchObject({ auth: 30, finance: 1095 })
    expect(put.mock.calls[0][2]).not.toHaveProperty('login_records_days')
  })
})
