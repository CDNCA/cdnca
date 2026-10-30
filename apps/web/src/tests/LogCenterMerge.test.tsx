import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { auditLogQuery, auditLogsApi, type AuditLogItem } from '../api/auditLogs'
import { backupHistoryApi } from '../api/backupHistory'
import { notificationHistoryApi } from '../api/notificationHistory'
import { useSessionStore } from '../auth/session'
import LogCenterPage from '../pages/LogCenterPage'
import { getDeclaredPaths, getNavigation } from '../routes/navigation'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 系统日志 merged into 日志中心.

const operation: AuditLogItem = {
  id: '01920000-0000-7000-8000-000000000011', occurred_at: '2026-10-25T01:00:00Z', time: '2026-10-25 09:00:00',
  category: 'site', category_label: '网站配置', action: 'site.update', catalogued: true,
  actor: '用户 alice', actor_kind: 'user', source_ip: '203.0.113.7', scope_id: '01920000-0000-7000-8000-0000000000aa',
  resource_type: 'site', resource_id: '01920000-0000-7000-8000-0000000000b1', resource: 'alpha.example.test',
  tenant_name: 'Tenant Alpha', actor_username: 'alice', user_agent: 'Mozilla/5.0 (Operation)',
  geo_code: 'CN', geo_region: '山东省', geo_city: '潍坊市',
  result: 'success', result_label: '成功', request_id: 'r1', summary: '用户 alice 修改网站 alpha.example.test 的配置', changes: [], fields: [],
}
const deleted: AuditLogItem = {
  ...operation, id: '01920000-0000-7000-8000-000000000012', resource_id: '9f8e7d6c-0000-7000-8000-0000000000b2',
  resource: '9f8e7d6c-0000-7000-8000-0000000000b2', resource_deleted: true, tenant_name: undefined, actor_username: 'root',
  user_agent: undefined, geo_code: undefined, geo_region: undefined, geo_city: undefined, summary: '管理员 root 修改网站',
}

function signInAdmin() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['platform.admin', 'system_configuration.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

beforeEach(() => signInAdmin())
afterEach(() => vi.restoreAllMocks())

describe('log center after the system-log merge', () => {
  it('orders the tabs 全部 / 登录与安全 / 操作 / 备份 / 发送记录 / 攻击日志 / 访问日志', async () => {
    vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<LogCenterPage />)
    const tabs = await screen.findAllByRole('tab')
    expect(tabs.map((tab) => tab.textContent)).toEqual(['全部', '登录与安全', '操作', '备份', '发送记录', '攻击日志', '访问日志'])
  })

  it('shows tenant, username, object name, 国家-省-市 and UA, and marks deleted objects', async () => {
    vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [operation, deleted] })
    renderWithProviders(<LogCenterPage />)
    const table = within(await screen.findByRole('table'))
    // redesign-a：租户并入「操作人」列次行，对象并入「内容」列次行，地理位置/UA 并入「来源」列。
    for (const header of ['操作人', '内容', '来源']) {
      expect(table.getByRole('columnheader', { name: header })).toBeInTheDocument()
    }
    await table.findByText('Tenant Alpha')
    for (const text of ['alice', '中国-山东省-潍坊市', 'Mozilla/5.0 (Operation)', '平台', 'root', '已删除的对象（9f8e7d6c）']) {
      expect(table.getByText(text)).toBeInTheDocument()
    }
    expect(table.getByText('alpha.example.test')).toHaveAttribute('title', operation.resource_id)
  })

  it('filters 登录与安全 by auth and 操作 by every other category or the chosen one', async () => {
    const list = vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [operation] })
    renderWithProviders(<LogCenterPage />)
    const user = userEvent.setup()
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ category: 'all', excludeCategory: undefined }))

    await user.click(screen.getByRole('tab', { name: '登录与安全' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ category: 'auth' }))

    await user.click(screen.getByRole('tab', { name: '操作' }))
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ category: undefined, excludeCategory: 'auth' }))
    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    await user.click(screen.getByRole('combobox', { name: '所有分类' }))
    const option = (label: string) => screen.queryByText(label, { selector: '.ant-select-item-option-content' })
    expect(await screen.findByText('财务', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(option('登录与安全')).not.toBeInTheDocument()
    await user.click(option('财务')!)
    await waitFor(() => expect(list.mock.calls.at(-1)?.[1]).toMatchObject({ category: 'finance', excludeCategory: undefined }))
    expect(auditLogQuery({ excludeCategory: 'auth' })).toBe('?exclude_category=auth')
    expect(() => auditLogQuery({ excludeCategory: 'misc' as never })).toThrow()
  })

  it('moves 备份 and 发送记录 over with their own data sources', async () => {
    const list = vi.spyOn(auditLogsApi, 'list').mockResolvedValue({ items: [] })
    const backups = vi.spyOn(backupHistoryApi, 'list').mockResolvedValue({
      items: [{ backup_id: 'run-merged', started_at: '2026-10-25T01:00:00Z', completed_at: '2026-10-25T01:05:00Z', state: 'succeeded', result_code: 'backup_succeeded', outcome_unknown: false, signature_valid: true, terminal_state: 'recorded', reason_code: 'terminal_recorded' }],
      total_count: 1, unconfigured: false,
    } as Awaited<ReturnType<typeof backupHistoryApi.list>>)
    const sent = vi.spyOn(notificationHistoryApi, 'list').mockResolvedValue({ items: [], total_count: 0 } as unknown as Awaited<ReturnType<typeof notificationHistoryApi.list>>)
    renderWithProviders(<LogCenterPage />)
    const user = userEvent.setup()
    await waitFor(() => expect(list).toHaveBeenCalled())
    const auditCalls = list.mock.calls.length

    await user.click(screen.getByRole('tab', { name: '备份' }))
    expect(await screen.findByText('已完成')).toBeInTheDocument()
    expect(backups).toHaveBeenCalled()
    expect(screen.getByRole('columnheader', { name: '备份时间' })).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '发送记录' }))
    await waitFor(() => expect(sent).toHaveBeenCalled())
    expect(list.mock.calls.length).toBe(auditCalls)
  })

  it('removes 系统日志 from the admin menu and keeps 日志中心', () => {
    const system = getNavigation('admin', undefined, ['platform.admin']).find((item) => item.key === 'system')
    const keys = system?.children?.map((item) => item.key) ?? []
    expect(keys).toContain('/sys/log-center')
    expect(keys).not.toContain('/sys/log')
    expect(system?.children?.map((item) => item.label)).not.toContain('系统日志')
    expect(getDeclaredPaths()).not.toContain('/sys/log')
  })
})
