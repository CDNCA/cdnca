import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { backupHistoryApi } from '../api/backupHistory'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { systemLogMessage } from '../i18n/systemLog'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import SystemBackupLogPanel from './SystemBackupLogPanel'

const emptyPage = { schema: 'cdnca.control-backup-history/v1' as const, items: [], total_count: 0, snapshot_at: '2026-09-28T10:00:00Z' }

beforeEach(async () => {
  await changeLocale('zh-CN')
  const reader = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['platform.admin'] })
  useSessionStore.getState().setSession(authResponse(reader), reader)
  vi.spyOn(backupHistoryApi, 'list').mockResolvedValue(emptyPage)
})

it('renders the four signed-history columns and shows an unknown terminal outcome in details', async () => {
  vi.mocked(backupHistoryApi.list).mockResolvedValue({
    ...emptyPage,
    items: [{ backup_id: 'run-unknown', started_at: '2026-09-28T09:00:00Z', state: 'unknown', result_code: 'backup_outcome_unknown', outcome_unknown: true, signature_valid: true, terminal_state: 'unavailable', reason_code: 'terminal_unavailable' }],
    total_count: 1,
  })
  renderWithProviders(<SystemBackupLogPanel />)
  expect(await screen.findByText('终态未记录')).toBeInTheDocument()
  expect(screen.getAllByRole('columnheader').map((header) => header.textContent)).toEqual(['备份时间', '完成时间', '状态', '结果'])
  expect(screen.getByText('未记录')).toBeInTheDocument()
  expect(screen.getByText('结果未知')).toBeInTheDocument()
  expect(screen.getByText('终态未记录')).toBeInTheDocument()
  await userEvent.setup().click(screen.getByRole('button', { name: '查看详情' }))
  const dialog = within(screen.getByRole('dialog', { name: '备份详情' }))
  expect(dialog.getByText('run-unknown')).toBeInTheDocument()
  expect(dialog.getByText('终态未记录')).toBeInTheDocument()
  expect(dialog.getByText('尚未取得可验证的结束记录')).toBeInTheDocument()
  expect(dialog.queryByText('terminal_unavailable')).not.toBeInTheDocument()
})

it('matches the competitor header with only refresh and cursor paging, without extra filters', async () => {
  const user = userEvent.setup()
  vi.mocked(backupHistoryApi.list).mockResolvedValue({
    ...emptyPage, total_count: 20, next_cursor: 'cursor-1',
    items: [{ backup_id: 'run-done', started_at: '2026-09-28T09:00:00Z', completed_at: '2026-09-28T09:00:09Z', state: 'succeeded', result_code: 'backup_succeeded', outcome_unknown: false, signature_valid: true, terminal_state: 'succeeded', reason_code: 'terminal_recorded' }],
  })
  renderWithProviders(<SystemBackupLogPanel />)
  expect(await screen.findByText('已完成')).toBeInTheDocument()
  expect(screen.getByText('备份日志')).toBeInTheDocument()
  expect(screen.getByText('共 20 条记录，当前页 1 条')).toBeInTheDocument()
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  expect(screen.queryByRole('combobox', { name: '所有状态' })).not.toBeInTheDocument()
  expect(backupHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), { limit: 10, cursor: undefined })
  await user.click(screen.getByRole('button', { name: '2' }))
  await waitFor(() => expect(backupHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ cursor: 'cursor-1' })))
  await user.click(screen.getByRole('button', { name: '刷新' }))
  await waitFor(() => expect(backupHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), { limit: 10, cursor: undefined }))
})

it('distinguishes unavailable history from ordinary loading failures', async () => {
  vi.mocked(backupHistoryApi.list).mockRejectedValueOnce(new ApiError('API request failed', 503, 'backup_history_unavailable'))
  renderWithProviders(<SystemBackupLogPanel />)
  // Load failures open the shared feedback dialog (FeedbackWhen) instead of an in-page Alert.
  expect(await screen.findByRole('dialog')).toHaveTextContent('备份历史暂不可用')

  vi.mocked(backupHistoryApi.list).mockRejectedValueOnce(new ApiError('API request failed', 500, 'request_failed'))
  fireEvent.click(screen.getAllByRole('button', { name: '刷新' })[0])
  expect(await screen.findByRole('dialog')).toHaveTextContent('备份历史加载失败')
})

it.each([
  ['zh-CN', '备份时间'], ['zh-TW', '備份時間'], ['en-US', 'Backup time'],
] as const)('localizes backup-history labels in %s', async (locale, column) => {
  await changeLocale(locale)
  renderWithProviders(<SystemBackupLogPanel />)
  expect(screen.getByRole('columnheader', { name: column })).toBeInTheDocument()
  expect(systemLogMessage(locale, 'backupStateUnknown')).not.toBe('backupStateUnknown')
})

it('does not request history for a tenant principal', async () => {
  const tenant = principal({ scope_kind: 'tenant', tenant_id: '11111111-1111-4111-8111-111111111111', permissions: ['platform.admin'] })
  useSessionStore.getState().setSession(authResponse(tenant), tenant)
  renderWithProviders(<SystemBackupLogPanel />)
  expect(screen.getByRole('alert')).toHaveTextContent('没有备份历史查看权限')
  expect(backupHistoryApi.list).not.toHaveBeenCalled()
})

it.each([
  ['zh-CN', '查看详情', '备份详情', '成功', '已取得可验证的结束记录', '备份成功'],
  ['zh-TW', '查看詳情', '備份詳情', '成功', '已取得可驗證的結束記錄', '備份成功'],
  ['en-US', 'View details', 'Backup details', 'Succeeded', 'A verified completion record is available', 'Backup succeeded'],
] as const)('localizes recorded result, reason, and terminal state in %s', async (locale, open, title, state, reason, result) => {
  await changeLocale(locale)
  vi.mocked(backupHistoryApi.list).mockResolvedValue({
    ...emptyPage,
    items: [{ backup_id: 'run-finished', state: 'succeeded', result_code: 'backup_succeeded', outcome_unknown: false, signature_valid: true, terminal_state: 'succeeded', reason_code: 'terminal_recorded' }],
    total_count: 1,
  })
  renderWithProviders(<SystemBackupLogPanel />)
  await userEvent.setup().click(await screen.findByRole('button', { name: open }))
  const dialog = within(screen.getByRole('dialog', { name: title }))
  expect(dialog.getAllByText(state)).toHaveLength(2)
  expect(dialog.getByText(reason)).toBeInTheDocument()
  expect(dialog.getByText(result)).toBeInTheDocument()
  expect(dialog.queryByText('terminal_recorded')).not.toBeInTheDocument()
  expect(dialog.queryByText('succeeded')).not.toBeInTheDocument()
  expect(dialog.queryByText(/backup_succeeded/)).not.toBeInTheDocument()
})

it('labels future codes as unrecognized without inventing their meaning', async () => {
  vi.mocked(backupHistoryApi.list).mockResolvedValue({
    ...emptyPage,
    items: [{ backup_id: 'run-new-code', state: 'unknown', result_code: 'future_result', outcome_unknown: false, signature_valid: true, terminal_state: 'future_terminal', reason_code: 'future_reason' }],
    total_count: 1,
  })
  renderWithProviders(<SystemBackupLogPanel />)
  await userEvent.setup().click(await screen.findByRole('button', { name: '查看详情' }))
  const dialog = within(screen.getByRole('dialog', { name: '备份详情' }))
  for (const code of ['future_result', 'future_reason', 'future_terminal']) {
    expect(dialog.getByText(`未识别的记录代码（${code}）`)).toBeInTheDocument()
  }
})

it('keeps the final page count and supports back navigation', async () => {
  vi.mocked(backupHistoryApi.list).mockImplementation(async (_token, filters) => ({
    ...emptyPage, total_count: 11, next_cursor: filters.cursor ? undefined : 'cursor-1',
  }))
  const user = userEvent.setup()
  renderWithProviders(<SystemBackupLogPanel />)
  await waitFor(() => expect(screen.getByRole('button', { name: '下一页' })).toBeEnabled())
  await user.click(screen.getByRole('button', { name: '下一页' }))
  await waitFor(() => expect(screen.getByRole('button', { name: '2' })).toHaveAttribute('aria-current', 'page'))
  expect(screen.getByText('共 11 条')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: '上一页' }))
  await waitFor(() => expect(screen.getByRole('button', { name: '1' })).toHaveAttribute('aria-current', 'page'))
})


it('offers the observed 10, 30, 100, and 300 row sizes and requests the selected size', async () => {
  renderWithProviders(<SystemBackupLogPanel />)
  const user = userEvent.setup()
  await user.click(screen.getByRole('combobox', { name: '条/页' }))
  expect(screen.getAllByText(/^(10|30|100|300) 条\/页$/, { selector: '.ant-select-item-option-content' }).map((option) => option.textContent)).toEqual(['10 条/页', '30 条/页', '100 条/页', '300 条/页'])
  await user.click(screen.getByText('300 条/页', { selector: '.ant-select-item-option-content' }))
  await waitFor(() => expect(backupHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ limit: 300, cursor: undefined })))
})

// fix-flags2 E4: a control plane with no backup runner answers an empty page
// flagged unconfigured; the table says so instead of "no backup logs" or 503.
it('explains an unconfigured backup target instead of an outage', async () => {
  vi.mocked(backupHistoryApi.list).mockResolvedValue({ ...emptyPage, unconfigured: true })
  renderWithProviders(<SystemBackupLogPanel />)
  expect(await screen.findByText('尚未配置备份目标，没有历史')).toBeInTheDocument()
  expect(screen.queryByText('暂无备份日志')).not.toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
