import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiError } from '../api/auth'
import { notificationHistoryApi, type NotificationHistoryFact, type NotificationHistoryPage } from '../api/notificationHistory'
import { useSessionStore } from '../auth/session'
import { changeLocale, type UserLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import SystemSentLogPanel from './SystemSentLogPanel'

// 加载/请求失败从页内 Alert 改为 FeedbackWhen 居中弹窗（.cdnca-feedback）
const findFeedback = () => waitFor(() => { const element = document.querySelector<HTMLElement>('.cdnca-feedback'); if (!element) throw new Error('no feedback dialog'); return element })

const outboxID = '11111111-1111-4111-8111-111111111111'
const messageID = '22222222-2222-4222-8222-222222222222'
const fact: NotificationHistoryFact = {
  id: `${outboxID}:2`, outbox_id: outboxID, scope_id: messageID, message_id: messageID, sequence: 2,
  attempt_number: 4, failure_count: 2, generation: 1, fact_kind: 'retry_scheduled', state: 'retry_wait',
  failure_code: 'dispatch_unavailable', observed_at: '2026-09-28T01:02:03Z', event_type: 'announcement.published',
  recipient_user_id: messageID, recipient_user_display_id: '15', recipient_kind: 'member', channel: 'email',
  replay_of_outbox_id: null, recipient_address: null, recipient_address_state: 'unavailable',
}
const page = (items: NotificationHistoryFact[] = []): NotificationHistoryPage => ({ schema: 'cdnca.notification-delivery-history/v1', items, total_count: items.length })

function setSession(permissions = ['system_configuration.read']) {
  const owner = principal({ scope_kind: 'platform', tenant_id: null, permissions })
  useSessionStore.getState().setSession(authResponse(owner), owner)
}

beforeEach(async () => {
  // 高级筛选的展开状态记在 localStorage，每个用例从收起开始。
  window.localStorage.removeItem('cdnca.advancedFilters.system-sent-log')
  await changeLocale('zh-CN')
  setSession()
  vi.spyOn(notificationHistoryApi, 'list').mockResolvedValue(page())
})

it('renders the eight reference columns from real history fields and labels unavailable snapshots', async () => {
  vi.mocked(notificationHistoryApi.list).mockResolvedValue(page([fact, {
    ...fact, id: `${outboxID}:3`, sequence: 3, recipient_user_id: null, recipient_user_display_id: null, recipient_kind: 'anonymous', failure_code: null,
  }]))
  renderWithProviders(<SystemSentLogPanel />)
  expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['收件人', '消息ID', '标题/内容', '媒介', '失败次数', '状态', '原因', '发送时间'])
  const row = await screen.findByText('用户 15')
  expect(within(row.closest('tr')!).getByText('2', { selector: 'td' })).toBeInTheDocument()
  expect(within(row.closest('tr')!).getByText('等待重试')).toBeInTheDocument()
  expect(within(row.closest('tr')!).getByText('发送服务暂不可用')).toBeInTheDocument()
  expect(screen.getByText('匿名收件人')).toBeInTheDocument()
  expect(screen.getAllByText('暂无历史快照')).toHaveLength(4)
  expect(screen.getAllByText(messageID)).toHaveLength(2)
})

it('never marks accepted, unknown, cancelled, or pending history as delivered', async () => {
  const states: NotificationHistoryFact['state'][] = ['delivered', 'accepted', 'unknown', 'cancelled', 'pending', 'retry_wait', 'permanent_failed', 'exhausted']
  vi.mocked(notificationHistoryApi.list).mockResolvedValue(page(states.map((state, index) => ({ ...fact, id: `${outboxID}:${index + 1}`, sequence: index + 1, state }))))
  const { container } = renderWithProviders(<SystemSentLogPanel />)
  await screen.findByText('供应商已接受')
  expect(container.querySelectorAll('.ant-tag-success')).toHaveLength(1)
  expect(container.querySelector('.ant-tag-success')).toHaveTextContent('已送达')
  expect(container.querySelectorAll('.ant-tag-error')).toHaveLength(3)
  expect(screen.getByText('结果待确认')).toBeInTheDocument()
  expect(screen.getByText('已取消')).toBeInTheDocument()
})

it('sends all five filters through canonical contracts and supports 300 rows per page', async () => {
  const user = userEvent.setup()
  renderWithProviders(<SystemSentLogPanel />)
  // fix-advfilter：用户ID、消息ID 收进「高级筛选」，常显 类型/媒介/状态。
  await user.click(screen.getByRole('button', { name: '高级筛选' }))
  fireEvent.change(screen.getByRole('textbox', { name: '用户ID' }), { target: { value: '15' } })
  fireEvent.change(screen.getByRole('textbox', { name: '消息ID' }), { target: { value: messageID } })
  await user.click(screen.getByRole('combobox', { name: '所有类型' }))
  // 2026-09-29 起类型筛选为业务事件（套餐/流量/证书等事件），不再有“公告”。
  await user.click(screen.getByText('套餐即将到期', { selector: '.ant-select-item-option-content' }))
  await user.click(screen.getByRole('combobox', { name: '所有媒介' }))
  await user.click(screen.getByText('短信', { selector: '.ant-select-item-option-content' }))
  await user.click(screen.getByRole('combobox', { name: '所有状态' }))
  await user.click(screen.getByText('失败', { selector: '.ant-select-item-option-content' }))
  await user.click(screen.getByRole('combobox', { name: '条/页' }))
  await user.click(screen.getByText('300 条/页', { selector: '.ant-select-item-option-content' }))
  await waitFor(() => expect(notificationHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({
    userID: '15', messageID, eventType: 'package-expiring', channel: 'sms', result: 'failure', limit: 300,
  }), expect.any(AbortSignal)))
  expect(vi.mocked(notificationHistoryApi.list).mock.lastCall?.[1]).not.toHaveProperty('from')
  await user.click(screen.getByRole('combobox', { name: '所有状态' }))
  await user.click(screen.getByText('所有状态', { selector: '.ant-select-item-option-content' }))
  await waitFor(() => expect(vi.mocked(notificationHistoryApi.list).mock.lastCall?.[1].result).toBeUndefined())
  // 已启用的高级条件以标签显示，× 去掉后立即按其余条件重查。
  expect(screen.getByRole('button', { name: '高级筛选 · 2' })).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '移除条件 用户ID' }))
  await waitFor(() => expect(vi.mocked(notificationHistoryApi.list).mock.lastCall?.[1]).toMatchObject({ userID: undefined, messageID, channel: 'sms' }))
  expect(screen.getByRole('textbox', { name: '用户ID' })).toHaveValue('')
})

it('rejects a display ID beyond the backend int64 range before requesting', async () => {
  renderWithProviders(<SystemSentLogPanel />)
  await waitFor(() => expect(notificationHistoryApi.list).toHaveBeenCalledOnce())
  fireEvent.click(screen.getByRole('button', { name: '高级筛选' }))
  fireEvent.change(screen.getByRole('textbox', { name: '用户ID' }), { target: { value: '9223372036854775808' } })
  expect(screen.getByRole('alert')).toHaveTextContent('请输入用户 ID')
  expect(notificationHistoryApi.list).toHaveBeenCalledOnce()
  fireEvent.change(screen.getByRole('textbox', { name: '用户ID' }), { target: { value: '9223372036854775807' } })
  await waitFor(() => expect(notificationHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ userID: '9223372036854775807' }), expect.any(AbortSignal)))
})

it('blocks invalid filters, hides previous rows, and resumes when corrected', async () => {
  vi.mocked(notificationHistoryApi.list).mockResolvedValue(page([fact]))
  renderWithProviders(<SystemSentLogPanel />)
  await screen.findByText('用户 15')
  vi.mocked(notificationHistoryApi.list).mockClear()
  fireEvent.click(screen.getByRole('button', { name: '高级筛选' }))
  fireEvent.change(screen.getByRole('textbox', { name: '消息ID' }), { target: { value: 'not-uuid' } })
  expect(screen.getByRole('alert')).toHaveTextContent('请输入规范的小写消息 UUID')
  expect(screen.queryByText('用户 15')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: '刷新' })).toBeDisabled()
  expect(notificationHistoryApi.list).not.toHaveBeenCalled()
  fireEvent.change(screen.getByRole('textbox', { name: '消息ID' }), { target: { value: messageID } })
  await screen.findByText('用户 15')
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it('follows only returned cursors and refreshes from the first page', async () => {
  const nextCursor = `${outboxID}:1`
  vi.mocked(notificationHistoryApi.list).mockImplementation(async (_token, filters) => ({
    ...page(filters.cursor ? [{ ...fact, recipient_user_display_id: '16' }] : [fact]), total_count: 50,
    ...(filters.cursor ? {} : { next_cursor: nextCursor }),
  }))
  renderWithProviders(<SystemSentLogPanel />)
  await screen.findByText('用户 15')
  expect(screen.getByRole('button', { name: '5' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: '下一页' }))
  await screen.findByText('用户 16')
  expect(notificationHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ cursor: nextCursor }), expect.any(AbortSignal))
  expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: '刷新' }))
  await screen.findByText('用户 15')
  expect(notificationHistoryApi.list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({ cursor: undefined }), expect.any(AbortSignal))
})

it('uses localized errors, hides rows after a failed refresh, and retries', async () => {
  vi.mocked(notificationHistoryApi.list).mockResolvedValueOnce(page([fact])).mockRejectedValueOnce(new ApiError('raw service detail', 503, 'unavailable')).mockResolvedValueOnce(page())
  renderWithProviders(<SystemSentLogPanel />)
  await screen.findByText('用户 15')
  fireEvent.click(screen.getByRole('button', { name: '刷新' }))
  expect(await findFeedback()).toHaveTextContent('发信日志加载失败，请刷新重试')
  expect(screen.queryByText('raw service detail')).not.toBeInTheDocument()
  expect(screen.queryByText('用户 15')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '刷新' }))
  await waitFor(() => expect(screen.queryByText('发信日志加载失败，请刷新重试')).not.toBeInTheDocument())
})

it('requires platform.admin or system configuration read permission', () => {
  setSession(['identity.self.read'])
  renderWithProviders(<SystemSentLogPanel />)
  expect(screen.getByRole('alert')).toHaveTextContent('没有发信日志查看权限')
  expect(notificationHistoryApi.list).not.toHaveBeenCalled()
})

it('accepts platform.admin without system configuration read permission', async () => {
  setSession(['platform.admin'])
  renderWithProviders(<SystemSentLogPanel />)
  await waitFor(() => expect(notificationHistoryApi.list).toHaveBeenCalled())
  expect(screen.queryByText('没有发信日志查看权限')).not.toBeInTheDocument()
})

it('removes old history immediately when read permission is revoked', async () => {
  vi.mocked(notificationHistoryApi.list).mockResolvedValue(page([fact]))
  renderWithProviders(<SystemSentLogPanel />)
  await screen.findByText('用户 15')
  act(() => setSession([]))
  expect(screen.queryByText('用户 15')).not.toBeInTheDocument()
  expect(screen.getByRole('alert')).toHaveTextContent('没有发信日志查看权限')
})

it.each<[UserLocale, string, string]>([
  ['zh-TW', '標題/內容', '暫無歷史快照'], ['en-US', 'Title/content', 'Historical snapshot unavailable'], ['qps-ploc', '［标~题~/~内~容~］', '［暂~无~历~史~快~照~］'],
])('renders the %s language resources without missing keys', async (locale, heading, unavailable) => {
  await changeLocale(locale)
  vi.mocked(notificationHistoryApi.list).mockResolvedValue(page([fact]))
  renderWithProviders(<SystemSentLogPanel />)
  expect(screen.getByRole('columnheader', { name: heading })).toBeInTheDocument()
  await waitFor(() => expect(screen.getAllByText(unavailable)).toHaveLength(2))
})


it('shows recorded masked contacts and distinguishes call time from record time', async () => {
  vi.mocked(notificationHistoryApi.list).mockResolvedValue(page([{ ...fact, recipient_address: 'm***@example.test', recipient_address_state: 'masked', provider_call_started_at: '2026-09-28T01:01:02Z' }]))
  renderWithProviders(<SystemSentLogPanel />)
  expect(await screen.findByText('m***@example.test')).toBeInTheDocument()
  expect(screen.getByText('2026/09/28 09:01:02')).toBeInTheDocument()
  expect(screen.getByText('记录时间：2026/09/28 09:02:03')).toBeInTheDocument()
  expect(screen.getAllByText('暂无历史快照')).toHaveLength(1)
})

it.each([
  ['zh-CN', '发送已取消', '发送结果尚未确认'],
  ['zh-TW', '發送已取消', '發送結果尚未確認'],
  ['en-US', 'Delivery cancelled', 'Delivery result not yet confirmed'],
] as const)('translates recorded cancellation and unknown delivery reasons in %s', async (locale, cancelled, unknown) => {
  await changeLocale(locale)
  vi.mocked(notificationHistoryApi.list).mockResolvedValue(page([{ ...fact, failure_code: 'cancelled' }, { ...fact, id: `${outboxID}:3`, sequence: 3, failure_code: 'provider_outcome_unknown' }]))
  renderWithProviders(<SystemSentLogPanel />)
  expect(await screen.findByText(cancelled)).toBeInTheDocument()
  expect(screen.getByText(unknown)).toBeInTheDocument()
})
