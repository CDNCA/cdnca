import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'

import { ApiError } from '../api/auth'
import { notificationsApi, type NotificationDeliveryPolicy } from '../api/notifications'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import NotificationDeliveryPolicyPanel from './NotificationDeliveryPolicyPanel'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const policy: NotificationDeliveryPolicy = {
  schema: 'cdnca.notification-delivery-policy/v1', window_mode: 'all_day',
  window_start: '00:00', window_end: '23:59', timezone: 'Asia/Shanghai', revision: 4, changed: false,
  events: [
    { event_type: 'announcement.published', enabled: true, sms_enabled: false, email_enabled: true, repeat_count: 1, interval_hours: 24, supported: true },
    { event_type: 'certificate.expired', enabled: false, sms_enabled: false, email_enabled: false, repeat_count: 1, interval_hours: 24, supported: false },
  ],
}

function authenticate(token = 'policy-token', permissions = ['system_configuration.read', 'system_configuration.manage'], update: 'new' | 'refresh' = 'new') {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor, update)
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((next) => { resolve = next })
  return { promise, resolve }
}

async function openEvents() {
  const user = userEvent.setup()
  await user.click(await screen.findByRole('button', { name: '全部展开' }))
  return user
}

describe('NotificationDeliveryPolicyPanel', () => {
  it('renders only server events, exposes unsupported facts, and expands/collapses all groups', async () => {
    authenticate()
    const read = vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    expect(await screen.findByRole('radio', { name: '全天' })).toBeChecked()
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveAttribute('aria-expanded', 'false')
    const user = await openEvents()
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveTextContent('公告发布通知已开启邮件')
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveTextContent('邮件 / 短信')
    await user.click(screen.getByRole('switch', { name: '公告发布 开关' }))
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveTextContent('已关闭')
    await user.click(screen.getByRole('checkbox', { name: '公告发布 邮件' }))
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveTextContent('未选择通知渠道')
    expect(screen.getByRole('button', { name: /证书已过期/ })).not.toHaveTextContent('已开启')
    expect(screen.getByRole('switch', { name: '证书已过期 开关' })).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: '证书已过期 邮件' })).toBeDisabled()
    expect(screen.getByText('该事件尚未接入通知发送，当前配置不可启用。')).toBeInTheDocument()
    expect(screen.queryByText('二次实名')).not.toBeInTheDocument()
    expect(read).toHaveBeenCalledWith('policy-token')
    await user.click(screen.getByRole('button', { name: '全部收起' }))
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveAttribute('aria-expanded', 'false')
  })

  it('saves custom hours and event switches/counts with the original revision, then reads persisted changes', async () => {
    authenticate()
    const saved = { ...policy, window_mode: 'custom' as const, window_start: '08:00', window_end: '22:00', revision: 5, changed: true,
      events: [{ ...policy.events[0], enabled: false, sms_enabled: true, repeat_count: 3, interval_hours: 6 }, policy.events[1]] }
    const read = vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValueOnce(policy).mockResolvedValue(saved)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockResolvedValue(saved)
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('radio', { name: '自定义' }).closest('label')!)
    expect(screen.getByRole('textbox', { name: '通知时间段' })).toHaveValue('8-22')
    await user.click(screen.getByRole('switch', { name: '公告发布 开关' }))
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    fireEvent.change(screen.getByRole('spinbutton', { name: '公告发布 连续通知次数' }), { target: { value: '3' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '公告发布 间隔小时' }), { target: { value: '6' } })
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    await screen.findByText('通知策略已保存')
    expect(put).toHaveBeenCalledWith('policy-token', {
      window_mode: 'custom', window_start: '08:00', window_end: '22:00', timezone: 'Asia/Shanghai', events: saved.events,
    }, 4, expect.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/))
    await user.click(screen.getByRole('button', { name: '刷新策略' }))
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('textbox', { name: '通知时间段' })).toHaveValue('8-22')
    expect(screen.getByText('修订版本 5')).toBeInTheDocument()
  })

  it('rejects invalid custom windows and empty counts before any write, preserving supported event values', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy')
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('radio', { name: '自定义' }).closest('label')!)
    fireEvent.change(screen.getByRole('textbox', { name: '通知时间段' }), { target: { value: '25-29' } })
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    expect(screen.getByText('请输入有效的时间段，例如 8-22 或 08:30-22:15。')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: '通知时间段' }), { target: { value: '08:30-22:15' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: '公告发布 连续通知次数' }), { target: { value: '' } })
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    expect(screen.getByText('连续通知次数须为 1–10 的整数，间隔小时须为 1–168 的整数。')).toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()
  })

  // fix-fielderr-be5：服务端按提交顺序拒绝 events[n].interval_hours 时标在该事件的间隔小时框下（展开该事件），不出通用错误条；再编辑即清
  it('marks a refused event field under its control and clears it on the next edit', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-policy'), { field: 'events[0].interval_hours', reason: 'out_of_range' }))
    const user = userEvent.setup()
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await user.click(await screen.findByRole('radio', { name: '自定义' }).then((radio) => radio.closest('label')!))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const help = await screen.findByText('间隔小时：超出允许的范围')
    expect(help).toHaveAttribute('role', 'alert')
    const interval = screen.getByRole('spinbutton', { name: '公告发布 间隔小时' })
    expect(interval.closest('.ant-input-number-group-wrapper, .ant-input-number')).toHaveClass(/status-error/)
    expect(screen.getByRole('button', { name: /公告发布/ })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.queryByText('通知策略字段无效，请检查后重试。')).not.toBeInTheDocument()
    fireEvent.change(interval, { target: { value: '12' } })
    expect(screen.queryByText('间隔小时：超出允许的范围')).not.toBeInTheDocument()
  })

  it('marks a refused custom window under the window box', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-policy'), { field: 'window_end', reason: 'invalid_format' }))
    const user = userEvent.setup()
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await user.click(await screen.findByRole('radio', { name: '自定义' }).then((radio) => radio.closest('label')!))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    expect(await screen.findByText('格式不正确')).toHaveAttribute('role', 'alert')
    expect(screen.getByRole('textbox', { name: '通知时间段' }).closest('.ant-input, .ant-input-affix-wrapper')).toHaveClass(/status-error/)
  })

  it('locks uncertain outcomes and retries the identical body, revision and request key with a refreshed session token', async () => {
    authenticate('old-token')
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const saved = { ...policy, revision: 5, changed: true, events: [{ ...policy.events[0], sms_enabled: true }, policy.events[1]] }
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockRejectedValueOnce(new ApiError('private network detail', 0, 'network_error')).mockResolvedValue(saved)
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    expect(await screen.findByText('保存结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '公告发布 短信' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存通知策略' })).toBeDisabled()
    expect(screen.queryByText('private network detail')).not.toBeInTheDocument()
    act(() => authenticate('fresh-token', undefined, 'refresh'))
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await screen.findByText('通知策略已保存')
    expect(put.mock.calls[1]?.slice(1)).toEqual(put.mock.calls[0]?.slice(1))
    expect(put.mock.calls[1]?.[0]).toBe('fresh-token')
  })

  it('drops an uncertain draft only through close and refresh and reloads the actual policy', async () => {
    authenticate()
    const read = vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockRejectedValue(new ApiError('upstream details', 503, 'notification_unavailable'))
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    await user.click(await screen.findByRole('button', { name: '关闭并刷新' }))
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2))
    expect(screen.getByRole('checkbox', { name: '公告发布 短信' })).not.toBeChecked()
    expect(screen.queryByText('保存结果待确认')).not.toBeInTheDocument()
    expect(put).toHaveBeenCalledTimes(1)
  })

  it('requires a refresh after CAS conflict without offering an uncertain retry', async () => {
    authenticate()
    const read = vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValueOnce(policy).mockResolvedValue({ ...policy, revision: 9 })
    vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockRejectedValue(new ApiError('private conflict', 409, 'version_conflict'))
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    await screen.findByText('通知策略版本已变化，请刷新后重新编辑。')
    expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存通知策略' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '刷新策略' }))
    await screen.findByText('修订版本 9')
    expect(read).toHaveBeenCalledTimes(2)
  })

  it('renders translated read failures and recovers by refresh without exposing the server error', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockRejectedValueOnce(new ApiError('private database error', 500, 'internal_error')).mockResolvedValue(policy)
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    expect(await screen.findByText('通知策略加载失败，请刷新重试。')).toBeInTheDocument()
    expect(screen.queryByText('private database error')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '刷新策略' }))
    expect(await screen.findByRole('radio', { name: '全天' })).toBeChecked()
  })

  it('does not call the API without read permission and keeps read-only policy controls disabled', async () => {
    authenticate('read-only', [])
    const read = vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy')
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    expect(screen.getByText('无权访问通知策略')).toBeInTheDocument()
    expect(read).not.toHaveBeenCalled()
    act(() => authenticate('read-only', ['system_configuration.read']))
    await openEvents()
    expect(screen.getByRole('checkbox', { name: '公告发布 短信' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存通知策略' })).toBeDisabled()
    expect(put).not.toHaveBeenCalled()
  })

  it('isolates stale writes and drafts when changing sessions and never stores tokens in query keys or mutation attempts', async () => {
    authenticate('actor-a-token')
    const pending = deferred<NotificationDeliveryPolicy>()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockReturnValue(pending.promise)
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    render(<QueryClientProvider client={client}><NotificationDeliveryPolicyPanel /></QueryClientProvider>)
    const user = await openEvents()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const evidence = JSON.stringify({ queries: client.getQueryCache().getAll().map((q) => q.queryKey), variables: client.getMutationCache().getAll().map((m) => m.state.variables) })
    expect(evidence).not.toContain('actor-a-token')
    act(() => authenticate('actor-b-token'))
    await openEvents()
    expect(screen.getByRole('checkbox', { name: '公告发布 短信' })).not.toBeChecked()
    await act(async () => pending.resolve({ ...policy, revision: 5, changed: true, events: [{ ...policy.events[0], sms_enabled: true }, policy.events[1]] }))
    expect(screen.getByRole('checkbox', { name: '公告发布 短信' })).not.toBeChecked()
    expect(screen.queryByText('通知策略已保存')).not.toBeInTheDocument()
    expect(screen.getByText('修订版本 4')).toBeInTheDocument()
  })

  it('keeps an unknown outcome unwriteable after manage permission is revoked in the same epoch', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockRejectedValue(new ApiError('network', 0, 'network_error'))
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    await screen.findByText('保存结果待确认', { selector: OUTCOME_BAR })
    act(() => authenticate('new-token', ['system_configuration.read'], 'refresh'))
    expect(screen.getByRole('button', { name: '使用同一请求重试' })).toBeDisabled()
    expect(put).toHaveBeenCalledTimes(1)
  })

  it.each([['en-US', 'Notification window', 'Announcement published'], ['zh-TW', '通知時間段', '公告發布']] as const)('uses %s resources without raw event names for known events', async (locale, windowLabel, eventLabel) => {
    await changeLocale(locale)
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const region = await screen.findByTestId('notification-delivery-policy')
    expect(await within(region).findByText(windowLabel)).toBeInTheDocument()
    expect(within(region).getByRole('button', { name: new RegExp(eventLabel) })).toBeInTheDocument()
    expect(region).not.toHaveTextContent('announcement.published')
  })
})

describe('notification policy HTTP contract and time boundaries', () => {
  it('retries an unknown HTTP outcome with byte-identical JSON and request metadata', async () => {
    authenticate()
    const requests: { body: string; revision: string | null; requestID: string | null }[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method !== 'PUT') return new Response(JSON.stringify(policy), { status: 200 })
      const headers = new Headers(init.headers)
      requests.push({ body: String(init.body), revision: headers.get('If-Match'), requestID: headers.get('X-Request-ID') })
      if (requests.length === 1) throw new TypeError('network lost after commit')
      return new Response(JSON.stringify({ ...JSON.parse(String(init.body)), schema: policy.schema, revision: 5, changed: true }), { status: 200 })
    })
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    await user.click(screen.getByRole('button', { name: '保存通知策略' }))
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await screen.findByText('通知策略已保存')
    expect(requests).toHaveLength(2)
    expect(requests[1]).toEqual(requests[0])
    expect(requests[0].revision).toBe('"4"')
    expect(requests[0].requestID).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
  })

  it.each([['22-8', '22:00', '08:00'], ['8:30-22:15', '08:30', '22:15']] as const)('persists custom window %s without losing minute or overnight semantics', async (input, start, end) => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockImplementation(async (_token, value) => ({ ...value, schema: policy.schema, revision: 5, changed: true }))
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await screen.findByRole('radio', { name: '自定义' })
    await userEvent.click(screen.getByRole('radio', { name: '自定义' }).closest('label')!)
    fireEvent.change(screen.getByRole('textbox', { name: '通知时间段' }), { target: { value: input } })
    await userEvent.click(screen.getByRole('button', { name: '保存通知策略' }))
    await screen.findByText('通知策略已保存')
    expect(put).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ window_start: start, window_end: end, events: policy.events }), 4, expect.any(String))
  })

  it('saves the canonical all-day bounds when switching from a custom window', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue({ ...policy, window_mode: 'custom', window_start: '08:30', window_end: '22:15' })
    const put = vi.spyOn(notificationsApi, 'putDeliveryPolicy').mockImplementation(async (_token, value) => ({ ...value, schema: policy.schema, revision: 5, changed: true }))
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await userEvent.click((await screen.findByRole('radio', { name: '全天' })).closest('label')!)
    await userEvent.click(screen.getByRole('button', { name: '保存通知策略' }))
    await screen.findByText('通知策略已保存')
    expect(put).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ window_mode: 'all_day', window_start: '00:00', window_end: '23:59' }), 4, expect.any(String))
  })

  it('shows an empty policy without inventing event rows or permitting a write', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue({ ...policy, events: [] })
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await screen.findByText('暂无通知事件')
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存通知策略' })).toBeDisabled()
  })

  it('keeps drafts through a refresh of the same session but discards them after logout', async () => {
    authenticate('old-token')
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue(policy)
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    const user = await openEvents()
    await user.click(screen.getByRole('checkbox', { name: '公告发布 短信' }))
    act(() => authenticate('fresh-token', undefined, 'refresh'))
    expect(screen.getByRole('checkbox', { name: '公告发布 短信' })).toBeChecked()
    act(() => useSessionStore.getState().clearSession())
    expect(screen.queryByTestId('notification-delivery-policy')).not.toBeInTheDocument()
    act(() => authenticate('new-login-token'))
    await openEvents()
    expect(screen.getByRole('checkbox', { name: '公告发布 短信' })).not.toBeChecked()
  })

  it('names aggregated edge schedule alerts and dnspup probe pauses', async () => {
    authenticate()
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue({ ...policy, events: [
      { event_type: 'aggregated_edge.schedule.alert', enabled: true, sms_enabled: false, email_enabled: true, repeat_count: 1, interval_hours: 24, supported: true },
      { event_type: 'probe.dnspup.degraded', enabled: true, sms_enabled: false, email_enabled: true, repeat_count: 1, interval_hours: 24, supported: true },
      { event_type: 'node.security.waf_ban', enabled: true, sms_enabled: true, email_enabled: true, repeat_count: 1, interval_hours: 24, supported: true },
    ] })
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await openEvents()
    expect(screen.getByRole('switch', { name: '聚合边缘调度告警 开关' })).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'dnspup 拨测暂停 开关' })).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'WAF 自动封禁（同 IP 超阈值拉黑） 开关' })).toBeInTheDocument()
    expect(screen.queryByText(/其它通知事件/)).not.toBeInTheDocument()
  })

  it('names every node market notice kind (ML-17/20/23/27/31, direct top-ups, deposits)', async () => {
    authenticate()
    const kinds = [
      'market.downstream.attacked',
      'market.complaint.resolved',
      'market.complaint.actioned',
      'market.node.action',
      'market.site.paused',
      'market.site.resumed',
      'market.commission.low',
      'market.commission.exhausted',
      'market.commission.restored',
      'market.supply.outage',
      'market.supply.restored',
      'market.supply.cancel_available',
      'market.direct_topup.paid',
      'market.direct_topup.received',
      'market.seller.deposit_mode',
      'market.seller.deposit_shortfall',
      'market.seller.default_compensated',
      'market.seller.defaulted',
    ]
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue({ ...policy, events: kinds.map((event_type) => (
      { event_type, enabled: true, sms_enabled: false, email_enabled: true, repeat_count: 1, interval_hours: 24, supported: true })) })
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await openEvents()
    expect(screen.getAllByRole('switch', { name: /^节点市场：.+ 开关$/ })).toHaveLength(kinds.length)
    expect(screen.getByRole('switch', { name: '节点市场：抽成预付余额已用完 开关' })).toBeInTheDocument()
    expect(screen.queryByText(/其它通知事件/)).not.toBeInTheDocument()
  })

  it('names origin failover, direct top-up rejection and migrated account events', async () => {
    authenticate()
    const kinds = ['site.origin.failover', 'site.origin.recovered', 'payment.market_topup.rejected', 'identity.migrated_account']
    vi.spyOn(notificationsApi, 'getDeliveryPolicy').mockResolvedValue({ ...policy, events: kinds.map((event_type) => (
      { event_type, enabled: true, sms_enabled: false, email_enabled: true, repeat_count: 1, interval_hours: 24, supported: true })) })
    renderWithProviders(<NotificationDeliveryPolicyPanel />)
    await openEvents()
    for (const name of ['回源级别自动切换', '源站已恢复（可手动切回）', '直结充值到账报告被市场拒收', '账号已迁移到新平台']) {
      expect(screen.getByRole('switch', { name: `${name} 开关` })).toBeInTheDocument()
    }
    expect(screen.queryByText(/其它通知事件/)).not.toBeInTheDocument()
  })
})
