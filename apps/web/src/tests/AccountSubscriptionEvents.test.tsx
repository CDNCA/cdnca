import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import AccountSubscriptionsPage from '../pages/AccountSubscriptionsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const subscription = (event_type: string, revision = 0, supported = { sms: true, email: true }) => ({ event_type, sms_enabled: false, email_enabled: false,
  sms_supported: supported.sms, email_supported: supported.email, revision, changed: false })

afterEach(() => vi.unstubAllGlobals())

// fix-notifsub：公告与其余事件在"更多消息类型"折叠区里，默认收起。
async function openMore() {
  fireEvent.click(await screen.findByRole('button', { name: /更多消息类型/ }))
  return screen.findByRole('table', { name: /更多消息类型/ })
}

// tp-b7：原"套餐与工单通知"卡并进消息订阅表，公告是第一行，套餐/证书/工单事件逐行跟在后面，
// 列是手机提醒 / 邮件提醒两个开关，切换即保存，请求体与原卡相同。
describe('AccountSubscriptionsPage event rows', () => {
  it('lists announcement, package, certificate and ticket events in one table and saves one checkbox with the current revision', async () => {
    const user = principal({})
    useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      if (init?.method === 'PUT') return json({ ...subscription(event, 1), email_enabled: true, changed: true })
      return json(subscription(event))
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    await screen.findByRole('checkbox', { name: '证书到期 邮件提醒' })
    expect(screen.getAllByRole('table')).toHaveLength(1)
    for (const label of ['套餐到期', '流量超限', '防护规则切换', '带宽超限', '连接数超限', '证书到期']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
    expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['提醒类型', '手机提醒', '邮件提醒'])
    // 主表 6 个消息类型；公告 + 21 个租户事件各读一次。
    expect(screen.getAllByRole('row')).toHaveLength(1 + 6)
    expect(fetchMock.mock.calls.filter(([, i]) => !i?.method)).toHaveLength(22)
    expect(screen.queryByText('套餐与工单通知')).not.toBeInTheDocument()
    expect(screen.getByText('提醒项').parentElement).toHaveTextContent('提醒项 6')
    const more = await openMore()
    for (const label of ['公告发布', '工单已提交', '工单状态变化', '自动续费失败', '自动续费成功', 'WAF 自动排除已生效', 'WAF 自动排除已撤销', 'WAF 自动排除已到期']) {
      expect(within(more).getByText(label)).toBeInTheDocument()
    }
    expect(within(more).getByText(/网站攻击告警/)).toBeInTheDocument()
    expect(within(more).getAllByRole('row')).toHaveLength(1 + 10)
    const email = screen.getByRole('checkbox', { name: '客服回复 邮件提醒' })
    fireEvent.click(email)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/v1/account/notification-subscriptions/ticket.replied', expect.objectContaining({ method: 'PUT' })))
    const [, init] = fetchMock.mock.calls.find(([, i]) => i?.method === 'PUT')!
    expect(JSON.parse(init!.body as string)).toEqual({ sms_enabled: false, email_enabled: true })
    expect(new Headers(init!.headers).get('If-Match')).toBe('"0"')
    await waitFor(() => expect(email).toBeChecked())
    // 计数胶囊只统计主表的 6 个消息类型。
    expect(screen.getByText('邮件开启').parentElement).toHaveTextContent('邮件开启 0')
  })

  // fix-ticket2（546）：服务端为工单事件给出 inbox_enabled 时多一列站内信；只有工单行有开关，
  // 切换邮件时把当前站内信值一起带上，切换站内信只改站内信。
  it('shows the in-app column for ticket events and keeps it on email writes', async () => {
    const user = principal({})
    useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      const base = { ...subscription(event), ...(event.startsWith('ticket.') ? { inbox_enabled: true } : {}) }
      if (init?.method === 'PUT') return json({ ...base, ...JSON.parse(init.body as string), revision: 1, changed: true })
      return json(base)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    await screen.findByRole('checkbox', { name: '流量超限 邮件提醒' })
    // 主表没有工单事件，不出站内信列。
    expect(screen.getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['提醒类型', '手机提醒', '邮件提醒'])
    const more = await openMore()
    const inbox = screen.getByRole('checkbox', { name: '客服回复 站内信' })
    expect(inbox).toBeChecked()
    expect(within(more).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['提醒类型', '手机提醒', '邮件提醒', '站内信'])
    expect(within(within(more).getByText('自动续费失败').closest('tr')!).getAllByRole('checkbox')).toHaveLength(2)
    fireEvent.click(screen.getByRole('checkbox', { name: '客服回复 邮件提醒' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([, i]) => i?.method === 'PUT')).toBe(true))
    const [, first] = fetchMock.mock.calls.find(([, i]) => i?.method === 'PUT')!
    expect(JSON.parse(first!.body as string)).toEqual({ sms_enabled: false, email_enabled: true, inbox_enabled: true })
  })

  // vis-2：平台没开通的渠道整列隐藏；只要有一行支持某渠道，该列就显示，不支持的行留空不放假开关。
  it('hides a channel column no row supports and leaves unsupported cells empty', async () => {
    const user = principal({})
    useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      return json(subscription(event, 0, { sms: false, email: event !== 'ticket.created' }))
    }))
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    await openMore()
    await screen.findByRole('checkbox', { name: '客服回复 邮件提醒' })
    expect(screen.queryByRole('columnheader', { name: '手机提醒' })).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: /手机提醒/ })).not.toBeInTheDocument()
    expect(screen.queryByText('手机开启')).not.toBeInTheDocument()
    const row = screen.getByText('工单已提交').closest('tr')!
    expect(within(row).queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('shows only the operator ticket events after the announcement to a platform member who works tickets', async () => {
    const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['tickets.manage'] })
    useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'sub-token' }, admin)
    const fetchMock = vi.fn(async (path: string) => json({ ...subscription(decodeURIComponent(path.split('/').pop()!)),
      email_enabled: true }))
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    expect(await screen.findByRole('checkbox', { name: '有新工单 邮件提醒' })).toBeChecked()
    expect(screen.getByText('用户回复了工单')).toBeInTheDocument()
    expect(screen.queryByText('流量超限')).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([path]) => path).sort()).toEqual([
      '/v1/account/notification-subscriptions/announcement.published',
      '/v1/account/notification-subscriptions/ticket.staff.created',
      '/v1/account/notification-subscriptions/ticket.staff.overdue',
      '/v1/account/notification-subscriptions/ticket.staff.replied',
    ])
  })

  it('reads only the announcement row for a platform member without ticket permission', async () => {
    const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['custom'], permissions: ['sites.read'] })
    useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'sub-token' }, admin)
    const fetchMock = vi.fn(async (path: string) => json(subscription(decodeURIComponent(path.split('/').pop()!))))
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    expect(await screen.findByRole('checkbox', { name: '公告发布 邮件提醒' })).toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual(['/v1/account/notification-subscriptions/announcement.published'])
  })

  // notif-sub A8：22 个事件读取最多同时 4 个。
  it('reads the event rows at most four at a time', async () => {
    const user = principal({})
    useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
    let active = 0
    let peak = 0
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      if (event === 'announcement.published') return json(subscription(event))
      active += 1
      peak = Math.max(peak, active)
      await new Promise((resolve) => setTimeout(resolve, 5))
      active -= 1
      return json(subscription(event))
    }))
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    await openMore()
    await screen.findByRole('checkbox', { name: '工单状态变化 邮件提醒' })
    await waitFor(() => expect(screen.getAllByRole('checkbox', { name: /邮件提醒/ })).toHaveLength(6 + 10))
    expect(peak).toBeGreaterThan(1)
    expect(peak).toBeLessThanOrEqual(4)
  })

  // notif-sub A7：读取失败的行不消失，显示是哪一项失败并可单项重试；重试成功后恢复开关。
  it('keeps a failed row with its own error and retry, and restores it once the read succeeds', async () => {
    const user = principal({})
    useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
    let failing = true
    const fetchMock = vi.fn(async (path: string) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      if (event === 'ticket.replied' && failing) {
        return json({ error: { code: 'internal_error', message: 'internal_error', request_id: 'r-1' } }, 500)
      }
      return json(subscription(event))
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    const more = await openMore()
    const retry = await screen.findByRole('button', { name: '客服回复 重试' }, { timeout: 4000 })
    const row = screen.getByText('客服回复').closest('tr')!
    expect(within(row).getByText(/读取失败（internal_error）/)).toBeInTheDocument()
    expect(within(row).queryByRole('checkbox')).not.toBeInTheDocument()
    expect(within(more).getAllByRole('row')).toHaveLength(1 + 10)
    // 一次自动重试：失败事件共读 2 次。
    expect(fetchMock.mock.calls.filter(([path]) => String(path).endsWith('/ticket.replied'))).toHaveLength(2)
    failing = false
    fireEvent.click(retry)
    expect(await screen.findByRole('checkbox', { name: '客服回复 邮件提醒' })).toBeInTheDocument()
    expect(within(screen.getByText('客服回复').closest('tr')!).queryByText(/读取失败/)).not.toBeInTheDocument()
  })

  it('does not retry a deterministic refusal of one row', async () => {
    const user = principal({})
    useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
    const fetchMock = vi.fn(async (path: string) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      if (event === 'ticket.replied') return json({ error: { code: 'notification_not_found', message: 'x', request_id: 'r-2' } }, 404)
      return json(subscription(event))
    })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    await openMore()
    expect(await screen.findByRole('button', { name: '客服回复 重试' })).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([path]) => String(path).endsWith('/ticket.replied'))).toHaveLength(1)
  })

  // 原请求暂时 500、自动重试成功：不用点击就恢复显示，也不留错误。
  it('recovers a row on its own after a transient failure', async () => {
    const user = principal({})
    useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
    let failures = 1
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      const event = decodeURIComponent(path.split('/').pop()!)
      if (event === 'certificate.expired' && failures > 0) {
        failures -= 1
        return json({ error: { code: 'internal_error', message: 'internal_error', request_id: 'r-3' } }, 500)
      }
      return json(subscription(event))
    }))
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    // 证书已过期属于"证书到期"一组：组内全部读到后该行才出开关。
    expect(await screen.findByRole('checkbox', { name: '证书到期 邮件提醒' }, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.queryByText(/读取失败/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /重试/ })).not.toBeInTheDocument()
  })
})
