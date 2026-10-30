import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import AccountSubscriptionsPage from '../pages/AccountSubscriptionsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

type Row = { event_type: string; sms_enabled: boolean; email_enabled: boolean; sms_supported: boolean; email_supported: boolean; revision: number; changed: boolean }

// 服务端对从未设置的事件返回默认全开（revision 0）。
function server(options: { sms?: boolean; fail?: (event: string, method: string) => boolean } = {}) {
  const rows = new Map<string, Row>()
  const row = (event: string): Row => rows.get(event) ?? { event_type: event, sms_enabled: options.sms !== false, email_enabled: true,
    sms_supported: options.sms !== false, email_supported: true, revision: 0, changed: false }
  const fetchMock = vi.fn(async (path: string, init?: RequestInit) => {
    const event = decodeURIComponent(path.split('/').pop()!)
    const method = init?.method ?? 'GET'
    if (options.fail?.(event, method)) return json({ error: { code: 'internal_error', message: 'x', request_id: 'r-1' } }, 500)
    if (method === 'PUT') {
      const body = JSON.parse(init!.body as string) as { sms_enabled: boolean; email_enabled: boolean }
      const next = { ...row(event), ...body, revision: row(event).revision + 1, changed: true }
      rows.set(event, { ...next, changed: false })
      return json(next)
    }
    return json(row(event))
  })
  vi.stubGlobal('fetch', fetchMock)
  return { fetchMock, rows }
}

function signIn() {
  const user = principal({})
  useSessionStore.getState().setSession({ ...authResponse(user), access_token: 'sub-token' }, user)
}

const puts = (fetchMock: ReturnType<typeof vi.fn>) => fetchMock.mock.calls
  .filter(([, init]) => (init as RequestInit | undefined)?.method === 'PUT')
  .map(([path, init]) => ({ event: decodeURIComponent(String(path).split('/').pop()!), body: JSON.parse((init as RequestInit).body as string) }))

afterEach(() => vi.unstubAllGlobals())

describe('AccountSubscriptionsPage reference groups', () => {
  it('shows the six reference types first, each defaulted on, with the extra types collapsed', async () => {
    signIn()
    server()
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    await screen.findByRole('checkbox', { name: '证书到期 邮件提醒' })
    const main = screen.getAllByRole('table')[0]
    const labels = within(main).getAllByRole('row').slice(1).map((row) => row.querySelector('.account-subscription-item-label')?.textContent)
    expect(labels).toEqual(['套餐到期', '流量超限', '防护规则切换', '带宽超限', '连接数超限', '证书到期'])
    for (const label of labels) {
      expect(screen.getByRole('checkbox', { name: `${label} 手机提醒` })).toBeChecked()
      expect(screen.getByRole('checkbox', { name: `${label} 邮件提醒` })).toBeChecked()
    }
    // 这里是勾选框，不是开关。
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
    expect(screen.getByText('提醒项').parentElement).toHaveTextContent('提醒项 6')
    expect(screen.getByText('手机开启').parentElement).toHaveTextContent('手机开启 6')
    // 更多消息类型默认收起：公告、自动续费、攻击、WAF、工单行都不在页面上。
    const toggle = screen.getByRole('button', { name: /更多消息类型/ })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getAllByRole('table')).toHaveLength(1)
    expect(screen.queryByText('公告发布')).not.toBeInTheDocument()
    expect(screen.queryByText('自动续费失败')).not.toBeInTheDocument()
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    const more = await screen.findByRole('table', { name: /更多消息类型/ })
    for (const label of ['公告发布', '自动续费失败', '自动续费成功', 'WAF 自动排除已生效', '工单已提交', '客服回复']) {
      expect(within(more).getByText(label)).toBeInTheDocument()
    }
    expect(within(more).getByText(/网站攻击告警/)).toBeInTheDocument()
    expect(within(more).queryByText('流量超限')).not.toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: '自动续费失败 邮件提醒' })).toBeChecked()
  })

  it('writes one checkbox of a group to every event of that group and keeps the other channel', async () => {
    signIn()
    const { fetchMock } = server()
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    const sms = await screen.findByRole('checkbox', { name: '证书到期 手机提醒' })
    await waitFor(() => expect(sms).not.toBeDisabled())
    fireEvent.click(sms)
    await waitFor(() => expect(sms).not.toBeChecked())
    expect(puts(fetchMock).sort((a, b) => a.event.localeCompare(b.event))).toEqual([
      { event: 'certificate.expired', body: { sms_enabled: false, email_enabled: true } },
      { event: 'certificate.expiring', body: { sms_enabled: false, email_enabled: true } },
      { event: 'certificate.renew_failed', body: { sms_enabled: false, email_enabled: true } },
    ])
    expect(screen.getByRole('checkbox', { name: '证书到期 邮件提醒' })).toBeChecked()
    expect(screen.getByText('手机开启').parentElement).toHaveTextContent('手机开启 5')
  })

  it('marks a partly failed group write on its row and retries only what is still off target', async () => {
    signIn()
    let failing = true
    const { fetchMock } = server({ fail: (event, method) => failing && method === 'PUT' && event === 'package.monitor.traffic.recovered' })
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    const email = await screen.findByRole('checkbox', { name: '流量超限 邮件提醒' })
    await waitFor(() => expect(email).not.toBeDisabled())
    fireEvent.click(email)
    const retry = await screen.findByRole('button', { name: '流量超限 重试' })
    const row = screen.getByText('流量超限').closest('tr')!
    expect(within(row).getByText(/保存失败（internal_error）/)).toBeInTheDocument()
    // 其它行不受影响。
    expect(within(screen.getByText('带宽超限').closest('tr')!).queryByText(/失败/)).not.toBeInTheDocument()
    failing = false
    const before = puts(fetchMock).length
    fireEvent.click(retry)
    await waitFor(() => expect(within(row).queryByText(/保存失败/)).not.toBeInTheDocument())
    expect(puts(fetchMock).slice(before)).toEqual([
      { event: 'package.monitor.traffic.recovered', body: { sms_enabled: true, email_enabled: false } },
    ])
    expect(email).not.toBeChecked()
  })

  // 平台未开通的渠道整列不显示，分组表与更多消息类型一致。
  it('hides the SMS column in both tables when the platform has not opened SMS', async () => {
    signIn()
    server({ sms: false })
    renderWithProviders(<AccountSubscriptionsPage />, ['/account/subscribe'])
    await screen.findByRole('checkbox', { name: '套餐到期 邮件提醒' })
    expect(screen.queryByRole('columnheader', { name: '手机提醒' })).not.toBeInTheDocument()
    expect(screen.queryByText('手机开启')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /更多消息类型/ }))
    await screen.findByRole('table', { name: /更多消息类型/ })
    expect(screen.queryByRole('checkbox', { name: /手机提醒/ })).not.toBeInTheDocument()
  })
})
