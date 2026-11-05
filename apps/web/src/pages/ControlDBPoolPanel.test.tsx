import { screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { DBPoolSample, DBPoolStatus } from '../api/controlDBPool'
import { changeLocale } from '../i18n'
import { controlDBPoolMessages } from '../i18n/controlDBPool'
import { renderWithProviders } from '../test/render'
import ControlDBPoolPanel from './ControlDBPoolPanel'

const at = '2026-11-05T12:00:30Z'

function sample(overrides: Partial<DBPoolSample> = {}): DBPoolSample {
  return { at, max_conns: 20, total_conns: 20, in_use: 19, idle: 1, constructing: 0, resident_conns: 2, request_capacity: 18,
    acquires: 40, queued: 6, canceled: 1, avg_wait_ms: 250.4, reasons: ['saturated', 'canceled_acquire'], ...overrides }
}

function status(overrides: Partial<DBPoolStatus> = {}): DBPoolStatus {
  return { instance: 'ctl-a', interval_seconds: 10,
    thresholds: { enter_cycles: 3, recover_cycles: 3, saturation_margin: 1, slow_acquire_ms: 100, dedup_minutes: 15 },
    current: sample(), series: [sample({ in_use: 4, queued: 0, canceled: 0, avg_wait_ms: 1, reasons: [] }), sample()],
    residents: [{ name: 'market_security_listen', in_pool: true, since: at }, { name: 'package_traffic_wake_listen', in_pool: false, since: at }],
    firing: true, firing_since: at, firing_reasons: ['saturated', 'canceled_acquire'], notified: true, last_notified_at: at,
    pending_notifications: 0, ...overrides }
}

function respond(body: unknown, statusCode = 200) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify(body),
    { status: statusCode, headers: { 'Content-Type': 'application/json' } }))
}

describe('ControlDBPoolPanel', () => {
  it('shows the saturated pool, the request share, the last hour and the resident connections', async () => {
    const fetchSpy = respond(status())
    renderWithProviders(<ControlDBPoolPanel accessToken="token" />)
    const card = (await screen.findByRole('heading', { name: /主控数据库连接池/ })).closest('section')!
    expect(await within(card).findByText('连接池满载：请求在排队等待连接')).toBeInTheDocument()
    expect(within(card).getByText(/原因：连接已用满、请求等不到连接而放弃/)).toBeInTheDocument()
    expect(within(card).getByText('实例 ctl-a')).toBeInTheDocument()
    expect(within(card).getByText('19 / 20')).toBeInTheDocument()
    expect(within(card).getByText('空闲 1 / 共 18')).toBeInTheDocument()
    expect(within(card).getAllByText('250.4 毫秒').length).toBeGreaterThan(0)
    expect(within(card).getByText('节点市场安全策略监听（LISTEN）')).toBeInTheDocument()
    expect(within(card).getByText('已移出连接池（只占数据库连接数）')).toBeInTheDocument()
    expect(within(card).getByText(/连续 3 次采样满载（使用 ≥ 上限 − 1）或平均等待超过 100 毫秒/)).toBeInTheDocument()
    expect(within(card).queryByText(/本次未重复通知/)).not.toBeInTheDocument()
    const [url, init] = fetchSpy.mock.calls[0]
    expect(String(url)).toBe('/v1/admin/system-db-pool')
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
  })

  it('says when an alert was folded into the last one and when notifications wait for a retry', async () => {
    respond(status({ notified: false, pending_notifications: 2 }))
    renderWithProviders(<ControlDBPoolPanel accessToken="token" />)
    expect(await screen.findByText('距上次告警不足 15 分钟，本次未重复通知；仍未恢复则窗口过后补发。')).toBeInTheDocument()
    expect(screen.getByText('2 条告警通知写入失败，下个周期重试。')).toBeInTheDocument()
  })

  it('shows a healthy pool and the first-sample wait', async () => {
    respond(status({ firing: false, firing_since: null, firing_reasons: [], current: null, series: [], residents: [], last_notified_at: null }))
    renderWithProviders(<ControlDBPoolPanel accessToken="token" />)
    expect(await screen.findByText('连接池正常')).toBeInTheDocument()
    expect(screen.getByText('刚启动，10 秒后出第一个采样。')).toBeInTheDocument()
    expect(screen.getByText('当前没有常驻连接')).toBeInTheDocument()
  })

  it('tells an older control without the route and a refused session apart from a failure', async () => {
    respond({ error: { code: 'not_found', message: 'not_found', request_id: 'r' } }, 404)
    const first = renderWithProviders(<ControlDBPoolPanel accessToken="token" />)
    expect(await screen.findByText('当前主控版本不提供连接池监控')).toBeInTheDocument()
    first.unmount()
    vi.restoreAllMocks()
    respond({ error: { code: 'permission_denied', message: 'permission_denied', request_id: 'r' } }, 403)
    const second = renderWithProviders(<ControlDBPoolPanel accessToken="token" />)
    expect(await screen.findByText('没有查看连接池的权限')).toBeInTheDocument()
    second.unmount()
    vi.restoreAllMocks()
    respond({ unexpected: true })
    renderWithProviders(<ControlDBPoolPanel accessToken="token" />)
    expect(await screen.findByText('连接池状态读取失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
  })

  it('renders in English with the same keys', async () => {
    expect(Object.keys(controlDBPoolMessages['en-US']).sort()).toEqual(Object.keys(controlDBPoolMessages['zh-CN']).sort())
    await changeLocale('en-US')
    try {
      respond(status())
      renderWithProviders(<ControlDBPoolPanel accessToken="token" />)
      expect(await screen.findByText('Pool saturated: requests are queueing for connections')).toBeInTheDocument()
      expect(screen.getByText('1 free of 18')).toBeInTheDocument()
    } finally {
      await changeLocale('zh-CN')
    }
  })
})
