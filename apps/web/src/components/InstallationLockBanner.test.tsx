import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { supplyInUse } from '../api/marketSupplier'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { InstallationLockBanner } from './InstallationLockBanner'

// ADR 0014 LIC-BAN-06: GET /v1/installation-lock drives the banner (lic-ban2 installationlock.Lock).

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['sites.manage'] })
const banned = { locked: true, reason: 'installation_banned', ban_id: '0b0b0b0b-0b0b-40b0-80b0-0b0b0b0b0b0b', reason_code: 'abuse',
  reason_text: '违规转售', until: '2026-12-01T00:00:00Z' }

beforeEach(() => useSessionStore.getState().setSession({ ...authResponse(admin), access_token: 'tok' }, admin))
afterEach(async () => {
  vi.unstubAllGlobals()
  await i18n.changeLanguage('zh-CN')
})

describe('InstallationLockBanner', () => {
  it('renders nothing while unlocked', async () => {
    const fetchMock = vi.fn(async () => json({ locked: false }))
    vi.stubGlobal('fetch', fetchMock)
    const { container } = renderWithProviders(<InstallationLockBanner />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('shows reason and lift time for a timed ban, then unlocks after "check again"', async () => {
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) =>
      path === '/v1/installation-lock/check' && init?.method === 'POST' ? json({ locked: false }) : json(banned))
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText('本主控授权已被锁定，后台处于只读状态')).toBeInTheDocument()
    expect(screen.getByText('授权方已对本主控下发安全封禁 · 原因：违规转售')).toBeInTheDocument()
    expect(screen.getByText(/^预计 .+ 自动解除$/)).toBeInTheDocument()
    expect(screen.getByText(`ban_id ${banned.ban_id}`)).toBeInTheDocument()
    expect(fetchMock.mock.calls[0][1]?.headers).toEqual({ Authorization: 'Bearer tok' })
    fireEvent.click(screen.getByRole('button', { name: '重新检查' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([p, i]) => p === '/v1/installation-lock/check' && i?.method === 'POST')).toBe(true))
    expect(await screen.findByText('授权已恢复')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('本主控授权已被锁定，后台处于只读状态')).toBeNull())
  })

  // C15/AUTH-BAN-FEEDBACK-01: a failed "check again" says so and keeps the lock.
  it('reports a failed check and keeps the banner', async () => {
    const fetchMock = vi.fn(async (path: string, init?: RequestInit) =>
      path === '/v1/installation-lock/check' && init?.method === 'POST'
        ? json({ error: { code: 'license_unreachable', message: 'x', request_id: 'req-1234' } }, 503) : json(banned))
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText('本主控授权已被锁定，后台处于只读状态')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '重新检查' }))
    expect(await screen.findByText(/重新检查失败（license_unreachable），锁定状态未改变/)).toBeInTheDocument()
    expect(screen.getByText('本主控授权已被锁定，后台处于只读状态')).toBeInTheDocument()
  })

  // ui-leftover3 #3：横幅要给出处理办法，不只写原因。
  it('tells the operator what to do for an expired lease', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ locked: true, reason: 'lease_expired' })))
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText('授权租约已过期')).toBeInTheDocument()
    expect(screen.getByText(/^处理办法：主控未能按时向授权端续租/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重新检查' })).toBeInTheDocument()
  })

  // 每个原因写清对已有流量的影响、责任方与恢复条件。
  it('says a security ban stops traffic and who lifts it', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(banned)))
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText(/^影响：授权方下发了签名的安全封禁，本主控下全部节点已停止对外服务/)).toBeInTheDocument()
  })

  it.each([
    ['lease_expired', '授权租约已过期'],
    ['lease_revoked', '授权租约已被吊销'],
    ['service_ticket_expired', '节点服务凭证已过期，节点已冻结'],
  ])('says %s keeps existing traffic and freezes changes', async (reason, title) => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ locked: true, reason })))
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText(title)).toBeInTheDocument()
    expect(screen.getByText(/^影响：已发布的网站与四层转发继续服务，不会停流量；新增网站、扩容与升级暂停/)).toBeInTheDocument()
  })

  it('says permanent without until, in English too', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ ...banned, until: undefined, reason: 'lease_revoked', reason_text: undefined })))
    await i18n.changeLanguage('en-US')
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText("This controller's license is locked; the console is read-only")).toBeInTheDocument()
    expect(screen.getByText('The license lease was revoked')).toBeInTheDocument()
    expect(screen.getByText('No lift time set')).toBeInTheDocument()
  })

  // 授权端拒绝（master_ip_rebound）后，租约未到期也显示"已换绑"，写明网站不受影响；
  // 租约过期锁定后同时显示换绑原因与只读说明。
  it('shows the rebound notice while the lease is still valid', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ locked: false, rebound: true })))
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText('授权已换绑到其他服务器')).toBeInTheDocument()
    expect(screen.getByText(/已在运行的网站不受影响/)).toBeInTheDocument()
    expect(screen.queryByText('本主控授权已被锁定，后台处于只读状态')).toBeNull()
  })

  it('names the rebind as the cause once the lease locks', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ locked: true, reason: 'lease_expired', rebound: true })))
    renderWithProviders(<InstallationLockBanner />)
    expect(await screen.findByText('授权已换绑到其他服务器')).toBeInTheDocument()
    expect(screen.getByText('可以登录、查看数据、修改自己的密码与两步验证，其他修改暂不可用。')).toBeInTheDocument()
  })
})

describe('supply_in_use refusal', () => {
  it('reads the counts from the relay body and the node API error.details', () => {
    const relay = new ApiError('x', 409, 'supply_in_use') as ApiError & { refusal?: unknown }
    relay.refusal = { error: 'supply_in_use', online_available: 1, normal_subscriptions: 3 }
    expect(supplyInUse(relay)).toEqual({ online_available: 1, normal_subscriptions: 3 })
    const node = new ApiError('x', 409, 'supply_in_use') as ApiError & { refusal?: unknown }
    node.refusal = { error: { code: 'supply_in_use', details: { online_available: 2, normal_subscriptions: 5 } } }
    expect(supplyInUse(node)).toEqual({ online_available: 2, normal_subscriptions: 5 })
    expect(supplyInUse(new ApiError('x', 409, 'supply_in_use'))).toBeNull()
    expect(i18n.t('marketSupplier:supplyInUse', { online: 2, normal: 5 })).toBe(
      '当前还有 5 个正常订阅方在使用，操作后在线可用节点会从 2 个变为 0，已被拒绝。请保留至少 1 个在线可用节点，或等订阅到期/暂停后再操作。')
  })

})
