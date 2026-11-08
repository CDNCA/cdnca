import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { marketApi } from '../../api/market'
import type { PluginInstallation } from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { PlatformPluginsPanel } from './PluginMarketPage'

// 插件实测 F5 补项（B-补2 未决恢复被其他插件抹掉、B-补3 自停稀疏回读误报平台暂停）与
// PLUG-CLIENT-CLOCK-01 的页面提示。用例取自 plugin-live-acceptance-20261028/ui/PluginLiveReview.test.tsx。

const scopeID = '018cc251-f400-7def-8000-000000000040'
const authorizationID = '018cc251-f400-7def-8000-000000000041'
const otherAuthorizationID = '018cc251-f400-7def-8000-000000000044'
const verificationID = '018cc251-f400-7def-8000-000000000042'
const actor = principal({ scope_kind: 'platform', scope_id: scopeID, tenant_id: null, roles: ['platform_owner'],
  permissions: ['plugin_installations.platform.read', 'plugin_installations.platform.manage'] })
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function theme(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return { schema: 'cdnca.control.plugin-installation/v1', tenant_scope_id: scopeID, authorization_id: authorizationID,
    installation_id: '018cc251-f400-7def-8000-000000000043', verification_id: verificationID,
    plugin_id: 'review.example-theme', version: '1.0.0', resource_scope: 'platform', entrypoint_type: 'theme',
    manifest_sha256: 'a'.repeat(64), configuration_schema_sha256: 'b'.repeat(64), manifest_scopes: [],
    approved_scopes: [], sensitive_scopes: [], new_scopes: [], status: 'pending_confirmation', revision: 1,
    identity_generation: 0, lkg_verification_id: null, lkg_version: null, stable_reason_code: null,
    updated_at: '2026-10-28T08:00:00Z', authorization_status: 'pending_confirmation', ...overrides }
}

const enabled = theme({ status: 'enabled', authorization_status: 'enabled', revision: 2, identity_generation: 1,
  lkg_verification_id: verificationID, lkg_version: '1.0.0' })
const ownPaused = { ...enabled, status: 'disabled' as const, authorization_status: 'disabled' as const, revision: 3,
  paused_by: 'installation' as const, paused_reason: 'review own pause' }

function feedbackDialogs() {
  return screen.queryAllByRole('dialog').filter((item) => item.classList.contains('cdnca-feedback'))
}

async function closeFeedback() {
  const warning = feedbackDialogs()[0]!
  fireEvent.click(within(warning).getByRole('button', { name: 'Close' }))
  await waitFor(() => expect(feedbackDialogs()).toHaveLength(0))
}

function drawer() {
  return screen.getAllByRole('dialog').find((item) => item.classList.contains('plugin-market-drawer'))!
}

beforeEach(async () => {
  vi.restoreAllMocks()
  await changeLocale('zh-CN')
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(marketApi, 'advisories').mockResolvedValue([])
})

describe('插件生命周期恢复', () => {
  it('另一个插件的写操作被锁住，未知恢复的原请求一直保留', async () => {
    const paused = theme({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation', revision: 4 })
    const other = theme({ authorization_id: otherAuthorizationID, plugin_id: 'review.second-theme' })
    const writes: Array<{ url: string; key: string | null }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        writes.push({ url, key: new Headers(init.headers).get('Idempotency-Key') })
        if (url.endsWith('/resume')) return json({ error: { code: 'plugin_installation_result_unknown' } }, 503)
        return json({ installation: { ...other, status: 'enabled', authorization_status: 'enabled', revision: 2 } })
      }
      if (url.includes(`/${paused.authorization_id}`)) return json(paused)
      if (url.includes(`/${other.authorization_id}`)) return json(other)
      return json({ items: [paused, other] })
    })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText(paused.plugin_id)
    fireEvent.click(screen.getAllByRole('button', { name: '查看详情' })[0]!)
    fireEvent.click(await screen.findByRole('button', { name: '恢复使用' }))
    await screen.findByRole('button', { name: '重新恢复' })
    await closeFeedback()
    fireEvent.click(within(drawer()).getByRole('button', { name: 'Close' }))

    // B 的安装在列表与详情都不可开始；读列表/详情照常，并说明待处理的是哪个插件。
    expect(screen.getByRole('button', { name: '安装' })).toBeDisabled()
    expect(screen.getAllByText(/review\.example-theme.*恢复使用.*还没有确认结果/).length).toBeGreaterThan(0)
    fireEvent.click(screen.getAllByRole('button', { name: '查看详情' })[1]!)
    await waitFor(() => expect(within(drawer()).getAllByText('review.second-theme').length).toBeGreaterThan(0))
    for (const button of within(drawer()).queryAllByRole('button', { name: /安装|卸载|暂停|升级/ })) expect(button).toBeDisabled()
    expect(writes.map((write) => write.url)).toEqual([`/v1/platform/plugin-installations/${authorizationID}/resume`])
    expect(screen.getByRole('button', { name: '重新恢复' })).toBeEnabled()
  })

  it('重新恢复按原 key 重投；成功后只清掉自己的未决请求', async () => {
    const paused = theme({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation', revision: 4 })
    const resumed = { ...paused, status: 'enabled' as const, authorization_status: 'enabled' as const, revision: 5, paused_by: undefined }
    const writes: Array<{ url: string; key: string | null; body: unknown; ifMatch: string | null }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        const headers = new Headers(init.headers)
        writes.push({ url, key: headers.get('Idempotency-Key'), body: JSON.parse(String(init.body)), ifMatch: headers.get('If-Match') })
        return writes.length === 1 ? json({ error: { code: 'plugin_installation_result_unknown' } }, 503) : json({ installation: resumed })
      }
      if (url.includes(`/${paused.authorization_id}`)) return json(writes.length === 2 ? resumed : paused)
      return json({ items: [writes.length === 2 ? resumed : paused] })
    })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText(paused.plugin_id)
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    fireEvent.click(await screen.findByRole('button', { name: '恢复使用' }))
    await screen.findByRole('button', { name: '重新恢复' })
    await closeFeedback()
    fireEvent.click(screen.getByRole('button', { name: '重新恢复' }))
    await waitFor(() => expect(writes).toHaveLength(2))
    expect(writes[1]).toEqual(writes[0])
    await waitFor(() => expect(screen.queryByRole('button', { name: '重新恢复' })).not.toBeInTheDocument())
    expect(screen.queryByText(/还没有确认结果/)).not.toBeInTheDocument()
  })

  it('明确放弃时说明只丢弃本地恢复入口，之后可以继续其他操作', async () => {
    const paused = theme({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation', revision: 4 })
    const other = theme({ authorization_id: otherAuthorizationID, plugin_id: 'review.second-theme' })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') return json({ error: { code: 'plugin_installation_result_unknown' } }, 503)
      if (url.includes(`/${paused.authorization_id}`)) return json(paused)
      return json({ items: [paused, other] })
    })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText(paused.plugin_id)
    fireEvent.click(screen.getAllByRole('button', { name: '查看详情' })[0]!)
    fireEvent.click(await screen.findByRole('button', { name: '恢复使用' }))
    await screen.findByRole('button', { name: '重新恢复' })
    expect(within(feedbackDialogs()[0]!).getByText(/只丢弃本页的重试入口，不会撤销已经提交给服务端的操作/)).toBeInTheDocument()
    await closeFeedback()
    fireEvent.click(screen.getByRole('button', { name: '放弃这次操作并刷新' }))
    await waitFor(() => expect(screen.queryByRole('button', { name: '重新恢复' })).not.toBeInTheDocument())
    fireEvent.click(within(drawer()).getByRole('button', { name: 'Close' }))
    expect(screen.getByRole('button', { name: '安装' })).toBeEnabled()
  })

  it('换账号后旧未决请求不会跟到新账号', async () => {
    const paused = theme({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation', revision: 4 })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') return json({ error: { code: 'plugin_installation_result_unknown' } }, 503)
      if (url.includes(`/${paused.authorization_id}`)) return json(paused)
      return json({ items: [paused] })
    })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText(paused.plugin_id)
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    fireEvent.click(await screen.findByRole('button', { name: '恢复使用' }))
    await screen.findByRole('button', { name: '重新恢复' })
    const next = principal({ ...actor, user_id: '018cc251-f400-7def-8000-000000000099' })
    act(() => useSessionStore.getState().setSession(authResponse(next), next))
    await screen.findByText(paused.plugin_id)
    expect(screen.queryByRole('button', { name: '重新恢复' })).not.toBeInTheDocument()
  })
})

describe('自己暂停后的回读', () => {
  function pauseFetch(answer: PluginInstallation, detailAfterPause: () => Response) {
    let disabled = false
    const counters = { detailReads: 0, writes: [] as string[] }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        counters.writes.push(url)
        disabled = true
        return json({ installation: answer })
      }
      if (url.endsWith(`/${authorizationID}`)) {
        counters.detailReads += 1
        return disabled ? detailAfterPause() : json(enabled)
      }
      return json({ items: [disabled ? ownPaused : enabled] })
    })
    return counters
  }

  async function pauseFromDrawer() {
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText(enabled.plugin_id)
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    fireEvent.click(await screen.findByRole('button', { name: '暂停' }))
    expect(screen.queryByRole('textbox', { name: '原因' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '确认暂停' }))
    await screen.findByText('暂停已完成，当前状态：已暂停')
  }

  it.each(['complete', 'sparse'] as const)('%s 响应：不关详情回读到自己暂停并给“恢复使用”', async (metadata) => {
    const answer = metadata === 'complete' ? ownPaused
      : { ...ownPaused, authorization_status: undefined, paused_by: undefined, paused_reason: undefined }
    const counters = pauseFetch(answer, () => json(ownPaused))
    await pauseFromDrawer()
    expect(await screen.findByRole('button', { name: '恢复使用' })).toBeEnabled()
    expect(document.querySelector('.plugin-market-state-reason')).toHaveTextContent('你已暂停这个插件')
    expect(screen.queryByText(/平台已暂停/)).not.toBeInTheDocument()
    expect(counters.detailReads).toBeGreaterThanOrEqual(2)
    expect(counters.writes).toEqual([`/v1/platform/plugin-installations/${authorizationID}/disable`])
  })

  it('稀疏响应且回读失败：说暂停已提交、原因暂时读不到，不写平台暂停', async () => {
    const answer = { ...ownPaused, authorization_status: undefined, paused_by: undefined, paused_reason: undefined }
    pauseFetch(answer, () => json({ error: { code: 'plugin_installation_license_unavailable' } }, 503))
    await pauseFromDrawer()
    expect(await screen.findByText('暂停已提交，当前原因暂时无法读取')).toBeInTheDocument()
    expect(screen.queryByText(/平台已暂停/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '恢复使用' })).not.toBeInTheDocument()
    expect(within(drawer()).getByRole('button', { name: '刷新状态' })).toBeEnabled()
  })

  it('稀疏响应时回读到平台随后又暂停：显示平台处理，不给本地恢复', async () => {
    const answer = { ...ownPaused, authorization_status: undefined, paused_by: undefined, paused_reason: undefined }
    pauseFetch(answer, () => json({ ...ownPaused, paused_by: 'operator', paused_reason: 'review operator pause' }))
    await pauseFromDrawer()
    expect(await screen.findByText(/平台运营已暂停这个插件，原因：review operator pause/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '恢复使用' })).not.toBeInTheDocument()
  })

  it('未确认归属的暂停记录显示“正在确认暂停状态”而不是平台暂停', async () => {
    const unknownOwner = { ...ownPaused, authorization_status: undefined, paused_by: undefined, paused_reason: undefined }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith(`/${authorizationID}`)) return json(unknownOwner)
      return json({ items: [unknownOwner] })
    })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText(enabled.plugin_id)
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    expect(await within(drawer()).findByText('正在确认暂停状态')).toBeInTheDocument()
    expect(screen.queryByText(/平台已暂停/)).not.toBeInTheDocument()
  })
})

describe('授权响应校验未通过（PLUG-CLIENT-CLOCK-01 页面提示）', () => {
  it('恢复时给可重试提示并带请求编号，不要求重新购买', async () => {
    const paused = theme({ status: 'disabled', authorization_status: 'disabled', paused_by: 'installation', revision: 4 })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') {
        return json({ error: { code: 'plugin_installation_activation_response_invalid', request_id: '0123456789abcdef' } }, 502)
      }
      if (url.includes(`/${paused.authorization_id}`)) return json(paused)
      return json({ items: [paused] })
    })
    renderWithProviders(<PlatformPluginsPanel />)
    await screen.findByText(paused.plugin_id)
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }))
    fireEvent.click(await screen.findByRole('button', { name: '恢复使用' }))
    const dialog = await waitFor(() => {
      const found = feedbackDialogs()[0]
      expect(found).toBeDefined()
      return found!
    })
    expect(dialog).toHaveTextContent('授权响应校验未通过')
    expect(dialog).toHaveTextContent('尚未完成，请重试；持续失败请提供请求编号联系平台')
    expect(dialog).toHaveTextContent('0123456789abcdef')
    expect(dialog).not.toHaveTextContent(/购买|卸载/)
    // 校验失败发生在本地写入之前：不是“结果未知”，原操作按钮仍可直接重试。
    expect(screen.queryByRole('button', { name: '重新恢复' })).not.toBeInTheDocument()
    expect(within(drawer()).getByRole('button', { name: '恢复使用' })).toBeEnabled()
  })
})
