import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../../auth/session'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import PluginProvidersPage from './PluginProvidersPage'

const at = '2026-10-19T08:00:00Z'
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status,
  headers: { 'Content-Type': 'application/json' } }))

const passed = { plugin_id: 'com.example.dnsplus', version: '1.2.0', base_url: 'https://dns.dnsplus.example', kinds: ['dns'],
  status: 'active', contract_status: 'passed', contract_version: 'cdnca.provider-contract/v1', contract_checked_at: at,
  contract_report: { version: 'cdnca.provider-contract/v1', passed: true, duration_ms: 40,
    cases: [{ kind: 'dns', id: 'verify', passed: true }, { kind: 'dns', id: 'create_a', passed: true }] },
  enabled: false, usable: false, updated_at: at }
const failed = { ...passed, plugin_id: 'com.example.evil', kinds: ['sms'], contract_status: 'failed',
  contract_report: { version: 'cdnca.provider-contract/v1', passed: false, duration_ms: 30,
    cases: [{ kind: 'sms', id: 'verify', passed: true }, { kind: 'sms', id: 'rejects_bad_signature', passed: false, code: 'accepted_forged_request' }] } }

function authenticate(permissions = ['plugin_installations.read', 'plugin_installations.manage']) {
  const actor = principal({ scope_kind: 'platform', scope_id: '11111111-1111-4111-8111-111111111111', tenant_id: undefined, permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

afterEach(() => { vi.restoreAllMocks() })

describe('第三方服务商插件 (PA-22)', () => {
  it('shows contract results, lets a passed plugin be enabled and keeps a failed one disabled', async () => {
    authenticate()
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/admin/plugin-providers') return json({ items: [passed, failed] })
      if (url.pathname.endsWith('/enable') && init?.method === 'POST') return json({ ...passed, enabled: true, usable: true })
      return json({ error: { code: 'not_found' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginProvidersPage />, ['/sys/plugin-providers'])
    const passedRow = (await screen.findByText('com.example.dnsplus')).closest('tr')!
    const failedRow = screen.getByText('com.example.evil').closest('tr')!
    expect(within(passedRow).getByText('已通过')).toBeInTheDocument()
    expect(within(passedRow).getByText('2/2 项通过')).toBeInTheDocument()
    expect(within(failedRow).getByText('未通过')).toBeInTheDocument()
    expect(within(failedRow).getByRole('button', { name: /启用/ })).toBeDisabled()
    await user.click(within(failedRow).getByRole('button', { name: '查看用例' }))
    expect(await screen.findByText('accepted_forged_request')).toBeInTheDocument()
    await user.click(within(passedRow).getByRole('button', { name: /启用/ }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([input, init]) =>
      String(input).endsWith('/v1/admin/plugin-providers/com.example.dnsplus/enable') && init?.method === 'POST')).toBe(true))
    expect(await within(passedRow).findByText('可用')).toBeInTheDocument()
  })

  it('is read-only without plugin_installations.manage', async () => {
    authenticate(['plugin_installations.read'])
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ items: [passed] }))
    renderWithProviders(<PluginProvidersPage />, ['/sys/plugin-providers'])
    const row = (await screen.findByText('com.example.dnsplus')).closest('tr')!
    expect(within(row).getByRole('button', { name: /重新测试/ })).toBeDisabled()
    expect(within(row).getByRole('button', { name: /启用/ })).toBeDisabled()
  })
})

const tenantID = '33333333-3333-4333-8333-333333333333'
const stepUpToken = 'a'.repeat(43)
const payPlugin = { ...passed, plugin_id: 'com.example.payplus', kinds: ['payment'], high_risk: true,
  risk_notice: '支付插件属于高风险权限（测试文案）', tenant_id: tenantID,
  contract_report: { version: 'cdnca.provider-contract/v1', passed: true, duration_ms: 50,
    cases: [{ kind: 'payment', id: 'create_checkout', passed: true }, { kind: 'payment', id: 'rejects_tampered_callback', passed: true }] } }

describe('第三方支付插件二次确认 (PA-23)', () => {
  it('enables a payment plugin only after the risk notice and an MFA step-up bound to its tenant', async () => {
    authenticate()
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/admin/plugin-providers') return json({ items: [payPlugin] })
      if (url.pathname === '/v1/account/mfa/step-up-proofs') return json({ proof_id: '44444444-4444-4444-8444-444444444444',
        token: stepUpToken, method: 'totp', issued_at: at, expires_at: at, max_uses: 1, replayed: false }, 201)
      if (url.pathname.endsWith('/enable') && init?.method === 'POST') return json({ ...payPlugin, enabled: true, usable: true })
      return json({ error: { code: 'not_found' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginProvidersPage />, ['/sys/plugin-providers'])
    const row = (await screen.findByText('com.example.payplus')).closest('tr')!
    expect(within(row).getByText('高风险')).toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: /启用/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('支付插件属于高风险权限（测试文案）')).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('验证码'), '123456')
    await user.click(within(dialog).getByRole('button', { name: '验证并启用' }))
    expect(await within(dialog).findByText('请先确认风险提示')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('step-up-proofs'))).toBe(false)

    await user.click(within(dialog).getByRole('checkbox'))
    await user.click(within(dialog).getByRole('button', { name: '验证并启用' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([input, init]) =>
      String(input).endsWith('/com.example.payplus/enable') && init?.method === 'POST')).toBe(true))
    const proof = fetchMock.mock.calls.find(([input]) => String(input).includes('step-up-proofs'))!
    expect(JSON.parse(String(proof[1]!.body))).toMatchObject({ tenant_id: tenantID, audience: 'plugin.provider.enable_payment',
      action: 'plugin.provider.enable_payment', authentication: { method: 'totp', code: '123456' }, max_uses: 1 })
    const enable = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/enable'))!
    expect(JSON.parse(String(enable[1]!.body))).toEqual({ risk_acknowledged: true, step_up_token: stepUpToken })
    expect(await within(row).findByText('可用')).toBeInTheDocument()
  })

  it('shows a refused step-up in the dialog', async () => {
    authenticate()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = new URL(String(input), 'https://test.invalid')
      if (url.pathname === '/v1/admin/plugin-providers') return json({ items: [payPlugin] })
      if (url.pathname === '/v1/account/mfa/step-up-proofs') return json({ proof_id: '44444444-4444-4444-8444-444444444444',
        token: stepUpToken, method: 'totp', issued_at: at, expires_at: at, max_uses: 1, replayed: false }, 201)
      if (url.pathname.endsWith('/enable') && init?.method === 'POST')
        return json({ error: { code: 'plugin_provider_step_up_required', message: 'x' } }, 403)
      return json({ error: { code: 'not_found' } }, 404)
    })
    const user = userEvent.setup()
    renderWithProviders(<PluginProvidersPage />, ['/sys/plugin-providers'])
    const row = (await screen.findByText('com.example.payplus')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: /启用/ }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('checkbox'))
    await user.type(within(dialog).getByLabelText('验证码'), '000000')
    await user.click(within(dialog).getByRole('button', { name: '验证并启用' }))
    expect(await within(dialog).findByText('二次验证未通过，请重新输入验证码')).toBeInTheDocument()
  })

  it('G2: a failed list shows only the error with a retry, not the empty state', async () => {
    authenticate()
    let fail = true
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => (fail ? json({ error: { code: 'internal_error' } }, 500) : json({ items: [] })))
    const user = userEvent.setup()
    renderWithProviders(<PluginProvidersPage />, ['/sys/plugin-providers'])
    const failure = await screen.findByText('读取服务商插件失败', { selector: '.data-state-error span' })
    expect(screen.queryByText('还没有已授权的第三方服务商插件')).not.toBeInTheDocument()
    fail = false
    await user.click(within(failure.closest('.data-state-error') as HTMLElement).getByRole('button', { name: '重试' }))
    expect(await screen.findByText('还没有已授权的第三方服务商插件')).toBeInTheDocument()
  })
})
