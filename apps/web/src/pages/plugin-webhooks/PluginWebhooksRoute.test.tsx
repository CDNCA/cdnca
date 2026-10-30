import { screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { pluginWebhooksApi } from '../../api/pluginWebhooks'
import { useSessionStore } from '../../auth/session'
import { changeLocale } from '../../i18n'
import { isImplementedPath } from '../../routes/navigation'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import PluginWebhooksRoute from './PluginWebhooksRoute'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function features(pluginWebhooks: boolean): Response {
  return json({ features: { cache_control: false, custom_rbac: false, approval_center: false, plugin_webhooks: pluginWebhooks, market: false, package_auto_renew: false, origin_auth: false } })
}

function signIn() {
  const actor = principal({ permissions: ['plugin_webhooks.read'] })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: 'webhook-route-token' }, actor)
}

afterEach(() => vi.restoreAllMocks())

// live-click-C E1: with PLUGIN_WEBHOOK_RUNTIME_ENABLED unset the subscription
// routes are not mounted; menu and typed URL both follow plugin_webhooks.
describe('plugin webhook runtime gate', () => {
  it('keeps the shell from opening the page for both roles until the runtime is mounted', () => {
    for (const role of ['admin', 'user'] as const) {
      expect(isImplementedPath(role, '/sys/plugin-webhooks', ['plugin_webhooks.read'], [], [])).toBe(false)
      expect(isImplementedPath(role, '/sys/plugin-webhooks', ['plugin_webhooks.read'], [], ['plugin_webhooks'])).toBe(true)
    }
  })

  it('shows "feature not enabled" and never calls the subscription API when off', async () => {
    await changeLocale('zh-CN')
    signIn()
    const list = vi.spyOn(pluginWebhooksApi, 'listSubscriptions')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).endsWith('/v1/runtime-features') ? features(false) : json({ code: 'not_found' }, 404))
    renderWithProviders(<PluginWebhooksRoute />, ['/sys/plugin-webhooks'])
    expect(await screen.findByText('功能未启用')).toBeInTheDocument()
    expect(screen.queryByText('加载订阅失败')).not.toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
  })

  it('treats a failed runtime-features request as not enabled', async () => {
    await changeLocale('zh-CN')
    signIn()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ code: 'internal' }, 500))
    renderWithProviders(<PluginWebhooksRoute />, ['/sys/plugin-webhooks'])
    expect(await screen.findByText('功能未启用')).toBeInTheDocument()
  })

  it('mounts the page once plugin_webhooks is reported', async () => {
    await changeLocale('zh-CN')
    signIn()
    const list = vi.spyOn(pluginWebhooksApi, 'listSubscriptions').mockResolvedValue({ items: [] })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).endsWith('/v1/runtime-features') ? features(true) : json({ items: [] }))
    renderWithProviders(<PluginWebhooksRoute />, ['/sys/plugin-webhooks'])
    await waitFor(() => expect(list).toHaveBeenCalled())
    expect(screen.queryByText('功能未启用')).not.toBeInTheDocument()
  })
})
