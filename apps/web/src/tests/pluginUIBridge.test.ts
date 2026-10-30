import { describe, expect, it, vi } from 'vitest'

import {
  allowedMethods,
  frameURL,
  handleBridgeRequest,
  isHello,
  newNonce,
  protocolVersion,
  sandboxTokens,
  validApiRequest,
  validNavigatePath,
  type BridgeHost,
} from '../pluginui/bridge'

function host(): BridgeHost & { navigate: ReturnType<typeof vi.fn>; apiRequest: ReturnType<typeof vi.fn> } {
  return {
    context: () => ({
      protocol: protocolVersion, plugin_id: 'acme.reports', page_id: 'report',
      user: { id: 'u1', display_name: '管理员', role: 'admin' }, tenant: { scope_id: 's1', scope_kind: 'platform' },
      site_id: null, locale: 'zh-CN', theme: 'light',
    }),
    navigate: vi.fn(),
    apiRequest: vi.fn(async () => ({ status: 200, body: { ok: true } })),
  }
}

const request = (nonce: string, method: string, params?: unknown) =>
  ({ protocol: protocolVersion, nonce, id: 'r1', method, params })

describe('ui_page plugin bridge (PA-19)', () => {
  it('never grants the frame the host origin', () => {
    expect([...sandboxTokens]).toEqual(['allow-scripts', 'allow-forms'])
    expect(sandboxTokens).not.toContain('allow-same-origin')
    expect(sandboxTokens).not.toContain('allow-top-navigation')
    expect(sandboxTokens).not.toContain('allow-popups-to-escape-sandbox')
  })

  it('answers only the whitelisted methods', async () => {
    expect([...allowedMethods]).toEqual(['context.get', 'navigate', 'api.request'])
    const nonce = newNonce()
    for (const method of ['storage.get', 'cookie.get', 'session.token', 'eval', 'fetch', '__proto__', 'context.set']) {
      const response = await handleBridgeRequest(nonce, request(nonce, method), host())
      expect(response).toMatchObject({ ok: false, error: 'message_not_allowed', id: 'r1', nonce })
    }
  })

  it('ignores messages without this mount nonce or protocol', async () => {
    const nonce = newNonce()
    const target = host()
    expect(await handleBridgeRequest(nonce, request('other-nonce', 'context.get'), target)).toBeNull()
    expect(await handleBridgeRequest(nonce, { ...request(nonce, 'context.get'), protocol: 'x/v1' }, target)).toBeNull()
    expect(await handleBridgeRequest(nonce, { ...request(nonce, 'context.get'), id: '<script>' }, target)).toBeNull()
    expect(await handleBridgeRequest(nonce, 'context.get', target)).toBeNull()
    expect(isHello({ protocol: protocolVersion, type: 'cdnca.hello', nonce: 'x' }, nonce)).toBe(false)
    expect(isHello({ protocol: protocolVersion, type: 'cdnca.hello', nonce }, nonce)).toBe(true)
  })

  it('gives non-sensitive context only', async () => {
    const nonce = newNonce()
    const response = await handleBridgeRequest(nonce, request(nonce, 'context.get'), host())
    expect(response?.ok).toBe(true)
    const text = JSON.stringify(response?.result)
    expect(text).not.toMatch(/token|password|cookie|authorization|email|phone/i)
  })

  it('navigates only to in-app paths outside the auth flows', async () => {
    const nonce = newNonce()
    const target = host()
    for (const path of ['https://evil.example/', '//evil.example', 'javascript:alert(1)', '/login', '/account/api',
      '/reset-password?token=x', '/site/../login', 'site/list', '']) {
      expect(validNavigatePath(path)).toBe(false)
      const response = await handleBridgeRequest(nonce, request(nonce, 'navigate', { path }), target)
      expect(response).toMatchObject({ ok: false, error: 'navigate_path_not_allowed' })
    }
    expect(target.navigate).not.toHaveBeenCalled()
    const response = await handleBridgeRequest(nonce, request(nonce, 'navigate', { path: '/site/list?q=a' }), target)
    expect(response?.ok).toBe(true)
    expect(target.navigate).toHaveBeenCalledWith('/site/list?q=a')
  })

  it('forwards only well-formed plugin API calls to the proxy', async () => {
    const nonce = newNonce()
    const target = host()
    for (const params of [
      { method: 'GET', path: 'https://evil.example/x' },
      { method: 'GET', path: '/../admin' },
      { method: 'TRACE', path: '/x' },
      { method: 'GET', path: '/x', body: { a: 1 } },
      { method: 'POST', path: '/x', headers: { Authorization: 'Bearer stolen' } },
      { method: 'GET', path: '/x', query: 'a=<b>' },
    ]) {
      expect(validApiRequest(params)).toBe(false)
      const response = await handleBridgeRequest(nonce, request(nonce, 'api.request', params), target)
      expect(response).toMatchObject({ ok: false, error: 'api_request_invalid' })
    }
    expect(target.apiRequest).not.toHaveBeenCalled()
    const response = await handleBridgeRequest(nonce,
      request(nonce, 'api.request', { method: 'POST', path: '/reports', query: 'range=7d', body: { a: 1 } }), target)
    expect(response).toMatchObject({ ok: true, result: { status: 200, body: { ok: true } } })
    expect(target.apiRequest).toHaveBeenCalledWith({ method: 'POST', path: '/reports', query: 'range=7d', body: { a: 1 } })
  })

  it('reports proxy refusals by code', async () => {
    const nonce = newNonce()
    const target = host()
    target.apiRequest.mockRejectedValueOnce(Object.assign(new Error('x'), { code: 'plugin_ui_site_denied' }))
    const response = await handleBridgeRequest(nonce, request(nonce, 'api.request', { method: 'GET', path: '/x' }), target)
    expect(response).toMatchObject({ ok: false, error: 'plugin_ui_site_denied' })
  })

  it('passes the nonce in the fragment only', () => {
    expect(frameURL('https://ui.acme.example/report', 'abc')).toBe('https://ui.acme.example/report#cdnca-nonce=abc')
    expect(newNonce()).toMatch(/^[A-Za-z0-9_-]{22}$/)
    expect(newNonce()).not.toBe(newNonce())
  })
})

describe('plugin menu pages (PA-19)', () => {
  it('adds pages only under a visible parent group', async () => {
    const { getNavigation, pluginPageRoute, withPluginPages } = await import('../routes/navigation')
    const items = getNavigation('admin', (key) => key, ['sites.read'], [])
    const merged = withPluginPages(items, [
      { parentKey: 'monitor', key: '/plugin-ui/acme.reports/report', label: '报表' },
      { parentKey: 'nowhere', key: '/plugin-ui/acme.reports/other', label: '其他' },
    ])
    const monitor = merged.find((item) => item.key === 'monitor')
    expect(monitor?.children?.at(-1)).toEqual({ key: '/plugin-ui/acme.reports/report', label: '报表', implemented: true })
    expect(JSON.stringify(merged)).not.toContain('/plugin-ui/acme.reports/other')
    expect(pluginPageRoute.test('/plugin-ui/acme.reports/report')).toBe(true)
    expect(pluginPageRoute.test('/plugin-ui/../login')).toBe(false)
  })
})
