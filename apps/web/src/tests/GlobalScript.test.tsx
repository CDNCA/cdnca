import { waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { systemSettingsApi } from '../api/systemSettings'
import { useSessionStore } from '../auth/session'
import { GlobalScript, globalScriptSafeMode, injectGlobalScript } from '../components/GlobalScript'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const marker = 'script[data-cdnca-global-js]'

function signIn(overrides: Parameters<typeof principal>[0] = {}) {
  const user = principal(overrides)
  useSessionStore.getState().setSession(authResponse(user), user)
}

describe('全站JS代码（NF26）', () => {
  beforeEach(() => {
    sessionStorage.clear()
    window.history.replaceState(null, '', '/home')
    vi.spyOn(systemSettingsApi, 'public').mockResolvedValue({ system_name: 'cdnca', user_title: '', admin_title: '', purchase_notice: '', global_js: 'window.__cdncaGlobal = 1' })
  })
  afterEach(() => {
    document.querySelectorAll('[data-cdnca-global-js]').forEach((node) => node.remove())
  })

  it('注入的 <script> 带页面 CSP nonce，不依赖 unsafe-inline；片段里自带的 nonce 不被采用', () => {
    const page = document.createElement('script')
    page.nonce = 'page-nonce-0123456789abcdef'
    document.head.append(page)
    try {
      const remove = injectGlobalScript('<script nonce="forged">window.__a = 1</script><script src="https://stats.example.com/a.js"></script>')
      const injected = Array.from(document.querySelectorAll<HTMLScriptElement>(marker))
      expect(injected).toHaveLength(2)
      expect(injected.map((script) => script.nonce)).toEqual(['page-nonce-0123456789abcdef', 'page-nonce-0123456789abcdef'])
      remove()
      const removePlain = injectGlobalScript('window.__b = 1')
      expect(document.querySelector<HTMLScriptElement>(marker)?.nonce).toBe('page-nonce-0123456789abcdef')
      removePlain()
    } finally {
      page.remove()
    }
  })

  it('页面没有 nonce（开发服务器/原生安装）时不设置 nonce', () => {
    const remove = injectGlobalScript('window.__c = 1')
    expect(document.querySelector<HTMLScriptElement>(marker)?.nonce).toBe('')
    remove()
  })

  it('租户用户页面注入全站 JS，卸载时移除', async () => {
    signIn()
    const view = renderWithProviders(<GlobalScript />, ['/home'])
    await waitFor(() => expect(document.querySelector(marker)).not.toBeNull())
    expect(document.querySelector(marker)?.textContent).toBe('window.__cdncaGlobal = 1')
    expect(systemSettingsApi.public).toHaveBeenCalledWith('memory-only-access-token')
    view.unmount()
    expect(document.querySelector(marker)).toBeNull()
  })

  it('管理员会话与代登录会话都不加载', async () => {
    signIn({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'] })
    const admin = renderWithProviders(<GlobalScript />, ['/admin-home'])
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(systemSettingsApi.public).not.toHaveBeenCalled()
    expect(document.querySelector(marker)).toBeNull()
    admin.unmount()

    signIn({ impersonation: {
      grant_id: '33333333-3333-4333-8333-333333333333', actor_user_id: '44444444-4444-4444-8444-444444444444',
      actor_display_name: 'admin', subject_user_id: '11111111-1111-4111-8111-111111111111', subject_display_name: 'jason',
      tenant_id: '22222222-2222-4222-8222-222222222222', expires_at: '2099-01-01T00:00:00Z',
    } })
    renderWithProviders(<GlobalScript />, ['/home'])
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(systemSettingsApi.public).not.toHaveBeenCalled()
  })

  it('安全模式 ?safe_mode=1 在本标签页禁用，?safe_mode=0 恢复', async () => {
    window.history.replaceState(null, '', '/home?safe_mode=1')
    signIn()
    renderWithProviders(<GlobalScript />, ['/home'])
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(systemSettingsApi.public).not.toHaveBeenCalled()
    expect(document.querySelector(marker)).toBeNull()

    window.history.replaceState(null, '', '/site/list')
    expect(globalScriptSafeMode()).toBe(true)
    window.history.replaceState(null, '', '/site/list?safe_mode=0')
    expect(globalScriptSafeMode()).toBe(false)
  })

  it('HTML 片段里的 <script> 重新创建以便执行，其他节点原样保留', () => {
    const remove = injectGlobalScript('<script src="https://stats.example.test/a.js" async></script><noscript><img src="https://stats.example.test/p.gif"></noscript><script>window.__inline = 1</script>')
    const scripts = Array.from(document.querySelectorAll<HTMLScriptElement>(marker))
    expect(scripts).toHaveLength(2)
    expect(scripts[0].getAttribute('src')).toBe('https://stats.example.test/a.js')
    expect(scripts[0].hasAttribute('async')).toBe(true)
    expect(scripts[1].text).toBe('window.__inline = 1')
    expect(document.querySelector('noscript[data-cdnca-global-js]')).not.toBeNull()
    remove()
    expect(document.querySelectorAll('[data-cdnca-global-js]')).toHaveLength(0)
  })
})
