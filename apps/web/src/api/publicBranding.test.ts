import { vi } from 'vitest'

import { publicBranding } from './publicBranding'

vi.unmock('./publicBranding')

// 登录页匿名读系统名称，不带会话与 Cookie。
describe('publicBranding', () => {
  it('reads the anonymous branding subset without credentials', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      system_name: '云盾', user_title: '云盾用户控制台', admin_title: '云盾管理后台',
    }), { status: 200 }))
    await expect(publicBranding()).resolves.toEqual({ systemName: '云盾', userTitle: '云盾用户控制台', adminTitle: '云盾管理后台' })
    const [url, init] = fetchSpy.mock.calls[0]
    expect(String(url)).toMatch(/\/v1\/system-settings\/public$/)
    expect(init?.credentials).toBe('omit')
    expect(new Headers(init?.headers).has('Authorization')).toBe(false)
  })

  it.each([
    ['an error status', new Response('{}', { status: 503 })],
    ['extra fields', new Response(JSON.stringify({ system_name: 'a', user_title: 'b', admin_title: 'c', global_js: 'x' }), { status: 200 })],
    ['a non-string name', new Response(JSON.stringify({ system_name: 1, user_title: 'b', admin_title: 'c' }), { status: 200 })],
  ])('returns null for %s', async (_case, response) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response)
    await expect(publicBranding()).resolves.toBeNull()
  })
})
