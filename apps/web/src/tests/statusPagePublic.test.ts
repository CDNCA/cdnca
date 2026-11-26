import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// 公开状态页 /status/（apps/web 第二入口）：未开启时接口回 404 status_page_disabled，
// 页面要显示「状态页未开启」（中英文），开启后照常显示（consolefix）。
// 页面骨架直接取 status/index.html 的 body（去掉入口脚本），与真实页面一致。
const html = readFileSync(resolve(__dirname, '../../status/index.html'), 'utf8')
const body = html.slice(html.indexOf('<body>') + 6, html.indexOf('</body>')).replace(/<script[^>]*><\/script>/g, '')

const view = {
  schema: 'cdnca.status-page/v2', title: '服务状态', show_logo: false, status: 'operational',
  components: [{ key: 'c1', name: { zh: '华东线路', en: 'East line' }, note: { zh: '', en: '' }, status: 'operational', uptime_90d: 1, history: [] }],
  active: [], upcoming: [], recent: [], generated_at: '2026-11-12T00:00:00Z',
}

async function open(search: string, response: Response) {
  document.body.innerHTML = body
  window.history.replaceState(null, '', `/status/${search}`)
  const fetcher = vi.fn().mockResolvedValue(response)
  vi.stubGlobal('fetch', fetcher)
  vi.resetModules()
  await import('../status/main')
  // 加载结束的标志：main 的 aria-busy 回到 false（骨架本身就有子元素，不能按子元素数判断）。
  await vi.waitFor(() => expect(document.getElementById('status-main')).toHaveAttribute('aria-busy', 'false'))
  return fetcher
}

describe('public status page', () => {
  beforeEach(() => { vi.useRealTimers() })
  afterEach(() => { vi.unstubAllGlobals(); document.body.innerHTML = '' })

  it('shows the "not enabled" page in Chinese when the API answers status_page_disabled', async () => {
    const fetcher = await open('?lang=zh', new Response(JSON.stringify({ error: { code: 'status_page_disabled' } }), { status: 404 }))
    const main = document.getElementById('status-main')!
    expect(fetcher).toHaveBeenCalledWith('/v1/status-page/public', expect.anything())
    expect(main.textContent).toContain('状态页未开启')
    expect(main.textContent).toContain('服务方尚未公开状态页。')
    // 不是官网的 404 页，也不带重试按钮（未开启不是故障）。
    expect(main.textContent).not.toContain('页面不存在')
    expect(main.querySelector('button')).toBeNull()
  })

  it('shows the "not enabled" page in English', async () => {
    await open('?lang=en', new Response('{}', { status: 404 }))
    const main = document.getElementById('status-main')!
    expect(main.textContent).toContain('Status page is not enabled')
    expect(main.textContent).toContain('The provider has not made its status page public.')
    expect(document.documentElement.lang).toBe('en')
  })

  it('renders the components as usual once the page is enabled', async () => {
    await open('?lang=zh', new Response(JSON.stringify(view), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const main = document.getElementById('status-main')!
    expect(main.textContent).toContain('华东线路')
    expect(main.textContent).not.toContain('状态页未开启')
    expect(document.title).toBe('服务状态')
  })

  it('names main 「服务状态」 and only marks it busy, with a status message, while the request is in flight', async () => {
    document.body.innerHTML = body
    window.history.replaceState(null, '', '/status/?lang=zh')
    let answer: (response: Response) => void = () => {}
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((done) => { answer = done })))
    vi.resetModules()
    await import('../status/main')
    const main = screen.getByRole('main', { name: '服务状态' })
    expect(main).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('status')).toHaveTextContent('正在加载服务状态')
    answer(new Response(JSON.stringify(view), { status: 200 }))
    await vi.waitFor(() => expect(main).toHaveAttribute('aria-busy', 'false'))
    expect(screen.getByRole('main', { name: '服务状态' })).toBe(main)
    expect(main.textContent).not.toContain('正在加载服务状态')
  })

  it.each([
    ['disabled', new Response('{}', { status: 404 }), '状态页未开启'],
    ['public', new Response(JSON.stringify(view), { status: 200 }), '华东线路'],
  ])('keeps the main landmark named 「服务状态」 once the %s page has loaded', async (_, response, text) => {
    await open('?lang=zh', response)
    const main = screen.getByRole('main', { name: '服务状态' })
    expect(main).toHaveAttribute('aria-busy', 'false')
    expect(main.textContent).toContain(text)
    expect(main.textContent).not.toContain('正在加载服务状态')
  })

  it('names main "Service status" in English', async () => {
    await open('?lang=en', new Response(JSON.stringify(view), { status: 200 }))
    expect(screen.getByRole('main', { name: 'Service status' })).toHaveAttribute('aria-busy', 'false')
  })

  it('credits the brand in the footer only when the brand is on and named', async () => {
    const footer = () => document.getElementById('status-footer')!
    await open('?lang=zh', new Response(JSON.stringify({ ...view, title: ' Acme 云 ', show_logo: true }), { status: 200 }))
    expect(footer()).toBeVisible()
    expect(footer()).toHaveTextContent('由 Acme 云 提供')
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Acme 云')

    for (const settings of [{ title: 'Acme 云', show_logo: false }, { title: '', show_logo: true }, { title: '服务状态', show_logo: true }, { title: 'Service status', show_logo: true }]) {
      await open('?lang=zh', new Response(JSON.stringify({ ...view, ...settings }), { status: 200 }))
      expect(footer(), JSON.stringify(settings)).not.toBeVisible()
      expect(footer(), JSON.stringify(settings)).toBeEmptyDOMElement()
      expect(document.body.textContent).not.toContain('提供')
    }
  })

  it('shows no footer credit on the "not enabled" page', async () => {
    await open('?lang=zh', new Response('{}', { status: 404 }))
    expect(document.getElementById('status-footer')).not.toBeVisible()
    expect(document.getElementById('status-footer')).toBeEmptyDOMElement()
  })
})
