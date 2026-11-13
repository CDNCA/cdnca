import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// 公开状态页 /status/（apps/web 第二入口）：未开启时接口回 404 status_page_disabled，
// 页面要显示「状态页未开启」（中英文），开启后照常显示。
const body = `
  <div class="st-page">
    <header class="st-header">
      <img id="status-logo" class="st-logo" alt="" width="32" height="32" hidden />
      <h1 id="status-title" class="st-title"></h1>
      <a id="status-lang" class="st-lang" href="?lang=en"></a>
    </header>
    <main id="status-main" aria-busy="false"></main>
    <footer id="status-footer" class="st-footer st-muted"></footer>
  </div>`

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
  await vi.waitFor(() => expect(document.getElementById('status-main')!.children.length).toBeGreaterThan(0))
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
})
