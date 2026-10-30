import { act, render, screen, within } from '@testing-library/react'
import { App } from '../App'
import { parseMarkdown } from '../content/markdown'
import { loadSiteContent, normalize, safeHref, SEED, setSiteContent, SITE_CONTENT_PATH, type SiteContent } from '../content/siteContent'

const LOGO = `${SITE_CONTENT_PATH}/assets/${'a'.repeat(64)}`

function published(over: Partial<SiteContent> = {}) {
  return {
    schema: 'cdnca.site-content/v1',
    releases: [{ version: '1.0.36', date: '2026-11-01', notes: { zh: ['新增：后台编辑官网内容'], en: ['New: edit the website from the operator console'] } }, ...SEED.releases],
    docs: [...SEED.docs, { slug: 'faq', title: { zh: '常见问答', en: 'FAQ' }, description: { zh: '运营新增的文档页', en: 'A page added by the operator' }, body: { zh: '## 第一问\n\n答案在这里。', en: '## First\n\nThe answer.' } }],
    contact: { ...SEED.contact, items: [...SEED.contact.items, { kind: 'other', label: { zh: '工单', en: 'Tickets' }, value: 'support.example.com', href: 'javascript:alert(1)' }] },
    brand: { site_name: 'cdnca', logo: LOGO, favicon: null },
    ...over,
  }
}

function mockFetch(impl: () => Promise<Response>) {
  const fn = vi.fn(impl)
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => setSiteContent(SEED))

describe('受限 Markdown', () => {
  it('HTML、脚本与事件属性只作为文字渲染，不产生任何元素', () => {
    const body = '## <img src=x onerror=alert(1)>\n\n<script>alert(1)</script> 与 <a href="javascript:x">链接</a>\n\n- <b>粗</b>\n\n| <i>a</i> | b |\n| --- | --- |\n| <svg onload=1> | c |\n\n```<b>标签</b>\n<script>x</script>\n```'
    const doc = { slug: 'install-node', title: { zh: '节点安装', en: 'Install a node' }, description: SEED.docs[0].description, body: { zh: body, en: body } }
    act(() => setSiteContent({ ...SEED, docs: [doc] }))
    const { container } = render(<App pathname="/docs/install-node" />)
    const article = container.querySelector('article')!
    for (const tag of ['script', 'img', 'b', 'i', 'svg']) expect(article.querySelector(tag), tag).toBeNull()
    // 唯一的 <a> 是页头“查看文档目录”的站内跳转；正文里写的 <a href="javascript:…"> 只是文字
    expect([...article.querySelectorAll('a')].map((a) => a.getAttribute('href'))).toEqual(['#docs-nav'])
    expect(article.textContent).toContain('<script>alert(1)</script>')
    expect(within(article).getByRole('heading', { level: 2 })).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(article.querySelector('pre')).toHaveAttribute('aria-label', '<b>标签</b>')
  })

  it('块语法：标题、段落合并、提示、有序/无序列表、命令块与表格', () => {
    expect(parseMarkdown('## 标题\n第一行\n第二行\n\n> 提示一\n> 提示二\n\n1. 甲\n2. 乙\n- 丙\n\n```命令\nbash x.sh --yes\n```\n| a | b |\n| --- | --- |\n| 1 | 2 |')).toEqual([
      { h: { zh: '标题', en: '标题' }, level: 2, id: '标题' },
      { p: { zh: '第一行 第二行', en: '第一行 第二行' } },
      { note: { zh: '提示一 提示二', en: '提示一 提示二' } },
      { list: [{ zh: '甲', en: '甲' }, { zh: '乙', en: '乙' }], ordered: true },
      { list: [{ zh: '丙', en: '丙' }] },
      { cmd: 'bash x.sh --yes', label: { zh: '命令', en: '命令' } },
      { table: { head: [{ zh: 'a', en: 'a' }, { zh: 'b', en: 'b' }], rows: [[{ zh: '1', en: '1' }, { zh: '2', en: '2' }]] } },
    ])
  })

  it('联系方式链接只放行 https 与 mailto', () => {
    expect(safeHref('https://t.me/cdnca')).toBe('https://t.me/cdnca')
    expect(safeHref('mailto:a@example.com')).toBe('mailto:a@example.com')
    for (const bad of ['javascript:alert(1)', 'http://t.me/x', 'data:text/html,1', '//evil.example', ' https://x']) expect(safeHref(bad), bad).toBeUndefined()
  })
})

describe('官网取数', () => {
  it('成功：同源无凭据读取，替换更新日志、文档目录、联系方式与 logo；新增文档页可打开', async () => {
    const fetchMock = mockFetch(async () => new Response(JSON.stringify(published()), { status: 200 }))
    expect(await loadSiteContent()).toBe(true)
    expect(fetchMock).toHaveBeenCalledWith(SITE_CONTENT_PATH, expect.objectContaining({ credentials: 'omit' }))

    const changelog = render(<App pathname="/changelog" />)
    expect(screen.getByRole('heading', { level: 2, name: '1.0.36' })).toBeInTheDocument()
    expect(screen.getByText('新增：后台编辑官网内容')).toBeInTheDocument()
    expect(document.querySelector('.site-header img.brand-logo')).toHaveAttribute('src', LOGO)
    changelog.unmount()

    const faq = render(<App pathname="/en/docs/faq" />)
    expect(screen.getByRole('heading', { level: 1, name: 'FAQ' })).toBeInTheDocument()
    expect(within(screen.getByRole('navigation', { name: 'Docs' })).getByRole('link', { name: 'FAQ' })).toHaveAttribute('aria-current', 'page')
    faq.unmount()

    render(<App pathname="/about" />)
    const row = screen.getByText('support.example.com')
    expect(row.tagName).toBe('SPAN') // javascript: 链接不渲染成 <a>
  })

  it.each([
    ['网络错误', () => Promise.reject(new TypeError('offline'))],
    ['非 2xx', async () => new Response('{}', { status: 502 })],
    ['不是 JSON', async () => new Response('<html>', { status: 200 })],
    ['schema 不对', async () => new Response(JSON.stringify({ ...published(), schema: 'x' }), { status: 200 })],
    ['文档 slug 不合法', async () => new Response(JSON.stringify(published({ docs: [{ ...SEED.docs[0], slug: '../x' }] })), { status: 200 })],
    ['logo 不是同源资源', async () => new Response(JSON.stringify(published({ brand: { site_name: 'cdnca', logo: 'https://evil.example/x.png', favicon: null } })), { status: 200 })],
  ])('失败兜底（%s）：保留预渲染内容', async (_name, impl) => {
    mockFetch(impl as () => Promise<Response>)
    const ok = await loadSiteContent()
    render(<App pathname="/changelog" />)
    if (_name === 'logo 不是同源资源') {
      // 品牌部分不合格时只沿用默认品牌，其余内容照常替换
      expect(ok).toBe(true)
      expect(document.querySelector('.site-header img')).toBeNull()
      return
    }
    expect(ok).toBe(false)
    expect(screen.queryByText('1.0.36')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2, name: '1.0.35' })).toBeInTheDocument()
  })

  it('联系我们未发布（null）时沿用当前联系方式', () => {
    const next = normalize({ ...published(), contact: null }, SEED)!
    expect(next.contact).toEqual(SEED.contact)
    expect(next.docs.at(-1)!.slug).toBe('faq')
  })
})
