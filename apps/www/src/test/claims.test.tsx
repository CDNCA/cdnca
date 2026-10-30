import { renderToString } from 'react-dom/server'

// 定价口径集中在 content/claims.ts：置 null 后全站不再出现“主控免费”，主 CTA 换中性文字。
describe('FREE_CLAIM 关闭时', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock('../content/claims', async (orig) => ({ ...(await orig<typeof import('../content/claims')>()), FREE_CLAIM: null }))
  })
  afterEach(() => vi.doUnmock('../content/claims'))

  it('首页与功能页不再出现“免费”宣传', async () => {
    const { App } = await import('../App')
    const html = ['/', '/features', '/features/waf', '/en/'].map((p) => renderToString(<App pathname={p} />)).join('')
    expect(html).not.toContain('主控免费')
    expect(html).not.toContain('>免费使用<')
    expect(html).not.toContain('The control plane is free')
    expect(html).toContain('注册并开始')
  })
})
