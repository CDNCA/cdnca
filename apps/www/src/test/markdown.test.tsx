import { render } from '@testing-library/react'
import type { DocBlock as Block } from '../content/docs'
import { DOC_LINK_TARGET, headingId, parseInline, parseMarkdown, plainText } from '../content/markdown'
import { renderBlock } from '../pages/Docs'

const one = (md: string) => parseMarkdown(md)
const html = (md: string, lang: 'zh' | 'en' = 'zh') => {
  const { container } = render(<div>{one(md).map((b, i) => renderBlock(b, lang, i))}</div>)
  return container
}

describe('受限 Markdown：站内链接', () => {
  it('只认 /docs/<slug>、/docs/<slug>#<id> 与 #<id>', () => {
    expect(parseInline('见[主控安装](/docs/install-control)。')).toEqual(['见', { text: '主控安装', href: '/docs/install-control' }, '。'])
    expect(parseInline('[刷新](/docs/tenant-guide#cache)')).toEqual([{ text: '刷新', href: '/docs/tenant-guide#cache' }])
    expect(parseInline('[上一节](#before-you-start) 和 [下一节](#next)')).toEqual([
      { text: '上一节', href: '#before-you-start' }, ' 和 ', { text: '下一节', href: '#next' },
    ])
    for (const ok of ['/docs/a', '/docs/a-b-1', '/docs/a#x.y_z', '#a']) expect(DOC_LINK_TARGET.test(ok), ok).toBe(true)
  })

  it('其他目标一律按原文显示为文字', () => {
    for (const bad of [
      '[x](https://www.cdnca.com/)', '[x](http://a)', '[x](//evil.example/docs/a)', '[x](javascript:alert(1))',
      '[x](JavaScript:alert)', '[x](  javascript:alert)', '[x](data:text/html,1)', '[x](mailto:a@b.c)', '[x](vbscript:x)',
      '[x](install-control)', '[x](/docs/Install)', '[x](/docs/../admin)', '[x](/developers/api)', '[x](/docs/a b)',
      '[x](/docs/a"onmouseover=alert(1))', '[x](#)', '[x](/docs/)', '[x]( /docs/a)',
    ]) {
      expect(parseInline(bad), bad).toBe(bad)
      expect(DOC_LINK_TARGET.test(bad.slice(4, -1)), bad).toBe(false)
    }
    expect(parseInline('填写 [可选] 字段，f(x) 不是链接')).toBe('填写 [可选] 字段，f(x) 不是链接')
  })

  it('XSS：渲染后只有站内 <a>，没有脚本、事件属性或危险协议', () => {
    const md = [
      '<script>alert(1)</script> [安全](/docs/plugins)',
      '',
      '- [<img src=x onerror=alert(1)>](/docs/plugins)',
      '- [点我](javascript:alert(document.cookie))',
      '',
      '> [x](data:text/html;base64,PHNjcmlwdD4=) 与 [y](#ok)',
      '',
      '| a | b |',
      '| --- | --- |',
      '| [c](/docs/a" onclick="x) | [d](/docs/install-node#初始化) |',
    ].join('\n')
    const c = html(md)
    expect(c.querySelector('script, img, [onerror], [onclick]')).toBeNull()
    const hrefs = [...c.querySelectorAll('a')].map((a) => a.getAttribute('href'))
    expect(hrefs).toEqual(['/docs/plugins', '/docs/plugins', '#ok'])
    for (const h of hrefs) expect(h).toMatch(/^(\/docs\/|#)/)
    // 链接文字也是文本节点：尖括号原样显示，不成为元素
    expect(c.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(c.textContent).toContain('[点我](javascript:alert(document.cookie))')
    expect(c.textContent).toContain('<script>alert(1)</script>')
  })

  it('英文页的 /docs 链接加 /en 前缀，锚点链接不变', () => {
    const hrefs = [...html('[a](/docs/plugins#x) [b](#y)', 'en').querySelectorAll('a')].map((a) => a.getAttribute('href'))
    expect(hrefs).toEqual(['/en/docs/plugins#x', '#y'])
  })

  it('命令块里的方括号不解析', () => {
    const [b] = one("```\necho '[x](/docs/a)'\n```") as [Extract<Block, { cmd: string }>]
    expect(b.cmd).toBe("echo '[x](/docs/a)'")
  })
})

describe('受限 Markdown：标题锚点', () => {
  it('{#id} 指定锚点；未指定时按标题生成；重复加序号', () => {
    const hs = one('## 准备 {#before-you-start}\n\n## Install the Node\n\n### 安装节点\n\n## 安装节点\n\n#### 深层').filter((b): b is Extract<Block, { h: unknown }> => 'h' in b)
    expect(hs.map((h) => [h.h.zh, h.level, h.id])).toEqual([
      ['准备', 2, 'before-you-start'], ['Install the Node', 2, 'install-the-node'], ['安装节点', 3, '安装节点'], ['安装节点', 2, '安装节点-2'], ['深层', 3, '深层'],
    ])
    expect(headingId('  A / B：c?  ')).toBe('a-bc')
    expect(headingId('Step 1: Install')).toBe('step-1-install')
    expect(headingId('!!!')).toBe('section')
  })

  it('非法 {#...} 不当锚点，保留在标题文字里', () => {
    const [h] = one('## 标题 {#Bad Id}') as [Extract<Block, { h: unknown }>]
    expect(h.h.zh).toBe('标题 {#Bad Id}')
  })

  it('渲染出 h2/h3 的 id，可被 #锚点 链接到', () => {
    const c = html('## 一 {#one}\n\n### 二\n\n见[一](#one)')
    expect(c.querySelector('h2#one')).not.toBeNull()
    expect(c.querySelector('h3')?.id).toBe('二')
    expect(c.querySelector('a')?.getAttribute('href')).toBe('#one')
  })

  it('plainText 去掉链接语法', () => {
    expect(plainText(parseInline('先看[入口](/docs/getting-started#entries)再登录'))).toBe('先看入口再登录')
  })
})
