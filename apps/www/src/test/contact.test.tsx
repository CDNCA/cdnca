import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '../App'
import { render as ssr } from '../entry-server'
import { href } from '../i18n'
import { allPages } from '../routes'

const ZH_ROWS = [
  ['Telegram', '@cdnca1', 'https://t.me/cdnca1'],
  ['Email', 'cooperate@cdnca.com', 'mailto:cooperate@cdnca.com'],
  ['TG群', 'https://t.me/cdnca', 'https://t.me/cdnca'],
] as const

function mockClipboard(impl: () => Promise<void>) {
  const writeText = vi.fn(impl)
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
  return writeText
}

describe('页脚联系我们弹窗', () => {
  it.each(allPages().flatMap((p) => [href('zh', p.path), href('en', p.path)]))('%s 页脚有联系入口，无 JS 时指向联系页', (url) => {
    const { html } = ssr(url)
    const footer = html.slice(html.indexOf('<footer'))
    const target = url.startsWith('/en') ? '/en/about' : '/about'
    expect(footer).toMatch(new RegExp(`<a href="${target}" aria-haspopup="dialog">`))
  })

  it('不显示备案号字段或占位', () => {
    const { html } = ssr('/')
    expect(html).not.toMatch(/备案|ICP/i)
  })

  it('中文：点击打开，aria-modal、标题副标题、三行联系方式，焦点进入弹窗', async () => {
    const user = userEvent.setup()
    render(<App pathname="/docs" />)
    const footer = screen.getByRole('contentinfo')
    const trigger = within(footer).getByRole('link', { name: '联系我们' })
    await user.click(trigger)
    const dialog = screen.getByRole('dialog', { name: '联系我们' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAccessibleDescription('产品咨询、插件开发、节点供应合作等，均可联系')
    for (const [label, value, link] of ZH_ROWS) {
      expect(within(dialog).getByText(label)).toBeInTheDocument()
      expect(within(dialog).getByRole('link', { name: value })).toHaveAttribute('href', link)
      expect(within(dialog).getByRole('button', { name: `复制 ${label}` })).toBeInTheDocument()
    }
    expect(dialog).toContainElement(document.activeElement as HTMLElement)
  })

  it('Esc 关闭并把焦点还给入口', async () => {
    const user = userEvent.setup()
    render(<App pathname="/" />)
    const trigger = within(screen.getByRole('contentinfo')).getByRole('link', { name: '联系我们' })
    await user.click(trigger)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('关闭按钮与点击遮罩都能关闭', async () => {
    const user = userEvent.setup()
    render(<App pathname="/" />)
    const trigger = within(screen.getByRole('contentinfo')).getByRole('link', { name: '联系我们' })
    await user.click(trigger)
    await user.click(screen.getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(trigger)
    await user.click(document.querySelector('.modal-backdrop') as HTMLElement)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('焦点陷阱：Tab / Shift+Tab 在弹窗内循环', async () => {
    const user = userEvent.setup()
    render(<App pathname="/" />)
    await user.click(within(screen.getByRole('contentinfo')).getByRole('link', { name: '联系我们' }))
    const dialog = screen.getByRole('dialog')
    const close = within(dialog).getByRole('button', { name: '关闭' })
    const lastCopy = within(dialog).getByRole('button', { name: '复制 TG群' })
    expect(close).toHaveFocus()
    await user.tab({ shift: true })
    expect(lastCopy).toHaveFocus()
    await user.tab()
    expect(close).toHaveFocus()
    for (let i = 0; i < 12; i++) {
      await user.tab()
      expect(dialog).toContainElement(document.activeElement as HTMLElement)
    }
  })

  it('复制成功有提示，失败提示手动复制', async () => {
    const user = userEvent.setup()
    render(<App pathname="/" />)
    await user.click(within(screen.getByRole('contentinfo')).getByRole('link', { name: '联系我们' }))
    const dialog = screen.getByRole('dialog')
    const ok = mockClipboard(() => Promise.resolve())
    await user.click(within(dialog).getByRole('button', { name: '复制 Email' }))
    expect(ok).toHaveBeenCalledWith('cooperate@cdnca.com')
    expect(within(dialog).getByRole('status')).toHaveTextContent('已复制：cooperate@cdnca.com')
    mockClipboard(() => Promise.reject(new Error('denied')))
    await user.click(within(dialog).getByRole('button', { name: '复制 Telegram' }))
    expect(within(dialog).getByRole('status')).toHaveTextContent('复制失败，请手动复制')
  })

  it('英文版文案', async () => {
    const user = userEvent.setup()
    render(<App pathname="/en/features" />)
    await user.click(within(screen.getByRole('contentinfo')).getByRole('link', { name: 'Contact' }))
    const dialog = screen.getByRole('dialog', { name: 'Contact us' })
    expect(within(dialog).getByText(/plugin development, node supply partnerships/)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Copy Telegram group' })).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })
})

describe('联系页 /about', () => {
  it('中英文与弹窗同内容', () => {
    render(<App pathname="/about" />)
    const main = screen.getByRole('main')
    expect(within(main).getByRole('heading', { level: 1, name: '联系我们' })).toBeInTheDocument()
    expect(within(main).getByText('产品咨询、插件开发、节点供应合作等，均可联系')).toBeInTheDocument()
    for (const [, value, link] of ZH_ROWS) expect(within(main).getByRole('link', { name: value })).toHaveAttribute('href', link)
    expect(within(main).queryByText(/即将公布/)).not.toBeInTheDocument()
    const en = ssr('/en/about').html
    expect(en).toContain('Contact us')
    expect(en).toContain('cooperate@cdnca.com')
  })
})

describe('Esc 在焦点离开可聚焦元素时也生效', () => {
  it('焦点在 body 上按 Esc 关闭', async () => {
    const user = userEvent.setup()
    render(<App pathname="/" />)
    await user.click(within(screen.getByRole('contentinfo')).getByRole('link', { name: '联系我们' }))
    ;(document.activeElement as HTMLElement).blur()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
