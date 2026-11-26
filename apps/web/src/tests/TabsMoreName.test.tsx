import { fireEvent, render, screen } from '@testing-library/react'
import { ConfigProvider, Tabs } from 'antd'
import { afterEach, describe, expect, it } from 'vitest'

import { Tabs as LocalizedTabs } from '../components/Tabs'
import { useTabsConfig } from '../components/tabsConfig'
import { changeLocale } from '../i18n'

function Bar() {
  return <ConfigProvider tabs={useTabsConfig()}>
    <Tabs items={Array.from({ length: 12 }, (_, index) => ({ key: String(index), label: `页签 ${index}` }))} />
  </ConfigProvider>
}

// jsdom has no layout, so antd keeps the overflow button at visibility: hidden; show it as on a narrow screen.
function moreButton() {
  const more = document.querySelector<HTMLButtonElement>('.ant-tabs-nav-more')!
  more.style.visibility = 'visible'
  return more
}

// 所有页签栏的「更多」触发按钮读作「更多页签」（不是英文 ellipsis），随语言切换。
describe('tab bar overflow trigger', () => {
  it('is named 更多页签, More tabs in English', async () => {
    await changeLocale('zh-CN')
    const view = render(<Bar />)
    const more = moreButton()
    expect(screen.getByRole('button', { name: '更多页签' })).toBe(more)
    expect(screen.queryByRole('button', { name: 'ellipsis' })).toBeNull()
    await changeLocale('en-US')
    view.rerender(<Bar />)
    const english = moreButton()
    expect(screen.getByRole('button', { name: 'More tabs' })).toBe(english)
    await changeLocale('zh-CN')
  })
})

// jsdom 没有布局：给页签 100px 宽、按序排开，导航容器只有 150px，rc-tabs 挂载时量出放不下的页签收进「更多」。
const layoutProps = ['offsetWidth', 'offsetLeft'] as const
const originals = layoutProps.map((name) => [name, Object.getOwnPropertyDescriptor(HTMLElement.prototype, name)] as const)
function narrowLayout() {
  Object.defineProperty(HTMLElement.prototype, 'offsetWidth', { configurable: true, get(this: HTMLElement) {
    if (this.classList.contains('ant-tabs-tab')) return 100
    if (this.classList.contains('ant-tabs-nav-wrap')) return 150
    return 0
  } })
  Object.defineProperty(HTMLElement.prototype, 'offsetLeft', { configurable: true, get(this: HTMLElement) {
    if (!this.classList.contains('ant-tabs-tab')) return 0
    return Array.from(this.parentElement?.querySelectorAll(':scope > .ant-tabs-tab') ?? []).indexOf(this) * 100
  } })
}
afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(HTMLElement.prototype, name, descriptor)
  }
})

// 「更多」展开的页签列表可访问名是本地化的「其余页签」，不是 rc-tabs 默认的英文 expanded dropdown。
describe('tab bar overflow list', () => {
  it('is named 其余页签 (Other tabs in English) on every tab bar from the shared Tabs', async () => {
    await changeLocale('zh-CN')
    narrowLayout()
    const items = Array.from({ length: 6 }, (_, index) => ({ key: String(index), label: `页签 ${index}`, children: `内容 ${index}` }))
    const view = render(<LocalizedTabs items={items} />)
    fireEvent.mouseEnter(document.querySelector('.ant-tabs-nav-more')!)
    const list = await screen.findByRole('listbox')
    expect(list).toHaveAccessibleName('其余页签')
    expect(screen.queryByRole('listbox', { name: 'expanded dropdown' })).toBeNull()
    expect(screen.getAllByRole('option').length).toBeGreaterThan(0)
    view.unmount()

    await changeLocale('en-US')
    render(<LocalizedTabs items={items} />)
    fireEvent.mouseEnter(document.querySelector('.ant-tabs-nav-more')!)
    expect(await screen.findByRole('listbox', { name: 'Other tabs' })).toBeInTheDocument()
    await changeLocale('zh-CN')
  })
})
