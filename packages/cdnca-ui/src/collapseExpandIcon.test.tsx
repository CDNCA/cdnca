import { act, fireEvent, render, screen } from '@testing-library/react'
import { Collapse } from 'antd'
import { describe, expect, it } from 'vitest'

import { CdncaProvider } from './index'

// The shared root hides antd's English "expanded" / "collapsed" arrow label from screen readers; the header keeps
// aria-expanded.
describe('Collapse arrow', () => {
  it('names the header by its label only', () => {
    render(<CdncaProvider><Collapse items={[{ key: 'a', label: '套餐带宽预警', children: 'x' }]} /></CdncaProvider>)
    const header = screen.getByRole('button', { name: '套餐带宽预警' })
    expect(header).toHaveAttribute('aria-expanded', 'false')
    expect(document.querySelector('[aria-label="collapsed"],[aria-label="expanded"]')).toBeNull()
  })
})

// Space opens and closes the
// header like Enter, once per press (nested providers too), without the page scrolling; focus stays on the header.
describe('Collapse header keyboard', () => {
  it('toggles on Space and on Enter', () => {
    render(<CdncaProvider><CdncaProvider><Collapse items={[{ key: 'a', label: '诊断详情', children: '连接池' }]} /></CdncaProvider></CdncaProvider>)
    const header = screen.getByRole('button', { name: '诊断详情' })
    header.focus()
    const space = new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true })
    act(() => { header.dispatchEvent(space) })
    expect(space.defaultPrevented).toBe(true)
    expect(header).toHaveAttribute('aria-expanded', 'true')
    expect(header).toHaveFocus()
    act(() => { header.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true, repeat: true })) })
    expect(header).toHaveAttribute('aria-expanded', 'true')
    act(() => { header.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true })) })
    expect(header).toHaveAttribute('aria-expanded', 'false')
    fireEvent.keyDown(header, { key: 'Enter' })
    expect(header).toHaveAttribute('aria-expanded', 'true')
  })

  it('leaves Space alone outside collapse headers and on disabled headers', () => {
    render(<CdncaProvider><input aria-label="名称" /><Collapse items={[{ key: 'a', label: '只读', children: 'x', collapsible: 'disabled' }]} /></CdncaProvider>)
    const typing = new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true })
    act(() => { screen.getByRole('textbox', { name: '名称' }).dispatchEvent(typing) })
    expect(typing.defaultPrevented).toBe(false)
    const header = screen.getByRole('button', { name: '只读' })
    act(() => { header.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true })) })
    expect(header).toHaveAttribute('aria-expanded', 'false')
  })
})
