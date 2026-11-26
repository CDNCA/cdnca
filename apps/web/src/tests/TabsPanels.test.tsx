import { fireEvent, render, screen } from '@testing-library/react'
import { useEffect } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { Tabs } from '../components/Tabs'

function Loader({ name, onLoad }: { name: string; onLoad: (name: string) => void }) {
  useEffect(() => onLoad(name), [name, onLoad])
  return <p>{name} 正文</p>
}

function controlsResolve() {
  for (const tab of screen.getAllByRole('tab', { hidden: true })) {
    const id = tab.getAttribute('aria-controls')
    expect(id).toBeTruthy()
    const panel = document.getElementById(id!)
    expect(panel, `aria-controls ${id}`).not.toBeNull()
    expect(panel!.getAttribute('role')).toBe('tabpanel')
  }
}

// 从未激活过的页签也有面板外壳，正文不提前挂载。
describe('Tabs panel shells', () => {
  it('resolves every aria-controls on a direct open without mounting inactive content', () => {
    const onLoad = vi.fn()
    render(<Tabs defaultActiveKey="sold" items={[
      { key: 'manage', label: '管理', children: <Loader name="manage" onLoad={onLoad} /> },
      { key: 'sold', label: '已售', children: <Loader name="sold" onLoad={onLoad} /> },
    ]} />)
    controlsResolve()
    expect(onLoad.mock.calls.map(([name]) => name)).toEqual(['sold'])
    const inactive = document.getElementById(screen.getByRole('tab', { name: '管理' }).getAttribute('aria-controls')!)!
    expect(inactive.getAttribute('aria-hidden')).toBe('true')
    expect(getComputedStyle(inactive).display).toBe('none')
    expect(screen.queryByText('manage 正文')).toBeNull()

    fireEvent.click(screen.getByRole('tab', { name: '管理' }))
    expect(screen.getByText('manage 正文')).toBeTruthy()
    expect(onLoad.mock.calls.map(([name]) => name)).toEqual(['sold', 'manage'])
    controlsResolve()
  })

  it('keeps the page pattern children: key === tab ? content : null and explicit forceRender', () => {
    const view = render(<Tabs activeKey="a" items={[
      { key: 'a', label: 'A', children: 'A 正文' },
      { key: 'b', label: 'B', children: null },
      { key: 'c', label: 'C', children: 'C 表单', forceRender: true },
    ]} />)
    controlsResolve()
    expect(screen.getByText('C 表单')).toBeTruthy()
    view.rerender(<Tabs activeKey="b" items={[
      { key: 'a', label: 'A', children: null },
      { key: 'b', label: 'B', children: 'B 正文' },
      { key: 'c', label: 'C', children: 'C 表单', forceRender: true },
    ]} />)
    expect(screen.getByText('B 正文')).toBeTruthy()
    controlsResolve()
  })

  it('unmounts left content when destroyOnHidden', () => {
    const view = render(<Tabs activeKey="a" destroyOnHidden items={[
      { key: 'a', label: 'A', children: 'A 正文' },
      { key: 'b', label: 'B', children: 'B 正文' },
    ]} />)
    view.rerender(<Tabs activeKey="b" destroyOnHidden items={[
      { key: 'a', label: 'A', children: 'A 正文' },
      { key: 'b', label: 'B', children: 'B 正文' },
    ]} />)
    expect(screen.queryByText('A 正文')).toBeNull()
    controlsResolve()
  })
})

// rc-tabs 聚焦时插入的英文「Tab N of M」不进可访问树。
describe('Tabs focus announcement', () => {
  it('hides the hard-coded English position live region', () => {
    render(<Tabs items={[{ key: 'a', label: '用户列表' }, { key: 'b', label: '用户分组' }]} />)
    const tab = screen.getByRole('tab', { name: '用户列表' })
    fireEvent.focus(tab)
    const live = tab.querySelector('[aria-live]')
    expect(live?.textContent).toBe('Tab 1 of 2')
    expect(getComputedStyle(live!).display).toBe('none')
    expect(screen.getByRole('tab', { name: '用户列表' })).toBe(tab)
  })
})
