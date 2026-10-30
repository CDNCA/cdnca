import { fireEvent, render as rtlRender, screen, within } from '@testing-library/react'
import { useState, type ReactElement } from 'react'
import { Input } from 'antd'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AdvancedFilters, CdncaProvider } from './index'

const render = (ui: ReactElement) => rtlRender(ui, { wrapper: ({ children }) => <CdncaProvider>{children}</CdncaProvider> })

type Draft = { domain: string; ip: string; node: string }
const empty: Draft = { domain: '', ip: '', node: '' }

// A page in miniature: draft fields, applied filters, query log.
function Probe({ initial = empty, onQuery = vi.fn(), storageKey }: { initial?: Draft; onQuery?: (applied: Draft) => void; storageKey?: string }) {
  const [draft, setDraft] = useState(initial)
  const [applied, setApplied] = useState(initial)
  const query = (next: Draft = draft) => { setDraft(next); setApplied(next); onQuery(next) }
  const field = (key: keyof Draft, label: string) => (
    <Input aria-label={label} value={draft[key]} onChange={(event) => setDraft((current) => ({ ...current, [key]: event.target.value }))} />
  )
  return (
    <AdvancedFilters
      storageKey={storageKey}
      primary={field('domain', '域名')}
      items={[
        { key: 'ip', label: '客户端IP', field: field('ip', '客户端IP'), applied: applied.ip },
        { key: 'node', label: '节点ID', field: field('node', '节点ID'), applied: applied.node },
      ]}
      onQuery={() => query()}
      onReset={() => query(empty)}
      onClearAdvanced={() => query({ ...draft, ip: '', node: '' })}
      onRemove={(key) => query({ ...draft, [key]: '' })}
    />
  )
}

afterEach(() => window.localStorage.clear())

describe('AdvancedFilters', () => {
  it('keeps the common fields, query, reset and the advanced toggle on one bar; the panel starts closed', () => {
    render(<Probe />)
    const bar = document.querySelector('.cdnca-adv-filters-bar')!
    expect(within(bar as HTMLElement).getByLabelText('域名')).toBeVisible()
    expect(within(bar as HTMLElement).getByRole('button', { name: '查询' })).toBeInTheDocument()
    expect(within(bar as HTMLElement).getByRole('button', { name: '重置' })).toBeInTheDocument()
    const toggle = within(bar as HTMLElement).getByRole('button', { name: '高级筛选' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    const panel = document.getElementById(toggle.getAttribute('aria-controls')!)!
    expect(panel).toHaveAttribute('role', 'group')
    expect(panel).not.toBeVisible()
    expect(screen.queryByRole('list', { name: '已启用的高级条件' })).not.toBeInTheDocument()
  })

  it('counts the applied advanced conditions on the toggle and lists them as tags', () => {
    render(<Probe initial={{ domain: 'a.example.test', ip: '192.0.2.1', node: 'n1' }} />)
    expect(screen.getByRole('button', { name: '高级筛选 · 2' })).toBeInTheDocument()
    const tags = screen.getByRole('list', { name: '已启用的高级条件' })
    expect(within(tags).getAllByRole('listitem').map((item) => item.textContent)).toEqual(['客户端IP：192.0.2.1', '节点ID：n1'])
  })

  it('applies from the panel (button and Enter) and only counts what was applied', () => {
    const onQuery = vi.fn()
    render(<Probe onQuery={onQuery} />)
    fireEvent.click(screen.getByRole('button', { name: '高级筛选' }))
    expect(screen.getByRole('button', { name: '高级筛选' })).toHaveAttribute('aria-expanded', 'true')
    const panel = screen.getByRole('group', { name: '高级筛选' })
    fireEvent.change(within(panel).getByLabelText('客户端IP'), { target: { value: '192.0.2.9' } })
    expect(screen.getByRole('button', { name: '高级筛选' })).toBeInTheDocument()
    fireEvent.click(within(panel).getByRole('button', { name: '应用' }))
    expect(onQuery).toHaveBeenLastCalledWith({ domain: '', ip: '192.0.2.9', node: '' })
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()
    const node = within(panel).getByLabelText('节点ID')
    fireEvent.change(node, { target: { value: 'n2' } })
    fireEvent.keyDown(node, { key: 'Enter' })
    expect(onQuery).toHaveBeenLastCalledWith({ domain: '', ip: '192.0.2.9', node: 'n2' })
    expect(screen.getByRole('button', { name: '高级筛选 · 2' })).toBeInTheDocument()
  })

  it('removes one condition from its tag and queries again', () => {
    const onQuery = vi.fn()
    render(<Probe onQuery={onQuery} initial={{ domain: 'a.example.test', ip: '192.0.2.1', node: 'n1' }} />)
    fireEvent.click(screen.getByRole('button', { name: '移除条件 客户端IP' }))
    expect(onQuery).toHaveBeenLastCalledWith({ domain: 'a.example.test', ip: '', node: 'n1' })
    expect(screen.getByRole('button', { name: '高级筛选 · 1' })).toBeInTheDocument()
    expect(screen.getByRole('list', { name: '已启用的高级条件' })).toHaveTextContent('节点ID：n1')
  })

  it('clears every advanced condition but keeps the common ones', () => {
    const onQuery = vi.fn()
    render(<Probe onQuery={onQuery} initial={{ domain: 'a.example.test', ip: '192.0.2.1', node: 'n1' }} />)
    fireEvent.click(screen.getByRole('button', { name: '高级筛选 · 2' }))
    fireEvent.click(screen.getByRole('button', { name: '清空高级条件' }))
    expect(onQuery).toHaveBeenLastCalledWith({ domain: 'a.example.test', ip: '', node: '' })
    expect(screen.getByRole('button', { name: '高级筛选' })).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: '已启用的高级条件' })).not.toBeInTheDocument()
  })

  it('is reachable by keyboard: native button toggle, focus moves into the panel, Escape closes and returns focus', () => {
    render(<Probe />)
    const toggle = screen.getByRole('button', { name: '高级筛选' })
    expect(toggle.tagName).toBe('BUTTON')
    expect(document.getElementById(toggle.getAttribute('aria-controls')!)).toHaveAttribute('aria-label', '高级筛选')
    fireEvent.click(toggle)
    expect(screen.getByLabelText('客户端IP')).toHaveFocus()
    fireEvent.keyDown(screen.getByLabelText('客户端IP'), { key: 'Escape' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
    // Tags' remove buttons are native buttons with a spoken name.
  })

  it('remembers the open state per storage key', () => {
    const first = render(<Probe storageKey="probe" />)
    fireEvent.click(screen.getByRole('button', { name: '高级筛选' }))
    first.unmount()
    render(<Probe storageKey="probe" />)
    expect(screen.getByRole('button', { name: '高级筛选' })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('group', { name: '高级筛选' })).toBeVisible()
  })

  it('opens on mount with defaultOpen and names the query button as the page asks', () => {
    window.localStorage.setItem('cdnca.advancedFilters.probe', '0')
    const onQuery = vi.fn()
    render(<AdvancedFilters defaultOpen storageKey="probe" primary={null} queryText="刷新" queryIcon={<svg data-testid="query-icon" />}
      items={[{ key: 'ip', label: '客户端IP', field: <Input aria-label="客户端IP" /> }]}
      onQuery={onQuery} onClearAdvanced={vi.fn()} onRemove={vi.fn()} />)
    expect(screen.getByRole('group', { name: '高级筛选' })).toBeVisible()
    const refresh = screen.getByRole('button', { name: /刷新/ })
    expect(within(refresh).getByTestId('query-icon')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查询' })).not.toBeInTheDocument()
    fireEvent.click(refresh)
    expect(onQuery).toHaveBeenCalledTimes(1)
  })

  it('disables query, apply and Enter while queryDisabled', () => {
    const onQuery = vi.fn()
    render(<AdvancedFilters queryDisabled defaultOpen primary={null} items={[{ key: 'ip', label: '客户端IP', field: <Input aria-label="客户端IP" /> }]}
      onQuery={onQuery} onClearAdvanced={vi.fn()} onRemove={vi.fn()} />)
    expect(screen.getByRole('button', { name: '查询' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '应用' })).toBeDisabled()
    fireEvent.keyDown(screen.getByLabelText('客户端IP'), { key: 'Enter' })
    expect(onQuery).not.toHaveBeenCalled()
  })

  it('shows no toggle and no panel when there are no advanced items', () => {
    render(<AdvancedFilters primary={<Input aria-label="域名" />} items={[]} onQuery={vi.fn()} onClearAdvanced={vi.fn()} onRemove={vi.fn()} />)
    expect(screen.getByRole('button', { name: '查询' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '高级筛选' })).not.toBeInTheDocument()
    expect(screen.queryByRole('group', { name: '高级筛选' })).not.toBeInTheDocument()
  })

  it('tells the page the open state on mount and on each toggle (fix-advfilter2: load options only while open)', () => {
    const onOpenChange = vi.fn()
    window.localStorage.setItem('cdnca.advancedFilters.probe-open', '1')
    render(<AdvancedFilters storageKey="probe-open" onOpenChange={onOpenChange} primary={<Input aria-label="域名" />}
      items={[{ key: 'ip', label: '客户端IP', field: <Input aria-label="客户端IP" /> }]} onQuery={vi.fn()} onClearAdvanced={vi.fn()} onRemove={vi.fn()} />)
    expect(onOpenChange.mock.calls).toEqual([[true]])
    fireEvent.click(screen.getByRole('button', { name: '高级筛选' }))
    expect(onOpenChange.mock.calls).toEqual([[true], [false]])
  })
})
