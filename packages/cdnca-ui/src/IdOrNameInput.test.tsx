import { act, fireEvent, render as rtlRender, screen, waitFor } from '@testing-library/react'
import { useState, type ReactElement } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { CdncaProvider, IdOrNameInput, type IdOrNameOption } from './index'

const render = (ui: ReactElement) => rtlRender(ui, { wrapper: ({ children }) => <CdncaProvider>{children}</CdncaProvider> })

const users: IdOrNameOption[] = [{ id: '1001', name: 'alice' }, { id: '1002', name: 'alina' }]

function Probe({ search, onFilter }: { search?: (text: string, signal: AbortSignal) => Promise<IdOrNameOption[]>; onFilter: (id: string) => void }) {
  const [id, setID] = useState('')
  return <IdOrNameInput aria-label="用户" value={id} delay={0} search={search} onChange={(next) => { setID(next); onFilter(next) }} />
}

const box = () => screen.getByRole('combobox', { name: '用户' })
const type = (value: string) => fireEvent.change(box(), { target: { value } })

afterEach(() => vi.useRealTimers())

describe('IdOrNameInput', () => {
  it('a complete ID filters at once without waiting for suggestions', () => {
    const onFilter = vi.fn()
    render(<Probe search={() => new Promise(() => undefined)} onFilter={onFilter} />)
    type('1002')
    expect(onFilter).toHaveBeenLastCalledWith('1002')
  })

  it('a name suggests 名称（ID）; picking one filters by the ID', async () => {
    const onFilter = vi.fn()
    const search = vi.fn(async (text: string) => users.filter((user) => user.name.startsWith(text)))
    render(<Probe search={search} onFilter={onFilter} />)
    fireEvent.focus(box())
    type('ali')
    expect(onFilter).not.toHaveBeenCalled()
    const option = await screen.findByText('alina（1002）')
    fireEvent.click(option)
    expect(onFilter).toHaveBeenLastCalledWith('1002')
    expect(box()).toHaveValue('alina（1002）')
    expect(search).toHaveBeenCalledWith('ali', expect.any(AbortSignal))
  })

  it('a name that exactly matches one suggestion filters by its ID', async () => {
    const onFilter = vi.fn()
    render(<Probe search={async (text) => users.filter((user) => user.name.startsWith(text))} onFilter={onFilter} />)
    type('alice')
    await waitFor(() => expect(onFilter).toHaveBeenLastCalledWith('1001'))
  })

  it('drops the late answer of an older search', async () => {
    const answers: Record<string, (found: IdOrNameOption[]) => void> = {}
    const signals: Record<string, AbortSignal> = {}
    const search = (text: string, signal: AbortSignal) => new Promise<IdOrNameOption[]>((resolve) => { answers[text] = resolve; signals[text] = signal })
    render(<Probe search={search} onFilter={vi.fn()} />)
    fireEvent.focus(box())
    type('al')
    await waitFor(() => expect(answers.al).toBeDefined())
    type('ali')
    await waitFor(() => expect(answers.ali).toBeDefined())
    expect(signals.al.aborted).toBe(true)
    await act(async () => { answers.ali([users[1]]) })
    await act(async () => { answers.al([{ id: '9', name: 'albert' }]) })
    expect(await screen.findByText('alina（1002）')).toBeInTheDocument()
    expect(screen.queryByText('albert（9）')).not.toBeInTheDocument()
  })

  it('does not search while an input method is composing', async () => {
    const search = vi.fn(async () => users)
    render(<Probe search={search} onFilter={vi.fn()} />)
    fireEvent.compositionStart(box())
    type('zhang')
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(search).not.toHaveBeenCalled()
    type('张')
    fireEvent.compositionEnd(box())
    await waitFor(() => expect(search).toHaveBeenCalledWith('张', expect.any(AbortSignal)))
  })

  it('without access to the list (403) it falls back to IDs only', async () => {
    const onFilter = vi.fn()
    render(<Probe search={async () => { throw Object.assign(new Error('forbidden'), { status: 403 }) }} onFilter={onFilter} />)
    type('bob')
    await waitFor(() => expect(box()).toHaveAttribute('title', '只能按 ID 筛选（无权读取名称列表）'))
    type('bob2')
    expect(onFilter).toHaveBeenLastCalledWith('bob2')
  })

  it('without a search function free text is the ID', () => {
    const onFilter = vi.fn()
    render(<Probe onFilter={onFilter} />)
    type('ab-12')
    expect(onFilter).toHaveBeenLastCalledWith('ab-12')
  })
})

describe('IdOrNameInput extras', () => {
  it('a typed display ID that one suggestion carries filters by that row\'s ID', async () => {
    const onFilter = vi.fn()
    const search = async () => [{ id: '0b9b7c1e-1f7e-4c55-9d0b-2a6d4f3c8e11', code: '10086', name: 'carol' }]
    function UUIDOnly() {
      const [id, setID] = useState('')
      return <IdOrNameInput aria-label="用户" value={id} delay={0} search={search} isId={(text) => text.length === 36}
        onChange={(next) => { setID(next); onFilter(next) }} />
    }
    render(<UUIDOnly />)
    type('10086')
    await waitFor(() => expect(onFilter).toHaveBeenLastCalledWith('0b9b7c1e-1f7e-4c55-9d0b-2a6d4f3c8e11'))
  })

  it('freeText: any text filters as typed and still suggests', async () => {
    const onFilter = vi.fn()
    function Free() {
      const [id, setID] = useState('')
      return <IdOrNameInput aria-label="用户" value={id} delay={0} freeText search={async () => users} onChange={(next) => { setID(next); onFilter(next) }} />
    }
    render(<Free />)
    fireEvent.focus(box())
    type('ali')
    expect(onFilter).toHaveBeenLastCalledWith('ali')
    expect(await screen.findByText('alice（1001）')).toBeInTheDocument()
  })
})
