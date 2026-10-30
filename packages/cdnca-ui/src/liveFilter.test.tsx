import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useLiveApply } from './liveFilter'

type Filters = { name: string; owner: string }
const empty: Filters = { name: '', owner: '' }

// A page in miniature: draft fields, applied filters, the apply log.
function Probe({ onApply, valid = () => true }: { onApply: (next: Filters) => void; valid?: (draft: Filters) => boolean }) {
  const [draft, setDraft] = useState(empty)
  const [applied, setApplied] = useState(empty)
  const apply = (next: Filters) => { setApplied(next); onApply(next) }
  useLiveApply(draft, applied, apply, { valid: valid(draft) })
  return <>
    <input aria-label="名称" value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
    <select aria-label="用户" value={draft.owner} onChange={(event) => { const next = { ...draft, owner: event.target.value }; setDraft(next); apply(next) }}>
      <option value="">全部</option><option value="u1">u1</option>
    </select>
  </>
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('useLiveApply', () => {
  it('applies once, 400ms after the last keystroke', () => {
    const onApply = vi.fn()
    render(<Probe onApply={onApply} />)
    const input = screen.getByRole('textbox', { name: '名称' })
    for (const value of ['a', 'ab', 'abc']) {
      fireEvent.change(input, { target: { value } })
      act(() => { vi.advanceTimersByTime(200) })
    }
    expect(onApply).not.toHaveBeenCalled()
    act(() => { vi.advanceTimersByTime(399) })
    expect(onApply).toHaveBeenCalledTimes(1)
    expect(onApply).toHaveBeenLastCalledWith({ name: 'abc', owner: '' })
    act(() => { vi.advanceTimersByTime(2000) })
    expect(onApply).toHaveBeenCalledTimes(1)
  })

  it('does not apply while an input method is composing, then applies the committed text', () => {
    const onApply = vi.fn()
    render(<Probe onApply={onApply} />)
    const input = screen.getByRole('textbox', { name: '名称' })
    fireEvent.compositionStart(input)
    fireEvent.change(input, { target: { value: 'zhang' } })
    act(() => { vi.advanceTimersByTime(1000) })
    expect(onApply).not.toHaveBeenCalled()
    fireEvent.change(input, { target: { value: '张' } })
    fireEvent.compositionEnd(input)
    act(() => { vi.advanceTimersByTime(400) })
    expect(onApply).toHaveBeenCalledTimes(1)
    expect(onApply).toHaveBeenLastCalledWith({ name: '张', owner: '' })
  })

  it('does not apply an invalid draft', () => {
    const onApply = vi.fn()
    render(<Probe onApply={onApply} valid={(draft) => draft.name.length !== 2} />)
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'ab' } })
    act(() => { vi.advanceTimersByTime(1000) })
    expect(onApply).not.toHaveBeenCalled()
  })

  it('a select applied at once is not applied again by the timer', () => {
    const onApply = vi.fn()
    render(<Probe onApply={onApply} />)
    fireEvent.change(screen.getByRole('combobox', { name: '用户' }), { target: { value: 'u1' } })
    expect(onApply).toHaveBeenCalledTimes(1)
    act(() => { vi.advanceTimersByTime(1000) })
    expect(onApply).toHaveBeenCalledTimes(1)
  })

  it('a pending text change is dropped once the draft is applied another way', () => {
    const onApply = vi.fn()
    render(<Probe onApply={onApply} />)
    fireEvent.change(screen.getByRole('textbox', { name: '名称' }), { target: { value: 'x' } })
    fireEvent.change(screen.getByRole('combobox', { name: '用户' }), { target: { value: 'u1' } })
    expect(onApply).toHaveBeenLastCalledWith({ name: 'x', owner: 'u1' })
    act(() => { vi.advanceTimersByTime(1000) })
    expect(onApply).toHaveBeenCalledTimes(1)
  })
})
