import { act, renderHook } from '@testing-library/react'

import { useIdempotencyKey } from './idempotency'

describe('useIdempotencyKey', () => {
  // 卡 7（Codex 复查 10-27）：工单 A 的回复迟到返回时，不能清掉工单 B 正在用的键。
  it('completes only the key the settled request was sent with', () => {
    const { result } = renderHook(() => useIdempotencyKey('ticket-reply'))
    let first = ''
    let second = ''
    act(() => { first = result.current.keyFor({ id: 'A', body: 'x' }) })
    act(() => { second = result.current.keyFor({ id: 'B', body: 'y' }) })
    expect(second).not.toBe(first)
    act(() => result.current.complete(first)) // A's late response
    expect(result.current.keyFor({ id: 'B', body: 'y' })).toBe(second)
    act(() => result.current.complete(second))
    expect(result.current.keyFor({ id: 'B', body: 'y' })).not.toBe(second)
  })

  it('completes the current key when no key is given', () => {
    const { result } = renderHook(() => useIdempotencyKey('p'))
    const key = result.current.keyFor({ a: 1 })
    act(() => result.current.complete())
    expect(result.current.keyFor({ a: 1 })).not.toBe(key)
  })
})
