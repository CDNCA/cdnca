import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { clearPrefetched, installPrefetchFetch, prefetchGET, resetPrefetchForTest } from './prefetch'

const original = window.fetch

function body(text: string) {
  return new Response(text, { status: 200, headers: { 'Content-Type': 'application/json' } })
}

describe('prefetch', () => {
  let network: ReturnType<typeof vi.fn>
  beforeEach(() => {
    network = vi.fn(async (input: RequestInfo | URL) => body(String(input)))
    window.fetch = network as unknown as typeof fetch
    resetPrefetchForTest()
    installPrefetchFetch()
  })
  afterEach(() => {
    resetPrefetchForTest()
    window.fetch = original
  })

  it('serves the first matching GET from the prefetch and only once', async () => {
    prefetchGET('/api/items?page=1', 'include')
    expect(network).toHaveBeenCalledTimes(1)
    expect(network.mock.calls[0][1]).toMatchObject({ credentials: 'include' })

    const first = await window.fetch('/api/items?page=1', { credentials: 'include' })
    expect(await first.text()).toBe('/api/items?page=1')
    expect(network).toHaveBeenCalledTimes(1)

    await window.fetch('/api/items?page=1')
    expect(network).toHaveBeenCalledTimes(2)
  })

  it('does not hand a prefetched response to writes or other addresses', async () => {
    prefetchGET('/api/items?page=1')
    await window.fetch('/api/items?page=1', { method: 'POST', body: '{}' })
    await window.fetch('/api/items?page=2')
    expect(network).toHaveBeenCalledTimes(3)
    // still unclaimed: the GET picks it up
    await window.fetch('/api/items?page=1')
    expect(network).toHaveBeenCalledTimes(3)
  })

  it('drops unclaimed prefetches on clear and after they get old', async () => {
    prefetchGET('/api/a')
    clearPrefetched()
    await window.fetch('/api/a')
    expect(network).toHaveBeenCalledTimes(2)

    vi.useFakeTimers()
    try {
      prefetchGET('/api/b')
      vi.advanceTimersByTime(10_001)
      await window.fetch('/api/b')
      expect(network).toHaveBeenCalledTimes(4)
    } finally {
      vi.useRealTimers()
    }
  })

  it('swallows an unclaimed network failure', async () => {
    network.mockRejectedValueOnce(new TypeError('offline'))
    prefetchGET('/api/down')
    await new Promise((resolve) => setTimeout(resolve, 0))
    await expect(window.fetch('/api/down')).rejects.toThrow('offline')
  })
})
