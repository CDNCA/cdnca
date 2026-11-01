import { afterEach, describe, expect, it, vi } from 'vitest'
import { marketApi } from './market'

// 73 上市场不可用时源站回 502 {"error":"market_unavailable"}，经 Cloudflare 后
// 正文被换成 "error code: 502"（非 JSON），页面只显示 response_invalid，看不出是市场不可用。
describe('market call error bodies', () => {
  afterEach(() => vi.restoreAllMocks())

  it('reports a gateway error with a non-JSON body as market_unavailable, not response_invalid', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('error code: 502', { status: 502 }))
    await expect(marketApi.member('token')).rejects.toMatchObject({ status: 502, code: 'market_unavailable' })
  })

  it('keeps the market error code when the body is JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"error":"market_unavailable"}', { status: 502 }))
    await expect(marketApi.member('token')).rejects.toMatchObject({ status: 502, code: 'market_unavailable' })
  })

  it('still refuses a successful response that is not JSON', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<html></html>', { status: 200 }))
    await expect(marketApi.member('token')).rejects.toMatchObject({ code: 'response_invalid' })
  })
})
