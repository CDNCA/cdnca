// 首屏数据预取：入口在应用根、控制台壳和页面块还在下载时，就按当前路由
// 发出页面首屏要读的 GET；页面之后自己发同一地址的 GET 时直接接上这次响应，不再多一个往返。
// 不依赖 antd，入口可直接用。只接管“同一地址、GET、无请求体”的第一次调用，且只用一次：
// 之后的请求（翻页、刷新、重试）照常走网络。超过 maxAgeMs 未被取走的预取作废。
type Fetch = typeof fetch

interface Entry {
  response: Promise<Response>
  at: number
}

const maxAgeMs = 10_000
const pending = new Map<string, Entry>()
let network: Fetch | undefined

function keyOf(input: RequestInfo | URL): string | null {
  if (typeof input !== 'string' && !(input instanceof URL)) return null
  try {
    return new URL(input, window.location.href).href
  } catch {
    return null
  }
}

function take(key: string): Promise<Response> | null {
  const entry = pending.get(key)
  if (!entry) return null
  pending.delete(key)
  return Date.now() - entry.at <= maxAgeMs ? entry.response : null
}

/** Wraps window.fetch once so later GETs can pick up a prefetched response. */
export function installPrefetchFetch() {
  if (network) return
  network = window.fetch.bind(window)
  const base = network
  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    const key = method === 'GET' && init?.body == null && !init?.signal ? keyOf(input) : null
    return (key && take(key)) || base(input, init)
  }) as Fetch
}

/** Starts a same-origin GET now; the first matching page request uses its response. */
export function prefetchGET(path: string, credentials: RequestCredentials = 'same-origin') {
  if (!network) return
  const key = keyOf(path)
  if (!key || pending.has(key)) return
  const response = network(path, { credentials, headers: { Accept: 'application/json' } })
  // An unclaimed failure must not surface as an unhandled rejection.
  response.catch(() => undefined)
  pending.set(key, { response, at: Date.now() })
}

/** Drops every unclaimed prefetch (sign-out, session expiry). */
export function clearPrefetched() {
  pending.clear()
}

export function resetPrefetchForTest() {
  pending.clear()
  network = undefined
}
