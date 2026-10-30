import { ApiError } from '../api/auth'
import {
  l4RealtimeApi,
  type L4RealtimeAudience,
  type L4RealtimeFilters,
  type L4RealtimeProtocol,
  type L4RealtimeRow,
} from '../api/l4Realtime'
import { useSessionStore } from '../auth/session'

export type PortFilter = { listenPort: number; protocol?: L4RealtimeProtocol }
export type AppliedQuery = { filters: L4RealtimeFilters; ports: PortFilter[] }

export function currentAccess(ownerKey: string): string | null {
  const state = useSessionStore.getState()
  const principal = state.principal
  if (!principal || `${principal.user_id}:${principal.scope_kind}:${principal.scope_id}` !== ownerKey) return null
  return state.accessToken
}

const maxPagesPerRequest = 20

// A06：同端口不带协议（如 80）已覆盖 80/TCP、80/UDP，规范化后每个端口只查一次，避免重叠请求被重复求和。
export function parsePorts(value: string): PortFilter[] | null {
  const raw = value.trim()
  if (!raw) return []
  const protocols = new Map<number, Set<L4RealtimeProtocol | '*'>>()
  for (const token of raw.split(/[\s,，]+/)) {
    const match = /^(\d{1,5})(?:\/(TCP|UDP))?$/i.exec(token)
    const listenPort = match ? Number(match[1]) : 0
    if (!match || listenPort < 1 || listenPort > 65535) return null
    const protocol = (match[2]?.toLowerCase() ?? '*') as L4RealtimeProtocol | '*'
    const set = protocols.get(listenPort) ?? new Set()
    set.add(protocol)
    protocols.set(listenPort, set)
  }
  return [...protocols.entries()].sort(([left], [right]) => left - right).flatMap(([listenPort, set]) => {
    if (set.has('*') || (set.has('tcp') && set.has('udp'))) return [{ listenPort }]
    return [...set].map((protocol) => ({ listenPort, protocol: protocol as L4RealtimeProtocol }))
  })
}

export interface L4RealtimeRead {
  rows: L4RealtimeRow[]
  // false：某个条件读满页数预算后仍有游标，结果是否完整待确认（不等于一定缺数据）。
  complete: boolean
}

export async function readRows(
  ownerKey: string,
  audience: L4RealtimeAudience,
  applied: AppliedQuery,
  signal: AbortSignal,
): Promise<L4RealtimeRead> {
  const accessToken = currentAccess(ownerKey)
  if (!accessToken) throw new ApiError('Session changed', 403, 'l4_analytics_forbidden')
  const requests = applied.ports.length > 0 ? applied.ports : [{}]
  const result = await Promise.all(requests.map(async (port) => {
    const rows: L4RealtimeRow[] = []
    let cursor: string | undefined
    for (let page = 0; page < maxPagesPerRequest; page += 1) {
      const response = await l4RealtimeApi.read(accessToken, audience, { ...applied.filters, ...port, ...(cursor ? { cursor } : {}) }, signal)
      rows.push(...response.rows)
      cursor = response.next_cursor
      if (!cursor) break
    }
    return { rows, complete: !cursor }
  }))
  if (!currentAccess(ownerKey)) throw new ApiError('Session changed', 403, 'l4_analytics_forbidden')
  return { rows: result.flatMap((item) => item.rows), complete: result.every((item) => item.complete) }
}
