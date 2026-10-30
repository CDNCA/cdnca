import { ApiError, networkApiError, responseApiError } from './auth'
import type { L4RealtimeAudience } from './l4Realtime'

// 四层访问日志 (GET /v1/analytics/l4-session-logs) and 实时连接
// (GET/POST /v1/streams/{id}/live-connections).

export const l4EndReasons = ['closed', 'killed', 'geo_blocked', 'rate_limited', 'banned', 'conn_limited', 'bad_request',
  'forbidden', 'upstream_failed', 'internal_error', 'config_error', 'guard_blocked'] as const
export type L4EndReason = typeof l4EndReasons[number]

export interface L4SessionLogFilters {
  range: '1h' | '6h' | '12h' | '24h' | 'custom'
  from?: string
  to?: string
  tenantId?: string
  nodeId?: string
  streamId?: string
  listenPort?: number
  clientIp?: string
  endReason?: L4EndReason
  limit?: number
  cursor?: string
}

export interface L4SessionLogRow {
  event_id: string
  started_at: string
  finalized_at: string
  node_id: string
  site_id: string
  stream_id: string
  listener_id: string
  protocol: 'tcp' | 'udp'
  listen_port: number
  client_ip: string
  client_port: number
  peer_ip?: string
  upstream_addr?: string
  upstream_connect_ms?: number
  bytes_up: number
  bytes_down: number
  status_code: number
  end_reason: L4EndReason
}

export interface L4SessionLogResponse {
  rows: L4SessionLogRow[]
  next_cursor?: string
}

export interface L4LiveConnection {
  node_id: string
  session_key: string
  listener_id: string
  listen_port: number
  client_ip: string
  client_port: number
  peer_ip?: string
  upstream: string
  started_at?: string
  bytes_received?: number
  bytes_sent?: number
}

export interface L4LiveNode {
  node_id: string
  node_name: string
  state: 'ok' | 'unsupported' | 'offline' | 'error'
  error_code?: string
  can_close: boolean
  matched: number
  untracked: number
  connections: L4LiveConnection[]
}

export interface L4CloseResult {
  node_id: string
  state: L4LiveNode['state']
  error_code?: string
  results: { session_key: string; error_code?: string }[]
}

export interface L4AllLiveConnection extends L4LiveConnection {
  node_name: string
  stream_id: string
  stream_name: string
  can_close: boolean
}

export interface L4AllLiveResponse {
  streams: number
  streams_truncated: boolean
  truncated: boolean
  problems: { node_id: string; node_name: string; state: Exclude<L4LiveNode['state'], 'ok'>; error_code?: string }[]
  connections: L4AllLiveConnection[]
}

export interface L4AllLiveFilters {
  tenantId?: string
  streamId?: string
  nodeId?: string
  listenPort?: number
  clientIp?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function text(value: unknown): value is string {
  return typeof value === 'string'
}

function optional(value: unknown, check: (value: unknown) => boolean): boolean {
  return value === undefined || check(value)
}

async function request(accessToken: string, path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init, signal, credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  try {
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

// validClientFilter accepts an IPv4/IPv6 address or CIDR (the server checks it exactly).
export function validClientFilter(value: string): boolean {
  const raw = value.trim()
  if (raw === '') return true
  const [address, prefix, extra] = raw.split('/')
  if (extra !== undefined || (prefix !== undefined && !/^\d{1,3}$/.test(prefix))) return false
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
    return address.split('.').every((part) => Number(part) <= 255) && (prefix === undefined || Number(prefix) <= 32)
  }
  return /^[0-9a-f:.]+$/i.test(address) && address.includes(':') && (prefix === undefined || Number(prefix) <= 128)
}

function parseLogRow(value: unknown): L4SessionLogRow | null {
  if (!record(value) || !text(value.event_id) || !text(value.started_at) || !text(value.finalized_at) ||
    !uuidPattern.test(String(value.node_id)) || !uuidPattern.test(String(value.stream_id)) ||
    (value.protocol !== 'tcp' && value.protocol !== 'udp') || !count(value.listen_port) || !text(value.client_ip) ||
    !count(value.client_port) || !optional(value.peer_ip, text) || !optional(value.upstream_addr, text) ||
    !optional(value.upstream_connect_ms, count) || !count(value.bytes_up) || !count(value.bytes_down) ||
    !count(value.status_code) || !l4EndReasons.includes(value.end_reason as L4EndReason)) return null
  return value as unknown as L4SessionLogRow
}

async function readSessionLogs(accessToken: string, audience: L4RealtimeAudience, filters: L4SessionLogFilters,
  signal?: AbortSignal): Promise<L4SessionLogResponse> {
  const query = new URLSearchParams({ range: filters.range, timezone: 'UTC', limit: String(filters.limit ?? 50) })
  if (filters.range === 'custom') {
    if (!filters.from || !filters.to) throw new ApiError('Invalid window', 400, 'l4_analytics_invalid_request')
    query.set('from', filters.from)
    query.set('to', filters.to)
  }
  if (filters.tenantId) {
    if (audience !== 'admin' || !uuidPattern.test(filters.tenantId)) throw new ApiError('Tenant override is forbidden', 403, 'l4_analytics_forbidden')
    query.set('tenant_id', filters.tenantId)
  }
  if (filters.nodeId) query.set('node_id', filters.nodeId)
  if (filters.streamId) query.set('stream_id', filters.streamId)
  if (filters.listenPort) query.set('listen_port', String(filters.listenPort))
  if (filters.clientIp) query.set('client_ip', filters.clientIp)
  if (filters.endReason) query.set('end_reason', filters.endReason)
  if (filters.cursor) query.set('cursor', filters.cursor)
  const base = audience === 'admin' ? '/v1/admin/analytics' : '/v1/analytics'
  const raw = await request(accessToken, `${base}/l4-session-logs?${query}`, {}, signal)
  if (!record(raw) || raw.version !== 'l4-session-logs/v1' || !Array.isArray(raw.rows) ||
    !optional(raw.next_cursor, text)) throw invalidResponse()
  const rows = raw.rows.map(parseLogRow)
  if (rows.some((row) => row === null)) throw invalidResponse()
  return { rows: rows as L4SessionLogRow[], ...(raw.next_cursor ? { next_cursor: raw.next_cursor as string } : {}) }
}

function parseConnection(value: unknown): L4LiveConnection | null {
  if (!record(value) || !uuidPattern.test(String(value.node_id)) || !text(value.session_key) || !text(value.listener_id) ||
    !count(value.listen_port) || !text(value.client_ip) || !count(value.client_port) || !optional(value.peer_ip, text) ||
    !text(value.upstream) || !optional(value.started_at, text) || !optional(value.bytes_received, count) ||
    !optional(value.bytes_sent, count)) return null
  return value as unknown as L4LiveConnection
}

function parseNode(value: unknown): L4LiveNode | null {
  if (!record(value) || !uuidPattern.test(String(value.node_id)) || !text(value.node_name) ||
    !['ok', 'unsupported', 'offline', 'error'].includes(String(value.state)) || !optional(value.error_code, text) ||
    typeof value.can_close !== 'boolean' || !count(value.matched) || !count(value.untracked) || !Array.isArray(value.connections)) return null
  const connections = value.connections.map(parseConnection)
  if (connections.some((item) => item === null)) return null
  return { ...(value as unknown as L4LiveNode), connections: connections as L4LiveConnection[] }
}

async function listLive(accessToken: string, streamId: string, clientIp: string, signal?: AbortSignal): Promise<L4LiveNode[]> {
  const query = new URLSearchParams({ limit: '200' })
  if (clientIp.trim()) query.set('client_ip', clientIp.trim())
  const raw = await request(accessToken, `/v1/streams/${encodeURIComponent(streamId)}/live-connections?${query}`, {}, signal)
  if (!record(raw) || raw.stream_id !== streamId || !Array.isArray(raw.nodes)) throw invalidResponse()
  const nodes = raw.nodes.map(parseNode)
  if (nodes.some((item) => item === null)) throw invalidResponse()
  return nodes as L4LiveNode[]
}

// listAll is 实时连接 without a picked forward (GET /v1/l4-live-connections):
// every forward the session reaches, newest connection first.
async function listAll(accessToken: string, filters: L4AllLiveFilters, signal?: AbortSignal): Promise<L4AllLiveResponse> {
  const query = new URLSearchParams({ limit: '200' })
  if (filters.tenantId) query.set('tenant_id', filters.tenantId)
  if (filters.streamId) query.set('stream_id', filters.streamId)
  if (filters.nodeId) query.set('node_id', filters.nodeId)
  if (filters.listenPort) query.set('listen_port', String(filters.listenPort))
  if (filters.clientIp?.trim()) query.set('client_ip', filters.clientIp.trim())
  const raw = await request(accessToken, `/v1/l4-live-connections?${query}`, {}, signal)
  if (!record(raw) || !count(raw.streams) || typeof raw.streams_truncated !== 'boolean' || typeof raw.truncated !== 'boolean' ||
    !Array.isArray(raw.problems) || !Array.isArray(raw.connections)) throw invalidResponse()
  const problems = raw.problems.every((item) => record(item) && uuidPattern.test(String(item.node_id)) && text(item.node_name) &&
    ['unsupported', 'offline', 'error'].includes(String(item.state)) && optional(item.error_code, text))
  const connections = raw.connections.map((item) => record(item) && text(item.node_name) && uuidPattern.test(String(item.stream_id)) &&
    text(item.stream_name) && typeof item.can_close === 'boolean' ? parseConnection(item) : null)
  if (!problems || connections.some((item) => item === null)) throw invalidResponse()
  return raw as unknown as L4AllLiveResponse
}

async function closeLive(accessToken: string, streamId: string, nodeId: string, sessionKeys: string[]): Promise<L4CloseResult> {
  const raw = await request(accessToken, `/v1/streams/${encodeURIComponent(streamId)}/live-connections/close`, {
    method: 'POST', body: JSON.stringify({ node_id: nodeId, session_keys: sessionKeys }),
  })
  if (!record(raw) || raw.node_id !== nodeId || !text(raw.state) || !Array.isArray(raw.results)) throw invalidResponse()
  return raw as unknown as L4CloseResult
}

export const l4SessionLogsApi = { readSessionLogs, listLive, listAll, closeLive }
