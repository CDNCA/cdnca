import { ApiError, networkApiError, responseApiError } from './auth'

export type L4RealtimeAudience = 'tenant' | 'admin'
export type L4RealtimeRange = '1h' | '6h' | '12h' | '24h' | 'custom'
export type L4RealtimeProtocol = 'tcp' | 'udp'

export interface L4RealtimeFilters {
  range: L4RealtimeRange
  timezone?: string
  from?: string
  to?: string
  tenantId?: string
  siteId?: string
  streamId?: string
  nodeId?: string
  protocol?: L4RealtimeProtocol
  listenPort?: number
  limit?: number
  cursor?: string
}

export interface L4RealtimeSnapshot {
  at?: string
  source_watermark: number
  finalized_through: string
}

export interface L4RealtimeRow {
  bucket: string
  node_id: string
  site_id: string
  stream_id: string
  listener_id: string
  protocol: L4RealtimeProtocol
  listen_port: number
  sessions: number
  bytes_up: number
  bytes_down: number
  errors: number
}

export interface L4RealtimeResponse {
  version: 'l4-realtime/v1'
  meta: {
    range: L4RealtimeRange
    timezone: string
    from: string
    to: string
    snapshot: L4RealtimeSnapshot
  }
  totals: {
    sessions: number
    bytes_up: number
    bytes_down: number
    errors: number
  }
  rows: L4RealtimeRow[]
  next_cursor?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/
const fixedRanges = new Set<L4RealtimeRange>(['1h', '6h', '12h', '24h'])

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function invalidRequest(message: string): ApiError {
  return new ApiError(message, 400, 'l4_analytics_invalid_request')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key))
}

function uuid(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value) && value.toLowerCase() !== '00000000-0000-0000-0000-000000000000'
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && timestampPattern.test(value) && Number.isFinite(Date.parse(value))
}

function safeCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function positiveCount(value: unknown): value is number {
  return safeCount(value) && value > 0
}

function sameDate(left: string, right: string): boolean {
  return Date.parse(left) === Date.parse(right)
}

function parseSnapshot(value: unknown): L4RealtimeSnapshot | null {
  if (!record(value) || !exactKeys(value, ['source_watermark', 'finalized_through'], ['at']) ||
    !safeCount(value.source_watermark) || !timestamp(value.finalized_through) ||
    (value.at !== undefined && !timestamp(value.at))) return null
  if (value.at !== undefined && Date.parse(value.at) < Date.parse(value.finalized_through)) return null
  return value as unknown as L4RealtimeSnapshot
}

function parseRow(value: unknown): L4RealtimeRow | null {
  if (!record(value) || !exactKeys(value, [
    'bucket', 'node_id', 'site_id', 'stream_id', 'listener_id', 'protocol', 'listen_port',
    'sessions', 'bytes_up', 'bytes_down', 'errors',
  ]) || !timestamp(value.bucket) || !uuid(value.node_id) || !uuid(value.site_id) || !uuid(value.stream_id) ||
    !uuid(value.listener_id) || (value.protocol !== 'tcp' && value.protocol !== 'udp') ||
    typeof value.listen_port !== 'number' || !Number.isInteger(value.listen_port) || value.listen_port < 1 || value.listen_port > 65535 ||
    !positiveCount(value.sessions) || !safeCount(value.bytes_up) || !safeCount(value.bytes_down) ||
    !safeCount(value.errors) || value.errors > value.sessions) return null
  return value as unknown as L4RealtimeRow
}

function parseResponse(value: unknown, filters: L4RealtimeFilters): L4RealtimeResponse {
  if (!record(value) || !exactKeys(value, ['version', 'meta', 'totals', 'rows'], ['next_cursor']) ||
    value.version !== 'l4-realtime/v1' || !record(value.meta) || !exactKeys(value.meta, ['range', 'timezone', 'from', 'to', 'snapshot']) ||
    value.meta.range !== filters.range || value.meta.timezone !== (filters.timezone ?? 'UTC') ||
    !timestamp(value.meta.from) || !timestamp(value.meta.to) || Date.parse(value.meta.from) >= Date.parse(value.meta.to) ||
    filters.range === 'custom' && (!filters.from || !filters.to || !sameDate(value.meta.from as string, filters.from) || !sameDate(value.meta.to as string, filters.to))) {
    throw invalidResponse()
  }
  const snapshot = parseSnapshot(value.meta.snapshot)
  const metaTo = value.meta.to as string
  if (!snapshot || Date.parse(snapshot.finalized_through) > Date.parse(metaTo) ||
    !record(value.totals) || !exactKeys(value.totals, ['sessions', 'bytes_up', 'bytes_down', 'errors']) ||
    !safeCount(value.totals.sessions) || !safeCount(value.totals.bytes_up) || !safeCount(value.totals.bytes_down) || !safeCount(value.totals.errors) ||
    !Array.isArray(value.rows) || value.rows.length > (filters.limit ?? 10) ||
    (value.next_cursor !== undefined && (typeof value.next_cursor !== 'string' || value.next_cursor.length === 0 || value.next_cursor.length > 4096 || value.rows.length === 0))) {
    throw invalidResponse()
  }
  const rows = value.rows.map(parseRow)
  if (rows.some((row) => row === null)) throw invalidResponse()
  const parsedRows = rows as L4RealtimeRow[]
  let sessions = 0
  let bytesUp = 0
  let bytesDown = 0
  let errors = 0
  let previousKey: string | null = null
  for (const row of parsedRows) {
    const key = [Date.parse(row.bucket), row.node_id, row.site_id, row.stream_id, row.listener_id].join('|')
    if (previousKey !== null && previousKey >= key) throw invalidResponse()
    previousKey = key
    sessions += row.sessions
    bytesUp += row.bytes_up
    bytesDown += row.bytes_down
    errors += row.errors
    if (![sessions, bytesUp, bytesDown, errors].every(Number.isSafeInteger)) throw invalidResponse()
  }
  if (sessions !== value.totals.sessions || bytesUp !== value.totals.bytes_up || bytesDown !== value.totals.bytes_down || errors !== value.totals.errors) {
    throw invalidResponse()
  }
  return {
    version: 'l4-realtime/v1',
    meta: { ...value.meta, snapshot } as L4RealtimeResponse['meta'],
    totals: value.totals as L4RealtimeResponse['totals'],
    rows: parsedRows,
    ...(value.next_cursor === undefined ? {} : { next_cursor: value.next_cursor }),
  }
}

function queryString(audience: L4RealtimeAudience, filters: L4RealtimeFilters): string {
  const timezone = filters.timezone ?? 'UTC'
  if (!fixedRanges.has(filters.range) && filters.range !== 'custom') throw invalidRequest('Invalid realtime range')
  if (audience === 'admin' && filters.tenantId !== undefined && !uuid(filters.tenantId)) throw invalidRequest('Tenant is invalid')
  if (audience === 'tenant' && filters.tenantId !== undefined) throw new ApiError('Tenant override is forbidden', 403, 'l4_analytics_forbidden')
  if (filters.range === 'custom' && (!filters.from || !filters.to || !timestamp(filters.from) || !timestamp(filters.to) || Date.parse(filters.from) >= Date.parse(filters.to))) {
    throw invalidRequest('Invalid realtime window')
  }
  if (filters.range !== 'custom' && (filters.from !== undefined || filters.to !== undefined)) throw invalidRequest('Fixed ranges cannot include dates')
  if (timezone.trim() !== timezone || timezone === 'Local' || timezone.length === 0 || timezone.length > 128) throw invalidRequest('Invalid timezone')
  const limit = filters.limit ?? 10
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw invalidRequest('Invalid realtime limit')
  const optionalIDs = [filters.siteId, filters.streamId, filters.nodeId]
  if (optionalIDs.some((value) => value !== undefined && !uuid(value))) throw invalidRequest('Invalid realtime resource')
  if (filters.protocol !== undefined && filters.protocol !== 'tcp' && filters.protocol !== 'udp') throw invalidRequest('Invalid protocol')
  if (filters.listenPort !== undefined && (!Number.isInteger(filters.listenPort) || filters.listenPort < 1 || filters.listenPort > 65535)) throw invalidRequest('Invalid realtime port')
  if (filters.cursor !== undefined && (filters.cursor.length === 0 || filters.cursor.length > 4096)) throw invalidRequest('Invalid cursor')
  const query = new URLSearchParams({ range: filters.range, timezone })
  if (filters.range === 'custom') {
    query.set('from', filters.from!)
    query.set('to', filters.to!)
  }
  if (audience === 'admin' && filters.tenantId) query.set('tenant_id', filters.tenantId)
  if (filters.siteId) query.set('site_id', filters.siteId)
  if (filters.streamId) query.set('stream_id', filters.streamId)
  if (filters.nodeId) query.set('node_id', filters.nodeId)
  if (filters.protocol) query.set('protocol', filters.protocol)
  if (filters.listenPort) query.set('listen_port', String(filters.listenPort))
  query.set('limit', String(limit))
  if (filters.cursor) query.set('cursor', filters.cursor)
  return query.toString()
}

async function read(
  accessToken: string,
  audience: L4RealtimeAudience,
  filters: L4RealtimeFilters,
  signal?: AbortSignal,
): Promise<L4RealtimeResponse> {
  const base = audience === 'admin' ? '/v1/admin/analytics' : '/v1/analytics'
  let response: Response
  try {
    response = await fetch(`${apiRoot}${base}/l4-realtime?${queryString(audience, filters)}`, {
      credentials: 'include', signal, headers: { Authorization: `Bearer ${accessToken}` },
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let raw: unknown
  try {
    raw = await response.json()
  } catch {
    throw invalidResponse()
  }
  return parseResponse(raw, filters)
}

export const l4RealtimeApi = { read }
