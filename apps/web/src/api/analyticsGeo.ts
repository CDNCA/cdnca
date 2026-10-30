import { ApiError, networkApiError, responseApiError } from './auth'

export type AnalyticsGeoAudience = 'admin' | 'tenant'
export type AnalyticsGeoKind = 'access' | 'block'

export interface AnalyticsGeoEventIdentity {
  eventId: string
  occurredAt: string
  siteId: string
  nodeId: string
  clientIp: string
  tenantId?: string
  databaseVersion?: string
}

export interface AnalyticsGeoEvidence {
  event_id: string
  occurred_at: string
  site_id: string
  node_id: string
  source_country_code: string
  source_carrier: string
  country_code: string
  region: string
  city: string
  carrier: string
  asn: number
  address_family: 'ipv4' | 'ipv6'
  lookup_reason: 'prefix_match' | 'no_prefix_match'
  resolution: 'matched' | 'unknown'
  reconciliation: 'match' | 'mismatch' | 'unverified'
  prefix_length: number
  database_version: string
  database_provider: string
  database_sha256: string
  database_published_at: string
  database_effective_at: string
}

export interface AnalyticsGeoResponse { data: AnalyticsGeoEvidence }

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const eventPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const sha256Pattern = /^[0-9a-f]{64}$/

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exact(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === keys.length && keys.every((key) => key in value)
}

function dateTime(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value))
}

function bounded(value: unknown, maximum: number, allowEmpty = false): value is string {
  return typeof value === 'string' && value.length <= maximum && (allowEmpty || value.length > 0) &&
    value.trim() === value && [...value].every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127)
}

function canonicalIPFamily(value: unknown): 'ipv4' | 'ipv6' | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) return null
  if (!value.includes(':')) {
    const parts = value.split('.')
    return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
      ? 'ipv4'
      : null
  }
  try {
    const hostname = new URL(`http://[${value}]/`).hostname
    return hostname === `[${value}]` && value === value.toLowerCase() ? 'ipv6' : null
  } catch {
    return null
  }
}

function parseResponse(raw: unknown, event: AnalyticsGeoEventIdentity): AnalyticsGeoResponse {
  const keys = ['event_id', 'occurred_at', 'site_id', 'node_id', 'source_country_code', 'source_carrier',
    'country_code', 'region', 'city', 'carrier', 'asn', 'address_family', 'lookup_reason', 'resolution',
    'reconciliation', 'prefix_length', 'database_version', 'database_provider', 'database_sha256',
    'database_published_at', 'database_effective_at']
  if (!record(raw) || !exact(raw, ['data']) || !record(raw.data) || !exact(raw.data, keys)) throw invalidResponse()
  const value = raw.data
  const expectedFamily = canonicalIPFamily(event.clientIp)
  if (value.event_id !== event.eventId || value.occurred_at !== event.occurredAt || value.site_id !== event.siteId ||
    value.node_id !== event.nodeId || !eventPattern.test(String(value.event_id)) || !dateTime(value.occurred_at) ||
    !uuidPattern.test(String(value.site_id)) || !uuidPattern.test(String(value.node_id)) ||
    !bounded(value.source_country_code, 8, true) || !bounded(value.source_carrier, 128, true) ||
    !bounded(value.country_code, 16) || !bounded(value.region, 64) || !bounded(value.city, 128) || !bounded(value.carrier, 128) ||
    !Number.isInteger(value.asn) || Number(value.asn) < 0 || Number(value.asn) > 0xffff_ffff ||
    value.address_family !== expectedFamily ||
    value.lookup_reason !== 'prefix_match' && value.lookup_reason !== 'no_prefix_match' ||
    value.resolution !== 'matched' && value.resolution !== 'unknown' ||
    !['match', 'mismatch', 'unverified'].includes(String(value.reconciliation)) ||
    !Number.isInteger(value.prefix_length) || Number(value.prefix_length) < 0 || Number(value.prefix_length) > 128 ||
    typeof value.database_version !== 'string' || !versionPattern.test(value.database_version) ||
    !bounded(value.database_provider, 128) ||
    typeof value.database_sha256 !== 'string' || !sha256Pattern.test(value.database_sha256) ||
    !dateTime(value.database_published_at) || !dateTime(value.database_effective_at)) throw invalidResponse()
  if (value.resolution === 'unknown' && (value.country_code !== '__unknown__' || value.region !== '__unknown__' ||
    value.city !== '__unknown__' || value.carrier !== '__unknown__' || value.asn !== 0 || value.prefix_length !== 0 ||
    value.lookup_reason !== 'no_prefix_match')) throw invalidResponse()
  if (value.resolution === 'matched' && value.lookup_reason !== 'prefix_match') throw invalidResponse()
  return raw as unknown as AnalyticsGeoResponse
}

async function lookup(
  accessToken: string,
  audience: AnalyticsGeoAudience,
  kind: AnalyticsGeoKind,
  event: AnalyticsGeoEventIdentity,
  signal?: AbortSignal,
): Promise<AnalyticsGeoResponse> {
  if (!accessToken || !eventPattern.test(event.eventId) || !dateTime(event.occurredAt) ||
    !uuidPattern.test(event.siteId) || !uuidPattern.test(event.nodeId) || !canonicalIPFamily(event.clientIp) ||
    audience === 'admin' && (!event.tenantId || !uuidPattern.test(event.tenantId)) ||
    event.databaseVersion && !versionPattern.test(event.databaseVersion)) {
    throw new ApiError('Analytics geo request was invalid', 400, 'analytics_geo_invalid_request')
  }
  const from = new Date(event.occurredAt)
  const to = new Date(from.getTime() + 1)
  const query = new URLSearchParams({
    from: from.toISOString(), to: to.toISOString(), site_id: event.siteId, node_id: event.nodeId, client_ip: event.clientIp,
  })
  if (audience === 'admin') query.set('tenant_id', event.tenantId!)
  if (event.databaseVersion) query.set('database_version', event.databaseVersion)
  const base = audience === 'admin' ? '/v1/admin/analytics/logs' : '/v1/analytics/logs'
  let response: Response
  try {
    response = await fetch(`${apiRoot}${base}/${kind}/geo-evidence/${encodeURIComponent(event.eventId)}?${query}`, {
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
  return parseResponse(raw, event)
}

export const analyticsGeoApi = { lookup }
