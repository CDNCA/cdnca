import { ApiError } from './auth'
import { streamsApi, validStreamNewConnectionRate, type CreateStreamRequest, type Stream, type StreamBalanceWay, type StreamGeoAction, type StreamProtocol } from './streams'

export type QuickStreamParseError = 'empty' | 'invalid_entry' | 'port_range' | 'duplicate' | 'conflict'

export interface QuickStreamEntry {
  protocol: StreamProtocol
  listen_port: number
}

export interface QuickStreamParseRow {
  raw: string
  entry: QuickStreamEntry | null
  error: Exclude<QuickStreamParseError, 'empty'> | null
}

interface DNSPolicy {
  positive_min_ttl_seconds: number
  positive_max_ttl_seconds: number
  negative_ttl_seconds: number
  stale_if_error_seconds: number
  allow_private_addresses: boolean
}

interface GeoPolicy {
  enabled: boolean
  unknown_region_action: StreamGeoAction
  trusted_proxy_cidrs: string[]
  blocked_regions: string[]
  region_cidrs: Array<{ region: string; cidrs: string[] }>
}

export interface QuickStreamTemplate {
  id: string
  scope_id: string
  owner_id: string | null
  revision: number
  fields: {
    name: string
    remark: string
    protocol: StreamProtocol
    listen_address: '*'
    upstream_address: string
    upstream_host: string
    upstream_port: number
    dns_policy: DNSPolicy
    geo_policy: GeoPolicy
    connect_timeout_ms: number
    response_timeout_ms: number
    max_connections_per_client: number
    proxy_protocol_inbound: boolean
    proxy_protocol_v1: boolean
    balance_way: StreamBalanceWay
    enabled: boolean
    tls_passthrough: boolean
    server_names: string[]
    max_new_connections_per_client_per_second: number
    new_connection_burst: number
    new_connection_ban_seconds: number
    toa: boolean
    session_log_enabled: boolean
  }
}

export interface QuickStreamAttempt {
  input: CreateStreamRequest
  key: string
  template_id: string
  template_revision: number
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null
}

function positiveInteger(value: unknown, maximum: number): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1 && Number(value) <= maximum
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function dnsPolicy(value: unknown): DNSPolicy | null {
  const item = record(value)
  if (!item || !['positive_min_ttl_seconds', 'positive_max_ttl_seconds', 'negative_ttl_seconds', 'stale_if_error_seconds']
    .every((key) => Number.isSafeInteger(item[key]) && Number(item[key]) >= 0) ||
    typeof item.allow_private_addresses !== 'boolean') return null
  return value as DNSPolicy
}

function geoPolicy(value: unknown): GeoPolicy | null {
  const item = record(value)
  if (!item || typeof item.enabled !== 'boolean' ||
    (item.unknown_region_action !== 'allow' && item.unknown_region_action !== 'block') ||
    !stringArray(item.trusted_proxy_cidrs) || !stringArray(item.blocked_regions) || !Array.isArray(item.region_cidrs) ||
    !item.region_cidrs.every((entry) => {
      const region = record(entry)
      return region && typeof region.region === 'string' && stringArray(region.cidrs)
    })) return null
  return value as GeoPolicy
}

export function parseQuickStreamEntries(input: string, occupied: QuickStreamEntry[] = []): {
  entries: QuickStreamEntry[]
  rows: QuickStreamParseRow[]
  error: QuickStreamParseError | null
} {
  const tokens = input.trim().split(/[\s,，]+/u).filter(Boolean)
  if (tokens.length === 0) return { entries: [], rows: [], error: 'empty' }
  const seen = new Set<string>()
  const occupiedKeys = new Set(occupied.map((entry) => `${entry.protocol}:${entry.listen_port}`))
  const entries: QuickStreamEntry[] = []
  const rows: QuickStreamParseRow[] = []
  let firstError: QuickStreamParseError | null = null
  for (const token of tokens) {
    const match = /^(\d{1,5})(?:\/(tcp|udp))?$/i.exec(token)
    if (!match) {
      rows.push({ raw: token, entry: null, error: 'invalid_entry' })
      firstError ??= 'invalid_entry'
      continue
    }
    const listen_port = Number(match[1])
    if (!positiveInteger(listen_port, 65535)) {
      rows.push({ raw: token, entry: null, error: 'port_range' })
      firstError ??= 'port_range'
      continue
    }
    const protocol = (match[2]?.toLowerCase() ?? 'tcp') as StreamProtocol
    const entry = { protocol, listen_port }
    const identity = `${protocol}:${listen_port}`
    if (seen.has(identity)) {
      rows.push({ raw: token, entry, error: 'duplicate' })
      firstError ??= 'duplicate'
      continue
    }
    seen.add(identity)
    if (occupiedKeys.has(identity)) {
      rows.push({ raw: token, entry, error: 'conflict' })
      firstError ??= 'conflict'
      continue
    }
    rows.push({ raw: token, entry, error: null })
    entries.push(entry)
  }
  entries.sort((left, right) => left.protocol.localeCompare(right.protocol) || left.listen_port - right.listen_port)
  return { entries, rows, error: firstError }
}

export function quickStreamTemplate(stream: Stream): QuickStreamTemplate | null {
  const item = record(stream)
  const dns = dnsPolicy(item?.dns_policy)
  const geo = geoPolicy(item?.geo_policy)
  if (!item || !uuidPattern.test(String(item.id)) || !uuidPattern.test(String(item.scope_id)) ||
    (item.protocol !== 'tcp' && item.protocol !== 'udp') || item.listen_address !== '*' ||
    typeof item.name !== 'string' || typeof item.remark !== 'string' ||
    typeof item.upstream_address !== 'string' || typeof item.upstream_host !== 'string' ||
    !positiveInteger(item.upstream_port, 65535) || !positiveInteger(item.max_connections_per_client, 10000) ||
    !positiveInteger(item.revision, Number.MAX_SAFE_INTEGER) ||
    !positiveInteger(item.connect_timeout_ms, 30000) || !positiveInteger(item.response_timeout_ms, 600000) ||
    typeof item.proxy_protocol_inbound !== 'boolean' || typeof item.proxy_protocol_v1 !== 'boolean' ||
    (item.balance_way !== 'rr' && item.balance_way !== 'ip_hash') ||
    typeof item.enabled !== 'boolean' || typeof item.tls_passthrough !== 'boolean' || !stringArray(item.server_names) ||
    !validStreamNewConnectionRate(item.max_new_connections_per_client_per_second, item.new_connection_burst, item.new_connection_ban_seconds) ||
    typeof item.toa !== 'boolean' ||
    typeof item.session_log_enabled !== 'boolean' ||
    !dns || !geo) return null
  const hasAddress = item.upstream_address.trim() !== ''
  const hasHost = item.upstream_host.trim() !== ''
  if (hasAddress === hasHost || (item.protocol === 'udp' && (item.proxy_protocol_inbound || item.proxy_protocol_v1 || item.tls_passthrough || item.toa))) return null
  const owner = record(item.owner)
  const ownerID = typeof owner?.id === 'string' && uuidPattern.test(owner.id) ? owner.id : null
  return {
    id: item.id as string,
    scope_id: item.scope_id as string,
    owner_id: ownerID,
    revision: item.revision as number,
    fields: {
      name: item.name,
      remark: item.remark,
      protocol: item.protocol,
      listen_address: '*',
      upstream_address: item.upstream_address,
      upstream_host: item.upstream_host,
      upstream_port: item.upstream_port,
      dns_policy: dns,
      geo_policy: geo,
      connect_timeout_ms: item.connect_timeout_ms,
      response_timeout_ms: item.response_timeout_ms,
      max_connections_per_client: item.max_connections_per_client,
      proxy_protocol_inbound: item.proxy_protocol_inbound,
      proxy_protocol_v1: item.proxy_protocol_v1,
      balance_way: item.balance_way,
      enabled: item.enabled,
      tls_passthrough: item.tls_passthrough,
      server_names: [...item.server_names],
      max_new_connections_per_client_per_second: item.max_new_connections_per_client_per_second as number,
      new_connection_burst: item.new_connection_burst as number,
      new_connection_ban_seconds: item.new_connection_ban_seconds as number,
      toa: item.toa,
      session_log_enabled: item.session_log_enabled,
    },
  }
}

function quickName(name: string, entry: QuickStreamEntry): string {
  const suffix = `-${entry.protocol}-${entry.listen_port}`
  return `${[...name].slice(0, 128 - suffix.length).join('')}${suffix}`
}

export function buildQuickStreamAttempt(
  template: QuickStreamTemplate,
  entry: QuickStreamEntry,
  scopeKind: 'tenant' | 'platform',
  key: string,
): QuickStreamAttempt {
  if (entry.protocol !== template.fields.protocol || (scopeKind === 'platform' && !template.owner_id)) {
    throw new Error('stream quick-create template does not match the requested scope or protocol')
  }
  return {
    key,
    template_id: template.id,
    template_revision: template.revision,
    input: {
      ...template.fields,
      name: quickName(template.fields.name, entry),
      listen_port: entry.listen_port,
      ...(scopeKind === 'platform' ? {
        target_scope_id: template.scope_id,
        owner_id: template.owner_id!,
      } : {}),
    },
  }
}

export function quickStreamKey(): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `quick-stream-${suffix}`
}

export function quickStreamResultUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

export const streamQuickCreateApi = {
  create: (accessToken: string, attempt: QuickStreamAttempt) =>
    streamsApi.create(accessToken, attempt.input, attempt.key),
}
