import { ApiError, networkApiError } from './auth'

// The security ban list (封禁名单): manual bans and the
// nodes' automatic WAF / CC bans, per site; a release lifts a ban on every
// node serving the site. Tenants use /v1/security-bans, the platform
// /v1/admin/security-bans.

export type SecurityBanSource = 'waf' | 'cc' | 'manual'
export type SecurityBanState = 'active' | 'released' | 'expired'
export type SecurityBanAudience = 'tenant' | 'admin'

export interface SecurityBan {
  id: string
  tenant_scope_id: string
  site_id: string
  site_domain: string
  client_ip: string
  source: SecurityBanSource
  rule_id: string
  reason: string
  banned_at: string
  banned_until: string
  created_by: string | null
  released_at: string | null
  released_by: string | null
  state: SecurityBanState
}

export interface SecurityBanPage {
  items: SecurityBan[]
  total: number
  page: number
  limit: number
}

export interface SecurityBanQuery {
  page: number
  limit: number
  site_id?: string
  client_ip?: string
  state?: SecurityBanState
}

export interface SecurityBanCreateInput {
  site_id: string
  client_ip: string
  duration_seconds: number
  reason: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const codePattern = /^[a-z][a-z0-9_]{0,63}$/
const sources = new Set<SecurityBanSource>(['waf', 'cc', 'manual'])
const states = new Set<SecurityBanState>(['active', 'released', 'expired'])
const fields = ['id', 'tenant_scope_id', 'site_id', 'site_domain', 'client_ip', 'source', 'rule_id', 'reason', 'banned_at',
  'banned_until', 'created_by', 'released_at', 'released_by', 'state'] as const

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid security ban response', 502, 'invalid_response')
}

function time(value: unknown): boolean {
  return typeof value === 'string' && Number.isFinite(Date.parse(value))
}

function optionalUUID(value: unknown): boolean {
  return value === null || (typeof value === 'string' && uuidPattern.test(value))
}

function parseBan(value: unknown): SecurityBan {
  if (!record(value) || Object.keys(value).length !== fields.length || !fields.every((key) => key in value) ||
    !uuidPattern.test(String(value.id)) || !uuidPattern.test(String(value.tenant_scope_id)) || !uuidPattern.test(String(value.site_id)) ||
    typeof value.site_domain !== 'string' || typeof value.client_ip !== 'string' || value.client_ip.length > 45 ||
    !sources.has(value.source as SecurityBanSource) || typeof value.rule_id !== 'string' || typeof value.reason !== 'string' ||
    !time(value.banned_at) || !time(value.banned_until) || !optionalUUID(value.created_by) ||
    !(value.released_at === null || time(value.released_at)) || !optionalUUID(value.released_by) ||
    !states.has(value.state as SecurityBanState)) throw invalidResponse()
  return value as unknown as SecurityBan
}

function base(audience: SecurityBanAudience): string {
  return audience === 'admin' ? '/v1/admin/security-bans' : '/v1/security-bans'
}

async function send(token: string, path: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init, credentials: 'include', cache: 'no-store',
      headers: { Authorization: `Bearer ${token}`, ...init.headers },
    })
  } catch { throw networkApiError() }
  let body: unknown
  try { body = await response.json() } catch { throw invalidResponse() }
  if (!response.ok) {
    const error = record(body) && record(body.error) ? body.error : {}
    const code = typeof error.code === 'string' && codePattern.test(error.code) ? error.code : 'request_failed'
    throw new ApiError('API request failed', response.status, code, typeof error.request_id === 'string' ? error.request_id : undefined)
  }
  return body
}

async function list(token: string, audience: SecurityBanAudience, query: SecurityBanQuery): Promise<SecurityBanPage> {
  const params = new URLSearchParams({ page: String(query.page), limit: String(query.limit) })
  if (query.site_id) params.set('site_id', query.site_id)
  if (query.client_ip) params.set('client_ip', query.client_ip)
  if (query.state) params.set('state', query.state)
  const raw = await send(token, `${base(audience)}?${params.toString()}`)
  if (!record(raw) || !Array.isArray(raw.items) || !Number.isSafeInteger(raw.total) || !Number.isSafeInteger(raw.page) ||
    !Number.isSafeInteger(raw.limit)) throw invalidResponse()
  return { items: raw.items.map(parseBan), total: Number(raw.total), page: Number(raw.page), limit: Number(raw.limit) }
}

async function create(token: string, audience: SecurityBanAudience, input: SecurityBanCreateInput,
  idempotencyKey: string): Promise<SecurityBan> {
  const ban = parseBan(await send(token, base(audience), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  }))
  if (ban.site_id !== input.site_id) throw invalidResponse()
  return ban
}

async function release(token: string, audience: SecurityBanAudience, id: string): Promise<SecurityBan> {
  if (!uuidPattern.test(id)) throw new ApiError('Invalid security ban request', 400, 'invalid_request')
  const ban = parseBan(await send(token, `${base(audience)}/${id}/release`, { method: 'POST' }))
  if (ban.id !== id) throw invalidResponse()
  return ban
}

export const securityBansApi = { list, create, release }
