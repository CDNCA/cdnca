import { ApiError, networkApiError } from './auth'

// Named IP lists (IP 名单): WAF rule conditions
// "ip_list in_ip_list <id>" reference them; a list change republishes the
// sites whose policies use it. Tenants manage /v1/security-ip-lists (and see
// the platform's lists read only), the platform /v1/admin/security-ip-lists.

export type SecurityIPListAudience = 'tenant' | 'admin'

export interface SecurityIPList {
  id: string
  name: string
  description: string
  entries: string[]
  revision: number
  platform: boolean
  updated_at: string
}

export interface SecurityIPListInput {
  name: string
  description: string
  entries: string[]
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const codePattern = /^[a-z][a-z0-9_]{0,63}$/

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isList(value: unknown): value is SecurityIPList {
  return record(value) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.name === 'string' && typeof value.description === 'string' &&
    Array.isArray(value.entries) && value.entries.every((entry) => typeof entry === 'string') &&
    typeof value.revision === 'number' && Number.isInteger(value.revision) && value.revision > 0 &&
    typeof value.platform === 'boolean' && typeof value.updated_at === 'string'
}

function invalidResponse(): ApiError {
  return new ApiError('IP list response is invalid', 502, 'invalid_response')
}

function base(audience: SecurityIPListAudience): string {
  return `${apiRoot}${audience === 'admin' ? '/v1/admin/security-ip-lists' : '/v1/security-ip-lists'}`
}

function writeKey(): string {
  return `security-ip-list-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`}`
}

async function request(url: string, init: RequestInit, accessToken: string, idempotent: boolean): Promise<unknown> {
  const headers: Record<string, string> = { Accept: 'application/json', Authorization: `Bearer ${accessToken}` }
  if (init.body) headers['Content-Type'] = 'application/json'
  if (idempotent) headers['Idempotency-Key'] = writeKey()
  let response: Response
  try {
    response = await fetch(url, { ...init, headers, credentials: 'include', cache: 'no-store' })
  } catch { throw networkApiError() }
  if (response.status === 204) return null
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const error = record(body) && record(body.error) ? body.error : {}
    const code = typeof error.code === 'string' && codePattern.test(error.code) ? error.code : 'request_failed'
    throw new ApiError('API request failed', response.status, code, typeof error.request_id === 'string' ? error.request_id : undefined)
  }
  return body
}

export async function listSecurityIPLists(accessToken: string, audience: SecurityIPListAudience): Promise<SecurityIPList[]> {
  const body = await request(base(audience), { method: 'GET' }, accessToken, false)
  if (!record(body) || !Array.isArray(body.items) || !body.items.every(isList)) {
    throw invalidResponse()
  }
  return body.items
}

export async function createSecurityIPList(accessToken: string, audience: SecurityIPListAudience, input: SecurityIPListInput): Promise<SecurityIPList> {
  const body = await request(base(audience), { method: 'POST', body: JSON.stringify(input) }, accessToken, true)
  if (!isList(body)) throw invalidResponse()
  return body
}

export async function updateSecurityIPList(accessToken: string, audience: SecurityIPListAudience, list: SecurityIPList,
  input: SecurityIPListInput): Promise<SecurityIPList> {
  const body = await request(`${base(audience)}/${encodeURIComponent(list.id)}`,
    { method: 'PUT', body: JSON.stringify({ expected_revision: list.revision, ...input }) }, accessToken, true)
  if (!isList(body)) throw invalidResponse()
  return body
}

export async function deleteSecurityIPList(accessToken: string, audience: SecurityIPListAudience, list: SecurityIPList): Promise<void> {
  await request(`${base(audience)}/${encodeURIComponent(list.id)}?expected_revision=${list.revision}`, { method: 'DELETE' }, accessToken, true)
}

/** Splits a textarea into entries: one per line or comma, # starts a comment. */
export function parseIPListEntries(text: string): string[] {
  return text.split('\n').map((line) => line.replace(/#.*$/, '')).flatMap((line) => line.split(','))
    .map((value) => value.trim()).filter(Boolean)
}
