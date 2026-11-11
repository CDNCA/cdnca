import { ApiError, networkApiError, responseApiError } from './auth'

// String sets (字符串集合): WAF / ACL rule conditions on host,
// path, request_uri, user_agent, referer, header or ja4 with the operators
// in_string_set / not_in_string_set reference one set by id; a set change
// republishes the sites whose policies use it. Tenants manage
// /v1/security-string-sets (and see the platform's sets read only), the
// platform /v1/admin/security-string-sets. match_mode and case_sensitive are
// fixed at creation (an update must not send them).

export type SecurityStringSetAudience = 'tenant' | 'admin'

export const stringSetMatchModes = ['exact', 'prefix', 'suffix', 'contains', 'wildcard'] as const
export type StringSetMatchMode = (typeof stringSetMatchModes)[number]

/** Request values a string set condition may read (the rule condition field). */
export const stringSetConditionFields = ['host', 'path', 'request_uri', 'user_agent', 'referer', 'header', 'ja4'] as const
export type StringSetConditionField = (typeof stringSetConditionFields)[number]

/** Limits the server enforces (edgeconfig); the page checks them before saving. */
export const stringSetLimits = {
  maxEntries: 10000, maxWildcardEntries: 2000, maxEntryBytes: 512, maxTotalBytes: 256 * 1024,
  maxWildcardStars: 3, maxPerScope: 200, maxNameLength: 64, maxDescriptionLength: 512,
} as const

/** A list item: no entries (GET one set for them). */
export interface SecurityStringSetSummary {
  id: string
  name: string
  description: string
  match_mode: StringSetMatchMode
  case_sensitive: boolean
  entry_count: number
  reference_count: number
  revision: number
  platform: boolean
  updated_at: string
}

/** One set with its canonical entries (trimmed, unique, byte order; lower case when not case sensitive). */
export interface SecurityStringSet extends SecurityStringSetSummary {
  entries: string[]
}

export interface SecurityStringSetInput {
  name: string
  description: string
  match_mode: StringSetMatchMode
  case_sensitive: boolean
  entries: string[]
}

export interface SecurityStringSetUpdate {
  name: string
  description: string
  entries: string[]
}

export interface SecurityStringSetReference {
  policy_id: string
  policy_name: string
  policy_kind: string
  rule_count: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function count(value: unknown, minimum: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= minimum
}

function isSummary(value: unknown): value is SecurityStringSetSummary {
  return record(value) && typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.name === 'string' && typeof value.description === 'string' &&
    typeof value.match_mode === 'string' && (stringSetMatchModes as readonly string[]).includes(value.match_mode) &&
    typeof value.case_sensitive === 'boolean' && count(value.entry_count, 1) && count(value.reference_count, 0) &&
    count(value.revision, 1) && typeof value.platform === 'boolean' && typeof value.updated_at === 'string'
}

function isSet(value: unknown): value is SecurityStringSet {
  return isSummary(value) && record(value) && Array.isArray(value.entries) &&
    value.entries.every((entry) => typeof entry === 'string')
}

function isReference(value: unknown): value is SecurityStringSetReference {
  return record(value) && typeof value.policy_id === 'string' && uuidPattern.test(value.policy_id) &&
    typeof value.policy_name === 'string' && typeof value.policy_kind === 'string' && count(value.rule_count, 1)
}

function invalidResponse(): ApiError {
  return new ApiError('String set response is invalid', 502, 'invalid_response')
}

function base(audience: SecurityStringSetAudience): string {
  return `${apiRoot}${audience === 'admin' ? '/v1/admin/security-string-sets' : '/v1/security-string-sets'}`
}

function writeKey(): string {
  return `security-string-set-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`}`
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
  // A refused entry is validation_error with field entries[i] and the reason (ApiError.field / reason).
  if (!response.ok) throw await responseApiError(response)
  return response.json().catch(() => null)
}

function itemURL(audience: SecurityStringSetAudience, id: string): string {
  return `${base(audience)}/${encodeURIComponent(id)}`
}

export async function listSecurityStringSets(accessToken: string, audience: SecurityStringSetAudience): Promise<SecurityStringSetSummary[]> {
  const body = await request(base(audience), { method: 'GET' }, accessToken, false)
  if (!record(body) || !Array.isArray(body.items) || !body.items.every(isSummary)) throw invalidResponse()
  return body.items
}

export async function getSecurityStringSet(accessToken: string, audience: SecurityStringSetAudience, id: string): Promise<SecurityStringSet> {
  const body = await request(itemURL(audience, id), { method: 'GET' }, accessToken, false)
  if (!isSet(body)) throw invalidResponse()
  return body
}

export async function createSecurityStringSet(accessToken: string, audience: SecurityStringSetAudience,
  input: SecurityStringSetInput): Promise<SecurityStringSet> {
  const body = await request(base(audience), { method: 'POST', body: JSON.stringify(input) }, accessToken, true)
  if (!isSet(body)) throw invalidResponse()
  return body
}

export async function updateSecurityStringSet(accessToken: string, audience: SecurityStringSetAudience,
  set: Pick<SecurityStringSet, 'id' | 'revision'>, input: SecurityStringSetUpdate): Promise<SecurityStringSet> {
  const body = await request(itemURL(audience, set.id),
    { method: 'PUT', body: JSON.stringify({ expected_revision: set.revision, ...input }) }, accessToken, true)
  if (!isSet(body)) throw invalidResponse()
  return body
}

export async function deleteSecurityStringSet(accessToken: string, audience: SecurityStringSetAudience,
  set: Pick<SecurityStringSet, 'id' | 'revision'>): Promise<void> {
  await request(`${itemURL(audience, set.id)}?expected_revision=${set.revision}`, { method: 'DELETE' }, accessToken, true)
}

export async function listSecurityStringSetReferences(accessToken: string, audience: SecurityStringSetAudience,
  id: string): Promise<SecurityStringSetReference[]> {
  const body = await request(`${itemURL(audience, id)}/references`, { method: 'GET' }, accessToken, false)
  if (!record(body) || !Array.isArray(body.items) || !body.items.every(isReference)) throw invalidResponse()
  return body.items
}

/** POST /v1/security-policies/parse-user-agent: what the browser / device conditions see. */
export interface ParsedUserAgent {
  browser: string
  version: string | null
  device: string
}

export async function parseUserAgent(accessToken: string, userAgent: string): Promise<ParsedUserAgent> {
  const body = await request(`${apiRoot}/v1/security-policies/parse-user-agent`,
    { method: 'POST', body: JSON.stringify({ user_agent: userAgent }) }, accessToken, false)
  if (!record(body) || typeof body.browser !== 'string' || typeof body.device !== 'string' ||
    !(body.version === null || typeof body.version === 'string')) throw invalidResponse()
  return { browser: body.browser, version: body.version, device: body.device }
}

/**
 * Splits a textarea into entries: one per line, trimmed, blank lines dropped.
 * Unlike IP lists there is no comma split or # comment: both are valid member text.
 */
export function parseStringSetEntries(text: string): string[] {
  return text.split('\n').map((line) => line.trim()).filter(Boolean)
}
