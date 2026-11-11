import { ApiError, networkApiError, responseApiError } from './auth'

// 内容改写: GET/PUT /v1/sites/{id}/content-rewrite and the
// tester POST /v1/sites/{id}/content-rewrite/test (the node's algorithm,
// run on the control plane; nothing is stored).

export type RewriteKind = 'link' | 'replace' | 'https'
export type RewriteScheme = 'keep' | 'https' | 'http'
export type RewriteContentType = 'text/html' | 'text/css' | 'application/javascript'

export const rewriteKinds: RewriteKind[] = ['link', 'replace', 'https']
export const rewriteContentTypes: RewriteContentType[] = ['text/html', 'text/css', 'application/javascript']
export const REWRITE_MAX_RULES = 50
export const REWRITE_DEFAULT_MAX_BYTES = 2 << 20
export const REWRITE_MIN_MAX_BYTES = 64 << 10
export const REWRITE_MAX_MAX_BYTES = 16 << 20
export const REWRITE_MAX_TEST_BODY = 256 << 10

export interface RewriteRule {
  id: string
  name: string
  enabled: boolean
  kind: RewriteKind
  paths: string[]
  content_types: RewriteContentType[]
  from_hosts?: string[]
  to_host?: string
  scheme?: RewriteScheme
  find?: string
  replace?: string
  regex?: boolean
  ignore_case?: boolean
  include_site_domains?: boolean
  hosts?: string[]
}

export interface RewriteSettings {
  max_bytes: number
  rules: RewriteRule[]
}

export interface RewriteState {
  site_id: string
  version: number
  settings: RewriteSettings
  domains: string[]
}

export interface RewriteTestResult {
  body: string
  matched_rules: string[]
  replacements: number
  truncated: boolean
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/u, '')

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isRule(value: unknown): value is RewriteRule {
  return isRecord(value) && typeof value.id === 'string' && typeof value.name === 'string' &&
    typeof value.enabled === 'boolean' && rewriteKinds.includes(value.kind as RewriteKind) &&
    isStringList(value.paths) && isStringList(value.content_types)
}

export function isRewriteState(value: unknown): value is RewriteState {
  return isRecord(value) && typeof value.site_id === 'string' && typeof value.version === 'number' &&
    isRecord(value.settings) && typeof value.settings.max_bytes === 'number' &&
    Array.isArray(value.settings.rules) && value.settings.rules.every(isRule) && isStringList(value.domains)
}

function isTestResult(value: unknown): value is RewriteTestResult {
  return isRecord(value) && typeof value.body === 'string' && isStringList(value.matched_rules) &&
    typeof value.replacements === 'number' && typeof value.truncated === 'boolean'
}

async function request<T>(token: string, path: string, guard: (value: unknown) => value is T, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID(),
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  let value: unknown
  try { value = await response.json() } catch { value = undefined }
  if (!guard(value)) throw new ApiError('Invalid content rewrite response', 0, 'invalid_response')
  return value
}

/** A new rule's id: short, unique within the site. */
export function newRuleID(existing: RewriteRule[]): string {
  const taken = new Set(existing.map((rule) => rule.id))
  for (;;) {
    const id = `r-${crypto.randomUUID().slice(0, 8)}`
    if (!taken.has(id)) return id
  }
}

/** Splits a free-text host or path list into trimmed non-empty items. */
export function splitList(value: string): string[] {
  return value.split(/[\s,，、]+/u).map((item) => item.trim()).filter(Boolean)
}

const base = (siteId: string) => `/v1/sites/${encodeURIComponent(siteId)}/content-rewrite`

export const contentRewriteApi = {
  get(token: string, siteId: string, signal?: AbortSignal): Promise<RewriteState> {
    return request(token, base(siteId), isRewriteState, { signal })
  },
  replace(token: string, siteId: string, expectedVersion: number, settings: RewriteSettings): Promise<RewriteState> {
    return request(token, base(siteId), isRewriteState, {
      method: 'PUT',
      headers: { 'If-Match': `"${expectedVersion}"` },
      body: JSON.stringify(settings),
    })
  },
  test(token: string, siteId: string, input: { settings: RewriteSettings; path: string; content_type: string; body: string }): Promise<RewriteTestResult> {
    return request(token, `${base(siteId)}/test`, isTestResult, { method: 'POST', body: JSON.stringify(input) })
  },
}
