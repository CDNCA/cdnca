import { networkApiError, responseApiError } from './auth'

/** 站点访问控制：GET/PUT /v1/sites/{site_id}/access. */

export type RedirectStatus = 301 | 302 | 307 | 308

export interface HostRedirect {
  source_host: string
  target_host: string
  target_scheme: 'http' | 'https' | 'follow'
  target_port?: number
  status: RedirectStatus
  preserve_uri: boolean
}

export interface SiteHSTS {
  max_age_seconds: number
  include_subdomains: boolean
  preload: boolean
}

export type CompressionEncoding = 'br' | 'gzip'

export interface SiteCompression {
  enabled: boolean
  types: string[]
  min_length_bytes: number
  /** Absent = gzip only; Brotli needs nodes with EDGE_BROTLI. */
  encodings?: CompressionEncoding[]
  /** 0 or absent = the node default. */
  gzip_level?: number
  brotli_level?: number
}

/** JPEG/PNG to WebP for clients accepting image/webp (EDGE_WEBP). */
export interface SiteWebP {
  enabled: true
  quality?: number
}

export type ResponseRuleAction = 'headers' | 'log' | 'error_page' | 'block'
export type ResponseHeaderOp = 'exists' | 'absent' | 'equals' | 'regex'
export type ResponseHeaderActionKind = 'set' | 'add' | 'delete'

/**
 * A response phase rule (EDGE_RESPONSE_RULES): status ranges
 * (none = any) and header conditions, all of which must hold. headers rules
 * also run on cached responses; log, error_page and block only on the
 * origin's response, and a replaced response is not cached.
 */
export interface SiteResponseRule {
  id: string
  statuses?: { from: number; to: number }[]
  headers?: { name: string; op: ResponseHeaderOp; value?: string }[]
  action: ResponseRuleAction
  header_actions?: { kind: ResponseHeaderActionKind; name: string; value?: string }[]
  /** error_page / block status (400-599). */
  status?: number
}

export interface SiteRequestLimits {
  connections_per_ip?: number
  rate_bytes_per_second?: number
  rate_after_bytes?: number
}

export interface BasicAuthUser {
  username: string
  /** Set to add or change the password; omitted keeps the stored one. */
  password?: string
}

export interface SiteBasicAuth {
  realm: string
  users: BasicAuthUser[]
  exclude_path_prefixes: string[]
}

export interface SiteMaintenance {
  status: number
  content_type: 'text/html' | 'text/plain' | 'application/json'
  body: string
  retry_after_seconds?: number
  allowed_cidrs?: string[]
}

export interface SiteAccessSettings {
  host_redirects: HostRedirect[]
  hsts: SiteHSTS | null
  compression: SiteCompression | null
  limits: SiteRequestLimits | null
  basic_auth: SiteBasicAuth | null
  maintenance: SiteMaintenance | null
  webp?: SiteWebP | null
  response_rules?: SiteResponseRule[]
  force_https: { status: RedirectStatus; exclude_hosts: string[] }
}

export interface SiteAccessState {
  site_id: string
  version: number
  settings: SiteAccessSettings
  https_enabled: boolean
  force_https: boolean
  domains: string[]
  updated_at: string | null
}

/** One year: the HSTS preload list minimum. */
export const hstsPreloadMinimum = 31_536_000

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return (await response.json()) as T
}

function get(accessToken: string, siteID: string, signal?: AbortSignal): Promise<SiteAccessState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/access`, { signal })
}

function put(accessToken: string, siteID: string, version: number, settings: SiteAccessSettings,
  idempotencyKey: string): Promise<SiteAccessState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/access`, {
    method: 'PUT',
    headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${version}"` },
    body: JSON.stringify(settings),
  })
}

export const siteAccessApi = { get, put }
