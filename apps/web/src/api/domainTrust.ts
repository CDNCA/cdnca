import { ApiError, networkApiError, responseApiError } from './auth'

// Domain blocklist (#11) and domain ownership (#12): control-api
// internal/domaintrusthttp. Account routes use the tenant session; admin
// routes need platform scope + domains.security.manage.
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export const domainSecurityPermission = 'domains.security.manage'

export type OwnershipMethod = 'dns_txt' | 'http_file'
export type OwnershipStatus = 'pending' | 'verified' | 'expired' | 'revoked'

export interface DomainOwnership {
  id: string
  scope_id: string
  apex: string
  method: OwnershipMethod
  status: OwnershipStatus
  token?: string
  txt_name?: string
  http_url?: string
  verified_at?: string
  last_checked_at?: string
  last_failure_code: string
  created_at: string
  updated_at: string
  revision: number
}

export interface DomainConflict { domain: string; site_count: number; claimable: boolean }

export interface ClaimResult {
  apex: string
  domains: string[]
  suspended_sites: number
  notifications_sent: number
  notifications_failed: number
}

export interface ClaimSuspension {
  id: string
  scope_id: string
  site_id: string
  domain: string
  claimant_scope_id?: string
  created_at: string
  released_at?: string
  release_reason?: string
}

export type BlocklistMatch = 'root' | 'exact'

export interface BlocklistEntry {
  id: string
  pattern: string
  match_type: BlocklistMatch
  reason: string
  created_at: string
  updated_at: string
  revision: number
}

export interface BlocklistInput { pattern: string; match_type: BlocklistMatch; reason: string }

export interface BlocklistHit {
  site_id: string
  scope_id: string
  display_id: number
  domain: string
  pattern: string
  enabled: boolean
  revision: number
  owner_user_id: string
}

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE'

async function call<T>(token: string, method: Method, path: string, body?: unknown, key?: string, contentType = 'application/json'): Promise<T> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      method,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': `domain-trust-${crypto.randomUUID()}`,
        ...(body !== undefined ? { 'Content-Type': contentType } : {}),
        ...(key ? { 'Idempotency-Key': key } : {}),
      },
      ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204) return undefined as T
  try {
    return await response.json() as T
  } catch {
    throw new ApiError('Invalid response', 502, 'response_invalid')
  }
}

function items<T>(body: { items?: unknown }): T[] {
  if (!Array.isArray(body?.items)) throw new ApiError('Invalid response', 502, 'response_invalid')
  return body.items as T[]
}

export function newDomainTrustKey(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`
}

export const domainOwnershipApi = {
  list: async (token: string) => items<DomainOwnership>(await call(token, 'GET', '/v1/domain-ownerships')),
  start: (token: string, domain: string, method: OwnershipMethod) =>
    call<DomainOwnership>(token, 'POST', '/v1/domain-ownerships', { domain, method }),
  check: (token: string, domain: string) => call<DomainOwnership>(token, 'POST', '/v1/domain-ownerships/check', { domain }),
  revoke: (token: string, domain: string) => call<DomainOwnership>(token, 'POST', '/v1/domain-ownerships/revoke', { domain }),
  conflicts: async (token: string, domain: string) =>
    items<DomainConflict>(await call(token, 'GET', `/v1/domain-ownerships/conflicts?domain=${encodeURIComponent(domain)}`)),
  claim: (token: string, apex: string, domains: string[], key: string) =>
    call<ClaimResult>(token, 'POST', '/v1/domain-ownerships/claims', { apex, domains }, key),
  suspensions: async (token: string) => items<ClaimSuspension>(await call(token, 'GET', '/v1/domain-ownerships/suspensions')),
}

export const domainBlocklistApi = {
  list: async (token: string, search = '') =>
    items<BlocklistEntry>(await call(token, 'GET', `/v1/admin/domain-blocklist?search=${encodeURIComponent(search)}`)),
  create: (token: string, input: BlocklistInput, key: string) =>
    call<BlocklistEntry>(token, 'POST', '/v1/admin/domain-blocklist', input, key),
  update: (token: string, id: string, revision: number, input: BlocklistInput, key: string) =>
    call<BlocklistEntry>(token, 'PUT', `/v1/admin/domain-blocklist/${encodeURIComponent(id)}`, { ...input, expected_revision: revision }, key),
  remove: (token: string, id: string, revision: number, key: string) =>
    call<void>(token, 'DELETE', `/v1/admin/domain-blocklist/${encodeURIComponent(id)}?expected_revision=${revision}`, undefined, key),
  importText: (token: string, text: string, key: string) =>
    call<{ created: number; updated: number }>(token, 'POST', '/v1/admin/domain-blocklist/import', text, key, 'text/plain; charset=utf-8'),
  exportCSV: async (token: string): Promise<Blob> => {
    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/admin/domain-blocklist/export`, {
        credentials: 'include', headers: { Authorization: `Bearer ${token}` },
      })
    } catch {
      throw networkApiError()
    }
    if (!response.ok) throw await responseApiError(response)
    return response.blob()
  },
  hits: async (token: string, entryID?: string) =>
    items<BlocklistHit>(await call(token, 'GET', `/v1/admin/domain-blocklist/hits${entryID ? `?entry_id=${encodeURIComponent(entryID)}` : ''}`)),
  ownerships: async (token: string, apex = '', status = '') =>
    items<DomainOwnership>(await call(token, 'GET', `/v1/admin/domain-ownerships?apex=${encodeURIComponent(apex)}&status=${encodeURIComponent(status)}`)),
  revokeOwnership: (token: string, id: string) =>
    call<DomainOwnership>(token, 'POST', `/v1/admin/domain-ownerships/${encodeURIComponent(id)}/revoke`),
  suspensions: async (token: string, includeReleased: boolean) =>
    items<ClaimSuspension>(await call(token, 'GET', `/v1/admin/domain-claim-suspensions?include_released=${includeReleased}`)),
  release: (token: string, id: string) =>
    call<ClaimSuspension>(token, 'POST', `/v1/admin/domain-claim-suspensions/${encodeURIComponent(id)}/release`),
}

// Site write refusals carry the refused domain and its apex (httpapi
// writeDomainTrustError) so the create form can open the verification step.
export const ownershipErrorCodes = ['domain_ownership_required', 'domain_verified_by_other', 'domain_blocked'] as const
