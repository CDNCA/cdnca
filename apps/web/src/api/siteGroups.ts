import { ApiError, networkApiError, responseApiError } from './auth'

export interface SiteGroup {
  id: string
  scope_id: string
  name: string
  revision: number
  created_at: string
  updated_at: string
  deleted_at?: string | null
  remark?: string
  display_id?: string
}

export interface AdminSiteGroup extends SiteGroup {
  remark: string
  display_id: string
  user: { id: string; display_id: string; username: string } | null
  user_state: 'resolved' | 'missing' | 'ambiguous'
}

export interface SiteGroupListResponse {
  items: SiteGroup[]
  total: number
  page: number
  limit: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null
}

function parseGroup(value: unknown): SiteGroup {
  const item = record(value)
  const revision = item?.revision
  if (!item || typeof item.id !== 'string' || !uuidPattern.test(item.id) ||
    typeof item.scope_id !== 'string' || !uuidPattern.test(item.scope_id) ||
    typeof item.name !== 'string' || typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision < 1 ||
    typeof item.created_at !== 'string' || typeof item.updated_at !== 'string' ||
    (item.deleted_at !== undefined && item.deleted_at !== null && typeof item.deleted_at !== 'string') ||
    (item.remark !== undefined && (typeof item.remark !== 'string' || [...item.remark].length > 1024)) ||
    (item.display_id !== undefined && (typeof item.display_id !== 'string' || !/^[1-9]\d{0,18}$/.test(item.display_id)))) {
    throw invalidResponse()
  }
  return item as unknown as SiteGroup
}

async function request(accessToken: string, path: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const expected = init.method === 'POST' ? 201 : init.method === 'DELETE' ? 204 : 200
  if (response.status !== expected) throw invalidResponse()
  if (response.status === 204) return undefined
  return response.json().catch(() => { throw invalidResponse() })
}

function parseList(value: unknown): SiteGroupListResponse {
  const response = record(value)
  if (!response || !Array.isArray(response.items) || !Number.isSafeInteger(response.total) ||
    !Number.isSafeInteger(response.page) || !Number.isSafeInteger(response.limit) ||
    (response.total as number) < response.items.length || (response.page as number) < 1 ||
    (response.limit as number) < 1 || (response.limit as number) > 100 || response.items.length > (response.limit as number)) throw invalidResponse()
  const items = response.items.map(parseGroup)
  if (new Set(items.map((item) => `${item.scope_id}:${item.id}`)).size !== items.length || items.some((item) => item.deleted_at)) throw invalidResponse()
  return { items, total: response.total as number, page: response.page as number, limit: response.limit as number }
}

function parseAdminGroup(value: unknown): AdminSiteGroup {
  const group = parseGroup(value)
  const item = record(value)!
  const user = record(item.user)
  if (!group.display_id || typeof group.remark !== 'string' || !['resolved', 'missing', 'ambiguous'].includes(String(item.user_state)) ||
    (item.user_state === 'resolved'
      ? !user || typeof user.id !== 'string' || !uuidPattern.test(user.id) || typeof user.display_id !== 'string' || !/^[1-9]\d{0,18}$/.test(user.display_id) || typeof user.username !== 'string' || !user.username
      : item.user !== null)) throw invalidResponse()
  return item as unknown as AdminSiteGroup
}

export const siteGroupsApi = {
  list(accessToken: string, scopeID: string, page = 1, limit = 20) {
    return request(accessToken, `/v1/site-groups?scope_id=${encodeURIComponent(scopeID)}&page=${page}&limit=${limit}`).then((value) => {
      const result = parseList(value)
      if (result.page !== page || result.limit !== limit || result.items.some((item) => item.scope_id !== scopeID)) throw invalidResponse()
      return result
    })
  },
  listAdmin(accessToken: string, page = 1, limit = 10) {
    return request(accessToken, `/v1/admin/site-groups?page=${page}&limit=${limit}`).then((value) => {
      const result = parseList(value)
      const items = result.items.map(parseAdminGroup)
      if (result.page !== page || result.limit !== limit || new Set(items.map((item) => item.display_id)).size !== items.length) throw invalidResponse()
      return { ...result, items }
    })
  },
  get(accessToken: string, scopeID: string, id: string) {
    return request(accessToken, `/v1/site-groups/${encodeURIComponent(id)}?scope_id=${encodeURIComponent(scopeID)}`).then((value) => {
      const result = parseGroup(value)
      if (result.id !== id || result.scope_id !== scopeID || result.deleted_at || !result.display_id || typeof result.remark !== 'string') throw invalidResponse()
      return result
    })
  },
  create(accessToken: string, scopeID: string, name: string, key: string, remark?: string) {
    return request(accessToken, '/v1/site-groups', {
      method: 'POST', headers: { 'Idempotency-Key': key },
      body: JSON.stringify({ target_scope_id: scopeID, name, ...(remark === undefined ? {} : { remark }) }),
    }).then(parseGroup)
  },
  rename(accessToken: string, item: SiteGroup, name: string, key: string, remark?: string) {
    return request(accessToken, `/v1/site-groups/${encodeURIComponent(item.id)}?scope_id=${encodeURIComponent(item.scope_id)}`, {
      method: 'PATCH', headers: { 'Idempotency-Key': key, 'If-Match': `"${item.revision}"` },
      body: JSON.stringify({ expected_revision: item.revision, name, ...(remark === undefined ? {} : { remark }) }),
    }).then(parseGroup)
  },
  remove(accessToken: string, item: SiteGroup, key: string) {
    return request(accessToken, `/v1/site-groups/${encodeURIComponent(item.id)}?scope_id=${encodeURIComponent(item.scope_id)}`, {
      method: 'DELETE', headers: { 'Idempotency-Key': key, 'If-Match': `"${item.revision}"` },
    }).then(() => undefined)
  },
}
