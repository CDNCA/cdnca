import { ApiError, networkApiError, responseApiError } from './auth'
import type { StreamBalanceWay, StreamProtocol, StreamSettingName, StreamSettingScope } from './streams'

export interface StreamOwner {
  id: string
  display_name: string
}

export interface StreamGroup {
  id: string
  display_id: string
  scope_id: string
  owner: StreamOwner | null
  name: string
  remark: string
  stream_count: number
  revision: number
  created_at: string
  updated_at: string
}

export interface StreamGroupListResponse {
  items: StreamGroup[]
  total: number
  page: number
  limit: number
}

export interface StreamGroupFields {
  name: string
  remark: string
}

export interface CreateStreamGroupRequest extends StreamGroupFields {
  target_scope_id?: string
  owner_id?: string
}

export interface UpdateStreamGroupRequest extends StreamGroupFields {
  expected_revision: number
}

export interface StreamUserConfig {
  id: string
  display_id: string
  scope_id: string
  owner: StreamOwner | null
  setting_name: StreamSettingName
  setting_value: string
  scope_name: StreamSettingScope
  group: { id: string; name: string; remark: string } | null
  created_at: string
}

export interface StreamUserConfigListResponse {
  items: StreamUserConfig[]
  total: number
  page: number
  limit: number
}

export interface CreateStreamUserConfigRequest {
  target_scope_id?: string
  owner_id?: string
  setting_name: StreamSettingName
  setting_value: string
  scope_name: StreamSettingScope
  group_id?: string
}

export interface StreamListWindow {
  page: number
  limit: number
  search?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const displayIDPattern = /^[0-9]+$/u

function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function parseOwner(value: unknown): StreamOwner | null {
  if (value === null) return null
  const owner = record(value)
  if (!owner || !uuidPattern.test(String(owner.id)) || typeof owner.display_name !== 'string') {
    throw invalidResponse()
  }
  return value as StreamOwner
}

function parseGroup(value: unknown): StreamGroup {
  const item = record(value)
  if (!item || !uuidPattern.test(String(item.id)) || typeof item.display_id !== 'string' ||
    !displayIDPattern.test(item.display_id) || !uuidPattern.test(String(item.scope_id)) ||
    typeof item.name !== 'string' || typeof item.remark !== 'string' ||
    !integer(item.stream_count, 0) || !integer(item.revision, 1) ||
    typeof item.created_at !== 'string' || typeof item.updated_at !== 'string') {
    throw invalidResponse()
  }
  parseOwner(item.owner)
  return value as StreamGroup
}

function parseUserConfig(value: unknown): StreamUserConfig {
  const item = record(value)
  const group = item?.group === null || item?.group === undefined ? null : record(item.group)
  if (!item || !uuidPattern.test(String(item.id)) || typeof item.display_id !== 'string' ||
    !displayIDPattern.test(item.display_id) || !uuidPattern.test(String(item.scope_id)) ||
    typeof item.setting_name !== 'string' || typeof item.setting_value !== 'string' ||
    (item.scope_name !== 'global' && item.scope_name !== 'group') ||
    typeof item.created_at !== 'string' ||
    (item.group !== null && item.group !== undefined &&
      (!group || !uuidPattern.test(String(group.id)) || typeof group.name !== 'string' || typeof group.remark !== 'string'))) {
    throw invalidResponse()
  }
  parseOwner(item.owner)
  return value as StreamUserConfig
}

function parseListResponse<T>(value: unknown, parseItem: (item: unknown) => T): {
  items: T[]
  total: number
  page: number
  limit: number
} {
  const response = record(value)
  if (!response || !Array.isArray(response.items) ||
    !Number.isInteger(response.total) || !Number.isInteger(response.page) || !Number.isInteger(response.limit)) {
    throw invalidResponse()
  }
  return {
    items: response.items.map(parseItem),
    total: response.total as number,
    page: response.page as number,
    limit: response.limit as number,
  }
}

async function request(accessToken: string, path: string, init: RequestInit = {}): Promise<unknown> {
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
  if (!response.ok) {
    throw await responseApiError(response)
  }
  if (response.status === 204) return undefined
  try {
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

function windowQuery(path: string, params: StreamListWindow): string {
  const query = new URLSearchParams({ page: String(params.page), limit: String(params.limit) })
  if (params.search) query.set('search', params.search)
  return `${path}?${query}`
}

async function listGroups(accessToken: string, params: StreamListWindow): Promise<StreamGroupListResponse> {
  return parseListResponse(await request(accessToken, windowQuery('/v1/stream-groups', params)), parseGroup)
}

async function createGroup(accessToken: string, input: CreateStreamGroupRequest, key: string): Promise<StreamGroup> {
  return parseGroup(await request(accessToken, '/v1/stream-groups', {
    method: 'POST',
    headers: { 'Idempotency-Key': key },
    body: JSON.stringify(input),
  }))
}

async function updateGroup(
  accessToken: string,
  id: string,
  input: UpdateStreamGroupRequest,
  key: string,
): Promise<StreamGroup> {
  return parseGroup(await request(accessToken, `/v1/stream-groups/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Idempotency-Key': key, 'If-Match': `"${input.expected_revision}"` },
    body: JSON.stringify(input),
  }))
}

async function removeGroup(accessToken: string, item: StreamGroup, key: string): Promise<void> {
  await request(accessToken, `/v1/stream-groups/${encodeURIComponent(item.id)}`, {
    method: 'DELETE',
    headers: { 'Idempotency-Key': key, 'If-Match': `"${item.revision}"` },
  })
}

// 该资源在界面上称作「默认设置」，接口按 type=stream 区分转发/站点两类配置。
async function listUserConfigs(accessToken: string, params: StreamListWindow): Promise<StreamUserConfigListResponse> {
  const query = new URLSearchParams({ type: 'stream', page: String(params.page), limit: String(params.limit) })
  if (params.search) query.set('search', params.search)
  return parseListResponse(await request(accessToken, `/v1/user-configs?${query}`), parseUserConfig)
}

async function createUserConfig(
  accessToken: string,
  input: CreateStreamUserConfigRequest,
  key: string,
): Promise<StreamUserConfig> {
  return parseUserConfig(await request(accessToken, '/v1/user-configs', {
    method: 'POST',
    headers: { 'Idempotency-Key': key },
    body: JSON.stringify(input),
  }))
}

async function removeUserConfig(accessToken: string, item: StreamUserConfig, key: string): Promise<void> {
  await request(accessToken, `/v1/user-configs/${encodeURIComponent(item.id)}`, {
    method: 'DELETE',
    headers: { 'Idempotency-Key': key },
  })
}

/** 新建草稿的生效默认（全局→所选分组覆盖）；null = 未配置该项。 */
export interface StreamEffectiveDefaults {
  protocol: StreamProtocol | null
  proxy_protocol_inbound: boolean | null
  balance_way: StreamBalanceWay | null
}

function parseEffectiveDefaults(value: unknown): StreamEffectiveDefaults {
  const item = record(value)
  if (!item || Object.keys(item).length !== 3 ||
    !(item.protocol === null || item.protocol === 'tcp' || item.protocol === 'udp') ||
    !(item.proxy_protocol_inbound === null || typeof item.proxy_protocol_inbound === 'boolean') ||
    !(item.balance_way === null || item.balance_way === 'rr' || item.balance_way === 'ip_hash')) {
    throw invalidResponse()
  }
  return item as unknown as StreamEffectiveDefaults
}

// L4-DEFAULT-01：管理员代建传归属租户与用户，普通用户不传（服务端取本人）。
async function effectiveDefaults(accessToken: string, params: { target_scope_id?: string; owner_id?: string; group_ids: string[] }): Promise<StreamEffectiveDefaults> {
  const query = new URLSearchParams({ type: 'stream' })
  if (params.target_scope_id) query.set('target_scope_id', params.target_scope_id)
  if (params.owner_id) query.set('owner_id', params.owner_id)
  for (const id of params.group_ids) query.append('group_id', id)
  return parseEffectiveDefaults(await request(accessToken, `/v1/user-configs/effective?${query}`))
}

export const streamGroupsApi = {
  createGroup,
  createUserConfig,
  effectiveDefaults,
  listGroups,
  listUserConfigs,
  removeGroup,
  removeUserConfig,
  updateGroup,
}
