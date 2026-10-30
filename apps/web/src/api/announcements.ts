import { networkApiError, responseApiError, type ApiError } from './auth'

export type AnnouncementStatus = 'draft' | 'scheduled' | 'published' | 'withdrawn' | 'archived'
export type WithdrawalVisibility = 'retain' | 'hide'
export type AnnouncementFormat = 'content' | 'link'

export interface AudienceInput {
  all: boolean
  user_ids: string[]
  group_ids: string[]
}

export interface Audience {
  all: boolean
  user_ids?: string[]
  group_ids?: string[]
}

export interface GlobalRoleTarget { scope_id: string; role_id: string }
export interface GlobalUserTarget { scope_id: string; user_id: string }

export interface GlobalAudience {
  all_tenants: boolean
  tenant_scope_ids: string[]
  role_targets: GlobalRoleTarget[]
  user_targets: GlobalUserTarget[]
}

export interface GlobalAnnouncementInput extends GlobalAudience {
  title: string
  body: string
  format?: AnnouncementFormat
  link_url?: string
  sort_order?: number
  visible?: boolean
  popup?: boolean
  red?: boolean
  bold?: boolean
  withdrawal_visibility: WithdrawalVisibility
}

export interface GlobalAnnouncement {
  id: string
  platform_scope_id: string
  version: number
  revision: number
  status: 'draft' | 'published' | 'withdrawn'
  title: string
  body: string
  format: AnnouncementFormat
  link_url?: string
  sort_order: number
  visible: boolean
  popup: boolean
  red: boolean
  bold: boolean
  audience: GlobalAudience
  withdrawal_visibility: WithdrawalVisibility
  recipient_count: number
  published_at?: string
  withdrawn_at?: string
  created_at: string
  state_changed_at: string
  archived: boolean
  lifecycle_revision: number
  archived_at?: string
  replayed?: boolean
}

export interface GlobalAnnouncementPage { items: GlobalAnnouncement[]; next_cursor?: string }

export interface Announcement {
  id: string
  scope_id: string
  version: number
  head_version: number
  revision: number
  status: AnnouncementStatus
  title: string
  body: string
  format: AnnouncementFormat
  link_url?: string
  sort_order: number
  visible: boolean
  popup: boolean
  red: boolean
  bold: boolean
  audience: Audience
  withdrawal_visibility: WithdrawalVisibility
  scheduled_at?: string
  published_at?: string
  withdrawn_at?: string
  created_at: string
  state_changed_at: string
  archived: boolean
  lifecycle_revision: number
  archived_at?: string
  replayed?: boolean
}

export interface AnnouncementPage { items: Announcement[]; next_cursor?: string }

export interface InboxMessage {
  id: string
  announcement_id: string
  announcement_version: number
  title: string
  body: string
  format?: AnnouncementFormat
  link_url?: string
  sort_order?: number
  visible?: boolean
  popup?: boolean
  red?: boolean
  bold?: boolean
  published_at: string
  delivered_at?: string
  read_at?: string
  state_revision: number
}

export interface InboxPage { items: InboxMessage[]; next_cursor?: string; total?: number }
export interface InboxState { event_id: string; delivered_at?: string; read_at?: string; revision: number; replayed?: boolean }

export interface AnnouncementInput extends AudienceInput {
  title: string
  body: string
  format?: AnnouncementFormat
  link_url?: string
  sort_order?: number
  visible?: boolean
  popup?: boolean
  red?: boolean
  bold?: boolean
  withdrawal_visibility: WithdrawalVisibility
}

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
  return response.status === 204 ? undefined as T : await response.json() as T
}

export function newAnnouncementIdempotencyKey(operation: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `${operation}-${suffix}`
}

function writeHeaders(idempotencyKey: string, revision: number): HeadersInit {
  return { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${revision}"` }
}

function query(params: Record<string, string | number | undefined>): string {
  const values = Object.entries(params).filter(([, value]) => value !== undefined && value !== '')
  return values.length === 0 ? '' : `?${new URLSearchParams(values.map(([name, value]) => [name, String(value)]))}`
}

export type AudienceKind = 'tenant' | 'role' | 'user'
export interface AudienceDirectoryEntry { id: string; scope_id?: string; name: string; detail?: string; system?: boolean }
export interface AudienceDirectory { items: AudienceDirectoryEntry[] }
export interface AudienceCount { announcement_id: string; version?: number; recipient_count: number }
export type AudienceDirectoryQuery = { kind: AudienceKind; scope_id?: string } & ({ search: string; ids?: never } | { ids: string[]; search?: never })

function directoryPath(base: string, params: AudienceDirectoryQuery): string {
  return `${base}${query({
    kind: params.kind, scope_id: params.scope_id,
    search: params.ids ? undefined : params.search.trim(), ids: params.ids?.join(','),
  })}`
}

function audienceDirectory(accessToken: string, params: AudienceDirectoryQuery) {
  return request<AudienceDirectory>(accessToken, directoryPath('/v1/admin/announcements/audience-directory', params))
}

function audienceCount(accessToken: string, id: string) {
  return request<AudienceCount>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}/audience/count`)
}

function globalAudienceDirectory(accessToken: string, params: AudienceDirectoryQuery) {
  return request<AudienceDirectory>(accessToken, directoryPath('/v1/admin/announcements/global/audience-directory', params))
}

function globalAudienceCount(accessToken: string, id: string) {
  return request<AudienceCount>(accessToken, `/v1/admin/announcements/global/${encodeURIComponent(id)}/audience/count`)
}

function list(accessToken: string, params: { status?: AnnouncementStatus; limit?: number; cursor?: string } = {}) {
  return request<AnnouncementPage>(accessToken, `/v1/admin/announcements${query(params)}`)
}

function get(accessToken: string, id: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}`)
}

function create(accessToken: string, input: AnnouncementInput, idempotencyKey: string) {
  return request<Announcement>(accessToken, '/v1/admin/announcements', {
    method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(input),
  })
}

function update(accessToken: string, id: string, input: AnnouncementInput & { version: number; expected_revision: number }, idempotencyKey: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}`, {
    method: 'PATCH', headers: writeHeaders(idempotencyKey, input.expected_revision), body: JSON.stringify(input),
  })
}

function schedule(accessToken: string, id: string, input: { version: number; expected_revision: number; publish_at: string }, idempotencyKey: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}/schedule`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, input.expected_revision), body: JSON.stringify(input),
  })
}

function publish(accessToken: string, id: string, input: { version: number; expected_revision: number }, idempotencyKey: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}/publish`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, input.expected_revision), body: JSON.stringify(input),
  })
}

function revise(accessToken: string, id: string, input: AnnouncementInput & { expected_head_version: number }, idempotencyKey: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}/revise`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, input.expected_head_version), body: JSON.stringify(input),
  })
}

function withdraw(accessToken: string, id: string, input: { version: number; expected_revision: number }, idempotencyKey: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}/withdraw`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, input.expected_revision), body: JSON.stringify(input),
  })
}

function archive(accessToken: string, id: string, revision: number, idempotencyKey: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}/archive`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: JSON.stringify({ expected_lifecycle_revision: revision }),
  })
}

function restore(accessToken: string, id: string, revision: number, idempotencyKey: string) {
  return request<Announcement>(accessToken, `/v1/admin/announcements/${encodeURIComponent(id)}/restore`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: JSON.stringify({ expected_lifecycle_revision: revision }),
  })
}

function inbox(accessToken: string, params: { filter?: 'read' | 'unread' | 'popup'; limit?: number; cursor?: string; offset?: number } = {}) {
  return request<InboxPage>(accessToken, `/v1/account/messages${query(params)}`)
}

function state(accessToken: string, eventId: string, operation: 'delivered' | 'read', revision: number, idempotencyKey: string) {
  return request<InboxState>(accessToken, `/v1/account/messages/${encodeURIComponent(eventId)}/${operation}`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: JSON.stringify({ expected_revision: revision }),
  })
}

function listGlobal(accessToken: string, params: { status?: 'draft' | 'published' | 'withdrawn' | 'archived'; limit?: number; cursor?: string } = {}) {
  return request<GlobalAnnouncementPage>(accessToken, `/v1/admin/announcements/global${query(params)}`)
}

function getGlobal(accessToken: string, id: string) {
  return request<GlobalAnnouncement>(accessToken, `/v1/admin/announcements/global/${encodeURIComponent(id)}`)
}

function createGlobal(accessToken: string, input: GlobalAnnouncementInput, idempotencyKey: string) {
  return request<GlobalAnnouncement>(accessToken, '/v1/admin/announcements/global', {
    method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(input),
  })
}

function updateGlobal(accessToken: string, id: string, input: GlobalAnnouncementInput & { expected_revision: number }, idempotencyKey: string) {
  return request<GlobalAnnouncement>(accessToken, `/v1/admin/announcements/global/${encodeURIComponent(id)}`, {
    method: 'PATCH', headers: writeHeaders(idempotencyKey, input.expected_revision), body: JSON.stringify(input),
  })
}

function transitionGlobal(accessToken: string, id: string, operation: 'publish' | 'withdraw', revision: number, idempotencyKey: string) {
  return request<GlobalAnnouncement>(accessToken, `/v1/admin/announcements/global/${encodeURIComponent(id)}/${operation}`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: JSON.stringify({ expected_revision: revision }),
  })
}

function globalLifecycle(accessToken: string, id: string, operation: 'archive' | 'restore', revision: number, idempotencyKey: string) {
  return request<GlobalAnnouncement>(accessToken, `/v1/admin/announcements/global/${encodeURIComponent(id)}/${operation}`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: JSON.stringify({ expected_lifecycle_revision: revision }),
  })
}

export const announcementsApi = { archive, audienceCount, audienceDirectory, create, get, inbox, list, publish, restore, revise, schedule, state, update, withdraw }
export const globalAnnouncementsApi = {
  archive: (accessToken: string, id: string, revision: number, idempotencyKey: string) => globalLifecycle(accessToken, id, 'archive', revision, idempotencyKey),
  audienceCount: globalAudienceCount,
  audienceDirectory: globalAudienceDirectory,
  create: createGlobal,
  get: getGlobal,
  list: listGlobal,
  publish: (accessToken: string, id: string, revision: number, idempotencyKey: string) => transitionGlobal(accessToken, id, 'publish', revision, idempotencyKey),
  restore: (accessToken: string, id: string, revision: number, idempotencyKey: string) => globalLifecycle(accessToken, id, 'restore', revision, idempotencyKey),
  update: updateGlobal,
  withdraw: (accessToken: string, id: string, revision: number, idempotencyKey: string) => transitionGlobal(accessToken, id, 'withdraw', revision, idempotencyKey),
}
export type AnnouncementApiError = ApiError
