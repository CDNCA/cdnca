import { ApiError, networkApiError } from './auth'

// Support tickets (control-api internal/tickets, 302_tickets). Customers use
// /v1/tickets (own tickets only); platform staff use /v1/admin/tickets with
// tickets.read / tickets.manage.
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export const ticketsReadPermission = 'tickets.read'
export const ticketsManagePermission = 'tickets.manage'

export const ticketStatuses = ['open', 'processing', 'pending_customer', 'resolved', 'closed'] as const
export const ticketCategories = ['technical', 'billing', 'account', 'abuse', 'other'] as const
export const ticketPriorities = ['low', 'normal', 'high', 'urgent'] as const
export const ticketAttachmentTypes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf', 'text/plain']
export const maxTicketAttachmentBytes = 1 << 20
export const maxTicketAttachments = 5

export type TicketStatus = typeof ticketStatuses[number]
export type TicketCategory = typeof ticketCategories[number]
export type TicketPriority = typeof ticketPriorities[number]
export type TicketMode = 'user' | 'admin'

export interface Ticket {
  id: string
  ticket_no: number
  tenant_scope_id?: string
  user_id?: string
  username?: string
  category: TicketCategory
  subject: string
  priority: TicketPriority
  status: TicketStatus
  assignee_user_id?: string
  assignee_name?: string
  site_id?: string
  site_domain?: string
  order_id?: string
  unread: boolean
  sla_breached?: boolean
  revision: number
  last_message_at: string
  /** 最新一条可见消息的作者显示名（仅列表；客户视角客服带「客服」前缀） */
  last_reply_author?: string
  last_reply_author_kind?: 'customer' | 'staff'
  first_response_at?: string
  resolved_at?: string
  closed_at?: string
  reopenable_until?: string
  created_at: string
  updated_at: string
}

export interface TicketAttachment {
  id: string
  file_name: string
  mime_type: string
  size_bytes: number
  sha256: string
  created_at: string
}

export interface TicketMessage {
  id: string
  author_kind: 'customer' | 'staff'
  author_name: string
  body: string
  internal?: boolean
  attachments: TicketAttachment[]
  created_at: string
}

/** A ticket change shown as a system line (migration 543); assignee events carry names, the others values. */
export interface TicketEvent {
  id: string
  kind: 'status' | 'priority' | 'assignee' | 'closed' | 'reopened'
  from: string
  to: string
  actor_kind: 'customer' | 'staff'
  actor_name: string
  created_at: string
}

export interface TicketDetail { ticket: Ticket; messages: TicketMessage[]; events?: TicketEvent[] }
export interface TicketPage { items: Ticket[]; total: number; limit: number; offset: number }
export interface TicketSummary { unread: number; pending?: number; mine?: number; sla_breached?: number }
export interface TicketAssignee { user_id: string; username: string; display_name: string }

export interface TicketFilters {
  status?: TicketStatus
  category?: TicketCategory
  priority?: TicketPriority
  assignee?: string
  q?: string
  sla_breached?: boolean
  limit?: number
  offset?: number
}

export interface CreateTicketInput {
  category: TicketCategory
  subject: string
  body: string
  priority?: TicketPriority
  site_id?: string
  order_id?: string
  attachment_ids?: string[]
}

// fix-ticket2：管理端代用户新建（POST /v1/admin/tickets），首条内容由客服发出。
export interface StaffCreateTicketInput {
  user_id: string
  category: TicketCategory
  subject: string
  body: string
  priority?: TicketPriority
  assignee_user_id?: string
}

export interface ReplyTicketInput { body: string; attachment_ids?: string[]; internal?: boolean }

export interface UpdateTicketInput {
  expected_revision: number
  status?: TicketStatus
  priority?: TicketPriority
  assignee_user_id?: string
}

const codePattern = /^[a-z][a-z0-9_]{0,95}$/

async function call<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}`, ...(init.headers as Record<string, string> | undefined) },
    })
  } catch {
    throw networkApiError()
  }
  const text = await response.text()
  let body: unknown
  try { body = text ? JSON.parse(text) : undefined } catch { throw new ApiError('Invalid response', 502, 'response_invalid') }
  if (!response.ok) {
    const raw = (body as { code?: unknown } | undefined)?.code
    const code = typeof raw === 'string' && codePattern.test(raw) ? raw : 'request_failed'
    throw new ApiError('Ticket request failed', response.status, code)
  }
  return body as T
}

function json(method: string, value: unknown, key?: string): RequestInit {
  return {
    method,
    body: JSON.stringify(value),
    headers: { 'Content-Type': 'application/json', ...(key ? { 'Idempotency-Key': key } : {}) },
  }
}

function base(mode: TicketMode): string {
  return mode === 'admin' ? '/v1/admin/tickets' : '/v1/tickets'
}

function query(filters: TicketFilters): string {
  const params = new URLSearchParams()
  for (const [name, value] of Object.entries(filters)) {
    if (value === undefined || value === '' || value === false || (name === 'offset' && value === 0)) continue
    params.set(name, String(value))
  }
  const text = params.toString()
  return text ? `?${text}` : ''
}

function assertPage(body: unknown): TicketPage {
  const page = body as TicketPage | undefined
  if (!page || !Array.isArray(page.items) || typeof page.total !== 'number') {
    throw new ApiError('Invalid response', 502, 'response_invalid')
  }
  return page
}

function assertDetail(body: unknown): TicketDetail {
  const detail = body as TicketDetail | undefined
  if (!detail?.ticket || !Array.isArray(detail.messages)) throw new ApiError('Invalid response', 502, 'response_invalid')
  return detail
}

export const ticketsApi = {
  list: async (token: string, mode: TicketMode, filters: TicketFilters = {}) =>
    assertPage(await call(token, `${base(mode)}${query(filters)}`)),
  summary: (token: string, mode: TicketMode) => call<TicketSummary>(token, `${base(mode)}/summary`),
  get: async (token: string, mode: TicketMode, id: string) =>
    assertDetail(await call(token, `${base(mode)}/${encodeURIComponent(id)}`)),
  // create / reply take the caller's Idempotency-Key: one key per submission
  // (pages/market/idempotency.ts useIdempotencyKey), reused when the outcome is
  // unknown so a retry replays instead of filing or posting twice (p1-tickets).
  create: async (token: string, input: CreateTicketInput, key: string) =>
    assertDetail(await call(token, '/v1/tickets', json('POST', input, key))),
  staffCreate: async (token: string, input: StaffCreateTicketInput, key: string) =>
    assertDetail(await call(token, '/v1/admin/tickets', json('POST', input, key))),
  reply: async (token: string, mode: TicketMode, id: string, input: ReplyTicketInput, key: string) =>
    assertDetail(await call(token, `${base(mode)}/${encodeURIComponent(id)}/messages`, json('POST', input, key))),
  close: async (token: string, id: string) =>
    assertDetail(await call(token, `/v1/tickets/${encodeURIComponent(id)}/close`, { method: 'POST' })),
  reopen: async (token: string, id: string) =>
    assertDetail(await call(token, `/v1/tickets/${encodeURIComponent(id)}/reopen`, { method: 'POST' })),
  update: async (token: string, id: string, input: UpdateTicketInput) =>
    assertDetail(await call(token, `/v1/admin/tickets/${encodeURIComponent(id)}`, json('PATCH', input))),
  // fix-ticketops：软删除（204）；消息与附件保留在库，三端都不再可见。
  remove: async (token: string, id: string) => {
    await call(token, `/v1/admin/tickets/${encodeURIComponent(id)}`, { method: 'DELETE' })
  },
  assignees: async (token: string) => {
    const body = await call<{ items?: unknown }>(token, '/v1/admin/tickets/assignees')
    if (!Array.isArray(body?.items)) throw new ApiError('Invalid response', 502, 'response_invalid')
    return body.items as TicketAssignee[]
  },
  upload: (token: string, mode: TicketMode, file: File) =>
    call<TicketAttachment>(token, `${base(mode)}/attachments`, {
      method: 'POST',
      body: file,
      headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-File-Name': encodeURIComponent(file.name) },
    }),
  // Attachments need the bearer token, so they are fetched and handed to the
  // browser as a blob download.
  download: async (token: string, mode: TicketMode, attachment: TicketAttachment) => {
    let response: Response
    try {
      response = await fetch(`${apiRoot}${base(mode)}/attachments/${encodeURIComponent(attachment.id)}`, {
        credentials: 'include', headers: { Authorization: `Bearer ${token}` },
      })
    } catch {
      throw networkApiError()
    }
    if (!response.ok) throw new ApiError('Ticket attachment download failed', response.status, 'ticket_attachment_download_failed')
    return response.blob()
  },
}

// validateAttachment mirrors the server limits so the user learns early.
export function validateAttachment(file: File): 'type' | 'size' | null {
  if (!ticketAttachmentTypes.includes(file.type)) return 'type'
  if (file.size < 1 || file.size > maxTicketAttachmentBytes) return 'size'
  return null
}
