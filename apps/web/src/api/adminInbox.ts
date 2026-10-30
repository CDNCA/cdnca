import { ApiError, networkApiError, responseApiError } from './auth'

// Message center: platform administrators /v1/admin/inbox, tenant members
// /v1/account/inbox (in-app notices such as attack escalation, N23).
export interface AdminInboxMessage {
  id: string
  event_type: string
  params: Record<string, string>
  created_at: string
  read_at: string | null
}

export interface AdminInboxPage {
  items: AdminInboxMessage[]
  unread: number
  total: number
  next_cursor: string | null
  unread_only: boolean
  page_size: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function call<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, { ...init, credentials: 'include', cache: 'no-store', headers: { Authorization: `Bearer ${accessToken}` } })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204) return undefined as T
  const body: unknown = await response.json().catch(() => null)
  if (!body || typeof body !== 'object') throw new ApiError('Invalid message center response', 502, 'invalid_response')
  return body as T
}

export type InboxScope = 'admin' | 'account'

function inboxApi(base: string) {
  return {
    unreadCount: (accessToken: string) => call<{ unread: number }>(accessToken, `${base}/unread-count`),
    list: (accessToken: string, options: { unreadOnly?: boolean; cursor?: string | null; pageSize?: number } = {}) => {
      const query = new URLSearchParams({ page_size: String(options.pageSize ?? 20) })
      if (options.unreadOnly) query.set('unread', 'true')
      if (options.cursor) query.set('cursor', options.cursor)
      return call<AdminInboxPage>(accessToken, `${base}?${query}`)
    },
    read: (accessToken: string, id: string) => call<void>(accessToken, `${base}/${encodeURIComponent(id)}/read`, { method: 'POST' }),
    readAll: (accessToken: string) => call<{ marked: number }>(accessToken, `${base}/read-all`, { method: 'POST' }),
  }
}

export const adminInboxApi = inboxApi('/v1/admin/inbox')
export const accountInboxApi = inboxApi('/v1/account/inbox')
export const inboxApiFor = (scope: InboxScope) => scope === 'admin' ? adminInboxApi : accountInboxApi
export const inboxPathFor = (scope: InboxScope) => scope === 'admin' ? '/sys/inbox' : '/account/inbox'
