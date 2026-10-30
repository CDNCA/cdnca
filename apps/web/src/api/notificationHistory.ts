import { ApiError, networkApiError, responseApiError } from './auth'
import type { NotificationDeliveryState } from './notifications'

export interface NotificationHistoryFact {
  id: string
  scope_id: string
  outbox_id: string
  message_id: string
  sequence: number
  attempt_number: number
  failure_count: number
  generation: number
  fact_kind: string
  state: NotificationDeliveryState
  failure_code: string | null
  observed_at: string
  event_type: string
  recipient_user_id: string | null
  recipient_user_display_id: string | null
  recipient_kind: 'member' | 'anonymous'
  channel: 'email' | 'sms'
  replay_of_outbox_id: string | null
  recipient_address: string | null
  recipient_address_state: 'masked' | 'unavailable'
  provider_call_started_at?: string | null
}

export interface NotificationHistoryPage {
  schema: 'cdnca.notification-delivery-history/v1'
  items: NotificationHistoryFact[]
  total_count: number
  next_cursor?: string
}

export interface NotificationHistoryFilters {
  scopeID?: string
  channel?: 'email' | 'sms'
  state?: NotificationDeliveryState
  result?: 'success' | 'failure'
  eventType?: string
  userID?: string
  messageID?: string
  from?: string
  to?: string
  limit?: number
  cursor?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const displayIDPattern = /^[1-9][0-9]{0,18}$/
const codePattern = /^[a-z][a-z0-9._-]{0,95}$/
const states = new Set<NotificationDeliveryState>(['pending', 'dispatching', 'retry_wait', 'accepted', 'unknown', 'delivered', 'permanent_failed', 'exhausted', 'cancelled'])
const factKinds = new Set(['dispatch_started', 'provider_accepted', 'provider_unknown', 'provider_delivered', 'retry_scheduled', 'permanent_failed', 'exhausted', 'lease_unknown', 'provider_receipt', 'cancelled', 'replay_created'])
const factKeys = new Set(['id', 'scope_id', 'outbox_id', 'message_id', 'sequence', 'attempt_number', 'failure_count', 'generation', 'fact_kind', 'state', 'failure_code', 'observed_at', 'event_type', 'recipient_user_id', 'recipient_user_display_id', 'recipient_kind', 'channel', 'replay_of_outbox_id', 'recipient_address', 'recipient_address_state', 'provider_call_started_at'])

export function isNotificationHistoryID(value: string, allowDisplayID = false): boolean {
  return uuidPattern.test(value) || allowDisplayID && isDisplayID(value)
}

function isDisplayID(value: string): boolean {
  return displayIDPattern.test(value) && BigInt(value) <= 9223372036854775807n
}

function isInstant(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isFact(value: unknown): value is NotificationHistoryFact {
  if (!isRecord(value) || (Object.keys(value).length < factKeys.size - 1 || Object.keys(value).length > factKeys.size) || !Object.keys(value).every((key) => factKeys.has(key))) return false
  return ['scope_id', 'outbox_id', 'message_id'].every((key) => typeof value[key] === 'string' && uuidPattern.test(value[key])) &&
    ['sequence', 'generation', 'attempt_number', 'failure_count'].every((key) => Number.isSafeInteger(value[key]) && (value[key] as number) >= (key === 'sequence' || key === 'generation' ? 1 : 0)) &&
    value.id === `${value.outbox_id}:${value.sequence}` &&
    typeof value.fact_kind === 'string' && factKinds.has(value.fact_kind) && states.has(value.state as NotificationDeliveryState) &&
    (value.failure_code === null || typeof value.failure_code === 'string' && codePattern.test(value.failure_code)) &&
    isInstant(value.observed_at) && typeof value.event_type === 'string' && codePattern.test(value.event_type) &&
    (value.recipient_user_id === null || typeof value.recipient_user_id === 'string' && uuidPattern.test(value.recipient_user_id)) &&
    (value.recipient_user_display_id === null || typeof value.recipient_user_display_id === 'string' && isDisplayID(value.recipient_user_display_id)) &&
    (value.recipient_kind === 'member' || value.recipient_kind === 'anonymous') && (value.channel === 'email' || value.channel === 'sms') &&
    (value.replay_of_outbox_id === null || typeof value.replay_of_outbox_id === 'string' && uuidPattern.test(value.replay_of_outbox_id)) &&
    (value.recipient_address_state === 'unavailable' && value.recipient_address === null ||
      value.recipient_address_state === 'masked' && typeof value.recipient_address === 'string' && value.recipient_address.length <= 320 && /^(?:[A-Za-z0-9]?\*{3}@[A-Za-z0-9.-]+|\*{3}[0-9]{4})$/.test(value.recipient_address)) &&
    (value.provider_call_started_at === undefined || value.provider_call_started_at === null || isInstant(value.provider_call_started_at))
}

function historyQuery(filters: NotificationHistoryFilters): string {
  const query = new URLSearchParams()
  const fields: Record<keyof NotificationHistoryFilters, [string, (value: never) => boolean]> = {
    scopeID: ['scope_id', (value: string) => uuidPattern.test(value)],
    channel: ['channel', (value: string) => value === 'email' || value === 'sms'],
    state: ['state', (value: NotificationDeliveryState) => states.has(value)],
    result: ['result', (value: string) => value === 'success' || value === 'failure'],
    eventType: ['event_type', (value: string) => codePattern.test(value)],
    userID: ['user_id', (value: string) => isNotificationHistoryID(value, true)],
    messageID: ['message_id', (value: string) => uuidPattern.test(value)],
    from: ['from', isInstant], to: ['to', isInstant],
    limit: ['limit', (value: number) => Number.isSafeInteger(value) && value >= 1 && value <= 300],
    cursor: ['cursor', (value: string) => typeof value === 'string' && value.length > 0 && value.length <= 4096],
  }
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined) continue
    const field = fields[key as keyof NotificationHistoryFilters]
    if (!field || typeof value !== (key === 'limit' ? 'number' : 'string') || !field[1](value as never)) throw new ApiError('Invalid history filters', 400, 'validation_error')
    query.set(field[0], String(value))
  }
  if (filters.from && filters.to && (Date.parse(filters.from) >= Date.parse(filters.to) || Date.parse(filters.to) - Date.parse(filters.from) > 31 * 86_400_000)) {
    throw new ApiError('Invalid history range', 400, 'validation_error')
  }
  return query.size ? `?${query}` : ''
}

export const notificationHistoryApi = {
  async list(token: string, filters: NotificationHistoryFilters, signal?: AbortSignal): Promise<NotificationHistoryPage> {
    if (!token || /\s/.test(token)) throw new ApiError('Invalid session', 401, 'invalid_session')
    const suffix = historyQuery(filters)
    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/admin/notifications/delivery-history${suffix}`, {
        credentials: 'include', headers: { Authorization: `Bearer ${token}` }, signal,
      })
    } catch (error) {
      if (signal?.aborted) throw error
      throw networkApiError()
    }
    if (!response.ok) throw await responseApiError(response)
    const value: unknown = await response.json().catch(() => null)
    if (response.status !== 200 || !isRecord(value) || value.schema !== 'cdnca.notification-delivery-history/v1' ||
      Object.keys(value).some((key) => !['schema', 'items', 'total_count', 'next_cursor'].includes(key)) ||
      !Array.isArray(value.items) || value.items.length > 300 || !value.items.every(isFact) ||
      !Number.isSafeInteger(value.total_count) || (value.total_count as number) < value.items.length ||
      (value.next_cursor !== undefined && (typeof value.next_cursor !== 'string' || value.next_cursor.length === 0 || value.next_cursor.length > 4096))) {
      throw new ApiError('Invalid delivery history response', 502, 'invalid_response')
    }
    return value as unknown as NotificationHistoryPage
  },
}
