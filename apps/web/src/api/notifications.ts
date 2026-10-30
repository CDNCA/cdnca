import { ApiError, networkApiError, responseApiError } from './auth'

export interface NotificationChannels {
  sms_enabled: boolean
  email_enabled: boolean
  sms_supported: boolean
  email_supported: boolean
  revision: number
  changed: boolean
}

export interface NotificationDeliveryPolicyEvent {
  event_type: string
  enabled: boolean
  sms_enabled: boolean
  email_enabled: boolean
  repeat_count: number
  interval_hours: number
  supported: boolean
}

export interface NotificationDeliveryPolicy {
  schema: 'cdnca.notification-delivery-policy/v1'
  window_mode: 'all_day' | 'custom'
  window_start: string
  window_end: string
  timezone: string
  revision: number
  changed: boolean
  events: NotificationDeliveryPolicyEvent[]
}

export interface NotificationTemplate {
  template_id: string
  version: number
  channel: 'email' | 'sms'
  subject: string
  body: string
  variables: string[]
  created_at: string
  changed: boolean
}

export interface NotificationTemplatePage { items: NotificationTemplate[] }

export interface NotificationSubscription {
  event_type: AccountNotificationEventType
  sms_enabled: boolean
  email_enabled: boolean
  sms_supported: boolean
  email_supported: boolean
  // fix-ticket2（迁移 546）：只有工单事件带站内信开关。
  inbox_enabled?: boolean
  revision: number
  changed: boolean
}

export const accountNotificationEventTypes = [
  'announcement.published',
  'package.monitor.traffic.triggered',
  'package.monitor.traffic.recovered',
  'package.monitor.bandwidth.triggered',
  'package.monitor.bandwidth.recovered',
  'package.monitor.connections.triggered',
  'package.monitor.connections.recovered',
  'package.monitor.expiration.triggered',
  'package.monitor.expiration.recovered',
  'package.monitor.cc_rule_auto_switch',
  'security.attack.detected',
  'security.waf.auto_exclusion_active',
  'security.waf.auto_exclusion_revoked',
  'security.waf.auto_exclusion_expired',
  'package.auto_renew.succeeded',
  'package.auto_renew.failed',
  'certificate.expiring',
  'certificate.expired',
  'certificate.renew_failed',
  'ticket.created',
  'ticket.replied',
  'ticket.status_changed',
  'ticket.staff.created',
  'ticket.staff.replied',
  'ticket.staff.overdue',
] as const

export type AccountNotificationEventType = typeof accountNotificationEventTypes[number]

export interface NotificationRuntimeHealth {
  enabled: boolean
  state: string
  ready: boolean
  worker_running: boolean
  enabled_channels: number
  consecutive_failures?: number
  last_error_class?: string
}

export type NotificationDeliveryState =
  'pending' | 'dispatching' | 'retry_wait' | 'accepted' | 'unknown' | 'delivered' |
  'permanent_failed' | 'exhausted' | 'cancelled'

export type NotificationAttemptOutcome =
  'leased' | 'succeeded' | 'accepted' | 'unknown' | 'temporary_failure' |
  'permanent_failure' | 'exhausted' | 'lease_expired' | 'cancelled'

export interface NotificationDeliveryLog {
  scope_id: string
  outbox_id: string
  event_type: string
  channel: 'email' | 'sms'
  template_id: string
  template_version: number
  generation: number
  state: NotificationDeliveryState
  revision: number
  attempt_count: number
  provider?: string
  failure_code?: string
  retry_at?: string
  accepted_at?: string
  completed_at?: string
  replay_of_outbox_id?: string
  created_at: string
  updated_at: string
}

export interface NotificationDeliveryLogPage { items: NotificationDeliveryLog[]; next_cursor?: string }

export interface NotificationDeliveryAttempt {
  attempt_number: number
  outcome: NotificationAttemptOutcome
  failure_code?: string
  next_attempt_at?: string
  lease_expires_at: string
  claimed_at: string
  completed_at?: string
}

export interface NotificationDeliveryAttemptPage { outbox_id: string; items: NotificationDeliveryAttempt[] }

export interface NotificationDeliveryFilters {
  scopeID?: string
  channel?: 'email' | 'sms'
  state?: NotificationDeliveryState
  limit?: number
  cursor?: string
}

export interface SwitchWrite { sms_enabled: boolean; email_enabled: boolean }
// 订阅写入可带站内信开关（仅工单事件；不带则保留原值）。
export interface SubscriptionWrite extends SwitchWrite { inbox_enabled?: boolean }

// SEC-ACCOUNT-07: GET /v1/account/notification-messages — the caller's own
// event messages; site/package IDs are facts recorded at event time.
export interface OwnNotificationMessage {
  id: string
  type: string
  title: string | null
  site_id: string | null
  package_id: string | null
  created_at: string
  content: string | null
}
export interface OwnNotificationMessagePage { schema: 'cdnca.notification-own-messages/v1'; items: OwnNotificationMessage[]; total: number }
// site/package: name (domain / package name) or display-ID keyword when no full ID is given (fix-livefilter2).
export interface OwnNotificationMessageFilters { type?: string; siteID?: string; packageID?: string; site?: string; package?: string; limit?: number; offset?: number }
export interface TemplateWrite { subject: string; body: string; variables: string[] }

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const requestIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/

type ResponseValidator<T> = (value: unknown) => value is T

async function request<T>(
  accessToken: string,
  path: string,
  expectedStatus: number,
  validate: ResponseValidator<T>,
  init: RequestInit = {},
): Promise<T> {
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
  if (response.status !== expectedStatus) {
    if (!response.ok) throw await responseApiError(response)
    throw invalidResponseError(response)
  }
  let value: unknown
  try {
    value = await response.json()
  } catch {
    throw invalidResponseError(response)
  }
  if (!validate(value)) throw invalidResponseError(response)
  return value
}

function invalidResponseError(response: Response) {
  const requestID = response.headers?.get?.('X-Request-ID') ?? null
  return new ApiError('Invalid API response', 0, 'invalid_response',
    requestID !== null && requestIDPattern.test(requestID) ? requestID : undefined)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  const actual = Object.keys(value)
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key))
}

function hasAllowedKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]) {
  const actual = Object.keys(value)
  return required.every((key) => Object.hasOwn(value, key)) &&
    actual.every((key) => required.includes(key) || optional.includes(key))
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const stableCodePattern = /^[a-z][a-z0-9._-]{0,95}$/
const deliveryStates = new Set<NotificationDeliveryState>([
  'pending', 'dispatching', 'retry_wait', 'accepted', 'unknown', 'delivered',
  'permanent_failed', 'exhausted', 'cancelled',
])
const attemptOutcomes = new Set<NotificationAttemptOutcome>([
  'leased', 'succeeded', 'accepted', 'unknown', 'temporary_failure',
  'permanent_failure', 'exhausted', 'lease_expired', 'cancelled',
])

function isDateTime(value: unknown) {
  return typeof value === 'string' && value.length >= 20 && value.length <= 64 && Number.isFinite(Date.parse(value))
}

function isOptionalDateTime(value: Record<string, unknown>, key: string) {
  return !Object.hasOwn(value, key) || isDateTime(value[key])
}

function isDeliveryLog(value: unknown): value is NotificationDeliveryLog {
  if (!isRecord(value) || !hasAllowedKeys(value, [
    'scope_id', 'outbox_id', 'event_type', 'channel', 'template_id', 'template_version', 'generation',
    'state', 'revision', 'attempt_count', 'created_at', 'updated_at',
  ], ['provider', 'failure_code', 'retry_at', 'accepted_at', 'completed_at', 'replay_of_outbox_id'])) return false
  return typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.outbox_id === 'string' && uuidPattern.test(value.outbox_id) &&
    typeof value.event_type === 'string' && stableCodePattern.test(value.event_type) &&
    (value.channel === 'email' || value.channel === 'sms') &&
    typeof value.template_id === 'string' && stableCodePattern.test(value.template_id) &&
    Number.isSafeInteger(value.template_version) && (value.template_version as number) >= 1 &&
    Number.isSafeInteger(value.generation) && (value.generation as number) >= 1 &&
    typeof value.state === 'string' && deliveryStates.has(value.state as NotificationDeliveryState) &&
    Number.isSafeInteger(value.revision) && (value.revision as number) >= 0 &&
    Number.isSafeInteger(value.attempt_count) && (value.attempt_count as number) >= 0 &&
    (!Object.hasOwn(value, 'provider') || (
      typeof value.provider === 'string' && value.provider.length >= 1 && value.provider.length <= 64 &&
      !Array.from(value.provider).some((character) => {
        const code = character.charCodeAt(0)
        return code <= 0x1f || code === 0x7f
      })
    )) && (!Object.hasOwn(value, 'failure_code') || (
      typeof value.failure_code === 'string' && stableCodePattern.test(value.failure_code)
    )) &&
    ['retry_at', 'accepted_at', 'completed_at'].every((key) => isOptionalDateTime(value, key)) &&
    (!Object.hasOwn(value, 'replay_of_outbox_id') || (
      typeof value.replay_of_outbox_id === 'string' && uuidPattern.test(value.replay_of_outbox_id)
    )) && isDateTime(value.created_at) && isDateTime(value.updated_at)
}

function isDeliveryLogPage(value: unknown): value is NotificationDeliveryLogPage {
  return isRecord(value) && hasAllowedKeys(value, ['items'], ['next_cursor']) &&
    Array.isArray(value.items) && value.items.length <= 100 && value.items.every(isDeliveryLog) &&
    (!Object.hasOwn(value, 'next_cursor') || (
      typeof value.next_cursor === 'string' && uuidPattern.test(value.next_cursor)
    ))
}

function isDeliveryAttempt(value: unknown): value is NotificationDeliveryAttempt {
  return isRecord(value) && hasAllowedKeys(value,
    ['attempt_number', 'outcome', 'lease_expires_at', 'claimed_at'],
    ['failure_code', 'next_attempt_at', 'completed_at']) &&
    Number.isSafeInteger(value.attempt_number) && (value.attempt_number as number) >= 1 &&
    typeof value.outcome === 'string' && attemptOutcomes.has(value.outcome as NotificationAttemptOutcome) &&
    (!Object.hasOwn(value, 'failure_code') || (
      typeof value.failure_code === 'string' && stableCodePattern.test(value.failure_code)
    )) &&
    ['next_attempt_at', 'completed_at'].every((key) => isOptionalDateTime(value, key)) &&
    isDateTime(value.lease_expires_at) && isDateTime(value.claimed_at)
}

function isDeliveryAttemptPage(value: unknown): value is NotificationDeliveryAttemptPage {
  return isRecord(value) && hasExactKeys(value, ['outbox_id', 'items']) &&
    typeof value.outbox_id === 'string' && uuidPattern.test(value.outbox_id) &&
    Array.isArray(value.items) && value.items.length <= 100 && value.items.every(isDeliveryAttempt)
}

function hasRevision(value: Record<string, unknown>) {
  return Number.isSafeInteger(value.revision) && (value.revision as number) >= 0
}

function isNotificationChannels(value: unknown): value is NotificationChannels {
  return isRecord(value) && hasExactKeys(value, [
    'sms_enabled', 'email_enabled', 'sms_supported', 'email_supported', 'revision', 'changed',
  ]) && typeof value.sms_enabled === 'boolean' && typeof value.email_enabled === 'boolean' &&
    typeof value.sms_supported === 'boolean' && typeof value.email_supported === 'boolean' &&
    (!value.sms_enabled || value.sms_supported) && (!value.email_enabled || value.email_supported) && hasRevision(value) &&
    typeof value.changed === 'boolean'
}

function isPolicyEvent(value: unknown): value is NotificationDeliveryPolicyEvent {
  return isRecord(value) && hasExactKeys(value, ['event_type', 'enabled', 'sms_enabled', 'email_enabled', 'repeat_count', 'interval_hours', 'supported']) &&
    typeof value.event_type === 'string' && stableCodePattern.test(value.event_type) &&
    typeof value.enabled === 'boolean' && typeof value.sms_enabled === 'boolean' && typeof value.email_enabled === 'boolean' &&
    Number.isSafeInteger(value.repeat_count) && (value.repeat_count as number) >= 1 && (value.repeat_count as number) <= 10 &&
    Number.isSafeInteger(value.interval_hours) && (value.interval_hours as number) >= 1 && (value.interval_hours as number) <= 168 &&
    typeof value.supported === 'boolean' && (value.supported || (!value.enabled && !value.sms_enabled && !value.email_enabled))
}

// 通知策略事件条数上限。主控按事件目录整表返回策略（10-22 为 75 条），所以必须大于
// 目录总数并留余量；与 control-api notificationcontrol maxDeliveryPolicyEvents、
// api/control-notifications.openapi.yaml DeliveryPolicyWrite.events.maxItems 同值。
export const maxNotificationPolicyEvents = 256

function isNotificationDeliveryPolicy(value: unknown): value is NotificationDeliveryPolicy {
  return isRecord(value) && hasExactKeys(value, ['schema', 'window_mode', 'window_start', 'window_end', 'timezone', 'revision', 'changed', 'events']) &&
    value.schema === 'cdnca.notification-delivery-policy/v1' && (value.window_mode === 'all_day' || value.window_mode === 'custom') &&
    typeof value.window_start === 'string' && /^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(value.window_start) &&
    typeof value.window_end === 'string' && /^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(value.window_end) &&
    typeof value.timezone === 'string' && value.timezone.length >= 1 && value.timezone.length <= 64 && hasRevision(value) &&
    typeof value.changed === 'boolean' && Array.isArray(value.events) &&
    value.events.length <= maxNotificationPolicyEvents && value.events.every(isPolicyEvent)
}

function isNotificationTemplate(value: unknown): value is NotificationTemplate {
  return isRecord(value) && hasExactKeys(value, [
    'template_id', 'version', 'channel', 'subject', 'body', 'variables', 'created_at', 'changed',
  ]) && typeof value.template_id === 'string' &&
    Number.isSafeInteger(value.version) && (value.version as number) >= 1 &&
    (value.channel === 'email' || value.channel === 'sms') && typeof value.subject === 'string' &&
    typeof value.body === 'string' && Array.isArray(value.variables) &&
    value.variables.every((item) => typeof item === 'string') && typeof value.created_at === 'string' &&
    typeof value.changed === 'boolean'
}

function isNotificationTemplatePage(value: unknown): value is NotificationTemplatePage {
  return isRecord(value) && hasExactKeys(value, ['items']) &&
    Array.isArray(value.items) && value.items.every(isNotificationTemplate)
}

function isNotificationSubscription(value: unknown): value is NotificationSubscription {
  return isRecord(value) && hasAllowedKeys(value, [
    'event_type', 'sms_enabled', 'email_enabled', 'sms_supported', 'email_supported', 'revision', 'changed',
  ], ['inbox_enabled']) && accountNotificationEventTypes.includes(value.event_type as AccountNotificationEventType) &&
    (value.inbox_enabled === undefined || typeof value.inbox_enabled === 'boolean') &&
    typeof value.sms_enabled === 'boolean' && typeof value.email_enabled === 'boolean' &&
    typeof value.sms_supported === 'boolean' && typeof value.email_supported === 'boolean' &&
    (!value.sms_enabled || value.sms_supported) && (!value.email_enabled || value.email_supported) && hasRevision(value) &&
    typeof value.changed === 'boolean'
}

function isNotificationRuntimeHealth(value: unknown): value is NotificationRuntimeHealth {
  return isRecord(value) && hasAllowedKeys(value, [
    'enabled', 'state', 'ready', 'worker_running', 'enabled_channels',
  ], ['consecutive_failures', 'last_error_class']) && typeof value.enabled === 'boolean' && typeof value.state === 'string' &&
    typeof value.ready === 'boolean' && typeof value.worker_running === 'boolean' &&
    Number.isSafeInteger(value.enabled_channels) && (value.enabled_channels as number) >= 0 &&
    (value.consecutive_failures === undefined ||
      Number.isSafeInteger(value.consecutive_failures) && (value.consecutive_failures as number) >= 0) &&
    (value.last_error_class === undefined || typeof value.last_error_class === 'string')
}

function sameSwitchResponse(response: NotificationChannels | NotificationSubscription, value: SwitchWrite, revision: number) {
  return response.sms_enabled === value.sms_enabled && response.email_enabled === value.email_enabled &&
    response.revision === revision + (response.changed ? 1 : 0)
}

function sameStrings(first: string[], second: string[]) {
  return first.length === second.length && first.every((value, index) => value === second[index])
}

function getChannels(accessToken: string) {
  return request(accessToken, '/v1/admin/notifications/channels', 200, isNotificationChannels)
}

function putChannels(accessToken: string, value: SwitchWrite, revision: number, requestKey: string) {
  return request(accessToken, '/v1/admin/notifications/channels', 200, (response): response is NotificationChannels =>
    isNotificationChannels(response) && sameSwitchResponse(response, value, revision), {
	    method: 'PUT', headers: { 'If-Match': `"${revision}"`, 'X-Request-ID': requestKey }, body: JSON.stringify(value),
  })
}

function getDeliveryPolicy(accessToken: string) {
  return request(accessToken, '/v1/admin/notifications/policy', 200, isNotificationDeliveryPolicy)
}

function putDeliveryPolicy(accessToken: string, value: Omit<NotificationDeliveryPolicy, 'schema' | 'revision' | 'changed'>, revision: number, requestKey: string) {
  return request(accessToken, '/v1/admin/notifications/policy', 200, (response): response is NotificationDeliveryPolicy =>
    isNotificationDeliveryPolicy(response) && response.revision === revision + (response.changed ? 1 : 0) &&
    response.window_mode === value.window_mode && response.window_start === value.window_start && response.window_end === value.window_end &&
    response.timezone === value.timezone && JSON.stringify(response.events) === JSON.stringify(value.events), {
      method: 'PUT', headers: { 'If-Match': `"${revision}"`, 'X-Request-ID': requestKey }, body: JSON.stringify(value),
    })
}

function listTemplates(accessToken: string) {
  return request(accessToken, '/v1/admin/notifications/templates', 200, isNotificationTemplatePage)
}

function putTemplate(
  accessToken: string,
  templateId: string,
  version: number,
  channel: 'email' | 'sms',
  value: TemplateWrite,
  requestKey: string,
) {
  return request(accessToken,
    `/v1/admin/notifications/templates/${encodeURIComponent(templateId)}/versions/${version}/${channel}`,
    200, (response): response is NotificationTemplate => isNotificationTemplate(response) &&
      response.template_id === templateId && response.version === version && response.channel === channel &&
      response.subject === value.subject && response.body === value.body && sameStrings(response.variables, value.variables), {
	      method: 'PUT', headers: { 'X-Request-ID': requestKey }, body: JSON.stringify(value),
    })
}

function getSubscription(accessToken: string, eventType: AccountNotificationEventType) {
  return request(accessToken,
    `/v1/account/notification-subscriptions/${encodeURIComponent(eventType)}`, 200,
    (response): response is NotificationSubscription => isNotificationSubscription(response) && response.event_type === eventType)
}

function putSubscription(
  accessToken: string,
  eventType: AccountNotificationEventType,
  value: SubscriptionWrite,
  revision: number,
  requestKey: string,
) {
  return request(accessToken,
    `/v1/account/notification-subscriptions/${encodeURIComponent(eventType)}`, 200,
    (response): response is NotificationSubscription => isNotificationSubscription(response) &&
      response.event_type === eventType && sameSwitchResponse(response, value, revision) &&
      (value.inbox_enabled === undefined || response.inbox_enabled === value.inbox_enabled), {
	      method: 'PUT', headers: { 'If-Match': `"${revision}"`, 'X-Request-ID': requestKey }, body: JSON.stringify(value),
    })
}

function isOwnMessage(value: unknown): value is OwnNotificationMessage {
  const nullableUUID = (item: unknown) => item === null || (typeof item === 'string' && uuidPattern.test(item))
  const nullableText = (item: unknown) => item === null || typeof item === 'string'
  return isRecord(value) && hasExactKeys(value, ['id', 'type', 'title', 'site_id', 'package_id', 'created_at', 'content']) &&
    typeof value.id === 'string' && uuidPattern.test(value.id) && typeof value.type === 'string' && stableCodePattern.test(value.type) &&
    nullableText(value.title) && nullableUUID(value.site_id) && nullableUUID(value.package_id) &&
    isDateTime(value.created_at) && nullableText(value.content)
}

function isOwnMessagePage(value: unknown): value is OwnNotificationMessagePage {
  return isRecord(value) && hasExactKeys(value, ['schema', 'items', 'total']) && value.schema === 'cdnca.notification-own-messages/v1' &&
    Array.isArray(value.items) && value.items.length <= 100 && value.items.every(isOwnMessage) &&
    Number.isSafeInteger(value.total) && (value.total as number) >= 0
}

async function listOwnMessages(accessToken: string, filters: OwnNotificationMessageFilters = {}) {
  const { type, siteID, packageID, site, package: pkg, limit, offset } = filters
  const keyword = (value: string | undefined) => value === undefined || (value.length > 0 && value.length <= 128 && value === value.trim() && ![...value].some((char) => char.charCodeAt(0) < 0x20 || char.charCodeAt(0) === 0x7f))
  if ((type !== undefined && !stableCodePattern.test(type)) || (siteID !== undefined && !uuidPattern.test(siteID)) ||
    (packageID !== undefined && !uuidPattern.test(packageID)) || !keyword(site) || !keyword(pkg) ||
    (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)) ||
    (offset !== undefined && (!Number.isSafeInteger(offset) || offset < 0 || offset > 10000))) {
    throw new ApiError('Invalid message filters', 400, 'validation_error')
  }
  const query = new URLSearchParams()
  if (type !== undefined) query.set('type', type)
  if (siteID !== undefined) query.set('site_id', siteID)
  if (packageID !== undefined) query.set('package_id', packageID)
  if (site !== undefined) query.set('site', site)
  if (pkg !== undefined) query.set('package', pkg)
  if (limit !== undefined) query.set('limit', String(limit))
  if (offset !== undefined && offset > 0) query.set('offset', String(offset))
  const suffix = query.size > 0 ? `?${query.toString()}` : ''
  return request(accessToken, `/v1/account/notification-messages${suffix}`, 200, isOwnMessagePage)
}

function getRuntimeHealth(accessToken: string) {
  return request(accessToken, '/v1/notification-runtime-health', 200, isNotificationRuntimeHealth)
}

async function listDeliveries(accessToken: string, filters: NotificationDeliveryFilters) {
  if (!isRecord(filters) || !hasAllowedKeys(filters, [], ['scopeID', 'channel', 'state', 'limit', 'cursor'])) {
    throw new ApiError('Invalid delivery filters', 400, 'validation_error')
  }
  const value = filters as NotificationDeliveryFilters
  if ((value.scopeID !== undefined && !uuidPattern.test(value.scopeID)) ||
    (value.channel !== undefined && value.channel !== 'email' && value.channel !== 'sms') ||
    (value.state !== undefined && !deliveryStates.has(value.state)) ||
    (value.limit !== undefined && (!Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > 100)) ||
    (value.cursor !== undefined && !uuidPattern.test(value.cursor))) {
    throw new ApiError('Invalid delivery filters', 400, 'validation_error')
  }
  const query = new URLSearchParams()
  if (value.scopeID !== undefined) query.set('scope_id', value.scopeID)
  if (value.channel !== undefined) query.set('channel', value.channel)
  if (value.state !== undefined) query.set('state', value.state)
  if (value.limit !== undefined) query.set('limit', String(value.limit))
  if (value.cursor !== undefined) query.set('cursor', value.cursor)
  const suffix = query.size > 0 ? `?${query.toString()}` : ''
  return request(accessToken, `/v1/admin/notifications/deliveries${suffix}`, 200, isDeliveryLogPage)
}

async function listDeliveryAttempts(accessToken: string, outboxID: string) {
  if (!uuidPattern.test(outboxID)) throw new ApiError('Invalid outbox ID', 400, 'validation_error')
  return request(accessToken, `/v1/admin/notifications/deliveries/${outboxID}/attempts`, 200,
    (value): value is NotificationDeliveryAttemptPage => isDeliveryAttemptPage(value) && value.outbox_id === outboxID)
}

export const notificationsApi = {
  getChannels, putChannels, getDeliveryPolicy, putDeliveryPolicy, listTemplates, putTemplate,
  getSubscription, putSubscription, getRuntimeHealth, listOwnMessages,
  listDeliveries, listDeliveryAttempts,
}

export function newNotificationRequestKey() {
  return crypto.randomUUID()
}
