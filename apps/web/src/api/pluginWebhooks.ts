import { ApiError, networkApiError, responseApiError } from './auth'

export type PluginWebhookSubscriptionStatus = 'active' | 'revoked'
export type PluginWebhookDeliveryStatus =
  | 'pending'
  | 'queued'
  | 'claimed'
  | 'retry_scheduled'
  | 'delivered'
  | 'dead_letter_pending'
  | 'dead_lettered'
  | 'revoked'

export const pluginWebhookEventTypes = [
  'io.cdnca.certificate.v1.expiry_reached',
  'io.cdnca.certificate.v1.status_changed',
  'io.cdnca.deployment.v1.status_changed',
  'io.cdnca.dns.v1.changed',
  'io.cdnca.dns.v1.deleted',
  'io.cdnca.node.v1.status_changed',
  'io.cdnca.security.v1.incident_detected',
  'io.cdnca.site.v1.updated',
  'io.cdnca.usage.v1.threshold_reached',
  'io.cdnca.webhook.v1.test',
] as const
export type PluginWebhookEventType = typeof pluginWebhookEventTypes[number]
export const pluginWebhookEventType: PluginWebhookEventType = 'io.cdnca.webhook.v1.test'
export const pluginWebhookDeploymentEventType: PluginWebhookEventType = 'io.cdnca.deployment.v1.status_changed'
// Public domain events (extension-catalog.json status=available). Each needs a
// bound installation that was granted the event's permission.
export const pluginWebhookDomainEventTypes = [
  'io.cdnca.deployment.v1.status_changed',
  'io.cdnca.site.v1.updated',
  'io.cdnca.certificate.v1.status_changed',
  'io.cdnca.certificate.v1.expiry_reached',
  'io.cdnca.node.v1.status_changed',
  'io.cdnca.usage.v1.threshold_reached',
  'io.cdnca.security.v1.incident_detected',
] as const satisfies readonly PluginWebhookEventType[]
const pluginWebhookEventTypeSet = new Set<string>(pluginWebhookEventTypes)

export interface PluginWebhookSubscription {
  id: string
  tenant_scope_id: string
  name: string
  target_url: string
  event_types: PluginWebhookEventType[]
  status: PluginWebhookSubscriptionStatus
  revision: number
  active_secret_version_id: string
  installation_authorization_id?: string
  installation_id?: string
  plugin_id?: string
  site_ids?: string[]
  created_at: string
  updated_at: string
}

export interface PluginWebhookDelivery {
  id: string
  subscription_id: string
  event_id: string
  replay_of?: string
  status: PluginWebhookDeliveryStatus
  attempt_count: number
  next_attempt_at?: string
  created_at: string
  completed_at?: string
}

export interface PluginWebhookSubscriptionPage {
  items: PluginWebhookSubscription[]
  next_cursor?: string
}

export interface PluginWebhookDeliveryPage {
  items: PluginWebhookDelivery[]
  next_cursor?: string
}

export interface PluginWebhookCreateInput {
  name: string
  target_url: string
  event_types: PluginWebhookEventType[]
  installation_authorization_id?: string
  /** Only site-bound events of these sites; omit for every event. */
  site_ids?: string[]
}

export interface PluginWebhookReplayRangeInput {
  from: string
  to: string
  statuses?: Array<'delivered' | 'dead_lettered'>
  event_types?: PluginWebhookEventType[]
  limit: number
}

export interface PluginWebhookReplayRangeResult {
  items: Array<{ replay_of: string, delivery?: PluginWebhookDelivery, outcome: 'replayed' | 'already_replayed' | 'permission_denied' | 'rate_limited' }>
  remaining: boolean
}

export interface PluginWebhookSubscriptionReceipt {
  subscription: PluginWebhookSubscription
  secret: string
}

export interface PluginWebhookDeliveryReceipt {
  delivery: PluginWebhookDelivery
}

export interface PluginWebhookRotationReceipt {
  rotation_id: string
  key_id: string
  status: 'pending'
  expires_at: string
  secret: string
  subscription_revision: number
}

export interface PluginWebhookSubscriptionResult {
  subscription: PluginWebhookSubscription
}

export interface PluginWebhookListQuery {
  cursor?: string
  limit?: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const secretPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/
const targetURLPattern = /^https:\/\/(?=[A-Za-z0-9.-]{1,253}(?::443)?(?:\/|$))(?![0-9.]+(?::443)?(?:\/|$))(?:(?!xn--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?!xn--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?::443)?(?:\/[^?#]*)?$/i
const deliveryStatuses = new Set<PluginWebhookDeliveryStatus>([
  'pending', 'queued', 'claimed', 'retry_scheduled', 'delivered',
  'dead_letter_pending', 'dead_lettered', 'revoked',
])

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, allowed: string[]): boolean {
  const keys = new Set(allowed)
  return Object.keys(value).every((key) => keys.has(key))
}

function uuid(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && !Number.isNaN(Date.parse(value))
}

function uint(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function validPluginWebhookSecret(value: unknown): value is string {
  if (typeof value !== 'string' || !secretPattern.test(value)) return false
  try {
    const decoded = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '=')
    if (decoded.length !== 32) return false
    return btoa(decoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') === value
  } catch {
    return false
  }
}

function validTargetURL(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 2048 &&
    value.trim() === value && targetURLPattern.test(value)
}

function parseSubscription(value: unknown): PluginWebhookSubscription {
  if (!record(value) || !exactKeys(value, [
    'id', 'tenant_scope_id', 'name', 'target_url', 'event_types', 'status', 'revision',
    'active_secret_version_id', 'installation_authorization_id', 'installation_id', 'plugin_id', 'site_ids', 'created_at', 'updated_at',
  ]) || !uuid(value.id) || !uuid(value.tenant_scope_id) ||
    typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 128 ||
    typeof value.target_url !== 'string' || value.target_url.length < 1 || value.target_url.length > 2048 ||
    !Array.isArray(value.event_types) || value.event_types.length < 1 || value.event_types.length > 16 ||
    new Set(value.event_types).size !== value.event_types.length || value.event_types.some((eventType) => typeof eventType !== 'string' || !pluginWebhookEventTypeSet.has(eventType)) ||
    (value.status !== 'active' && value.status !== 'revoked') || !uint(value.revision, 1) ||
    !uuid(value.active_secret_version_id) ||
    (value.installation_authorization_id !== undefined && !uuid(value.installation_authorization_id)) ||
    (value.installation_id !== undefined && !uuid(value.installation_id)) ||
    (value.plugin_id !== undefined && (typeof value.plugin_id !== 'string' || value.plugin_id.length < 1 || value.plugin_id.length > 256)) ||
    (value.site_ids !== undefined && !validSiteIDs(value.site_ids)) ||
    !timestamp(value.created_at) || !timestamp(value.updated_at)) {
    throw invalidResponse()
  }
  return value as unknown as PluginWebhookSubscription
}

function validSiteIDs(value: unknown): value is string[] {
  return Array.isArray(value) && value.length >= 1 && value.length <= 100 && new Set(value).size === value.length &&
    value.every((item) => uuid(item))
}

const replayOutcomes = new Set(['replayed', 'already_replayed', 'permission_denied', 'rate_limited'])

function parseReplayRangeResult(value: unknown): PluginWebhookReplayRangeResult {
  if (!record(value) || !exactKeys(value, ['items', 'remaining']) || typeof value.remaining !== 'boolean' ||
    !Array.isArray(value.items) || value.items.length > 100) {
    throw invalidResponse()
  }
  for (const item of value.items) {
    if (!record(item) || !exactKeys(item, ['replay_of', 'delivery', 'outcome']) || !uuid(item.replay_of) ||
      typeof item.outcome !== 'string' || !replayOutcomes.has(item.outcome)) {
      throw invalidResponse()
    }
    if (item.delivery !== undefined) parseDelivery(item.delivery)
  }
  return value as unknown as PluginWebhookReplayRangeResult
}

function parseDelivery(value: unknown): PluginWebhookDelivery {
  if (!record(value) || !exactKeys(value, [
    'id', 'subscription_id', 'event_id', 'replay_of', 'status', 'attempt_count',
    'next_attempt_at', 'created_at', 'completed_at',
  ]) || !uuid(value.id) || !uuid(value.subscription_id) || !uuid(value.event_id) ||
    (value.replay_of !== undefined && !uuid(value.replay_of)) ||
    (typeof value.status !== 'string' || !deliveryStatuses.has(value.status as PluginWebhookDeliveryStatus)) ||
    !uint(value.attempt_count, 0, 5) || (value.next_attempt_at !== undefined && !timestamp(value.next_attempt_at)) ||
    !timestamp(value.created_at) || (value.completed_at !== undefined && !timestamp(value.completed_at))) {
    throw invalidResponse()
  }
  return value as unknown as PluginWebhookDelivery
}

function parseSubscriptionPage(value: unknown): PluginWebhookSubscriptionPage {
  if (!record(value) || !exactKeys(value, ['items', 'next_cursor']) || !Array.isArray(value.items) ||
    value.items.length > 100 || (value.next_cursor !== undefined && typeof value.next_cursor !== 'string')) {
    throw invalidResponse()
  }
  return { items: value.items.map(parseSubscription), ...(value.next_cursor ? { next_cursor: value.next_cursor } : {}) }
}

function parseDeliveryPage(value: unknown): PluginWebhookDeliveryPage {
  if (!record(value) || !exactKeys(value, ['items', 'next_cursor']) || !Array.isArray(value.items) ||
    value.items.length > 100 || (value.next_cursor !== undefined && typeof value.next_cursor !== 'string')) {
    throw invalidResponse()
  }
  return { items: value.items.map(parseDelivery), ...(value.next_cursor ? { next_cursor: value.next_cursor } : {}) }
}

function parseSubscriptionReceipt(value: unknown): PluginWebhookSubscriptionReceipt {
  if (!record(value) || !exactKeys(value, ['subscription', 'secret']) || !validPluginWebhookSecret(value.secret)) throw invalidResponse()
  return { subscription: parseSubscription(value.subscription), secret: value.secret as string }
}

function parseDeliveryReceipt(value: unknown): PluginWebhookDeliveryReceipt {
  if (!record(value) || !exactKeys(value, ['delivery'])) throw invalidResponse()
  return { delivery: parseDelivery(value.delivery) }
}

function parseRotationReceipt(value: unknown): PluginWebhookRotationReceipt {
  if (!record(value) || !exactKeys(value, ['rotation_id', 'key_id', 'status', 'expires_at', 'secret', 'subscription_revision']) ||
    !uuid(value.rotation_id) || !uuid(value.key_id) || value.status !== 'pending' || !timestamp(value.expires_at) ||
    !validPluginWebhookSecret(value.secret) || !uint(value.subscription_revision, 1)) {
    throw invalidResponse()
  }
  return value as unknown as PluginWebhookRotationReceipt
}

function parseSubscriptionResult(value: unknown): PluginWebhookSubscriptionResult {
  if (!record(value) || !exactKeys(value, ['subscription'])) throw invalidResponse()
  return { subscription: parseSubscription(value.subscription) }
}

async function request<T>(accessToken: string, path: string, init: RequestInit = {}, parse: (value: unknown) => T): Promise<T> {
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
  try {
    return parse(await response.json())
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw invalidResponse()
  }
}

function path(scopeID: string, suffix = ''): string {
  if (!uuid(scopeID)) throw new ApiError('Invalid tenant scope', 400, 'invalid_request')
  return `/v1/tenant-scopes/${encodeURIComponent(scopeID)}/plugin-webhook-subscriptions${suffix}`
}

function query(values: PluginWebhookListQuery): string {
  const params = new URLSearchParams()
  if (values.limit !== undefined) {
    if (!Number.isInteger(values.limit) || values.limit < 1 || values.limit > 100) throw new ApiError('Invalid limit', 400, 'invalid_request')
    params.set('limit', String(values.limit))
  }
  if (values.cursor !== undefined) {
    if (values.cursor.length > 1024 || [...values.cursor].some((character) => {
      const code = character.charCodeAt(0)
      return code < 0x20 || code === 0x7f
    })) throw new ApiError('Invalid cursor', 400, 'invalid_request')
    params.set('cursor', values.cursor)
  }
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

function writeHeaders(idempotencyKey: string, revision?: number): HeadersInit {
  if (!idempotencyPattern.test(idempotencyKey)) throw new ApiError('Invalid idempotency key', 400, 'invalid_request')
  return {
    'Idempotency-Key': idempotencyKey,
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

function emptyBody(): BodyInit { return '{}' }

async function listSubscriptions(accessToken: string, scopeID: string, values: PluginWebhookListQuery = {}) {
  return request(accessToken, `${path(scopeID)}${query(values)}`, {}, parseSubscriptionPage)
}

async function createSubscription(accessToken: string, scopeID: string, input: PluginWebhookCreateInput, idempotencyKey: string) {
  const testOnly = input.event_types.length === 1 && input.event_types[0] === pluginWebhookEventType
  if (input.event_types.length < 1 || input.event_types.length > 16 || new Set(input.event_types).size !== input.event_types.length ||
    input.event_types.some((eventType) => !pluginWebhookEventTypeSet.has(eventType)) || input.name.trim() !== input.name || input.name.length < 1 || input.name.length > 128 || !validTargetURL(input.target_url) ||
    (testOnly && input.installation_authorization_id !== undefined) || (!testOnly && !uuid(input.installation_authorization_id)) ||
    (input.site_ids !== undefined && (!validSiteIDs(input.site_ids) || testOnly))) {
    throw new ApiError('Invalid subscription input', 400, 'invalid_request')
  }
  return request(accessToken, path(scopeID), { method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input) }, parseSubscriptionReceipt)
}

async function getSubscription(accessToken: string, scopeID: string, subscriptionID: string) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}`), {}, parseSubscription)
}

async function createTestDelivery(accessToken: string, scopeID: string, subscriptionID: string, idempotencyKey: string) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/test-deliveries`), { method: 'POST', headers: writeHeaders(idempotencyKey), body: emptyBody() }, parseDeliveryReceipt)
}

async function listDeliveries(accessToken: string, scopeID: string, subscriptionID: string, values: PluginWebhookListQuery = {}) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/deliveries${query(values)}`), {}, parseDeliveryPage)
}

async function getDelivery(accessToken: string, scopeID: string, subscriptionID: string, deliveryID: string) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/deliveries/${encodeURIComponent(deliveryID)}`), {}, parseDelivery)
}

async function replayDelivery(accessToken: string, scopeID: string, subscriptionID: string, deliveryID: string, idempotencyKey: string) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/deliveries/${encodeURIComponent(deliveryID)}/replays`), { method: 'POST', headers: writeHeaders(idempotencyKey), body: emptyBody() }, parseDeliveryReceipt)
}

async function replayDeliveryRange(accessToken: string, scopeID: string, subscriptionID: string, input: PluginWebhookReplayRangeInput, idempotencyKey: string) {
  if (!timestamp(input.from) || !timestamp(input.to) || Date.parse(input.from) >= Date.parse(input.to) ||
    !Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100) {
    throw new ApiError('Invalid replay range', 400, 'invalid_request')
  }
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/delivery-replays`), { method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input) }, parseReplayRangeResult)
}

async function rotateSecret(accessToken: string, scopeID: string, subscriptionID: string, revision: number, idempotencyKey: string) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/secret-rotations`), { method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: emptyBody() }, parseRotationReceipt)
}

async function activateSecret(accessToken: string, scopeID: string, subscriptionID: string, rotationID: string, revision: number, idempotencyKey: string) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/secret-rotations/${encodeURIComponent(rotationID)}/activate`), { method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: emptyBody() }, parseSubscriptionResult)
}

async function revokeSubscription(accessToken: string, scopeID: string, subscriptionID: string, revision: number, idempotencyKey: string) {
  return request(accessToken, path(scopeID, `/${encodeURIComponent(subscriptionID)}/revoke`), { method: 'POST', headers: writeHeaders(idempotencyKey, revision), body: emptyBody() }, parseSubscriptionResult)
}

export const pluginWebhooksApi = {
  activateSecret,
  createSubscription,
  createTestDelivery,
  getDelivery,
  getSubscription,
  listDeliveries,
  listSubscriptions,
  replayDelivery,
  replayDeliveryRange,
  revokeSubscription,
  rotateSecret,
}

export function newPluginWebhookIdempotencyKey(operation: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `plugin-webhook-${operation}-${suffix}`
}
