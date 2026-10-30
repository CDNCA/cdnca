import { ApiError, networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

// NF37 / PA-25: WAF rule libraries fed by a subscription URL. Only platform
// operators manage them; the control plane fetches the URL (https, public
// addresses only) and keeps the last good snapshot. A tenant subscribes and
// gets its own user layer rule pack; every snapshot whose rules changed adds
// a version of that pack, which a site runs only once it is published again.
export interface WAFRuleSubscription {
  id: string
  name: string
  description: string
  source_url: string
  interval_minutes: number
  enabled: boolean
  revision: number
  feed_version: string
  feed_generated_at: string
  rule_count: number
  last_attempt_at: string | null
  last_success_at: string | null
  last_error: string
  next_fetch_at: string
  subscribers: number
  pending_sites: number
  updated_at: string
}

// A published site still mounting an older version of a subscriber pack.
export interface WAFSubscriptionPendingSite {
  site_id: string
  domain: string
  published_version: string
}

// One tenant's rule pack of a subscription.
export interface WAFSubscriptionPack {
  subscription_id: string
  tenant_scope_id: string
  tenant_name: string
  pack_id: string
  current_version: string
  latest_version: string
  update_policy: 'auto' | 'manual'
  subscribed_at: string
  pending_sites: WAFSubscriptionPendingSite[]
}

// A subscription as a tenant sees it (no URL or fetch errors).
export interface TenantWAFRuleSubscription {
  id: string
  name: string
  description: string
  revision: number
  feed_version: string
  rule_count: number
  synced_at: string | null
  deleted: boolean
  subscribed: boolean
  pack: WAFSubscriptionPack | null
}

export interface WAFRuleSubscriptionInput {
  name: string
  description: string
  source_url: string
  interval_minutes: number
  enabled: boolean
}

async function request<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID(),
        ...(init.body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204) return undefined as T
  try {
    return await response.json() as T
  } catch {
    throw new ApiError('invalid response', 502, 'invalid_response')
  }
}

// A site whose bound platform library copy has a newer version than the one
// it runs. Publishing is a confirmed security activation.
export interface WAFPendingPublication {
  site_id: string
  domain: string
  policy_id: string
  active_version: number
  latest_version: number
  updated_at: string
  publishing: boolean
  last_target_node_ids: string[]
}

// A WAF rule library as GET /v1/waf-rule-libraries lists it: platform libraries delivered by the license
// center (origin system; subscribing copies it into the caller's scope) and the caller's own libraries (custom).
export interface WAFRuleLibrary {
  id: string
  name: string
  description: string
  origin: 'system' | 'custom'
  scope: 'global' | 'user'
  owner?: string
  enabled: boolean
  subscription: 'not_subscribed' | 'subscribed' | 'update_available' | 'not_applicable'
  protected: boolean
  revision: number
  updated_at: string
}

export const wafRuleSubscriptionsApi = {
  libraries: (token: string) =>
    request<{ items: WAFRuleLibrary[] }>(token, `/v1/waf-rule-libraries?${new URLSearchParams({ page: '1', limit: '100' })}`).then((result) => result.items ?? []),
  subscribeLibrary: (token: string, id: string) =>
    request<void>(token, `/v1/waf-rule-libraries/${encodeURIComponent(id)}/subscribe`, { method: 'POST' }),
  unsubscribeLibrary: (token: string, id: string) =>
    request<void>(token, `/v1/waf-rule-libraries/${encodeURIComponent(id)}/subscription`, { method: 'DELETE' }),
  refreshLibraries: (token: string) =>
    request<void>(token, '/v1/waf-rule-libraries/subscriptions/refresh', { method: 'POST' }),
  pendingPublications: (token: string) =>
    request<{ items: WAFPendingPublication[] }>(token, '/v1/waf-rule-libraries/pending-publications').then((result) => result.items ?? []),
  list: (token: string) =>
    request<{ items: WAFRuleSubscription[] }>(token, '/v1/waf-rule-subscriptions').then((result) => result.items ?? []),
  create: (token: string, input: WAFRuleSubscriptionInput) =>
    request<WAFRuleSubscription>(token, '/v1/waf-rule-subscriptions', { method: 'POST', body: JSON.stringify(input) }),
  update: (token: string, id: string, input: WAFRuleSubscriptionInput) =>
    request<WAFRuleSubscription>(token, `/v1/waf-rule-subscriptions/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(input) }),
  remove: (token: string, id: string) =>
    request<void>(token, `/v1/waf-rule-subscriptions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  sync: (token: string, id: string) =>
    request<WAFRuleSubscription>(token, `/v1/waf-rule-subscriptions/${encodeURIComponent(id)}/sync`, { method: 'POST' }),
  packs: (token: string, subscriptionID?: string) =>
    request<{ items: WAFSubscriptionPack[] }>(token, `/v1/waf-rule-subscriptions/packs${subscriptionID ? `?${new URLSearchParams({ subscription_id: subscriptionID })}` : ''}`)
      .then((result) => result.items ?? []),
  available: (token: string) =>
    request<{ items: TenantWAFRuleSubscription[] }>(token, '/v1/waf-rule-subscriptions/available').then((result) => result.items ?? []),
  subscribe: (token: string, id: string) =>
    request<TenantWAFRuleSubscription>(token, `/v1/waf-rule-subscriptions/${encodeURIComponent(id)}/subscribe`, { method: 'POST' }),
  unsubscribe: (token: string, id: string) =>
    request<void>(token, `/v1/waf-rule-subscriptions/${encodeURIComponent(id)}/subscription`, { method: 'DELETE' }),
}

// rulePackSiteLink opens the site level of the rule pack page, where the
// site's final order is shown and published.
export function rulePackSiteLink(siteID: string): string {
  return `/site/rule-packs?${new URLSearchParams({ site_id: siteID })}`
}

// Client-side mirror of the server's URL check (wafsubscription.ValidateURL);
// the server decides, this only gives the operator early feedback.
export function subscriptionURLProblem(value: string): 'scheme' | 'credentials' | 'internal' | null {
  let parsed: URL
  try {
    parsed = new URL(value.trim())
  } catch {
    return 'scheme'
  }
  if (parsed.protocol !== 'https:' || parsed.hash) return 'scheme'
  if (parsed.username || parsed.password) return 'credentials'
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || /^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) || /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host) ||
    (host.includes(':') && (host === '::1' || /^f[cd]/.test(host) || /^fe80:/.test(host)))) return 'internal'
  return null
}
