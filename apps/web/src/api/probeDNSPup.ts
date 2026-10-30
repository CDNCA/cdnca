import { ApiError, attachFieldRefusal, networkApiError } from './auth'

// Official plugin module.probe.dnspup (control-api internal/dnspupprobe).
// Platform scope + system.probe_dnspup.manage; enabling and testing also
// need the module in the licence.

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export const probeDNSPupPermission = 'system.probe_dnspup.manage'
export const probeDNSPupModule = 'module.probe.dnspup'

export type OriginProbeSource = 'node' | 'dnspup' | 'controller'
export type EdgeProbeSource = 'node' | 'dnspup'

export interface ProbeDNSPupStatus {
  licensed: boolean
  enabled: boolean
  active: boolean
  base_url: string
  api_key: string
  secret_configured: boolean
  secret_fingerprint?: string
  source_domain: string
  origin_sources: OriginProbeSource[]
  edge_sources: EdgeProbeSource[]
  revision: number
  settings_updated_at: string
  account_checked_at: string | null
  async_capable: boolean
  monthly_limit: number
  monthly_used: number
  account_error_code: string
  paused_until: string | null
  pause_reason: '' | 'quota_exceeded' | 'rate_limited' | 'unauthorized' | 'unavailable'
  pause_code: string
}

/** api_secret omitted keeps the stored secret (same API key and host only); "" clears it. */
export interface ProbeDNSPupInput {
  enabled: boolean
  base_url: string
  api_key: string
  api_secret?: string
  source_domain: string
  origin_sources: OriginProbeSource[]
  edge_sources: EdgeProbeSource[]
}

export interface ProbeDNSPupTestResult {
  ok: boolean
  http_status: number
  async_capable: boolean
  http_allowed: boolean
  tcping_allowed: boolean
  monthly_limit: number
  monthly_used: number
  allowed_tools: string[]
  error_code?: string
}

async function call<T>(token: string, path: string, init: RequestInit = {}, key?: string): Promise<T> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...(key ? { 'Idempotency-Key': key } : {}),
      },
    })
  } catch {
    throw networkApiError()
  }
  const text = await response.text()
  let body: unknown
  try { body = text ? JSON.parse(text) : undefined } catch { throw new ApiError('Invalid response', 502, 'response_invalid') }
  if (!response.ok) {
    const error = (body as { error?: { code?: unknown; request_id?: unknown; details?: unknown } } | undefined)?.error
    const code = typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,95}$/.test(error.code) ? error.code : 'request_failed'
    throw attachFieldRefusal(new ApiError('dnspup probe request failed', response.status, code,
      typeof error?.request_id === 'string' ? error.request_id : undefined), error?.details)
  }
  return body as T
}

const path = '/v1/admin/probe-dnspup'

export const probeDNSPupApi = {
  status: (token: string) => call<ProbeDNSPupStatus>(token, path),
  save: (token: string, input: ProbeDNSPupInput, key: string) =>
    call<ProbeDNSPupStatus>(token, path, { method: 'PUT', body: JSON.stringify(input) }, key),
  test: (token: string, input: ProbeDNSPupInput, key: string) =>
    call<ProbeDNSPupTestResult>(token, `${path}/tests`, { method: 'POST', body: JSON.stringify(input) }, key),
}

// Node availability probing from dnspup checkpoints
// (control-api internal/nodednspupprobe). dnspup meters requests: one per
// probed node address and round, whatever the checkpoint count.

export type DNSPupMonitorGroup = 'domestic' | 'telecom' | 'unicom' | 'mobile' | 'overseas'
export const dnspupMonitorGroups: DNSPupMonitorGroup[] = ['telecom', 'unicom', 'mobile', 'domestic', 'overseas']
export const dnspupNodeIntervals = [0, 60, 300, 900] as const

export interface DNSPupNodeMonitoringSettings {
  interval_seconds: (typeof dnspupNodeIntervals)[number]
  groups: DNSPupMonitorGroup[]
  points_per_group: number
  failure_percent: number
  failure_rounds: number
  recovery_rounds: number
  low_balance: number
}

export interface DNSPupNodeMonitoringStatus extends DNSPupNodeMonitoringSettings {
  revision: number
  plugin_active: boolean
  licensed: boolean
  budget_state: 'normal' | 'low' | 'exhausted'
  effective_interval_seconds: number
  monthly_limit: number
  monthly_used: number
  account_checked_at: string | null
  paused_until: string | null
  balance_unit: 'request'
  max_addresses_per_round: number
  estimate: {
    addresses: number
    checkpoints_per_round: number
    rounds_per_day: number
    requests_per_day: number
    requests_per_month: number
  }
}

/** Requests per day / month of settings for addresses probed addresses (same rule as the server). */
export function estimateDNSPupNodeRequests(settings: Pick<DNSPupNodeMonitoringSettings, 'interval_seconds'>, addresses: number) {
  const roundsPerDay = settings.interval_seconds > 0 ? Math.floor(86400 / settings.interval_seconds) : 0
  return { roundsPerDay, perDay: roundsPerDay * addresses, perMonth: roundsPerDay * addresses * 30 }
}

const nodeMonitoringPath = `${path}/node-monitoring`

export const dnspupNodeMonitoringApi = {
  status: (token: string) => call<DNSPupNodeMonitoringStatus>(token, nodeMonitoringPath),
  save: (token: string, settings: DNSPupNodeMonitoringSettings, key: string) =>
    call<DNSPupNodeMonitoringStatus>(token, nodeMonitoringPath, { method: 'PUT', body: JSON.stringify(settings) }, key),
}
