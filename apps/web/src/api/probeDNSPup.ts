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

// Checkpoint selection (migration 638): groups are area × carrier.
export type ProbeArea = 'mainland' | 'hkmotw' | 'overseas'
export type ProbeCarrier = 'telecom' | 'unicom' | 'mobile' | 'edu' | 'bgp' | 'other'
export type ProbeFailure = 'ok' | 'refused' | 'timeout' | 'reset' | 'tls' | 'http' | 'dns' | 'other'
export const probeAreas: ProbeArea[] = ['mainland', 'hkmotw', 'overseas']
export const probeCarriers: ProbeCarrier[] = ['telecom', 'unicom', 'mobile', 'edu', 'bgp', 'other']
export const nodeProbeTypes = ['tcping', 'ping', 'http'] as const
export type NodeProbeType = (typeof nodeProbeTypes)[number]

export interface ProbeSelection {
  areas?: ProbeArea[]
  carriers?: ProbeCarrier[]
  include_provinces?: string[]
  exclude_provinces?: string[]
  exclude_checkpoints?: string[]
  points_per_group: number
  rotate?: boolean
}

export interface DNSPupNodeMonitoringSettings {
  interval_seconds: (typeof dnspupNodeIntervals)[number]
  groups: DNSPupMonitorGroup[]
  points_per_group: number
  failure_percent: number
  failure_rounds: number
  recovery_rounds: number
  low_balance: number
  probe_type?: NodeProbeType
  selection?: ProbeSelection | null
  line_alert_min_points?: number
  line_alert_rounds?: number
  auto_diagnose?: boolean
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

// Purposes (api/control-probe-dnspup.openapi.yaml): one shared dnspup quota,
// metered per purpose; when the month cannot be covered report slows first,
// then schedule; availability is never stopped here.
export type ProbePurpose = 'node_availability' | 'origin_failover' | 'edge_health' | 'plugin' | 'diagnose'

export interface ProbeGate {
  stopped: boolean
  factor: number
  reason?: 'disabled' | 'monthly_cap' | 'account_budget' | 'account_slowdown'
  daily_average: number
  projected_monthly: number
}

export interface ProbePurposeStatus {
  purpose: ProbePurpose
  class: 1 | 2 | 3
  enabled: boolean
  monthly_cap: number
  interval_seconds: number
  /** edge_health only: tcping (default) / https. */
  probe_type?: EdgeProbeType
  used_this_month: number
  gate: ProbeGate
}

export interface ProbePurposesView {
  purposes: ProbePurposeStatus[]
  monthly_limit: number
  monthly_used: number
  projected_monthly: number
}

export interface ProbePurposeInput {
  purpose: ProbePurpose
  enabled: boolean
  monthly_cap: number
  interval_seconds: number
  probe_type?: EdgeProbeType
}

export const edgeProbeTypes = ['tcping', 'https'] as const
export type EdgeProbeType = typeof edgeProbeTypes[number]

export interface ProbeMatrixCell {
  area: string
  carrier: ProbeCarrier
  total: number
  ok: number
  availability: number
  avg_latency_ms: number
  top_failure?: ProbeFailure
}

export interface ProbeMatrix {
  subject: 'node' | 'edge'
  id: string
  window: ProbeWindow
  cells: ProbeMatrixCell[]
  series: { at: string; total: number; availability: number; avg_latency_ms: number }[]
}

export const probeWindows = ['1h', '6h', '24h', '7d'] as const
export type ProbeWindow = (typeof probeWindows)[number]

export interface ProbeOverride {
  id: string
  subject_kind: 'node' | 'line_group'
  node_id?: string
  tenant_scope_id?: string
  line_group_id?: string
  subject_name: string
  probe_type: NodeProbeType | null
  selection: ProbeSelection | null
  revision: number
}

export interface ProbeOverrideInput {
  node_id?: string
  tenant_scope_id?: string
  line_group_id?: string
  probe_type?: NodeProbeType
  selection?: ProbeSelection
}

export interface ProbeDiagnosis {
  id: string
  status: 'pending' | 'completed' | 'failed'
  type: string
  target: string
  error_code?: string
  created_at: string
  traces?: unknown
}

export const probeDNSPupUnifiedApi = {
  purposes: (token: string) => call<ProbePurposesView>(token, `${path}/purposes`),
  savePurposes: (token: string, purposes: ProbePurposeInput[], key: string) =>
    call<ProbePurposesView>(token, `${path}/purposes`, { method: 'PUT', body: JSON.stringify({ purposes }) }, key),
  matrix: (token: string, subject: 'node' | 'edge', id: string, window: ProbeWindow) =>
    call<ProbeMatrix>(token, `${path}/matrix?${new URLSearchParams({ subject, id, window })}`),
  edgeSubjects: (token: string) => call<{ items: string[] }>(token, `${path}/edge-subjects`),
  overrides: (token: string) => call<{ items: ProbeOverride[] }>(token, `${nodeMonitoringPath}/overrides`),
  saveOverride: (token: string, input: ProbeOverrideInput, key: string) =>
    call<ProbeOverride>(token, `${nodeMonitoringPath}/overrides`, { method: 'PUT', body: JSON.stringify(input) }, key),
  deleteOverride: (token: string, id: string, key: string) =>
    call<undefined>(token, `${nodeMonitoringPath}/overrides/${encodeURIComponent(id)}`, { method: 'DELETE' }, key),
  diagnose: (token: string, input: { target: string; node_id?: string; checkpoints: string[] }, key: string) =>
    call<ProbeDiagnosis>(token, `${path}/diagnoses`, { method: 'POST', body: JSON.stringify(input) }, key),
  diagnosis: (token: string, id: string) => call<ProbeDiagnosis>(token, `${path}/diagnoses/${encodeURIComponent(id)}`),
}
