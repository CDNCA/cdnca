import { ApiError, networkApiError, responseApiError } from './auth'
import type { NodeSchedulingScope } from './nodeScheduling'

// 线路组智能调度（后端 control-api nodeschedulerhttp smart_schedule）。
// 开启后按访客运营商（或省份+运营商）把该线路解析到延迟最低、健康、未满载的 top_n 台节点，
// 线路无可用节点时按 省份运营商 → 同运营商全国 → 默认线路 回退。默认关闭，关闭时与现状一致。

export type SmartScheduleGranularity = 'carrier' | 'province_carrier'
export type SmartScheduleCarrier = 'telecom' | 'unicom' | 'mobile'

export interface SmartScheduleSelectedNode {
  address: string
  endpoint_id: string
  latency_ms: number | null
  healthy: boolean
  load_percent: number | null
}

export type SmartScheduleLineSource = 'latency' | 'static' | 'fallback'

export interface SmartScheduleLine {
  /** telecom/unicom/mobile，或 `<省>:<carrier>`（如 `广东:mobile`）。 */
  scope: string
  dns_line: string
  /** latency：按延迟选出；static：无延迟样本，沿用现状全部节点；fallback：本级无合格节点，回退上级线路。 */
  source: SmartScheduleLineSource
  selected: SmartScheduleSelectedNode[]
  /** 本线路没有可用节点、借用了哪条线路的结果（同 scope 格式）。 */
  fallback_from?: string
  updated_at: string
}

export interface SmartScheduleSettings {
  enabled: boolean
  top_n: number
  granularity: SmartScheduleGranularity
  latency_window_minutes: number
  max_load_percent: number
}

export interface SmartSchedule extends SmartScheduleSettings {
  fallback: string
  lines: SmartScheduleLine[]
  probe_source: { dnspup: boolean; peer_nodes: boolean }
  /** 当前 DNS 服务商是否支持省份线路；false 时只按运营商粒度写线路。 */
  province_lines_supported: boolean
  revision: number
}

export interface LatencyMatrixRow {
  province: string
  carrier: string
  endpoint_id: string
  address: string
  p50_ms: number
  samples: number
  last_at: string
}

export const smartScheduleLimits = {
  topN: { min: 1, max: 20, default: 3 },
  windowMinutes: { min: 5, max: 60, default: 15 },
  maxLoadPercent: { min: 1, max: 100, default: 85 },
} as const

export const smartScheduleDefaults: SmartScheduleSettings = {
  enabled: false,
  top_n: smartScheduleLimits.topN.default,
  granularity: 'carrier',
  latency_window_minutes: smartScheduleLimits.windowMinutes.default,
  max_load_percent: smartScheduleLimits.maxLoadPercent.default,
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function requestID(action: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `smart-schedule-${action}-${suffix}`
}

function idempotencyKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

async function request<T>(accessToken: string, path: string, action: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID(action),
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204 || init.method === 'PUT') return undefined as T
  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError('Invalid API response', response.status, 'invalid_response')
  }
}

function groupPath(groupID: string, suffix: string, scope: NodeSchedulingScope, query: Record<string, string> = {}): string {
  const params = new URLSearchParams(query)
  if (scope.kind === 'platform') params.set('target_scope_id', scope.targetScopeId)
  const text = params.toString()
  return `/v1/node-line-groups/${encodeURIComponent(groupID)}/${suffix}${text ? `?${text}` : ''}`
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
const optionalNumber = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) ? value : null

function invalid(): never {
  throw new ApiError('Invalid API response', 200, 'invalid_response')
}

export function validateSmartSchedule(value: unknown): SmartSchedule {
  if (!isRecord(value) || typeof value.enabled !== 'boolean' || typeof value.top_n !== 'number' ||
    (value.granularity !== 'carrier' && value.granularity !== 'province_carrier') ||
    typeof value.latency_window_minutes !== 'number' || typeof value.max_load_percent !== 'number' ||
    !Array.isArray(value.lines) || !isRecord(value.probe_source)) invalid()
  const lines = value.lines.map((line): SmartScheduleLine => {
    if (!isRecord(line) || typeof line.scope !== 'string' || !Array.isArray(line.selected)) invalid()
    return {
      scope: line.scope,
      dns_line: typeof line.dns_line === 'string' ? line.dns_line : '',
      source: line.source === 'latency' || line.source === 'fallback' ? line.source : 'static',
      selected: line.selected.map((node): SmartScheduleSelectedNode => {
        if (!isRecord(node) || typeof node.address !== 'string') invalid()
        return {
          address: node.address,
          endpoint_id: typeof node.endpoint_id === 'string' ? node.endpoint_id : '',
          latency_ms: optionalNumber(node.latency_ms),
          healthy: node.healthy === true,
          load_percent: optionalNumber(node.load_percent),
        }
      }),
      ...(typeof line.fallback_from === 'string' && line.fallback_from ? { fallback_from: line.fallback_from } : {}),
      updated_at: typeof line.updated_at === 'string' ? line.updated_at : '',
    }
  })
  return {
    enabled: value.enabled,
    top_n: value.top_n,
    granularity: value.granularity,
    latency_window_minutes: value.latency_window_minutes,
    max_load_percent: value.max_load_percent,
    fallback: typeof value.fallback === 'string' ? value.fallback : 'carrier_then_default',
    lines,
    probe_source: { dnspup: value.probe_source.dnspup === true, peer_nodes: value.probe_source.peer_nodes === true },
    province_lines_supported: value.province_lines_supported !== false,
    revision: typeof value.revision === 'number' ? value.revision : 0,
  }
}

export function validateLatencyMatrix(value: unknown): LatencyMatrixRow[] {
  if (!isRecord(value) || !Array.isArray(value.rows)) invalid()
  return value.rows.map((row): LatencyMatrixRow => {
    if (!isRecord(row) || typeof row.province !== 'string' || typeof row.carrier !== 'string' ||
      typeof row.address !== 'string' || typeof row.p50_ms !== 'number') invalid()
    return {
      province: row.province,
      carrier: row.carrier,
      endpoint_id: typeof row.endpoint_id === 'string' ? row.endpoint_id : '',
      address: row.address,
      p50_ms: row.p50_ms,
      samples: typeof row.samples === 'number' ? row.samples : 0,
      last_at: typeof row.last_at === 'string' ? row.last_at : '',
    }
  })
}

export const smartScheduleApi = {
  get: async (token: string, scope: NodeSchedulingScope, groupID: string): Promise<SmartSchedule> =>
    validateSmartSchedule(await request(token, groupPath(groupID, 'smart-schedule', scope), 'get')),
  // PUT 返回同 GET 视图；这里不依赖响应体，保存后由调用方重新 GET。
  save: async (token: string, scope: NodeSchedulingScope, groupID: string, input: SmartScheduleSettings): Promise<void> => {
    await request<unknown>(token, groupPath(groupID, 'smart-schedule', scope), 'save', {
      method: 'PUT',
      // 同线路组其它写接口：X-Request-ID + Idempotency-Key，不需 If-Match。
      headers: { 'Idempotency-Key': idempotencyKey() },
      body: JSON.stringify(input),
    })
  },
  latencyMatrix: async (token: string, scope: NodeSchedulingScope, groupID: string, windowMinutes: number): Promise<LatencyMatrixRow[]> =>
    validateLatencyMatrix(await request(token, groupPath(groupID, 'latency-matrix', scope, { window: String(windowMinutes) }), 'latency-matrix')),
}
