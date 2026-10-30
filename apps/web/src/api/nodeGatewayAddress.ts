import { ApiError, networkApiError } from './auth'

// 维护升级 → 节点设置「更换主控连接地址」(control-api internal/nodegatewayaddr,
// fix-nodegw). Platform scope; reads need nodes.read, writes nodes.manage and
// a platform MFA step-up (audience nodeGatewayAddressStepUpAudience).

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const root = '/v1/admin/node-gateway-address-changes'

export const nodeGatewayAddressStepUpAudience = 'node-gateway-address'
export const nodeGatewayAddressStepUpAction = 'node.gateway_address.change'

export type GatewayAddressTargetKind = 'all' | 'region' | 'nodes'
export type GatewayAddressNodeState = 'pending' | 'delivered' | 'probing' | 'switched' | 'failed' | 'superseded'

export interface GatewayAddressCounts {
  pending: number
  probing: number
  switched: number
  failed: number
  superseded: number
}

export interface GatewayAddressNodeStatus {
  node_id: string
  display_id: string
  name: string
  region: string
  state: GatewayAddressNodeState
  error_code?: string
  attempts: number
  active_address?: string
  reported_at?: string
  updated_at: string
}

export interface GatewayAddressChange {
  id: string
  address: string
  server_name: string
  target_kind: GatewayAddressTargetKind
  region?: string
  node_count: number
  counts: GatewayAddressCounts
  created_at: string
  created_by_user_id: string
  nodes?: GatewayAddressNodeStatus[]
}

export interface CreateGatewayAddressChangeInput {
  address: string
  server_name: string
  target_kind: GatewayAddressTargetKind
  region?: string
  node_ids?: string[]
}

const hostPort = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$/
const serverNamePattern = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/

/** HOST:PORT with a port in 1..65535 (IPv6 in brackets). */
export function validGatewayAddress(value: string): boolean {
  const match = hostPort.exec(value.trim())
  if (!match) return false
  const port = Number(match[2])
  return String(port) === match[2] && port >= 1 && port <= 65535
}

/** Empty (defaults to the address host) or a DNS name / IP literal. */
export function validServerName(value: string): boolean {
  const trimmed = value.trim()
  return trimmed === '' || serverNamePattern.test(trimmed) || /^[0-9A-Fa-f:.]+$/.test(trimmed)
}

/** A change is finished when no node is waiting, probing or failed. */
export function gatewayAddressChangeComplete(counts: GatewayAddressCounts): boolean {
  return counts.pending === 0 && counts.probing === 0 && counts.failed === 0
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
  try { body = text ? JSON.parse(text) : undefined } catch { throw new ApiError('Invalid response', 502, 'invalid_response') }
  if (!response.ok) {
    const error = (body as { error?: { code?: unknown; request_id?: unknown } } | undefined)?.error
    const code = typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,95}$/.test(error.code) ? error.code : 'request_failed'
    throw new ApiError('Gateway address change request failed', response.status, code,
      typeof error?.request_id === 'string' ? error.request_id : undefined)
  }
  return body as T
}

const post = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })

export const nodeGatewayAddressApi = {
  list: (token: string) => call<{ items: GatewayAddressChange[] }>(token, root),
  get: (token: string, id: string) => call<GatewayAddressChange>(token, `${root}/${encodeURIComponent(id)}`),
  create: (token: string, input: CreateGatewayAddressChangeInput, stepUpToken: string) =>
    call<GatewayAddressChange>(token, root, post({ ...input, step_up_token: stepUpToken })),
  retry: (token: string, id: string, stepUpToken: string, nodeIDs?: string[]) =>
    call<{ retried: number }>(token, `${root}/${encodeURIComponent(id)}/retry`,
      post({ step_up_token: stepUpToken, ...(nodeIDs?.length ? { node_ids: nodeIDs } : {}) })),
}

/** Platform MFA proof (TOTP) for one gateway address write; bound server-side to the request. */
export async function createGatewayAddressStepUp(token: string, code: string): Promise<string> {
  const proof = await call<{ token?: unknown }>(token, '/v1/account/mfa/step-up-proofs', post({
    audience: nodeGatewayAddressStepUpAudience, action: nodeGatewayAddressStepUpAction,
    authentication: { method: 'totp', code }, ttl_seconds: 300, max_uses: 1,
  }), `ngw-step-up-${globalThis.crypto.randomUUID()}`)
  if (typeof proof?.token !== 'string' || proof.token === '') throw new ApiError('Invalid response', 502, 'invalid_response')
  return proof.token
}
