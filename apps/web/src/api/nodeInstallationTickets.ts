import { ApiError, networkApiError, responseApiError } from './auth'

// PF09: GET /v1/nodes/installation-tickets?node_id=… (nodes.read)
// answers each node's last reported ServiceTicket. An expired ticket freezes the
// node: existing sites keep serving, new publications,
// scaling and upgrades wait for a renewed ticket.
export type NodeTicketState = 'valid' | 'expired' | 'no_ticket' | 'unknown'
export type NodeTicketNodeStatus = 'serving' | 'banned' | 'service_ticket_expired' | 'no_ticket'

export interface NodeTicket {
  node_id: string
  state: NodeTicketState
  node_status?: NodeTicketNodeStatus
  issued_at: string | null
  not_after: string | null
  days_left: number | null
  reported_at: string | null
}

export interface NodeTicketBatch {
  observed_at: string
  items: NodeTicket[]
}

/** The node keeps serving but takes nothing new: its ticket ended (by time or by its own report). */
export function nodeTicketFrozen(ticket: NodeTicket | undefined): boolean {
  return !!ticket && ticket.node_status !== 'banned' &&
    (ticket.state === 'expired' || ticket.node_status === 'service_ticket_expired')
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const nodeIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const states: readonly string[] = ['valid', 'expired', 'no_ticket', 'unknown']
const nodeStatuses: readonly string[] = ['serving', 'banned', 'service_ticket_expired', 'no_ticket']
export const maxNodeTicketBatch = 300

function invalid(): ApiError {
  return new ApiError('Invalid node installation tickets', 502, 'invalid_response')
}

function time(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && value.length <= 64 && !Number.isNaN(Date.parse(value)))
}

function parseTicket(value: unknown, nodeID: string): NodeTicket {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid()
  const v = value as Record<string, unknown>
  if (v.node_id !== nodeID || typeof v.state !== 'string' || !states.includes(v.state) ||
    (v.node_status !== undefined && (typeof v.node_status !== 'string' || !nodeStatuses.includes(v.node_status))) ||
    !time(v.issued_at) || !time(v.not_after) || !time(v.reported_at) ||
    !(v.days_left === null || (Number.isSafeInteger(v.days_left) && (v.days_left as number) >= 0))) throw invalid()
  return {
    node_id: nodeID, state: v.state as NodeTicketState, node_status: v.node_status as NodeTicketNodeStatus | undefined,
    issued_at: v.issued_at, not_after: v.not_after, days_left: v.days_left as number | null, reported_at: v.reported_at,
  }
}

async function getNodeTickets(accessToken: string, ids: readonly string[], signal?: AbortSignal): Promise<NodeTicketBatch> {
  if (ids.length < 1 || ids.length > maxNodeTicketBatch || new Set(ids).size !== ids.length ||
    ids.some((id) => !nodeIDPattern.test(id))) {
    throw new ApiError('Invalid node ticket identifiers', 400, 'validation_error')
  }
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/nodes/installation-tickets?${new URLSearchParams(ids.map((id) => ['node_id', id]))}`, {
      method: 'GET', credentials: 'include', cache: 'no-store', signal,
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const value: unknown = await response.json().catch(() => null)
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid()
  const v = value as Record<string, unknown>
  if (typeof v.observed_at !== 'string' || !time(v.observed_at) || !Array.isArray(v.items) || v.items.length !== ids.length) {
    throw invalid()
  }
  return { observed_at: v.observed_at, items: v.items.map((item, index) => parseTicket(item, ids[index])) }
}

export const nodeInstallationTicketsApi = { get: getNodeTickets }
