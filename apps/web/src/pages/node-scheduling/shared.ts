import type { TFunction } from 'i18next'

import { ApiError } from '../../api/auth'
import type {
  NodeLineGroup,
  NodeLineGroupSnapshotInput,
  NodeSchedulingCommandMetadata,
  NodeSchedulingScope,
  NodeSchedulingWriteMetadata,
} from '../../api/nodeScheduling'
import type { Principal } from '../../api/auth'

export const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

const unicodeWhiteSpaceCodePoints = '\\u0009-\\u000d\\u0020\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000'
const unicodeWhiteSpaceBoundaryPattern = new RegExp(
  `^[${unicodeWhiteSpaceCodePoints}]+|[${unicodeWhiteSpaceCodePoints}]+$`,
  'gu',
)
const unicodeControlPattern = /\p{Cc}/u

export function trimUnicodeWhiteSpace(value: string): string {
  return value.replace(unicodeWhiteSpaceBoundaryPattern, '')
}

export function validCodePointLength(value: string, minimum: number, maximum: number): boolean {
  const trimmedLength = Array.from(trimUnicodeWhiteSpace(value)).length
  return !unicodeControlPattern.test(value) && trimmedLength >= minimum && Array.from(value).length <= maximum
}

export function validStableKey(value: string, maximum: number): boolean {
  return Array.from(value).length <= maximum && Array.from(trimUnicodeWhiteSpace(value)).length >= 1
}

export function schedulingAccess(
  principal: Principal | null,
  targetScopeID: string,
): { canRead: boolean; canManage: boolean } {
  const permissions = principal?.permissions ?? []
  const wildcard = permissions.includes('platform.admin')
  const canRead = wildcard || permissions.includes('node_scheduling.read')
  const canManageScope = principal?.scope_kind === 'tenant' || (
    principal?.scope_kind === 'platform' && uuidPattern.test(principal.scope_id) &&
    targetScopeID.toLowerCase() === principal.scope_id.toLowerCase()
  )
  return {
    canRead,
    canManage: Boolean(canRead && canManageScope && (wildcard || permissions.includes('node_scheduling.manage'))),
  }
}

export function schedulingScope(
  principal: Principal | null,
  targetScopeID: string,
): NodeSchedulingScope | null {
  if (!principal) return null
  if (principal.scope_kind === 'tenant') return { kind: 'tenant' }
  return uuidPattern.test(targetScopeID) ? { kind: 'platform', targetScopeId: targetScopeID } : null
}

export function requestMetadata(action: string): NodeSchedulingCommandMetadata {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return {
    requestId: `node-scheduling-${action}-${suffix}`,
    idempotencyKey: `node-scheduling-${action}-${suffix}`,
  }
}

export function revisionMetadata(action: string, expectedRevision: number): NodeSchedulingWriteMetadata {
  return { ...requestMetadata(action), expectedRevision }
}

export function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500 || error.code === 'invalid_response'
}

export function schedulingError(error: unknown, t: TFunction<'nodeScheduling'>): string {
  if (!(error instanceof ApiError)) return t('errors.requestFailed')
  const known = new Set([
    'node_scheduling_invalid_request',
    'node_scheduling_unauthenticated',
    'node_scheduling_permission_denied',
    'node_scheduling_platform_write_forbidden',
    'node_scheduling_not_found',
    'node_scheduling_name_conflict',
    'node_scheduling_revision_conflict',
    'node_scheduling_idempotency_conflict',
    'node_scheduling_reference_conflict',
    'node_scheduling_endpoint_address_not_on_node',
    'node_scheduling_invalid_sort_order',
    'node_scheduling_no_healthy_endpoint',
    'topology_cycle_rejected',
    'node_scheduling_target_snapshot_conflict',
    'node_scheduling_target_snapshot_unavailable',
    'node_scheduling_unavailable',
    'l2_condition_invalid_regex',
  ])
  const message = known.has(error.code) ? t(`errors.${error.code}`) : t('errors.requestFailed')
  return error.requestId ? t('errors.withRequestId', { message, requestId: error.requestId }) : message
}

export function snapshotFromGroup(group: NodeLineGroup): NodeLineGroupSnapshotInput {
  return {
    name: group.name,
    region: group.region,
    resolved_value: group.resolved_value,
    ipv4_resolved_value: group.ipv4_resolved_value ?? '',
    l2_config_id: group.l2_config_id ?? null,
    failover_mode: group.failover_mode ?? 'primary_offline',
    note: group.note,
    sort_order: group.sort_order,
    health_policy: { ...group.health_policy },
    endpoints: group.endpoints.map((endpoint) => ({
      id: endpoint.id,
      node_id: endpoint.node_id,
      address: endpoint.address,
      port: endpoint.port,
      region: endpoint.region,
      carrier: endpoint.carrier,
      priority: endpoint.priority,
      sort_order: endpoint.sort_order ?? 100,
      weight: endpoint.weight,
      enabled: endpoint.enabled,
    })),
  }
}

export function validIPAddress(value: string): boolean {
  const candidate = trimUnicodeWhiteSpace(value)
  const ipv4 = candidate.split('.')
  if (ipv4.length === 4 && ipv4.every(
    (part) => /^\d{1,3}$/.test(part) && Number(part) <= 255 && String(Number(part)) === part,
  )) return true
  if (!candidate.includes(':') || !/^[0-9a-f:]+$/i.test(candidate)) return false
  const sides = candidate.split('::')
  if (sides.length > 2) return false
  const groups = sides.flatMap((side) => side ? side.split(':') : [])
  return groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group)) &&
    (sides.length === 2 ? groups.length < 8 : groups.length === 8)
}
