import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import type { ScopeKind } from '../api/auth'
import { streamGroupsApi, type StreamEffectiveDefaults } from '../api/streamGroups'
import type { StreamBalanceWay, StreamProtocol } from '../api/streams'
import { useSessionStore } from '../auth/session'
import { currentPrincipalCanReadStreams, staleStreamRead, uuidPattern } from './streamForm'

/** 新建草稿在没有「默认设置」时的兜底值（与服务端未填时一致）。 */
export const draftFallback = { protocol: 'tcp' as StreamProtocol, balance_way: 'rr' as StreamBalanceWay, proxy_protocol_inbound: false }

export type DraftDefaultField = keyof typeof draftFallback

export interface DraftDefaults {
  protocol: StreamProtocol
  balance_way: StreamBalanceWay
  proxy_protocol_inbound: boolean
}

export function resolveDraftDefaults(effective: StreamEffectiveDefaults | undefined): DraftDefaults {
  return {
    protocol: effective?.protocol ?? draftFallback.protocol,
    balance_way: effective?.balance_way ?? draftFallback.balance_way,
    proxy_protocol_inbound: effective?.proxy_protocol_inbound ?? draftFallback.proxy_protocol_inbound,
  }
}

/**
 * L4-DEFAULT-01：新建草稿按归属（管理员代建为所选用户）与所选分组读取生效默认。
 * 只在归属已确定时请求；管理员未选用户前用兜底值。owner 未定或读失败时 defaults 为兜底，不阻塞新建。
 */
export function useStreamDraftDefaults({ open, isAdmin, scopeKind, scopeID, sessionEpoch, targetScopeID, ownerID, groupIDs }: {
  open: boolean
  isAdmin: boolean
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  targetScopeID?: string
  ownerID?: string
  groupIDs?: string[]
}): { defaults: DraftDefaults; ready: boolean } {
  const target = isAdmin ? targetScopeID?.trim().toLowerCase() ?? '' : ''
  const owner = isAdmin ? ownerID?.trim().toLowerCase() ?? '' : 'self'
  const groups = [...(groupIDs ?? [])].sort()
  const known = !isAdmin || (uuidPattern.test(target) && uuidPattern.test(owner))
  const query = useQuery({
    queryKey: ['stream-draft-defaults', scopeKind, scopeID, sessionEpoch, target, owner, groups.join(',')],
    queryFn: async () => {
      if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
      const result = await streamGroupsApi.effectiveDefaults(useSessionStore.getState().accessToken ?? '',
        isAdmin ? { target_scope_id: target, owner_id: owner, group_ids: groups } : { group_ids: groups })
      if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
      return result
    },
    enabled: open && known,
    staleTime: 30_000,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  return { defaults: resolveDraftDefaults(query.data), ready: !known || !query.isFetching }
}

/**
 * 默认值变化（打开、换归属用户、改分组）时写入草稿，跳过用户已手动改过的字段（touched）：
 * 显式选择优先于任何默认。
 */
export function useApplyDraftDefaults(defaults: DraftDefaults, ready: boolean, apply: (values: Partial<DraftDefaults>) => void,
  touched: () => Set<DraftDefaultField>, open: boolean) {
  const applied = useRef<string>('')
  const key = `${defaults.protocol}|${defaults.balance_way}|${defaults.proxy_protocol_inbound}`
  useEffect(() => {
    if (!open) {
      applied.current = ''
      return
    }
    if (!ready || applied.current === key) return
    applied.current = key
    const skip = touched()
    const values: Partial<DraftDefaults> = {}
    for (const field of Object.keys(defaults) as DraftDefaultField[]) {
      if (!skip.has(field)) (values as Record<string, unknown>)[field] = defaults[field]
    }
    apply(values)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, ready, open])
}
