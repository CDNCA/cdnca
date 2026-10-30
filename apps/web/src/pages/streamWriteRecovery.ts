import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import type { ScopeKind } from '../api/auth'

// fix-l4flow3 L4-007：结果未知的写入（原目标、请求体、修订、幂等键）按 作用域/会话/对象 放在查询缓存里，
// 离开路由、关闭弹窗后仍在，回来只能按原请求确认。会话或作用域变化即换键，旧记录取不到。
export interface WriteRecoveryScope {
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
}

const root = 'stream-write-recovery'

function scopeKey({ scopeKind, scopeID, sessionEpoch }: WriteRecoveryScope) {
  return [root, scopeKind, scopeID, sessionEpoch] as const
}

export function useWriteRecovery<T extends object>(scope: WriteRecoveryScope, target: string) {
  const client = useQueryClient()
  const queryKey = [...scopeKey(scope), target]
  const { data } = useQuery<T | null>({ queryKey, queryFn: () => null, initialData: null, enabled: false, gcTime: Infinity, staleTime: Infinity })
  return {
    attempt: data ?? null,
    // 结果未知：记下这次请求。结果确定：只清掉同一次请求，迟到的旧请求结果不能清掉当前记录。
    settle: (attempt: T, unknown: boolean) => {
      if (unknown) client.setQueryData(queryKey, attempt)
      // 缓存写入会做结构共享，取回的不一定是同一个对象，按内容比（每次请求的幂等键不同）。
      else if (JSON.stringify(client.getQueryData(queryKey)) === JSON.stringify(attempt)) client.setQueryData(queryKey, null)
    },
    clear: () => client.setQueryData(queryKey, null),
  }
}

// 会话失效或失去权限时清掉本作用域的全部记录。
export function dropWriteRecovery(client: QueryClient, scope: WriteRecoveryScope) {
  client.removeQueries({ queryKey: scopeKey(scope) })
}
