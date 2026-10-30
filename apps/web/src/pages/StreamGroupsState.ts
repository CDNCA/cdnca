import { useEffect, useRef, useState } from 'react'
import { useIsMutating, useMutation, useQuery, useQueryClient, type QueryKey } from '@tanstack/react-query'
import { ApiError } from '../api/auth'
import { writeKey, writeOutcomeUnknown } from './streamForm'

type WriteAttempt<Input, Item> = { kind: 'create'; input: Input; key: string } |
  { kind: 'delete'; items: Array<{ item: Item; key: string }> }

// 两个面板使用相同的创建与逐条删除契约，恢复时保留原始请求身份。
export function useStreamPanelWrites<Input, Item extends { id: string }>({
  canWrite, sameSession, blocked, create, remove, invalidate, created, deleted, recoveryKey,
}: {
  canWrite: () => boolean
  sameSession: () => boolean
  blocked: boolean
  create: (input: Input, key: string) => Promise<unknown>
  remove: (item: Item, key: string) => Promise<void>
  invalidate: () => Promise<unknown>
  created: () => void
  deleted: (failedIDs: string[]) => void
  recoveryKey: QueryKey
}) {
  const client = useQueryClient()
  const inFlight = useIsMutating({ mutationKey: recoveryKey }) > 0
  const recovery = useQuery<WriteAttempt<Input, Item> | null>({ queryKey: recoveryKey, queryFn: () => null, initialData: null, enabled: false, gcTime: Infinity })
  const retryAttempt = recovery.data ?? null
  const setRetryAttempt = (attempt: WriteAttempt<Input, Item> | null) => client.setQueryData(recoveryKey, attempt)
  const pendingAttempt = useRef<WriteAttempt<Input, Item> | null>(null)
  const mounted = useRef(true)
  const allowedRef = useRef(canWrite)
  allowedRef.current = canWrite
  const sessionRef = useRef(sameSession)
  sessionRef.current = sameSession
  const blockedRef = useRef(blocked)
  blockedRef.current = blocked
  const [resource, scopeKind, scopeID, sessionEpoch] = recoveryKey
  useEffect(() => {
    const key = [resource, scopeKind, scopeID, sessionEpoch]
    mounted.current = true
    return () => {
      mounted.current = false
      if (!sessionRef.current()) client.removeQueries({ queryKey: key, exact: true })
      else if (pendingAttempt.current) client.setQueryData(key, pendingAttempt.current)
    }
  }, [client, resource, scopeKind, scopeID, sessionEpoch])
  const active = () => mounted.current && allowedRef.current()
  const busy = useRef(false)
  const [error, setError] = useState<ApiError | null>(null)
  const fail = (reason: unknown, attempt: WriteAttempt<Input, Item>) => {
    setError(reason instanceof ApiError ? reason : new ApiError('request failed', 0, 'network_error'))
    setRetryAttempt(writeOutcomeUnknown(reason) ? attempt : null)
  }
  const mutation = useMutation({
    mutationKey: recoveryKey,
    retry: false,
    mutationFn: async (attempt: WriteAttempt<Input, Item>) => {
      if (!active()) throw new ApiError('permission denied', 403, 'permission_denied')
      if (attempt.kind === 'create') { await create(attempt.input, attempt.key); return [] }
      return Promise.allSettled(attempt.items.map(({ item, key }) => remove(item, key)))
    },
    onSuccess: async (results, attempt) => {
      pendingAttempt.current = null
      if (!sessionRef.current()) return
      setRetryAttempt(null)
      if (mounted.current) setError(null)
      if (attempt.kind === 'create') { if (active()) created() }
      else {
        const failed = attempt.items.filter((_, index) => results[index].status === 'rejected')
        const unknown = attempt.items.filter((_, index) => {
          const result = results[index]
          return result.status === 'rejected' && writeOutcomeUnknown(result.reason)
        })
        const failure = results.find((result) => result.status === 'rejected')
        if (active() && failure?.status === 'rejected') fail(failure.reason, attempt)
        setRetryAttempt(unknown.length ? { kind: 'delete', items: unknown } : null)
        if (active()) deleted(failed.map(({ item }) => item.id))
      }
      if (allowedRef.current()) await invalidate()
    },
    onError: (reason, attempt) => {
      pendingAttempt.current = null
      if (active()) fail(reason, attempt)
      else if (sessionRef.current()) setRetryAttempt(writeOutcomeUnknown(reason) ? attempt : null)
    },
    onSettled: () => { busy.current = false; pendingAttempt.current = null },
  })
  const run = (attempt: WriteAttempt<Input, Item>) => {
    if (!active() || blockedRef.current || busy.current || client.isMutating({ mutationKey: recoveryKey }) > 0) return
    const recovery = client.getQueryData<WriteAttempt<Input, Item>>(recoveryKey)
    if (recovery && recovery !== attempt) return
    busy.current = true
    pendingAttempt.current = attempt
    if (!retryAttempt) setError(null)
    mutation.mutate(attempt)
  }
  return {
    error,
    pending: mutation.isPending || inFlight,
    uncertain: Boolean(retryAttempt),
    clearError: () => { if (!retryAttempt) setError(null) },
    create: (input: Input) => { if (!retryAttempt) run({ kind: 'create', input, key: writeKey('create-stream-panel') }) },
    remove: (items: Item[]) => { if (!retryAttempt) run({ kind: 'delete', items: items.map((item) => ({ item, key: writeKey(`delete-${item.id}`) })) }) },
    retry: () => { if (retryAttempt) run(retryAttempt) },
  }
}
