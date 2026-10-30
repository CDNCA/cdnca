import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Select } from 'antd'
import { useTranslation } from 'react-i18next'
import type { ScopeKind } from '../api/auth'
import { usersApi, type ManagedUser } from '../api/users'
import { useSessionStore } from '../auth/session'
import { currentPrincipalCanReadStreams, staleStreamRead } from './streamForm'

// 「用户选择」：输入 ID、邮箱、用户名、手机号搜索租户用户（GET /v1/users 的 search 覆盖用户名/昵称/邮箱/手机号，
// 纯数字按用户 ID）。选中后同时给出租户作用域与归属用户，提交仍是 target_scope_id + owner_id。
// 只在平台会话且有 identity.users.manage / platform.admin 时使用；否则调用方回退为手填 UUID。
export default function StreamOwnerSelect({ scopeKind, scopeID, sessionEpoch, id, value, onPick }: {
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  id?: string
  value?: string
  onPick: (user: Pick<ManagedUser, 'id' | 'scope_id'> | null) => void
}) {
  const { t } = useTranslation('streams')
  const [search, setSearch] = useState('')
  const [opened, setOpened] = useState(false)
  const query = useQuery({
    queryKey: ['stream-owner-options', scopeKind, scopeID, sessionEpoch, search],
    queryFn: async () => {
      if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
      const term = search.trim()
      const result = await usersApi.list(useSessionStore.getState().accessToken ?? '', {
        page: 1, limit: 20, ...(/^\d+$/u.test(term) ? { display_id: term } : term ? { search: term } : {}),
      })
      if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
      return result.items
    },
    enabled: opened,
    staleTime: 30_000,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  const items = query.data ?? []
  return (
    <Select
      id={id}
      value={value || undefined}
      showSearch
      allowClear
      filterOption={false}
      onSearch={setSearch}
      loading={query.isFetching}
      placeholder={t('form.ownerSearchPlaceholder')}
      notFoundContent={query.isFetching ? null : query.isError ? t('form.ownerOptionsFailed') : t('form.ownerNotFound')}
      options={items.map((user) => ({
        value: user.id,
        label: `${user.username}（${user.display_id}）${user.email ? ` · ${user.email}` : ''}`,
      }))}
      onOpenChange={(visible) => { if (visible) setOpened(true) }}
      onChange={(next: string | undefined) => {
        const user = items.find((entry) => entry.id === next)
        onPick(user ? { id: user.id, scope_id: user.scope_id } : null)
      }}
    />
  )
}
