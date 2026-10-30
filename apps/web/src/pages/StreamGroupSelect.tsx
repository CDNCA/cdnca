import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Select } from 'antd'
import { useTranslation } from 'react-i18next'
import type { ScopeKind } from '../api/auth'
import type { Stream } from '../api/streams'
import { streamGroupsApi } from '../api/streamGroups'
import { useSessionStore } from '../auth/session'
import { currentPrincipalCanReadStreams, staleStreamRead, uuidPattern } from './streamForm'

// 分组选项只在用户真正展开下拉时才请求，避免给列表页多加一个常驻查询。
export default function StreamGroupSelect({ open, scopeKind, scopeID, sessionEpoch, targetScopeID, groups, id, value, onChange }: {
  open: boolean
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  targetScopeID: string
  groups: Stream['groups']
  id?: string
  value?: string[]
  onChange?: (value: string[]) => void
}) {
  const { t } = useTranslation('streams')
  const [opened, setOpened] = useState(false)
  const optionsQuery = useQuery({
    queryKey: ['stream-form-group-options', scopeKind, scopeID, sessionEpoch, targetScopeID],
    queryFn: async () => {
      const options: Array<{ value: string; label: string }> = []
      for (let page = 1; ; page += 1) {
        if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
        const response = await streamGroupsApi.listGroups(useSessionStore.getState().accessToken ?? '', { page, limit: 100 })
        if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
        options.push(...response.items.filter((group) => group.scope_id === targetScopeID)
          .map((group) => ({ value: group.id, label: group.name })))
        if (page * response.limit >= response.total || response.items.length === 0) return options
      }
    },
    enabled: open && opened && uuidPattern.test(targetScopeID),
    staleTime: 60_000,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  return (
    <Select
      id={id}
      value={value ?? []}
      onChange={onChange}
      mode="multiple"
      allowClear
      showSearch
      optionFilterProp="label"
      placeholder={t('form.groupPlaceholder')}
      disabled={!open || !uuidPattern.test(targetScopeID)}
      loading={optionsQuery.isFetching}
      options={optionsQuery.data ?? groups.map((group) => ({ value: group.id, label: group.name }))}
      onOpenChange={(visible) => { if (visible) setOpened(true) }}
    />
  )
}
