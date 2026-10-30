import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Select } from 'antd'
import { useTranslation } from 'react-i18next'
import type { ScopeKind } from '../api/auth'
import { streamGroupsApi } from '../api/streamGroups'
import { currentPrincipalCanReadStreams, staleStreamRead } from './streamForm'
import { useSessionStore } from '../auth/session'

// 转发列表「所属分组」筛选：转发分组，值为分组 ID。
export default function StreamFilterSelect({ kind, scopeKind, scopeID, sessionEpoch, value, onChange }: {
  kind: 'group'
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  value?: string
  onChange: (value?: string) => void
}) {
  const { t } = useTranslation('streams')
  const [opened, setOpened] = useState(false)
  const queryClient = useQueryClient()
  const currentAccess = () => {
    if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) throw staleStreamRead
    return useSessionStore.getState().accessToken ?? ''
  }
  const queryKey = ['stream-filter-options', scopeKind, scopeID, sessionEpoch, kind]
  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const options = new Map<string, string>()
      for (let page = 1; ; page += 1) {
        const token = currentAccess()
        const response = await streamGroupsApi.listGroups(token, { page, limit: 100 })
        currentAccess()
        for (const item of response.items) {
          if (scopeKind === 'tenant' && item.scope_id !== scopeID) throw staleStreamRead
          options.set(item.id, item.name)
        }
        if (page * response.limit >= response.total || response.items.length === 0) break
      }
      return [...options].map(([id, name]) => ({ value: id, name }))
    },
    enabled: opened,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  useEffect(() => () => {
    if (!currentPrincipalCanReadStreams(scopeKind, scopeID, sessionEpoch)) queryClient.removeQueries({ queryKey: ['stream-filter-options', scopeKind, scopeID, sessionEpoch] })
  }, [queryClient, scopeKind, scopeID, sessionEpoch])
  return <Select
    aria-label={t(`filters.${kind}`)}
    value={value}
    onChange={onChange}
    allowClear
    showSearch
    optionFilterProp="label"
    placeholder={t('filters.selectPlaceholder')}
    loading={query.isFetching}
    options={!query.isError ? query.data?.map((item) => ({ value: item.value, label: item.name })) : []}
    notFoundContent={query.isError ? <div role="alert">{t('filters.optionsFailed')}<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button></div> : undefined}
    onOpenChange={(open) => { if (open) setOpened(true) }}
  />
}
