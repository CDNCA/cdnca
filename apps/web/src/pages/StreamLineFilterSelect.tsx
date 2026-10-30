import { useQuery } from '@tanstack/react-query'
import { Select } from 'antd'
import { useTranslation } from 'react-i18next'
import { regionsApi } from '../api/nodes'
import { nodeSchedulingApi } from '../api/nodeScheduling'
import { useSessionStore } from '../auth/session'

// 转发列表筛选「区域」「线路分组」（平台）：区域目录与平台线路组，值为 ID，筛选在服务端按转发的线路做。
export default function StreamLineFilterSelect({ kind, value, onChange, enabled = true }: {
  kind: 'region' | 'line_group'
  value?: string
  onChange: (value?: string) => void
  /** fix-advfilter2：放在收起的高级筛选面板里时，展开前不读选项。 */
  enabled?: boolean
}) {
  const { t } = useTranslation('streams')
  const principal = useSessionStore((state) => state.principal)
  const query = useQuery({
    queryKey: ['stream-line-filter-options', principal?.scope_id, kind],
    queryFn: async () => {
      const token = useSessionStore.getState().accessToken ?? ''
      if (kind === 'region') {
        const options: Array<{ value: string; label: string }> = []
        for (let page = 1; ; page += 1) {
          const result = await regionsApi.list(token, { page, page_size: 300 })
          options.push(...result.data.map((item) => ({ value: item.id, label: item.name })))
          if (page * 300 >= result.count) return options
        }
      }
      const groups = await nodeSchedulingApi.list(token, { kind: 'platform', targetScopeId: principal?.scope_id ?? '' })
      return groups.items.map((item) => ({ value: item.id, label: item.region ? `${item.name}（${item.region}）` : item.name }))
    },
    enabled: enabled && Boolean(principal),
    retry: false,
  })
  return <Select aria-label={t(kind === 'region' ? 'filters.region' : 'filters.lineGroup')} allowClear showSearch optionFilterProp="label"
    placeholder={t('filters.unlimited')} loading={query.isFetching} options={query.data ?? []} value={value} onChange={onChange}
    notFoundContent={query.isError ? t('errors.requestFailed') : undefined} />
}
