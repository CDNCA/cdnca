import { useQuery } from '@tanstack/react-query'
import { Select } from 'antd'
import { useTranslation } from 'react-i18next'

import { regionsApi } from '../api/nodes'
import { useSessionStore } from '../auth/session'

// The node region picker. Line groups and packages only take catalogued
// regions (/v1/regions), so the node forms offer the same catalog instead of
// free text (D8).

/** Region catalog names, in catalog order; [] without regions.read. */
export function useRegionCatalogNames(ownerKey: string, enabled = true) {
  const principal = useSessionStore((state) => state.principal)
  const canRead = Boolean(principal && (principal.permissions.includes('platform.admin') ||
    principal.permissions.includes('regions.read')))
  return useQuery({
    queryKey: ['node-region-catalog', ownerKey],
    queryFn: async () => {
      const names: string[] = []
      for (let page = 1; ; page += 1) {
        const token = useSessionStore.getState().accessToken
        if (!token) throw new Error('Region catalog session ended during read')
        const result = await regionsApi.list(token, { page, page_size: 300 })
        names.push(...result.data.map((item) => item.name))
        if (page * 300 >= result.count) return names
      }
    },
    enabled: enabled && canRead,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
}

export function NodeRegionSelect({ id, value, onChange, names, loading, disabled }: {
  id?: string
  value?: string
  onChange?: (value: string) => void
  names: string[]
  loading?: boolean
  disabled?: boolean
}) {
  const { t } = useTranslation('nodes')
  // Keep a stored region that is not (or no longer) in the catalog visible.
  const options = [...new Set([...names, ...(value ? [value] : [])])]
  return (
    <Select
      id={id}
      aria-label={t('region.label')}
      allowClear
      showSearch
      placement="bottomLeft"
      virtual={false}
      listHeight={200}
      popupMatchSelectWidth
      classNames={{ popup: { root: 'node-select-popup node-region-field-popup' } }}
      placeholder={t('region.placeholder')}
      loading={loading}
      disabled={disabled}
      notFoundContent={loading ? undefined : t('region.catalogEmpty')}
      value={value || undefined}
      options={options.map((name) => ({ value: name, label: name }))}
      onChange={(next?: string) => onChange?.(next ?? '')}
    />
  )
}
