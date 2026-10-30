import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Select } from 'antd'
import { useTranslation } from 'react-i18next'

import { nodesApi } from '../api/nodes'
import { usersApi } from '../api/users'
import { useSessionStore } from '../auth/session'
import '../i18n/l4Realtime'

// Optional 租户 / 节点 filters of the platform 四层 pages: empty means the
// whole control plane. The tenant value is tenants.id (what L4 facts carry),
// found by searching tenant users.

// The picked option's text, for the applied-filter tags (fix-advfilter).
export function optionLabel(option: unknown): string | undefined {
  const label = (Array.isArray(option) ? option[0] : option as { label?: unknown } | undefined)?.label
  return typeof label === 'string' ? label : undefined
}

function accessToken(): string {
  return useSessionStore.getState().accessToken ?? ''
}

export function L4TenantSelect({ ownerKey, value, onChange }: { ownerKey: string; value?: string; onChange: (value?: string, label?: string) => void }) {
  const { t } = useTranslation('l4Realtime')
  const [search, setSearch] = useState('')
  const canList = useSessionStore((state) => state.principal?.permissions.some((code) => code === 'identity.users.manage' || code === 'platform.admin') ?? false)
  const users = useQuery({
    queryKey: ['l4-tenant-filter', ownerKey, search],
    queryFn: () => usersApi.list(accessToken(), { page: 1, limit: 20, ...(/^\d+$/u.test(search.trim()) ? { display_id: search.trim() } : search.trim() ? { search: search.trim() } : {}) }),
    enabled: canList, retry: false, refetchOnWindowFocus: false,
  })
  if (!canList) return null
  const options = [...new Map((users.data?.items ?? []).map((user) => [user.tenant_id, { value: user.tenant_id, label: `${user.username}（${user.display_id}）` }])).values()]
  return <Select className="l4-scope-filter" aria-label={t('filters.tenant')} placeholder={t('filters.allTenants')} allowClear showSearch filterOption={false}
    value={value} onSearch={setSearch} onChange={(next?: string, option?: unknown) => onChange(next ?? undefined, optionLabel(option))} loading={users.isFetching} options={options} style={{ width: 200 }} />
}

export function L4NodeSelect({ ownerKey, value, onChange }: { ownerKey: string; value?: string; onChange: (value?: string, label?: string) => void }) {
  const { t } = useTranslation('l4Realtime')
  // GET /v1/nodes needs nodes.read; a platform role without it gets no node filter.
  const canList = useSessionStore((state) => state.principal?.scope_kind === 'platform' &&
    state.principal.permissions.some((code) => code === 'nodes.read' || code === 'platform.admin'))
  const nodes = useQuery({
    queryKey: ['l4-node-filter', ownerKey],
    queryFn: () => nodesApi.list(accessToken(), { limit: 100 }),
    enabled: canList, retry: false, refetchOnWindowFocus: false,
  })
  if (!canList) return null
  return <Select className="l4-scope-filter" aria-label={t('filters.node')} placeholder={t('filters.allNodes')} allowClear showSearch optionFilterProp="label"
    value={value} onChange={(next?: string, option?: unknown) => onChange(next ?? undefined, optionLabel(option))} loading={nodes.isPending}
    options={(nodes.data?.items ?? []).map((node) => ({ value: node.id, label: `${node.name}${node.ipv4 ? ` (${node.ipv4})` : ''}` }))} style={{ width: 200 }} />
}
