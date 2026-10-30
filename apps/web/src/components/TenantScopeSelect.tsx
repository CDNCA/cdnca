import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Select } from 'antd'

import { usersApi, type ManagedUser } from '../api/users'

export const canonicalScopeUUIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export interface TenantScopeSelectProps {
  accessToken: string | null | undefined
  // Session-owner key so a session switch never reuses another owner's results.
  ownerKey: string
  // Listing tenant users needs identity.users.manage or platform.admin.
  canList: boolean
  value: string
  onChange: (scopeID: string) => void
  ariaLabel: string
  placeholder: string
  emptyText: string
  status?: 'error'
  className?: string
  queryKeyPrefix?: string
  // Called with the picked tenant user (null for a pasted scope UUID or a cleared value).
  onPickUser?: (user: ManagedUser | null) => void
}

// Searchable tenant picker for platform sessions: searches tenant users by
// username/email (or display ID when numeric); the option value is the user's
// scope_id. A pasted canonical scope UUID is offered as-is; any other text is
// only a search term and never becomes the target.
export default function TenantScopeSelect({
  accessToken, ownerKey, canList, value, onChange, ariaLabel, placeholder, emptyText, status, className,
  queryKeyPrefix = 'tenant-scope-select', onPickUser,
}: TenantScopeSelectProps) {
  const [search, setSearch] = useState('')
  const tenantsQuery = useQuery({
    queryKey: [queryKeyPrefix, ownerKey, search],
    queryFn: () => {
      const term = search.trim()
      return usersApi.list(accessToken!, {
        page: 1, limit: 20,
        ...(/^\d+$/u.test(term) ? { display_id: term } : canonicalScopeUUIDPattern.test(term) ? {} : { search: term }),
      })
    },
    enabled: Boolean(accessToken && canList),
    retry: false,
  })
  const options = useMemo(() => {
    const items = (tenantsQuery.data?.items ?? []).map((user) => ({
      value: user.scope_id,
      label: `${user.username}（${user.display_id}）${user.email ? ` · ${user.email}` : ''}`,
    }))
    for (const candidate of [search.trim(), value]) {
      if (canonicalScopeUUIDPattern.test(candidate) && !items.some((item) => item.value === candidate)) {
        items.push({ value: candidate, label: candidate })
      }
    }
    return items
  }, [search, tenantsQuery.data, value])
  return (
    <Select
      className={className}
      aria-label={ariaLabel}
      showSearch
      filterOption={false}
      placeholder={placeholder}
      value={value || undefined}
      status={status}
      loading={tenantsQuery.isFetching}
      options={options}
      onSearch={setSearch}
      onChange={(next: string | undefined) => {
        onChange(next ?? '')
        onPickUser?.(tenantsQuery.data?.items.find((user) => user.scope_id === next) ?? null)
      }}
      notFoundContent={emptyText}
    />
  )
}
