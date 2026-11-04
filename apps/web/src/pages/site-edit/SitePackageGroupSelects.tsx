import { useInfiniteQuery } from '@tanstack/react-query'
import { Button, Select } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { siteGroupsApi } from '../../api/siteGroups'
import type { SiteBasicConfig } from '../../api/sites'
import '../../i18n/siteCreate'

// The site editor's group select (the same query the create form uses).
export interface SiteGroupSelectProps {
  accessToken?: string
  // The site's tenant scope.
  scopeID: string
  platform: boolean
  ownerID: string
  // The site owner's name for the empty group hint (platform only).
  ownerName?: string
  value: SiteBasicConfig
  readOnly: boolean
  onChange: (value: SiteBasicConfig) => void
}

export function SiteGroupSelect({ accessToken, platform, scopeID, ownerID, ownerName, value, readOnly, onChange }: SiteGroupSelectProps) {
  const { t } = useTranslation(['sites', 'siteCreate'])
  const groups = useInfiniteQuery({
    queryKey: ['site-edit-groups', scopeID],
    enabled: Boolean(accessToken && scopeID),
    initialPageParam: 1,
    queryFn: ({ pageParam }) => siteGroupsApi.list(accessToken!, scopeID, pageParam, 20),
    getNextPageParam: (last) => last.page * last.limit < last.total ? last.page + 1 : undefined,
    retry: false,
  })
  const options = (groups.data?.pages.flatMap((page) => page.items) ?? []).filter((item) => !item.deleted_at)
  const current = value.group_id && !options.some((item) => item.id === value.group_id)
    ? [{ value: value.group_id, label: value.group_name || value.group_id }] : []
  return (
    <div className="site-group-select">
      <Select
        aria-label={t('edit.basic.fields.group')}
        value={value.group_id ?? undefined}
        allowClear
        showSearch
        optionFilterProp="label"
        disabled={readOnly}
        loading={groups.isFetching}
        placeholder={t('edit.basic.selectPlaceholder')}
        options={[...current, ...options.map((item) => ({ value: item.id, label: item.name }))]}
        onChange={(groupID?: string) => {
          const item = options.find((option) => option.id === groupID)
          onChange({ ...value, group_id: item?.id ?? null, group_name: item?.name ?? null })
        }}
        popupRender={(menu) => <>{menu}{groups.hasNextPage ? <Button block loading={groups.isFetchingNextPage} onClick={() => void groups.fetchNextPage()}>{t('siteCreate:lookup.more')}</Button> : null}</>}
      />
      {groups.isError ? <small role="alert">{t('siteCreate:lookup.failed')} <Button size="small" onClick={() => void groups.refetch()}>{t('siteCreate:lookup.retry')}</Button></small> : null}
      {/* Groups belong to the site owner; say whose list is empty and where to add one. */}
      {groups.isSuccess && !groups.hasNextPage && !options.length ? <small className="site-group-empty">
        {platform ? t('edit.basic.groupEmptyOwner', { name: ownerName || ownerID }) : t('edit.basic.groupEmptySelf')}{' '}
        <Link to="/site/list" state={{ siteSubnav: 'groups', siteGroupCreateFor: { userID: ownerID, scopeID, name: ownerName ?? '' } }}>{t('edit.basic.groupCreate')}</Link>
      </small> : null}
    </div>
  )
}
