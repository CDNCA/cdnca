import { useEffect, useRef, useState } from 'react'
import { Alert, Radio, Select, Space, Spin, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { maxTargetTenants } from '../../api/pluginInstallations'
import { usersApi } from '../../api/users'
import '../../i18n/pluginInstallations'

import type { TargetsDraft, TenantOption } from './targetsDraft'


/**
 * Which tenants a tenant plugin is installed for: all tenants, or tenants found by
 * username / user ID through the management user list (a tenant's user carries its tenant scope). Without the
 * user list permission only "all tenants" can be chosen.
 */
export function TenantTargetsPicker({ token, value, onChange, canSearch, disabled }: {
  token: string; value: TargetsDraft; onChange: (value: TargetsDraft) => void; canSearch: boolean; disabled?: boolean
}) {
  const { t } = useTranslation('pluginInstallations')
  const [query, setQuery] = useState('')
  const [options, setOptions] = useState<TenantOption[]>([])
  const [loading, setLoading] = useState(false)
  const sequence = useRef(0)
  useEffect(() => {
    if (value.allTenants || !canSearch) return
    const current = ++sequence.current
    setLoading(true)
    const timer = setTimeout(() => {
      const text = query.trim()
      usersApi.list(token, { page: 1, limit: 20, ...(/^[1-9][0-9]{0,18}$/.test(text) ? { display_id: text } : text ? { search: text } : {}) })
        .then((result) => {
          if (current !== sequence.current) return
          const seen = new Set<string>()
          setOptions(result.items.filter((user) => user.scope_id && !seen.has(user.scope_id) && seen.add(user.scope_id))
            .map((user) => ({ value: user.scope_id, label: `${user.display_name || user.username} · ${user.display_id}` })))
        }, () => { if (current === sequence.current) setOptions([]) })
        .finally(() => { if (current === sequence.current) setLoading(false) })
    }, 250)
    return () => clearTimeout(timer)
  }, [canSearch, query, token, value.allTenants])
  return <Space direction="vertical" size={8} style={{ width: '100%' }} className="plugin-market-targets">
    <Typography.Text strong>{t('targets.title')}</Typography.Text>
    <Radio.Group value={value.allTenants ? 'all' : 'selected'} disabled={disabled}
      onChange={(event) => onChange({ ...value, allTenants: event.target.value === 'all' })}
      options={[{ value: 'all', label: t('targets.all') }, { value: 'selected', label: t('targets.selected'), disabled: !canSearch }]} />
    {!canSearch ? <Alert type="info" showIcon message={t('targets.noUserPermission')} /> : null}
    {!value.allTenants && canSearch ? <Select<string[]> mode="multiple" style={{ width: '100%' }} disabled={disabled}
      aria-label={t('targets.selected')} placeholder={t('targets.searchPlaceholder')} filterOption={false} showSearch
      maxCount={maxTargetTenants} onSearch={setQuery} value={value.tenants.map((tenant) => tenant.value)}
      notFoundContent={loading ? <Spin size="small" aria-label={t('targets.searching')} /> : t('targets.none')}
      options={[...value.tenants, ...options.filter((option) => !value.tenants.some((tenant) => tenant.value === option.value))]}
      onChange={(ids) => onChange({ ...value, tenants: ids.map((id) => value.tenants.find((tenant) => tenant.value === id)
        ?? options.find((option) => option.value === id) ?? { value: id, label: id }) })} /> : null}
    {!value.allTenants && value.tenants.length === 0 ? <Typography.Text type="danger">{t('targets.required')}</Typography.Text> : null}
  </Space>
}
