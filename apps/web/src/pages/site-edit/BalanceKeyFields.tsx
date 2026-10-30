import { Input, Select } from 'antd'
import { useTranslation } from 'react-i18next'

import { originForwarding, type OriginStickySource, type SiteOriginPool } from '../../api/sites'
import '../../i18n/siteOriginForwarding'
import { FormRow } from './SiteEditFields'

export interface BalanceKeyFieldsProps {
  pool: SiteOriginPool
  readOnly?: boolean
  onChange: (value: SiteOriginPool) => void
}

// BalanceKeyFields: the key a custom hash or session affinity balance
// method needs, shown under 负载方式 only for that method.
export default function BalanceKeyFields({ pool, readOnly = false, onChange }: BalanceKeyFieldsProps) {
  const { t } = useTranslation('siteOriginForwarding')
  const forwarding = originForwarding(pool)
  const update = (changes: Partial<SiteOriginPool>) => onChange({ ...pool, ...changes })
  const stickyOptions = (['cookie', 'header', 'arg'] as OriginStickySource[]).map((value) => ({ value, label: t(`options.sticky.${value}`) }))

  if (pool.balance_method === 'hash') {
    return (
      <FormRow label={t('fields.hashKey')} tip={t('balance.help.hash')}>
        <Input aria-label={t('fields.hashKey')} disabled={readOnly} value={forwarding.hash_key ?? ''} placeholder="$cookie_uid$uri"
          onChange={(event) => update({ hash_key: event.target.value })} />
      </FormRow>
    )
  }
  if (pool.balance_method === 'sticky') {
    return (
      <FormRow label={t('fields.stickySource')} tip={t('balance.help.sticky')}>
        <div className="site-form-inline">
          <Select aria-label={t('fields.stickySource')} disabled={readOnly} value={forwarding.sticky?.source ?? 'cookie'} options={stickyOptions}
            onChange={(source) => update({ sticky: { source, name: forwarding.sticky?.name ?? '' } })} />
          <Input aria-label={t('fields.stickyName')} disabled={readOnly} value={forwarding.sticky?.name ?? ''} placeholder="cdnca_route"
            onChange={(event) => update({ sticky: { source: forwarding.sticky?.source ?? 'cookie', name: event.target.value } })} />
        </div>
      </FormRow>
    )
  }
  return null
}
