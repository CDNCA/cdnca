import { Select } from 'antd'
import { useTranslation } from 'react-i18next'

import type { OriginBalanceMethod } from '../../api/sites'

const methods: OriginBalanceMethod[] = ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random', 'hash', 'sticky']

export interface BalanceMethodChoicesProps {
  value: OriginBalanceMethod
  disabled?: boolean
  onChange: (value: OriginBalanceMethod) => void
}

// BalanceMethodChoices: 负载方式 as one compact select.
// The list shows each method's one-line use case; the full explanation of the
// chosen method sits behind the row's (?) (FormRow tip in BasicSiteTab).
export default function BalanceMethodChoices({ value, disabled = false, onChange }: BalanceMethodChoicesProps) {
  const { t } = useTranslation('sites')
  return (
    <Select
      className="site-balance-select"
      aria-label={t('edit.basic.aria.balanceMethod')}
      disabled={disabled}
      value={value}
      options={methods.map((method) => ({ value: method, label: t(`edit.basic.balanceChoice.${method}.name`) }))}
      optionRender={(option) => (
        <span className="site-balance-option">
          <span>{option.label}</span>
          <small>{t(`edit.basic.balanceChoice.${option.value as OriginBalanceMethod}.short`)}</small>
        </span>
      )}
      onChange={onChange}
    />
  )
}
