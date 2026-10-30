import { Radio, Tooltip } from 'antd'
import { useTranslation } from 'react-i18next'

import type { OriginBalanceMethod } from '../../api/sites'

const methods: OriginBalanceMethod[] = ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random', 'hash', 'sticky']

export interface BalanceMethodChoicesProps {
  value: OriginBalanceMethod
  disabled?: boolean
  onChange: (value: OriginBalanceMethod) => void
}

// BalanceMethodChoices: 负载方式 as option cards (fix-lbtags). Each card shows
// the name and a one-line use case; hovering or focusing it opens the full
// explanation, which screen readers get through aria-describedby.
export default function BalanceMethodChoices({ value, disabled = false, onChange }: BalanceMethodChoicesProps) {
  const { t } = useTranslation('sites')
  return (
    <div role="radiogroup" aria-label={t('edit.basic.aria.balanceMethod')}>
      <Radio.Group className="site-origin-choice-grid is-balance" name="site-balance-method" disabled={disabled}
        value={value} onChange={(event) => onChange(event.target.value as OriginBalanceMethod)}>
        {methods.map((method) => {
          const id = `site-balance-${method}`
          const name = t(`edit.basic.balanceChoice.${method}.name`)
          const detail = t(`edit.basic.balanceChoice.${method}.detail`)
          return (
            <Tooltip key={method} trigger={['hover', 'focus']} placement="top" mouseEnterDelay={0.2}
              classNames={{ root: 'site-balance-tip' }} title={<><strong>{name}</strong><p>{detail}</p></>}>
              <span className="site-balance-choice">
                <Radio value={method} className="site-origin-choice" aria-labelledby={`${id}-name`}
                  aria-describedby={`${id}-short ${id}-detail`}>
                  <strong id={`${id}-name`}>{name}</strong>
                  <span id={`${id}-short`}>{t(`edit.basic.balanceChoice.${method}.short`)}</span>
                  <span id={`${id}-detail`} className="visually-hidden">{detail}</span>
                </Radio>
              </span>
            </Tooltip>
          )
        })}
      </Radio.Group>
    </div>
  )
}
