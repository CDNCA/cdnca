import { useState } from 'react'
import { Segmented } from 'antd'
import { useTranslation } from 'react-i18next'

import { AnalyticsLogPage } from './SiteAccessLogPage'
import MarketSecurityLogPanel from './MarketSecurityLogPanel'
import '../i18n/marketSecurity'

type Source = 'local' | 'market'

export default function SiteBlockEventLogPage() {
  const { t } = useTranslation('analyticsLogs')
  const { t: mt } = useTranslation('marketSecurity')
  // ML-21: blocks on market-supplied sites happen on the supplier's nodes
  // and are relayed separately; the source switch shows them.
  const [source, setSource] = useState<Source>('local')
  return (
    <section className="analytics-page analytics-log-page" aria-labelledby="analytics-block-event-title">
      <div className="analytics-panel">
        <h1 id="analytics-block-event-title" className="visually-hidden">{t('title.blockEvents')}</h1>
        <div className="analytics-filter-field" role="group" aria-label={mt('source.label')}>
          <span>{mt('source.label')}</span>
          <Segmented<Source>
            value={source}
            onChange={setSource}
            options={[{ value: 'local', label: mt('source.local') }, { value: 'market', label: mt('source.market') }]}
          />
        </div>
      </div>
      {source === 'local' ? <AnalyticsLogPage kind="block" embedded /> : <MarketSecurityLogPanel />}
    </section>
  )
}
