import { useState } from 'react'
import { Tabs } from 'antd'
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
  // 来源用与访问日志「日志/导出」同款的 analytics-log-tabs 页签，不再用 Segmented + 小字标签。
  const [source, setSource] = useState<Source>('local')
  return (
    <section className="analytics-page analytics-log-page analytics-block-event-page" aria-labelledby="analytics-block-event-title">
      <div className="analytics-panel analytics-block-event-source" role="group" aria-label={mt('source.label')}>
        <h1 id="analytics-block-event-title" className="visually-hidden">{t('title.blockEvents')}</h1>
        <Tabs
          className="analytics-log-tabs"
          activeKey={source}
          items={[{ key: 'local', label: mt('source.local') }, { key: 'market', label: mt('source.market') }]}
          onChange={(value) => setSource(value as Source)}
        />
      </div>
      {source === 'local' ? <AnalyticsLogPage kind="block" embedded /> : <MarketSecurityLogPanel />}
    </section>
  )
}
