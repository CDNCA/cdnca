import { useSearchParams } from 'react-router-dom'
import { Tabs } from '../components/Tabs'
import { useTranslation } from 'react-i18next'

import { AnalyticsLogPage } from './SiteAccessLogPage'
import MarketSecurityLogPanel from './MarketSecurityLogPanel'
import { filterParam } from './filterUrl'
import '../i18n/marketSecurity'

type Source = 'local' | 'market'

export default function SiteBlockEventLogPage() {
  const { t } = useTranslation('analyticsLogs')
  const { t: mt } = useTranslation('marketSecurity')
  // ML-21: blocks on market-supplied sites happen on the supplier's nodes
  // and are relayed separately; the source switch shows them.
  // ui-align3：来源用与访问日志「日志/导出」同款的 analytics-log-tabs 页签，不再用 Segmented + 小字标签。
  // 来源写进 ?source=（本地节点为默认不写），刷新后停在原来源；
  // 换来源时清掉上一来源写的筛选键，新来源从默认条件开始（两个来源的条件键不通用）。
  const [searchParams, setSearchParams] = useSearchParams()
  const source: Source = filterParam(searchParams, 'source') === 'market' ? 'market' : 'local'
  const switchSource = (next: Source) => {
    if (next === source) return
    setSearchParams(next === 'market' ? { source: 'market' } : {})
  }
  // 两个来源的正文放进各自页签面板；隐藏的来源卸载，再切回时从 URL 重新读条件。
  return (
    <section className="analytics-page analytics-log-page analytics-block-event-page" aria-labelledby="analytics-block-event-title">
      <h1 id="analytics-block-event-title" className="visually-hidden">{t('title.blockEvents')}</h1>
      <div className="analytics-block-event-source">
        <Tabs
          className="analytics-log-tabs"
          activeKey={source}
          destroyOnHidden
          renderTabBar={(props, DefaultTabBar) => (
            <div className="analytics-panel analytics-block-event-tabbar" role="group" aria-label={mt('source.label')}><DefaultTabBar {...props} /></div>
          )}
          items={[
            { key: 'local', label: mt('source.local'), children: <AnalyticsLogPage kind="block" embedded /> },
            { key: 'market', label: mt('source.market'), children: <MarketSecurityLogPanel /> },
          ]}
          onChange={(value) => switchSource(value as Source)}
        />
      </div>
    </section>
  )
}
