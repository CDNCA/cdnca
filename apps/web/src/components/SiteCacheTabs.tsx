import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import '../i18n/cacheOperations'
import './SiteCacheTabs.css'

export type SiteCacheTab = 'purge' | 'history'

export default function SiteCacheTabs({
  active,
  showHistory = true,
  historyHref = '/site/cache-clean/history',
  extra,
}: {
  active: SiteCacheTab
  showHistory?: boolean
  /** Where 操作记录 opens (an administrator's records are /site/cache-clean?tab=history). */
  historyHref?: string
  /** Toolbar shown at the right end of the tab row (like antd Tabs tabBarExtraContent). */
  extra?: ReactNode
}) {
  const { t } = useTranslation('cacheOperations')
  const tabs = (
    <nav className="site-cache-tabs" aria-label={t('tabs.label')} role="tablist">
      <Link
        className={`site-cache-tab${active === 'purge' ? ' is-active' : ''}`}
        to="/site/cache-clean"
        role="tab"
        aria-selected={active === 'purge'}
      >
        {t('tabs.purge')}
      </Link>
      {showHistory ? (
        <Link
          className={`site-cache-tab${active === 'history' ? ' is-active' : ''}`}
          to={historyHref}
          role="tab"
          aria-selected={active === 'history'}
        >
          {t('tabs.history')}
        </Link>
      ) : null}
    </nav>
  )
  if (!extra) return tabs
  return (
    <div className="site-cache-tabs-row">
      {tabs}
      <div className="site-cache-tabs-extra">{extra}</div>
    </div>
  )
}
