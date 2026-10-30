import { Alert, Empty, Tabs } from 'antd'
import { useTranslation } from 'react-i18next'

import '../i18n/pluginUI'
import type { PluginUIPage } from '../api/pluginUI'
import { PluginFrame } from './PluginFrame'
import { pluginPageTitle } from './usePluginUIPages'

// The site detail "扩展" tab (PA-19): the site_tab pages of enabled ui_page
// plugins, each in its own sandboxed frame with this site's ID in context.
export function SitePluginTab({ siteId, pages }: { siteId: string; pages: readonly PluginUIPage[] }) {
  const { t, i18n } = useTranslation('pluginUI')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  if (pages.length === 0) return <Empty />
  return (
    <section className="site-plugin-tab">
      <Alert type="info" showIcon style={{ marginBottom: 12 }} message={t('tabHint')} />
      <Tabs
        destroyInactiveTabPane
        items={pages.map((page) => {
          const title = pluginPageTitle(page, locale)
          return {
            key: `${page.plugin_id}/${page.page_id}`,
            label: title,
            children: <PluginFrame key={`${page.plugin_id}/${page.page_id}/${siteId}`} page={page} siteID={siteId} title={title} />,
          }
        })}
      />
    </section>
  )
}
