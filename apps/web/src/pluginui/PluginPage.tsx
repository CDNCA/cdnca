import { Alert, Typography } from 'antd'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import '../i18n/pluginUI'
import { useSessionStore } from '../auth/session'
import { RouteStatusPage } from '../components/RouteErrorBoundary'
import { PluginFrame } from './PluginFrame'
import { pluginPageTitle, usePluginUIPages } from './usePluginUIPages'

// /plugin-ui/:pluginId/:pageId — a menu-mounted ui_page plugin page.
export default function PluginPage() {
  const { pluginId, pageId } = useParams()
  const accessToken = useSessionStore((state) => state.accessToken)
  const pages = usePluginUIPages(accessToken, { cachedOnly: true })
  const { t, i18n } = useTranslation('pluginUI')
  const page = pages.find((candidate) => candidate.mount === 'menu' && candidate.plugin_id === pluginId &&
    candidate.page_id === pageId)
  if (!page) return pages.length === 0 ? null : <RouteStatusPage status="404" />
  const title = pluginPageTitle(page, i18n.resolvedLanguage ?? 'zh-CN')
  return (
    <section className="plugin-ui-page">
      <Typography.Title level={4}>{title}</Typography.Title>
      <Alert type="info" showIcon style={{ marginBottom: 12 }}
        message={t('pageHint', { plugin: page.plugin_id, origin: page.origin })} />
      <PluginFrame key={`${page.plugin_id}/${page.page_id}`} page={page} title={title} />
    </section>
  )
}
