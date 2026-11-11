import type { ReactNode } from 'react'
import { Alert, Tabs } from 'antd'
import { useTranslation } from 'react-i18next'

import type { PluginInstallation } from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import '../../i18n/pluginUI'
import { PluginFrame } from '../../pluginui/PluginFrame'
import { pluginPageTitle, usePluginUIPages } from '../../pluginui/usePluginUIPages'

/**
 * The plugin's own settings page (mount plugin_settings, admin only) as a 设置 tab of the installed plugin's detail,
 * in the same sandboxed frame and bridge as a menu page. Without such a page, or while the plugin is not enabled,
 * the detail stays as it is.
 */
export function PluginSettingsTabs({ installation, children }: { installation: PluginInstallation; children: ReactNode }) {
  const { t, i18n } = useTranslation('pluginInstallations')
  const { t: tUI } = useTranslation('pluginUI')
  const accessToken = useSessionStore((state) => state.accessToken)
  const pages = usePluginUIPages(accessToken)
  const page = installation.status === 'enabled'
    ? pages.find((candidate) => candidate.plugin_id === installation.plugin_id && candidate.mount === 'plugin_settings')
    : undefined
  if (!page) return <>{children}</>
  const title = pluginPageTitle(page, i18n.resolvedLanguage ?? 'zh-CN')
  return <Tabs destroyOnHidden items={[
    { key: 'overview', label: t('settingsTab.overview'), children },
    { key: 'settings', label: t('settingsTab.settings'), children: <>
      <Alert type="info" showIcon style={{ marginBottom: 12 }} message={tUI('pageHint', { plugin: page.plugin_id, origin: page.origin })} />
      <PluginFrame key={`${page.plugin_id}/${page.page_id}`} page={page} title={title} />
    </> },
  ]} />
}
