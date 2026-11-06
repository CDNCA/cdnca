import { Button, Empty, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import type { MarketLibraryItem, MarketLicense } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { usePluginUIPages } from '../../pluginui/usePluginUIPages'
import { isImplementedPath } from '../../routes/navigation'
import { PlatformPluginsPanel } from '../plugin-market/PluginMarketPage'
import { pluginName, usePluginCatalog } from '../plugin-market/usePluginCatalog'
import { configPath, ownedRows, type OwnedRow, type OwnedState } from './marketModel'

const stateColor: Record<OwnedState, string> = {
  enabled: 'success', installed: 'success', activating: 'processing', enable: 'warning', distributing: 'processing',
  pendingConfirm: 'gold', revoked: 'error',
}

/**
 * 我的插件：本主控已拥有的全部插件（官方功能模块、规则包、主题、页面插件…），名称取市场目录，状态与浏览页一致，
 * 可用的给“去配置”入口；主控管理员另在下方确认主题、规则包、页面插件和外部服务的安装（PlatformPluginsPanel，租户插件同时选租户）。
 */
export function OwnedPlugins({ licenses, library, modules, loading, platformPlugins }: {
  licenses: MarketLicense[]; library: MarketLibraryItem[]; modules: readonly string[]; loading: boolean; platformPlugins: boolean
}) {
  const { t, i18n } = useTranslation('marketStore')
  const { t: storeT } = useTranslation('pluginStore')
  const token = useSessionStore((s) => s.accessToken)
  const permissions = useSessionStore((s) => s.principal?.permissions)
  const catalog = usePluginCatalog(token, [...licenses.map((l) => l.plugin_id), ...library.map((item) => item.plugin_id)])
  const uiPages = usePluginUIPages(token)
  // 去配置只给本账号进得去的页面：插件页面已由服务端按角色/权限/功能码筛过，其余按菜单同一规则判断。
  const reachable = (path: string | null) => path && (path.startsWith('/plugin-ui/')
    || isImplementedPath('admin', path.split('?')[0], permissions, modules)) ? path : null
  const rows = ownedRows(licenses, library, [...modules], catalog, (plugin) => reachable(configPath(plugin, uiPages)))
  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <section aria-labelledby="owned-plugins-title">
        <Typography.Title level={5} id="owned-plugins-title">{t('owned.title')}</Typography.Title>
        <Typography.Paragraph type="secondary">{t('owned.hint')}</Typography.Paragraph>
        <Table<OwnedRow> rowKey="pluginID" size="small" loading={loading} dataSource={rows} pagination={false} scroll={{ x: 720 }}
          locale={{ emptyText: <Empty description={<><strong>{t('owned.emptyTitle')}</strong><div>{t('owned.emptyDescription')}</div></>} /> }}
          columns={[
            { title: t('owned.name'), key: 'name', render: (_: unknown, row) => <Space direction="vertical" size={0}>
              <strong>{pluginName(catalog, row.pluginID, i18n.resolvedLanguage)}</strong>
              {row.plugin ? <Typography.Text type="secondary" className="plugin-market-id">{row.pluginID}</Typography.Text> : null}
            </Space> },
            { title: t('owned.kind'), key: 'kind', width: 140, render: (_: unknown, row) => row.plugin
              ? storeT(`kinds.${row.plugin.kind}`, { defaultValue: row.plugin.kind }) : '—' },
            { title: t('owned.status'), key: 'status', width: 180, render: (_: unknown, row) =>
              <Tag color={stateColor[row.state]}>{t(`owned.states.${row.state}`)}</Tag> },
            { title: t('owned.actions'), key: 'actions', width: 160, render: (_: unknown, row) => row.path
              ? <Link to={row.path}><Button size="small">{t('owned.configure')}</Button></Link>
              : <Typography.Text type="secondary">{row.state === 'revoked' || row.state === 'activating' || row.state === 'distributing' ? '—'
                : row.state === 'pendingConfirm' ? (platformPlugins ? t('owned.confirmBelow') : t('owned.confirmByAdmin')) : t('owned.noPage')}</Typography.Text> },
          ]} />
      </section>
      {platformPlugins ? <section aria-labelledby="platform-plugins-title">
        <Typography.Title level={5} id="platform-plugins-title">{t('owned.platformTitle')}</Typography.Title>
        <PlatformPluginsPanel />
      </section> : null}
    </Space>
  )
}
