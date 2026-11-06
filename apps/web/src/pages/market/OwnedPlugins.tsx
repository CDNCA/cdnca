import { Button, Empty, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import type { MarketLibraryItem, MarketLicense } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { PlatformPluginsPanel } from '../plugin-market/PluginMarketPage'
import { pluginName, usePluginCatalog } from '../plugin-market/usePluginCatalog'
import { dependentsOf, localSwitchable, ownedRows, type OwnedRow, type OwnedState } from './marketModel'
import { useConfigPath, usePlatformInstallations } from './marketHooks'
import { FeatureSwitch, InstallationSwitch } from './PluginSwitch'

const stateColor: Record<OwnedState, string> = {
  enabled: 'success', installed: 'success', activating: 'processing', enable: 'warning', distributing: 'processing',
  pendingConfirm: 'gold', revoked: 'error', disabled: 'default', noVersion: 'default', awaitingSync: 'processing',
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
  const catalog = usePluginCatalog(token, [...licenses.map((l) => l.plugin_id), ...library.map((item) => item.plugin_id)])
  // 去配置只给本账号进得去的页面：插件页面已由服务端按角色/权限/功能码筛过，其余按菜单同一规则判断。
  const reachable = useConfigPath(modules)
  // 平台安装记录（有读权限才有）：区分已停用与待确认，并给停用/重新启用。
  const installations = usePlatformInstallations()
  const rows = ownedRows(licenses, library, [...modules], catalog, reachable, installations)
  const stopped = new Set(library.filter((item) => item.locally_disabled).map((item) => item.plugin_id))
  const name = (pluginID: string) => pluginName(catalog, pluginID, i18n.resolvedLanguage)
  // 停用 / 重新启用：功能类插件走本机停用名单，可安装类走它的平台安装记录。
  const toggleOf = (row: OwnedRow) => {
    const plugin = row.plugin
    if (plugin && localSwitchable(plugin) && (row.state === 'enabled' || row.state === 'disabled' && stopped.has(row.pluginID))) {
      const dependents = row.state === 'enabled' && plugin.feature_code
        ? dependentsOf(plugin.feature_code, [...catalog.values()], modules).map((p) => name(p.plugin_id)) : []
      return <FeatureSwitch plugin={plugin} name={name(row.pluginID)} stopped={row.state === 'disabled'} dependents={dependents} />
    }
    return row.installation && (row.state === 'installed' || row.state === 'enabled' || row.state === 'disabled')
      ? <InstallationSwitch installation={row.installation} name={name(row.pluginID)} /> : null
  }
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
            { title: t('owned.status'), key: 'status', width: 180, render: (_: unknown, row) => row.state === 'noVersion'
              ? <Tooltip title={t('owned.noVersionHint')}><Tag color={stateColor.noVersion}>{t('owned.states.noVersion')}</Tag></Tooltip>
              : <Tag color={stateColor[row.state]}>{t(`owned.states.${row.state}`)}</Tag> },
            { title: t('owned.actions'), key: 'actions', width: 220, render: (_: unknown, row) => {
              const toggle = toggleOf(row)
              if (row.path) return <Space size={4} wrap><Link to={row.path}><Button size="small">{t('owned.configure')}</Button></Link>{toggle}</Space>
              if (toggle) return toggle
              return <Typography.Text type="secondary">{row.state === 'revoked' || row.state === 'activating' || row.state === 'distributing' ||
                row.state === 'noVersion' || row.state === 'awaitingSync' ? '—'
                : row.state === 'pendingConfirm' ? (platformPlugins ? t('owned.confirmBelow') : t('owned.confirmByAdmin')) : t('owned.noPage')}</Typography.Text>
            } },
          ]} />
      </section>
      {platformPlugins ? <section aria-labelledby="platform-plugins-title">
        <Typography.Title level={5} id="platform-plugins-title">{t('owned.platformTitle')}</Typography.Title>
        <PlatformPluginsPanel />
      </section> : null}
    </Space>
  )
}
