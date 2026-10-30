import { useCallback, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Badge, Button, Card, Col, Descriptions, Drawer, Empty, Input, List, Result, Row, Select, Space, Spin, Tabs, Tag, Typography } from 'antd'
import { ShieldOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import { marketApi, marketUnavailable, type MarketLibraryItem, type MarketLicense, type MarketPlugin } from '../../api/market'
import { marketAccess } from '../../api/marketAccess'
import { useSessionStore } from '../../auth/session'
import { useGrantedModules } from '../../components/useGrantedModules'
import '../../i18n/pluginStore'
import { AdvisoryList } from '../plugin-market/AdvisoryList'
import { LicensesTab } from '../plugin-market/PluginStorePage'
import { PlatformPluginsPanel } from '../plugin-market/PluginMarketPage'
import { activePlans, highRiskPermission } from '../plugin-market/pluginStoreModel'
import { useAdvisories } from '../plugin-market/useAdvisories'
import { enablePath, planPrice, publisherOf, storeState, type StoreState } from './marketModel'
import { PriceTag, PublisherBadge } from './PriceTag'
import { PurchaseModal } from './PurchaseModal'
import { MarketNotJoined } from './MarketNotJoined'
import { useMarketConnection } from './useMarketConnection'
import { CursorPager, LoadFailure, useCursorPages } from '../node-market/supplier/shared'
import './messages'

import '../plugin-market/PluginMarketPage.css'
import './MarketStorePage.css'
import '../node-market/NodeMarketV2.css'
import { useFeedback } from '@cdnca/ui'
import { SellerSiteGuide } from '../node-market/SellerSiteGuide'

const codeOf = (error: unknown) => (error instanceof ApiError ? error.code : 'request_failed')

function LoadError({ error }: { error: unknown }) {
  const { t } = useTranslation('marketStore')
  if (marketUnavailable(error)) return <Alert type="info" showIcon message={t('errors.unavailable')} />
  if (error instanceof ApiError && error.status === 502) return <Alert type="warning" showIcon message={t('errors.notJoined')} />
  return <LoadFailure error={error} title={t('errors.load', { code: codeOf(error) })} />
}

interface Holdings { licenses: MarketLicense[]; library: MarketLibraryItem[]; modules: readonly string[] }

function StateHint({ plugin, state }: { plugin: MarketPlugin; state: StoreState }) {
  const { t } = useTranslation('marketStore')
  if (state === 'revoked') return <Alert type="error" showIcon message={t('state.revoked')} description={t('state.revokedHint')} />
  if (state === 'activating') return <Alert type="info" showIcon message={t('state.activatingHint')} />
  if (state === 'distributing') {
    // Themes and rule packs are instance-wide: the controller administrator confirms them under 我的插件.
    if (plugin.kind === 'theme' || plugin.kind === 'rule_pack') {
      return <Alert type="info" showIcon message={t('state.platformConfirm')}
        description={<>{t('state.platformConfirmHint')} <Link to="/sys/plugin-store?tab=mine">{t('state.goMine')}</Link></>} />
    }
    return <Alert type="info" showIcon message={t('state.distributing')} description={t('state.distributingHint')} />
  }
  if (state !== 'enable') return null
  const path = enablePath(plugin)
  return path ? <Alert type="success" showIcon message={<>{t('state.enableHint')} <Link to={path}>{path}</Link></>} />
    : <Alert type="success" showIcon message={t('state.enableTenant')} />
}

// StoreAction is the one button of the 获取/购买 → 同步 → 启用 flow.
function StoreAction({ plugin, state, canBuy, onBuy, onDownload, downloading }: {
  plugin: MarketPlugin; state: StoreState; canBuy: boolean; onBuy: () => void; onDownload: () => void; downloading: boolean
}) {
  const { t } = useTranslation('marketStore')
  const free = activePlans(plugin.price_plans ?? []).some((p) => p.kind === 'free')
  switch (state) {
    case 'purchase':
      return free ? <Button type="primary" disabled={!canBuy} loading={downloading} onClick={onDownload}>{t('state.get')}</Button>
        : <Button type="primary" disabled={!canBuy || !activePlans(plugin.price_plans ?? []).length} onClick={onBuy}>{t('state.purchase')}</Button>
    case 'distributing':
      // Themes and rule packs wait for a person (the controller administrator), not for a sync.
      return plugin.kind === 'theme' || plugin.kind === 'rule_pack'
        ? <Link to="/sys/plugin-store?tab=mine"><Button size="small">{t('state.goMine')}</Button></Link>
        : <Tag color="processing">{t('state.distributing')}</Tag>
    case 'enable': {
      const path = enablePath(plugin)
      return path ? <Link to={path}><Button>{t('state.enable')}</Button></Link> : <Tag color="processing">{t('state.pendingConfirm')}</Tag>
    }
    case 'enabled': return <Tag color="success">{t('state.enabled')}</Tag>
    case 'activating': return <Tag color="processing">{t('state.activating')}</Tag>
    case 'revoked': return <Tag color="error">{t('state.revoked')}</Tag>
  }
}

function useHoldings(token: string): Holdings & { refresh: () => void } {
  const client = useQueryClient()
  const licenses = useQuery({ queryKey: ['pluginStore', 'licenses'], queryFn: () => marketApi.licenses(token), enabled: !!token, retry: false })
  const library = useQuery({ queryKey: ['marketStore', 'library'], queryFn: () => marketApi.library(token), enabled: !!token, retry: false })
  const modules = useGrantedModules(token)
  const refresh = useCallback(() => {
    void client.invalidateQueries({ queryKey: ['pluginStore', 'licenses'] })
    void client.invalidateQueries({ queryKey: ['marketStore', 'library'] })
    void client.invalidateQueries({ queryKey: ['entitlement', 'modules'] })
  }, [client])
  return { licenses: licenses.data?.items ?? [], library: library.data ?? [], modules, refresh }
}

function PluginDetail({ plugin, state, actions }: {
  plugin: MarketPlugin; state: StoreState; actions: ReactNode
}) {
  const { t, i18n } = useTranslation('marketStore')
  const token = useSessionStore((s) => s.accessToken) ?? ''
  const query = useQuery({ queryKey: ['marketStore', 'plugin', plugin.id], queryFn: () => marketApi.plugin(token, plugin.id), enabled: !!token })
  const detail = query.data
  const info = detail?.plugin ?? plugin
  const latest = detail?.versions[0]
  const plans = activePlans(detail?.price_plans ?? plugin.price_plans ?? [])
  const english = i18n.resolvedLanguage === 'en-US'
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {query.error ? <LoadError error={query.error} /> : null}
      <Space wrap><PublisherBadge plugin={info} /><PriceTag plugin={{ ...info, price_plans: plans }} />{actions}</Space>
      <StateHint plugin={info} state={state} />
      <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{info.description_md || info.summary || info.plugin_id}</Typography.Paragraph>
      <Descriptions bordered size="small" column={1}>
        <Descriptions.Item label={t('detail.publisher')}>{t(`publisher.${publisherOf(info)}`)} · {info.namespace}</Descriptions.Item>
        <Descriptions.Item label={t('detail.kind')}>{info.kind}</Descriptions.Item>
        <Descriptions.Item label={t('detail.version')}>{latest?.version ?? info.latest_version ?? '—'}</Descriptions.Item>
        {info.feature_code ? <Descriptions.Item label={t('detail.featureCode')}><code>{info.feature_code}</code></Descriptions.Item> : null}
        <Descriptions.Item label={t('detail.plans')}>{plans.length ? plans.map((p) => planPrice(t, p)).join(' / ') : t('price.none')}</Descriptions.Item>
      </Descriptions>
      <div>
        <Typography.Title level={5}>{t('detail.permissions')}</Typography.Title>
        {latest?.permissions.length ? <Space wrap>{latest.permissions.map((p) => highRiskPermission(info, p)
          ? <Tag key={p} color="red" title={t('detail.highRisk')}><code>{p}</code></Tag> : <Tag key={p}><code>{p}</code></Tag>)}</Space>
          : <Typography.Text type="secondary">{t('detail.noPermissions')}</Typography.Text>}
      </div>
      <div>
        <Typography.Title level={5}>{t('detail.menus')}</Typography.Title>
        {latest?.ui_page ? <Space direction="vertical" style={{ width: '100%' }}>
          <Alert type="info" showIcon message={t('detail.originNotice', { origin: latest.ui_page.origin })} />
          <Descriptions size="small" column={1}>
            <Descriptions.Item label={t('detail.origin')}><code>{latest.ui_page.origin}</code></Descriptions.Item>
          </Descriptions>
          <List size="small" bordered dataSource={latest.ui_page.pages} renderItem={(page) => <List.Item>
            {t('detail.menuItem', { title: (english && page.title['en-US']) || page.title['zh-CN'], mount: t(`detail.mount.${page.mount}`) })}
            {page.menu_parent ? <Typography.Text type="secondary"> · {page.menu_parent}</Typography.Text> : null}
          </List.Item>} />
        </Space> : <Typography.Text type="secondary">{t('detail.noMenus')}</Typography.Text>}
      </div>
      {detail?.versions.length ? <div>
        <Typography.Title level={5}>{t('detail.versions')}</Typography.Title>
        <List size="small" dataSource={detail.versions} renderItem={(v) => <List.Item>
          <Space size={6}><strong>{v.version}</strong>{v.channel === 'beta' ? <Tag color="orange">{t('detail.beta')}</Tag> : null}</Space>
        </List.Item>} />
      </div> : null}
    </Space>
  )
}

function BrowseTab({ pendingAdvisories }: { pendingAdvisories: Set<string> }) {
  const { t } = useTranslation('marketStore')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((s) => s.accessToken) ?? ''
  const canBuy = marketAccess(useSessionStore((s) => s.principal)).purchase
  const holdings = useHoldings(token)
  const [draft, setDraft] = useState<{ q?: string; price?: 'free' | 'paid' }>({})
  const [filters, setFilters] = useState(draft)
  const [selected, setSelected] = useState<MarketPlugin | null>(null)
  const [buying, setBuying] = useState<MarketPlugin | null>(null)
  // ?feature=<code>: opened from a module page's 去购买 (components/PurchaseModuleLink); show the entry that unlocks it.
  const [params, setParams] = useSearchParams()
  const feature = params.get('feature')?.trim() ?? ''
  // ?kind=theme&applies_to=user|site: opened from a theme slot's 去插件市场找主题 (ThemesPage).
  const kind = params.get('kind') === 'theme' ? 'theme' as const : undefined
  const appliesTo = kind && (params.get('applies_to') === 'user' || params.get('applies_to') === 'site') ? params.get('applies_to') as 'user' | 'site' : undefined
  // Server pages of 50 by next_cursor; a new filter starts on page 1 (reset during render, no stale cursor goes out).
  const pages = useCursorPages()
  const filterKey = JSON.stringify([filters, kind, appliesTo])
  const [pagedFilter, setPagedFilter] = useState(filterKey)
  if (pagedFilter !== filterKey) { setPagedFilter(filterKey); pages.reset() }
  const query = useQuery({ queryKey: ['marketStore', 'plugins', filters, kind, appliesTo, pages.cursor], enabled: !!token,
    queryFn: () => marketApi.plugins(token, { q: filters.q, price: filters.price, kind, appliesTo, cursor: pages.cursor }) })
  const download = useMutation({
    mutationFn: (plugin: MarketPlugin) => marketApi.download(token, plugin.plugin_id),
    // The market only grants (or replays) the licence; whether it reached this controller is the library's answer.
    onSuccess: () => { holdings.refresh(); void message.success(t('download.done')) },
    // 402 purchase_required: no live licence of this controller yet, go straight to paying for it.
    onError: (error, plugin) => {
      if (!(error instanceof ApiError && error.status === 402)) return void feedback.error(t('errors.failed', { code: codeOf(error) }))
      if (canBuy && activePlans(plugin.price_plans ?? []).length) setBuying(plugin)
      else void feedback.warning(t('download.required'))
    },
  })
  const items = (query.data?.items ?? []).filter((plugin) => !feature || plugin.feature_code === feature)
  const stateOf = (plugin: MarketPlugin) => storeState(plugin, holdings.licenses, holdings.library, [...holdings.modules])
  const action = (plugin: MarketPlugin) => <StoreAction plugin={plugin} state={stateOf(plugin)} canBuy={canBuy} onBuy={() => setBuying(plugin)}
    onDownload={() => download.mutate(plugin)} downloading={download.isPending && download.variables?.id === plugin.id} />
  const bought = useCallback(() => {
    const plugin = buying
    setBuying(null)
    holdings.refresh()
    // Paid: take the licence for this controller right away; the card then shows 正在同步 until it is installed here.
    if (plugin) download.mutate(plugin)
  }, [buying, holdings, download])
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <div className="plugin-market-toolbar">
        <Input value={draft.q ?? ''} maxLength={64} placeholder={t('filters.search')} aria-label={t('filters.search')}
          onChange={(e) => setDraft({ ...draft, q: e.target.value })} onPressEnter={() => setFilters({ ...draft, q: draft.q?.trim() || undefined })} />
        <Select<'free' | 'paid'> allowClear style={{ minWidth: 120 }} placeholder={t('filters.anyPrice')} aria-label={t('filters.price')}
          value={draft.price} onChange={(price) => setDraft({ ...draft, price })}
          options={[{ value: 'free', label: t('price.free') }, { value: 'paid', label: t('price.paid') }]} />
        <Button type="primary" onClick={() => setFilters({ ...draft, q: draft.q?.trim() || undefined })}>{t('filters.apply')}</Button>
      </div>
      {feature && query.data ? <Alert type={items.length ? 'info' : 'warning'} showIcon
        message={t(items.length ? 'guide.feature' : 'guide.notFound', { code: feature })}
        action={<Button size="small" onClick={() => setParams({})}>{t('guide.showAll')}</Button>} /> : null}
      {query.error ? <LoadError error={query.error} /> : null}
      {query.isLoading ? <Spin /> : null}
      {!query.isLoading && !items.length ? <Empty /> : null}
      <Row gutter={[16, 16]}>
        {items.map((plugin) => {
          const state = stateOf(plugin)
          return <Col key={plugin.id} xs={24} sm={12} lg={8}>
            <Badge dot={pendingAdvisories.has(plugin.plugin_id)} offset={[-6, 6]} className="market-store-badge">
              <Card size="small" className={`market-store-card market-store-card--${state}`} data-testid={`market-card-${plugin.plugin_id}`}
                title={<Button type="link" className="market-store-title" onClick={() => setSelected(plugin)}>{plugin.title}</Button>}
                extra={<PublisherBadge plugin={plugin} />}
                actions={[<div key="action" className="market-store-action">{action(plugin)}</div>]}>
                <Typography.Paragraph type="secondary" ellipsis={{ rows: 2 }}>{plugin.summary || plugin.plugin_id}</Typography.Paragraph>
                <Space size={4} wrap>
                  <PriceTag plugin={plugin} />
                  {plugin.latest_version ? <Tag>{t('card.latest', { version: plugin.latest_version })}</Tag> : null}
                </Space>
                {state === 'revoked' ? <Typography.Paragraph type="danger" className="market-store-revoked">{t('state.revokedHint')}</Typography.Paragraph> : null}
              </Card>
            </Badge>
          </Col>
        })}
      </Row>
      {query.data && (pages.page > 1 || query.data.next_cursor)
        ? <CursorPager pages={pages} pageSize={50} count={query.data.items.length} next={query.data.next_cursor} busy={query.isFetching} /> : null}
      <Drawer className="plugin-market-drawer" width="min(760px, 100vw)" open={!!selected} onClose={() => setSelected(null)}
        title={selected ? `${selected.title} · ${selected.plugin_id}` : ''} destroyOnHidden>
        {selected ? <PluginDetail plugin={selected} state={stateOf(selected)} actions={action(selected)} /> : null}
      </Drawer>
      {buying ? <PurchaseModal plugin={buying} plans={buying.price_plans ?? []} token={token} onClose={() => setBuying(null)} onDone={bought} /> : null}
    </Space>
  )
}

export default function MarketStorePage() {
  const { t } = useTranslation('marketStore')
  const { t: storeT } = useTranslation('pluginStore')
  const token = useSessionStore((s) => s.accessToken) ?? ''
  const principal = useSessionStore((s) => s.principal)
  const access = marketAccess(principal)
  const [searchParams, setSearchParams] = useSearchParams()
  const { connected, recheck, rechecking } = useMarketConnection(access.browse ? token : '')
  const advisories = useAdvisories(token, access.browse && connected === true)
  if (!access.browse) return <Result status="error" icon={<ShieldOff size={72} aria-hidden="true" />} title={t('errors.forbidden')} />
  const pendingCount = advisories.items.filter((a) => !a.acknowledgement).length
  // 我的插件：本主控的平台插件（主题、规则包）待确认/已安装/失败，只给持平台插件安装权限的主控管理员。
  const platformPlugins = principal?.scope_kind === 'platform' &&
    Boolean(principal.permissions.includes('plugin_installations.platform.read'))
  const requestedTab = searchParams.get('tab')
  return (
    <div className="plugin-market-page market-store-v2">
      <div className="market-store-v2-head">
        <Typography.Title level={4}>{storeT('title')}</Typography.Title>
        <Typography.Text type="secondary">{t('subtitle')}</Typography.Text>
      </div>
      {connected === undefined ? <Spin /> : !connected ? <MarketNotJoined recheck={recheck} rechecking={rechecking} /> : <div className="market-store-v2-panel"><SellerSiteGuide scope="plugin" /><Tabs destroyOnHidden
        activeKey={requestedTab === 'mine' && platformPlugins ? 'mine' : requestedTab === 'licenses' || requestedTab === 'advisories' ? requestedTab : 'browse'}
        onChange={(key) => setSearchParams((current) => { const next = new URLSearchParams(current); next.set('tab', key); return next })} items={[
        { key: 'browse', label: t('tabs.browse'), children: <BrowseTab pendingAdvisories={advisories.pending} /> },
        ...(platformPlugins ? [{ key: 'mine', label: t('tabs.mine'), children: <PlatformPluginsPanel /> }] : []),
        { key: 'licenses', label: t('tabs.licenses'), children: <LicensesTab /> },
        { key: 'advisories', label: <Space size={6}>{t('tabs.advisories')}{pendingCount ? <Tag color="error" style={{ marginInlineEnd: 0 }}>{storeT('advisories.banner', { count: pendingCount })}</Tag> : null}</Space>,
          children: advisories.query.error ? <LoadError error={advisories.query.error} />
            : <AdvisoryList items={advisories.items} loading={advisories.query.isLoading} canAcknowledge={access.purchase} /> },
      ]} /></div>}
    </div>
  )
}
