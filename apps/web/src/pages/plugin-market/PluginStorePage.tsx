import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Badge, Button, Card, Checkbox, Descriptions, Drawer, Empty, Image, Input, List, Modal, Result, Select, Space, Table,
  Tabs, Tag, Typography,
} from 'antd'
import { ShieldOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  checkoutURL, marketApi, marketPluginKinds, marketUnavailable, newIdempotencyKey, type MarketLicense,
  type MarketOrder, type MarketPlugin, type MarketPluginKind, type MarketPricePlan, type PluginFilters,
} from '../../api/market'
import { marketAccess } from '../../api/marketAccess'
import { useSessionStore } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/pluginStore'
import { MarketAgreementFooter, useMarketAgreements } from '../market/MarketAgreements'
import { AdvisoryList } from './AdvisoryList'
import { activePlans, formatMinor, highRiskPermission, safeLink, saleRevision, terminalOrderStates } from './pluginStoreModel'
import { useAdvisories } from './useAdvisories'

import './PluginMarketPage.css'
import { useFeedback, FeedbackWhen } from '@cdnca/ui'
import { outcomeUnknown, useIdempotencyKey } from '../market/idempotency'


function useToken(): string {
  return useSessionStore((state) => state.accessToken) ?? ''
}

function codeOf(error: unknown): string {
  return error instanceof ApiError ? error.code : 'request_failed'
}

function useFail() {
  const { t } = useTranslation('pluginStore')
  const { message } = App.useApp()
  const feedback = useFeedback()
  return (error: unknown) => {
    if (marketUnavailable(error)) void message.info(t('errors.unavailable'))
    else void feedback.error(t('errors.failed', { code: codeOf(error) }))
  }
}

function LoadError({ error }: { error: unknown }) {
  const { t } = useTranslation('pluginStore')
  if (marketUnavailable(error)) return <Alert type="info" showIcon message={t('errors.unavailable')} />
  if (error instanceof ApiError && error.status === 502) return <Alert type="warning" showIcon message={t('errors.notJoined')} />
  return <FeedbackWhen title={t('errors.load', { code: codeOf(error) })} />
}

// OrderTracker polls an order after checkout until it settles (§5.3: 付款后出现安装候选).
function OrderTracker({ order, checkout, onDone }: { order: MarketOrder; checkout: string | null; onDone: () => void }) {
  const { t } = useTranslation('pluginStore')
  const token = useToken()
  const query = useQuery({
    queryKey: ['pluginStore', 'order', order.id], queryFn: () => marketApi.order(token, order.id), initialData: order,
    refetchInterval: (q) => (terminalOrderStates.has(q.state.data?.status ?? '') ? false : 5000),
  })
  const current = query.data ?? order
  const no = current.order_no
  const state = current.status === 'fulfilled' ? 'fulfilled' : current.status === 'paid' ? 'paid'
    : current.status === 'awaiting_payment' ? 'waiting' : 'expired'
  return <Alert closable onClose={onDone} showIcon type={state === 'fulfilled' ? 'success' : state === 'expired' ? 'warning' : 'info'}
    message={t(`order.${state}`, { no })}
    action={state === 'waiting' && checkout ? <Button size="small" href={checkout} target="_blank" rel="noopener noreferrer">{t('order.reopen')}</Button> : null} />
}

function PlanRow({ plugin, plan, canBuy, onOrdered }: {
  plugin: MarketPlugin; plan: MarketPricePlan; canBuy: boolean; onOrdered: (order: MarketOrder, checkout: string | null) => void
}) {
  const { t } = useTranslation('pluginStore')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const client = useQueryClient()
  const fail = useFail()
  const revision = saleRevision(plan) ?? plan.revision
  const priceChanged = (error: unknown) => {
    if (!(error instanceof ApiError && error.status === 409)) return false
    void feedback.warning(t('order.priceChanged'))
    void client.invalidateQueries({ queryKey: ['pluginStore', 'plugin', plugin.id] })
    return true
  }
  const order = useMutation({
    mutationFn: (trial: boolean) => marketApi.createOrder(token,
      { market: 'plugin', price_plan_id: plan.id, plan_revision: revision, ...(trial ? { trial: true } : {}) }, newIdempotencyKey('plugin-order')),
    onSuccess: (created) => {
      const url = checkoutURL(created.checkout_url)
      if (url) {
        window.open(url, '_blank', 'noopener,noreferrer')
        void message.success(t('order.opened'))
      } else if (created.checkout_url) {
        void feedback.error(t('order.blocked'))
      } else {
        void message.success(t('order.free'))
      }
      onOrdered(created.order, url)
    },
    onError: (error) => { if (!priceChanged(error)) fail(error) },
  })
  // Pay from the market prepaid balance (M2 plugin-purchases) instead of the portal.
  const prepaid = useMutation({
    mutationFn: () => marketApi.purchaseFromPrepaid(token, { price_plan_id: plan.id, plan_revision: revision }, newIdempotencyKey('plugin-prepaid')),
    onSuccess: () => {
      void message.success(t('order.prepaidDone'))
      void client.invalidateQueries({ queryKey: ['pluginStore', 'licenses'] })
    },
    onError: (error) => {
      if (priceChanged(error)) return
      if (error instanceof ApiError && error.status === 402) void feedback.error(t('order.insufficientBalance'))
      else if (error instanceof ApiError && error.code === 'already_licensed') void message.info(t('order.alreadyLicensed'))
      else fail(error)
    },
  })
  const price = plan.kind === 'free' ? t('plan.free') : formatMinor(plan.price_minor, plan.currency)
  return (
    <List.Item actions={canBuy ? [
      ...(plan.trial_days > 0 ? [<Button key="trial" loading={order.isPending} onClick={() => order.mutate(true)}>{t('plan.trial')}</Button>] : []),
      ...(plan.kind !== 'free' ? [<Button key="prepaid" loading={prepaid.isPending} onClick={() => prepaid.mutate()}>{t('plan.prepaid')}</Button>] : []),
      <Button key="buy" type="primary" loading={order.isPending} onClick={() => order.mutate(false)}>
        {plan.kind === 'free' ? t('plan.install') : t('plan.buy')}</Button>,
    ] : []}>
      <List.Item.Meta title={<Space size={6}>
        <span>{t(`plan.${plan.kind}`)}</span><strong>{price}</strong>
        {plan.kind === 'subscription' && plan.interval ? <span>{t(`plan.${plan.interval}`)}</span> : null}
      </Space>} description={plan.trial_days > 0 ? t('plan.trialDays', { days: plan.trial_days }) : null} />
    </List.Item>
  )
}

/** A plugin's package preview as a same-origin blob: URL (the route needs the session token); undefined without one. */
function usePluginPreview(token: string | null | undefined, row: string | undefined): string | undefined {
  const [url, setURL] = useState<string>()
  useEffect(() => {
    setURL(undefined)
    if (!token || !row) return
    let live = true
    let created: string | undefined
    void marketApi.pluginPreview(token, row).then((blob) => {
      if (!blob || !live) return
      created = URL.createObjectURL(blob)
      setURL(created)
    }).catch(() => undefined)
    return () => {
      live = false
      if (created) URL.revokeObjectURL(created)
    }
  }, [token, row])
  return url
}

function PluginDetail({ plugin, onClose }: { plugin: MarketPlugin | null; onClose: () => void }) {
  const { t, i18n } = useTranslation('pluginStore')
  const token = useToken()
  const canBuy = marketAccess(useSessionStore((state) => state.principal)).purchase
  const [tracked, setTracked] = useState<{ order: MarketOrder; checkout: string | null } | null>(null)
  const query = useQuery({ queryKey: ['pluginStore', 'plugin', plugin?.id], queryFn: () => marketApi.plugin(token, plugin!.id),
    enabled: !!token && !!plugin })
  const detail = query.data
  const info = detail?.plugin ?? plugin
  const latest = detail?.versions[0]
  const homepage = safeLink(info?.homepage)
  const support = safeLink(info?.support_url)
  // Only the package's own preview, relayed same-origin (…/plugins/{id}/preview, shown as a blob: URL);
  // the listing's screenshots are third-party URLs and are never rendered.
  const preview = usePluginPreview(token, info?.has_preview ? info.id : undefined)
  const plans = activePlans(detail?.price_plans ?? [])
  return (
    <Drawer className="plugin-market-drawer" width="min(760px, 100vw)" open={!!plugin} onClose={() => { setTracked(null); onClose() }}
      title={info ? `${info.title} · ${info.plugin_id}` : ''} destroyOnHidden>
      {query.error ? <LoadError error={query.error} /> : null}
      {tracked ? <OrderTracker order={tracked.order} checkout={tracked.checkout} onDone={() => setTracked(null)} /> : null}
      {info ? <Space direction="vertical" style={{ width: '100%' }} size="middle">
        {info.risk_class === 'privileged' ? <Alert type="warning" showIcon message={t('detail.privilegedHint')} /> : null}
        <Descriptions bordered size="small" column={1}>
          <Descriptions.Item label={t('detail.summary')}>
            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{info.description_md || info.summary || '—'}</Typography.Paragraph>
          </Descriptions.Item>
          <Descriptions.Item label={t('card.developer')}>{info.namespace}</Descriptions.Item>
          <Descriptions.Item label={t('filters.kind')}>{t(`kinds.${info.kind}`, { defaultValue: info.kind })}</Descriptions.Item>
          {homepage || support ? <Descriptions.Item label={t('detail.homepage')}><Space>
            {homepage ? <a href={homepage} target="_blank" rel="noopener noreferrer">{t('detail.homepage')}</a> : null}
            {support ? <a href={support} target="_blank" rel="noopener noreferrer">{t('detail.support')}</a> : null}
          </Space></Descriptions.Item> : null}
          {info.license_spdx ? <Descriptions.Item label={t('detail.license')}>{info.license_spdx}</Descriptions.Item> : null}
          {latest ? <Descriptions.Item label={t('detail.compat')}>
            {t('detail.controlAPI', { range: latest.compat?.control_api || t('detail.any') })} · {t('detail.edgeAgent', { range: latest.compat?.edge_agent || t('detail.any') })}
          </Descriptions.Item> : null}
        </Descriptions>
        {preview ? <Image src={preview} width={160} alt={t('detail.screenshots')} /> : null}
        {latest ? <div>
          <Typography.Title level={5}>{t('detail.permissions')}</Typography.Title>
          {latest.permissions_changed ? <Alert type="warning" showIcon style={{ marginBottom: 8 }} message={t('detail.permissionsChanged')} /> : null}
          <Space wrap>{latest.permissions.map((permission) => highRiskPermission(info, permission)
            ? <Tag key={permission} color="red" title={t('detail.highRisk')}><code>{permission}</code></Tag>
            : <Tag key={permission}><code>{permission}</code></Tag>)}</Space>
        </div> : null}
        <div>
          <Typography.Title level={5}>{t('detail.plans')}</Typography.Title>
          {plans.length ? <List bordered dataSource={plans} renderItem={(plan) =>
            <PlanRow plugin={info} plan={plan} canBuy={canBuy} onOrdered={(order, checkout) => setTracked({ order, checkout })} />} />
            : <Empty description={t('detail.noPlans')} />}
        </div>
        {detail?.versions.length ? <div>
          <Typography.Title level={5}>{t('detail.versions')}</Typography.Title>
          <List size="small" dataSource={detail.versions} renderItem={(version) => <List.Item>
            <List.Item.Meta title={<Space size={6}>
              <strong>{version.version}</strong>{version.channel === 'beta' ? <Tag color="orange">{t('detail.beta')}</Tag> : null}
              {version.permissions_changed ? <Tag color="warning">{t('detail.permissionsChanged')}</Tag> : null}
              {version.created_at ? <Typography.Text type="secondary">{formatDateTime(version.created_at, i18n.resolvedLanguage ?? 'zh-CN')}</Typography.Text> : null}
            </Space>} description={version.changelog_md ? <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}
              aria-label={t('detail.changelog')}>{version.changelog_md}</Typography.Paragraph> : null} />
          </List.Item>} />
        </div> : null}
      </Space> : null}
    </Drawer>
  )
}

function BrowseTab({ pendingAdvisories }: { pendingAdvisories: Set<string> }) {
  const { t } = useTranslation('pluginStore')
  const token = useToken()
  const [draft, setDraft] = useState<PluginFilters>({})
  const [filters, setFilters] = useState<PluginFilters>({})
  const [cursors, setCursors] = useState<string[]>([])
  const [selected, setSelected] = useState<MarketPlugin | null>(null)
  const cursor = cursors.at(-1)
  const query = useQuery({ queryKey: ['pluginStore', 'plugins', filters, cursor], enabled: !!token,
    queryFn: () => marketApi.plugins(token, { ...filters, cursor }) })
  const apply = () => { setFilters({ ...draft, q: draft.q?.trim() || undefined }); setCursors([]) }
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <div className="plugin-market-toolbar">
        <Input value={draft.q ?? ''} maxLength={64} placeholder={t('filters.search')} aria-label={t('filters.search')}
          onChange={(e) => setDraft({ ...draft, q: e.target.value })} onPressEnter={apply} />
        <Select<MarketPluginKind> allowClear style={{ minWidth: 150 }} placeholder={t('filters.anyKind')} aria-label={t('filters.kind')}
          value={draft.kind} onChange={(kind) => setDraft({ ...draft, kind })} options={marketPluginKinds.map((value) => ({ value, label: t(`kinds.${value}`) }))} />
        <Select<'free' | 'paid'> allowClear style={{ minWidth: 120 }} placeholder={t('filters.anyPrice')} aria-label={t('filters.price')}
          value={draft.price} onChange={(price) => setDraft({ ...draft, price })}
          options={[{ value: 'free', label: t('filters.free') }, { value: 'paid', label: t('filters.paid') }]} />
        <Select<'popular' | 'newest' | 'name'> allowClear style={{ minWidth: 120 }} placeholder={t('filters.sort')} aria-label={t('filters.sort')}
          value={draft.sort} onChange={(sort) => setDraft({ ...draft, sort })}
          options={(['popular', 'newest', 'name'] as const).map((value) => ({ value, label: t(`filters.${value}`) }))} />
        <Checkbox checked={!!draft.allVersions} onChange={(e) => setDraft({ ...draft, allVersions: e.target.checked })}>{t('filters.allVersions')}</Checkbox>
        <Button type="primary" onClick={apply}>{t('filters.apply')}</Button>
      </div>
      <Typography.Text type="secondary">{t('filters.compatHint')}</Typography.Text>
      {query.error ? <LoadError error={query.error} /> : null}
      <List<MarketPlugin> loading={query.isLoading} grid={{ gutter: 16, xs: 1, sm: 2, lg: 3 }} dataSource={query.data?.items ?? []}
        locale={{ emptyText: <Empty /> }} renderItem={(plugin) => (
          <List.Item>
            <Badge dot={pendingAdvisories.has(plugin.plugin_id)} offset={[-6, 6]}>
              <Card hoverable size="small" title={plugin.title} onClick={() => setSelected(plugin)}
                extra={<Tag>{t(`kinds.${plugin.kind}`, { defaultValue: plugin.kind })}</Tag>}>
                <Typography.Paragraph type="secondary" ellipsis={{ rows: 2 }}>{plugin.summary || plugin.plugin_id}</Typography.Paragraph>
                <Space size={4} wrap>
                  <Typography.Text>{t('card.developer')}：{plugin.namespace}</Typography.Text>
                  {plugin.latest_version ? <Tag>{t('card.latest', { version: plugin.latest_version })}</Tag> : null}
                  <Tag>{t('card.installs', { count: plugin.installs ?? 0 })}</Tag>
                  {plugin.risk_class === 'privileged' ? <Tag color="red">{t('card.privileged')}</Tag> : null}
                </Space>
              </Card>
            </Badge>
          </List.Item>
        )} />
      <Space>
        <Button disabled={!cursors.length} onClick={() => setCursors(cursors.slice(0, -1))}>‹</Button>
        <Button disabled={!query.data?.next_cursor || cursors.includes(query.data.next_cursor)}
          onClick={() => query.data?.next_cursor && setCursors([...cursors, query.data.next_cursor])}>{t('actions.more')}</Button>
      </Space>
      <PluginDetail plugin={selected} onClose={() => setSelected(null)} />
    </Space>
  )
}

const disputeReasons = ['not_as_described', 'not_working', 'duplicate_charge', 'other'] as const

export function LicensesTab() {
  const { t, i18n } = useTranslation('pluginStore')
  const { message, modal } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const client = useQueryClient()
  const fail = useFail()
  const canAct = marketAccess(useSessionStore((state) => state.principal)).purchase
  const query = useQuery({ queryKey: ['pluginStore', 'licenses'], queryFn: () => marketApi.licenses(token), enabled: !!token })
  const [tracked, setTracked] = useState<{ order: MarketOrder; checkout: string | null } | null>(null)
  const [disputing, setDisputing] = useState<MarketLicense | null>(null)
  const [reason, setReason] = useState<(typeof disputeReasons)[number]>('not_working')
  const [note, setNote] = useState('')
  const refresh = () => void client.invalidateQueries({ queryKey: ['pluginStore', 'licenses'] })
  const cancel = useMutation({ mutationFn: (l: MarketLicense) => marketApi.cancelLicense(token, l.id, newIdempotencyKey('license-cancel')),
    onSuccess: () => { void message.success(t('licenses.cancelled')); refresh() }, onError: fail })
  const resume = useMutation({ mutationFn: (l: MarketLicense) => marketApi.resumeLicense(token, l.id, newIdempotencyKey('license-resume')),
    onSuccess: () => { void message.success(t('licenses.resumed')); refresh() }, onError: fail })
  // PL-RENEWAL-01: a past-due or expired subscription renews on
  // the same licence from the prepaid balance. One key per licence until it is
  // answered (market-buy-idem): clicking again after a lost answer replays it.
  const renewKey = useIdempotencyKey('license-renew')
  const convertKey = useIdempotencyKey('license-convert')
  // The answer must show the licence active with a later period end.
  const renew = useMutation({
    mutationFn: (l: MarketLicense) => marketApi.renewLicense(token, l.id, renewKey.keyFor({ id: l.id })),
    onSuccess: (renewed, l) => {
      renewKey.complete()
      const before = l.current_period_end ? Date.parse(l.current_period_end) : 0
      const after = renewed.current_period_end ? Date.parse(renewed.current_period_end) : 0
      if (renewed.id === l.id && renewed.status === 'active' && after > before) {
        void message.success(t('licenses.renewed', { end: formatDateTime(renewed.current_period_end!, i18n.resolvedLanguage ?? 'zh-CN') }))
      } else void feedback.warning(t('licenses.renewUnconfirmed'))
      refresh()
    },
    onError: (error) => {
      if (outcomeUnknown(error)) return void feedback.warning(t('licenses.resultUnknown'))
      renewKey.complete()
      if (error instanceof ApiError && error.status === 402) void feedback.error(t('order.insufficientBalance'))
      else if (error instanceof ApiError && error.code === 'not_on_sale') void feedback.warning(t('licenses.renewNotOnSale'))
      else fail(error)
    },
  })
  // A trial converts by buying the plan (试用转正保留下单).
  const convert = useMutation({
    mutationFn: (l: MarketLicense) => marketApi.createOrder(token, { market: 'plugin', price_plan_id: l.plan_id!, plan_revision: l.plan_revision! },
      convertKey.keyFor({ id: l.id, plan: l.plan_id, revision: l.plan_revision })),
    onSuccess: (created) => {
      convertKey.complete()
      const url = checkoutURL(created.checkout_url)
      if (url) window.open(url, '_blank', 'noopener,noreferrer')
      else if (created.checkout_url) void feedback.error(t('order.blocked'))
      setTracked({ order: created.order, checkout: url })
    },
    onError: (error) => {
      if (outcomeUnknown(error)) return void feedback.warning(t('licenses.resultUnknown'))
      convertKey.complete()
      if (error instanceof ApiError && error.status === 409) void feedback.warning(t('order.priceChanged'))
      else fail(error)
    },
  })
  // Only licences bought through an order are disputable. One paid from the
  // prepaid balance has none (PL-PREPAID-DISPUTE-01): the button says so up
  // front; the market also answers 409 license_not_disputable for it.
  const dispute = useMutation({
    mutationFn: (l: MarketLicense) => marketApi.openDispute(token, {
      subject_kind: 'plugin_order', order_id: l.order_id!, reason_code: reason, note: note.trim(),
    }, newIdempotencyKey('dispute-open')),
    onSuccess: () => { setDisputing(null); setNote(''); void message.success(t('licenses.disputeOpened')) },
    onError: (error) => {
      if (error instanceof ApiError && (error.status === 503 || error.code === 'license_not_disputable')) {
        setDisputing(null)
        void feedback.warning(t('licenses.disputeNotLinked'))
      }
      else if (error instanceof ApiError && error.status === 409) void feedback.warning(t('licenses.disputeOpen'))
      else fail(error)
    },
  })
  if (query.error) return <LoadError error={query.error} />
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      {tracked ? <OrderTracker order={tracked.order} checkout={tracked.checkout} onDone={() => setTracked(null)} /> : null}
      <Table<MarketLicense> rowKey="id" size="small" loading={query.isLoading} dataSource={query.data?.items ?? []} pagination={{ pageSize: 20 }}
        locale={{ emptyText: t('licenses.empty') }} scroll={{ x: 960 }}
        columns={[
          { title: t('licenses.plugin'), dataIndex: 'plugin_id' },
          { title: t('licenses.kind'), dataIndex: 'kind', render: (v: string, l) => <Space direction="vertical" size={0}>
            <span>{t(`licenses.kinds.${v}`, { defaultValue: v })}</span>
            {l.claim_pricing ? <Typography.Text type="secondary" data-claim={l.claim_pricing}>{t(`licenses.claims.${l.claim_pricing}`)}</Typography.Text> : null}
            {l.promo_first_charge_at && l.current_period_end === l.promo_first_charge_at
              ? <Typography.Text type="warning">{t('licenses.promoCharge', { at: formatDateTime(l.promo_first_charge_at, i18n.resolvedLanguage ?? 'zh-CN') })}</Typography.Text> : null}
          </Space> },
          { title: t('licenses.status'), dataIndex: 'status', render: (v: string) =>
            <Tag color={v === 'active' || v === 'trialing' ? 'green' : v === 'past_due' ? 'orange' : 'default'}>{t(`licenses.states.${v}`, { defaultValue: v })}</Tag> },
          { title: t('licenses.periodEnd'), key: 'end', render: (_: unknown, l) => <Space direction="vertical" size={0}>
            {l.status === 'trialing' && l.trial_ends_at
              ? <span>{t('licenses.trialUntil', { end: formatDateTime(l.trial_ends_at, i18n.resolvedLanguage ?? 'zh-CN') })}</span>
              : <span>{l.current_period_end ? formatDateTime(l.current_period_end, i18n.resolvedLanguage ?? 'zh-CN') : '—'}</span>}
            {l.status === 'trialing' && l.cancel_at_period_end ? <Typography.Text type="secondary">{t('licenses.trialCancelled')}</Typography.Text> : null}
            {l.fallback_version ? <Typography.Text type="secondary">{t('licenses.fallback', { version: l.fallback_version })}</Typography.Text> : null}
          </Space> },
          { title: t('licenses.autoRenew'), key: 'renew', render: (_: unknown, l) => l.kind === 'subscription'
            ? (l.cancel_at_period_end ? t('licenses.off') : t('licenses.on')) : '—' },
          { key: 'actions', fixed: 'right', render: (_: unknown, l) => canAct ? <Space size={4} wrap>
            {l.status === 'trialing' && !l.cancel_at_period_end ?
              <Button size="small" danger loading={cancel.isPending}
                onClick={() => modal.confirm({ title: t('licenses.trialCancelConfirm'), onOk: () => cancel.mutateAsync(l) })}>{t('licenses.trialCancel')}</Button> : null}
            {l.status === 'trialing' && l.cancel_at_period_end ?
              <Button size="small" loading={resume.isPending} onClick={() => resume.mutate(l)}>{t('licenses.trialResume')}</Button> : null}
            {l.kind === 'subscription' && !l.cancel_at_period_end && (l.status === 'active' || l.status === 'past_due') ?
              <Button size="small" danger loading={cancel.isPending}
                onClick={() => modal.confirm({ title: t('licenses.cancelConfirm'), onOk: () => cancel.mutateAsync(l) })}>{t('licenses.cancel')}</Button> : null}
            {l.kind === 'subscription' && l.cancel_at_period_end && l.status === 'active' ?
              <Button size="small" loading={resume.isPending} onClick={() => resume.mutate(l)}>{t('licenses.resume')}</Button> : null}
            {l.kind === 'subscription' && (l.status === 'past_due' || l.status === 'expired') ?
              <Button size="small" type="primary" loading={renew.isPending}
                onClick={() => modal.confirm({ title: t('licenses.renewConfirm'), onOk: () => renew.mutateAsync(l) })}>{t('licenses.renew')}</Button> : null}
            {l.status === 'trialing' && l.plan_id && l.plan_revision ?
              <Button size="small" type="primary" loading={convert.isPending} onClick={() => convert.mutate(l)}>{t('licenses.convert')}</Button> : null}
            {l.kind !== 'free' && l.status !== 'trialing' ? <Button size="small" onClick={() => l.order_id ? setDisputing(l)
              : void feedback.warning(t('licenses.disputeNotLinked'))}>{t('licenses.dispute')}</Button> : null}
          </Space> : null },
        ]} />
      <Modal open={!!disputing} title={t('licenses.disputeTitle')} onCancel={() => setDisputing(null)} confirmLoading={dispute.isPending}
        okText={t('actions.confirm')} cancelText={t('actions.cancel')} okButtonProps={{ disabled: !note.trim() }}
        onOk={() => disputing && dispute.mutate(disputing)}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Select value={reason} onChange={setReason} aria-label={t('licenses.disputeReason')} style={{ width: '100%' }}
            options={disputeReasons.map((value) => ({ value, label: t(`licenses.reasons.${value}`) }))} />
          <Input.TextArea rows={4} maxLength={4000} aria-label={t('licenses.disputeNote')} placeholder={t('licenses.disputeNote')}
            value={note} onChange={(e) => setNote(e.target.value)} />
        </Space>
      </Modal>
    </Space>
  )
}

export default function PluginStorePage() {
  const { t } = useTranslation('pluginStore')
  const token = useToken()
  const access = marketAccess(useSessionStore((state) => state.principal))
  const advisories = useAdvisories(token, access.browse)
  const agreements = useMarketAgreements(access.browse ? token : '')
  if (!access.browse) {
    return <Result status="error" icon={<ShieldOff size={72} aria-hidden="true" />} title={t('errors.forbidden')} />
  }
  const pendingCount = advisories.items.filter((a) => !a.acknowledgement).length
  return (
    <div className="plugin-market-page">
      <h1>{t('title')}</h1>
      <p className="plugin-market-subtitle">{t('subtitle')}</p>
      <Tabs destroyOnHidden items={[
        { key: 'browse', label: t('tabs.browse'), children: <BrowseTab pendingAdvisories={advisories.pending} /> },
        { key: 'licenses', label: t('tabs.licenses'), children: <LicensesTab /> },
        { key: 'advisories', label: <Space size={6}>{t('tabs.advisories')}{pendingCount ? <Tag color="error" style={{ marginInlineEnd: 0 }}>{t('advisories.banner', { count: pendingCount })}</Tag> : null}</Space>,
          children: advisories.query.error ? <LoadError error={advisories.query.error} />
            : <AdvisoryList items={advisories.items} loading={advisories.query.isLoading} canAcknowledge={access.purchase} /> },
      ]} />
      <MarketAgreementFooter agreements={agreements} />
    </div>
  )
}
