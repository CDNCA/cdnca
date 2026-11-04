import type { ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Space, Tag, Tooltip, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, newIdempotencyKey, type MarketOfferListing } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import { gates, type Gate } from './offerLifecycleModel'
import { useFeedback } from '@cdnca/ui'
import { marketReason } from '@cdnca/ui/market-reasons'

// 我的上架 per row — status 已上架 / 下架中（预计 X 完成，N 个买方）/ 已下架（无买方），
// and 修改报价 / 下架 / 删除 enabled by state, a disabled one saying why. The market's lifecycle
// (offers.go OfferLifecycle) drives it; an older market without it keeps the plain status and no delete.

export function LifecycleTag({ offer, fallback }: { offer: MarketOfferListing; fallback: ReactNode }) {
  const { t } = useTranslation('nodeMarket')
  const l = offer.lifecycle
  if (!l || !['listed', 'delisting', 'delisted'].includes(l.state)) return <>{fallback}</>
  const color = l.state === 'listed' ? 'success' : l.state === 'delisting' ? 'warning' : 'default'
  return (
    <Space direction="vertical" size={0}>
      <Tag color={color}>{t(`life.states.${l.state}`)}</Tag>
      {l.state === 'delisting' ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t('life.delistingDetail', { at: l.completes_at ? formatDateTime(l.completes_at) : '—', count: l.active_subscriptions })}</Typography.Text> : null}
      {l.state !== 'listed' && l.renewing_subscriptions > 0 ? <Typography.Text type="warning" style={{ fontSize: 12 }}>
        {t('life.renewingDetail', { count: l.renewing_subscriptions })}</Typography.Text> : null}
      {l.operator_delisted ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t('life.operatorDelisted')}</Typography.Text> : null}
    </Space>
  )
}

// delistContent is the confirm text: with buyers in period (and when it completes), none, or a delisted
// offer whose old subscriptions still renew.
export function DelistContent({ offer }: { offer: MarketOfferListing }) {
  const { t } = useTranslation('nodeMarket')
  const l = offer.lifecycle
  const active = l?.active_subscriptions ?? 0
  const at = l?.completes_at ? formatDateTime(l.completes_at) : '—'
  if (offer.status === 'delisted' && l && l.renewing_subscriptions > 0) {
    return <Space direction="vertical"><Alert type="warning" showIcon message={t('life.delistRenewing', { count: l.renewing_subscriptions })} />
      <Typography.Text strong>{t('life.delistEta', { at })}</Typography.Text></Space>
  }
  if (!l) return <Alert type="warning" showIcon message={t('bulk.delistConfirm')} />
  if (active === 0) return <Alert type="info" showIcon message={t('life.delistNoBuyers')} />
  return <Space direction="vertical"><Alert type="warning" showIcon message={t('life.delistWithBuyers', { count: active })} />
    <Typography.Text strong>{t('life.delistEta', { at })}</Typography.Text></Space>
}

export function OfferLifecycleActions({ offer, onEdit }: { offer: MarketOfferListing; onEdit: () => void }) {
  const { t, i18n } = useTranslation('nodeMarket')
  const { message, modal } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const fail = (error: unknown) => {
    const code = error instanceof ApiError ? error.code : 'request_failed'
    const r = marketReason(code, i18n.language)
    void feedback.error(i18n.exists(`nodeMarket:life.errors.${code}`) ? t(`life.errors.${code}`)
      : r.known ? t('supplies.failedWith', { reason: r.reason, next: r.next }) : t('errors.failed', { code }))
  }
  const refresh = () => void client.invalidateQueries({ queryKey: ['nodeMarket'] })
  const delist = useMutation({
    mutationFn: () => marketApi.delistOffer(token, offer.id, newIdempotencyKey('offer-delist')),
    onSuccess: (next) => {
      void message.success((next.lifecycle?.active_subscriptions ?? 0) > 0 ? t('life.delistedWithBuyers') : t('life.delisted'))
      refresh()
    },
    onError: fail,
  })
  const remove = useMutation({
    mutationFn: () => marketApi.deleteOffer(token, offer.id, newIdempotencyKey('offer-delete')),
    onSuccess: () => { void message.success(t('life.deleted')); refresh() },
    onError: fail,
  })
  const g = gates(offer, t)
  const confirmDelist = () => modal.confirm({
    title: t('life.delistTitle', { name: offer.name }), content: <DelistContent offer={offer} />, width: 520,
    okText: t('life.delistOk'), okButtonProps: { danger: true }, onOk: () => delist.mutateAsync().catch(() => undefined),
  })
  const confirmDelete = () => modal.confirm({
    title: t('life.deleteTitle', { name: offer.name }), content: t('life.deleteConfirm'),
    okText: t('life.deleteOk'), okButtonProps: { danger: true }, onOk: () => remove.mutateAsync().catch(() => undefined),
  })
  // A disabled button does not fire hover events: the tooltip sits on a wrapper.
  const gated = (gate: Gate, button: ReactNode) => gate.ok ? button : <Tooltip title={gate.why}><span>{button}</span></Tooltip>
  return (
    <>
      <Button size="small" onClick={onEdit}>{t('life.edit')}</Button>
      {gated(g.delist, <Button size="small" danger disabled={!g.delist.ok} loading={delist.isPending} onClick={confirmDelist}>{t('life.delist')}</Button>)}
      {gated(g.delete, <Button size="small" danger type="text" disabled={!g.delete.ok} loading={remove.isPending} onClick={confirmDelete}>{t('life.delete')}</Button>)}
    </>
  )
}
