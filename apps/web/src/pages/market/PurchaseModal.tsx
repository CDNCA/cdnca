import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Modal, QRCode, Radio, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { checkoutURL, marketApi, type MarketOrder, type MarketPlugin, type MarketPricePlan } from '../../api/market'
import { activePlans, saleRevision, terminalOrderStates } from '../plugin-market/pluginStoreModel'
import { planPrice } from './marketModel'
import './messages'
import { useFeedback } from '@cdnca/ui'
import { outcomeUnknown, useIdempotencyKey } from './idempotency'

type Method = 'balance' | 'qr'

// The market's other 409 reasons for a purchase or order (plugin_seller.go conflictReason, pluginIdempotent).
const conflictMessages: Record<string, string> = {
  trial_used: 'pay.trialUsed', not_on_sale: 'pay.notOnSale', not_renewable: 'pay.notRenewable',
  idempotency_conflict: 'pay.keyConflict',
}
// 409 request_in_progress: the first attempt with this key is still running, so the key is kept and
// "check result" replays it (it may still charge).
const inProgress = (error: unknown) => error instanceof ApiError && error.status === 409 && error.code === 'request_in_progress'

// PurchaseModal pays for one plan inside the page (ADR 0007 §8.5): the market prepaid balance first; when it
// is short, a cashier order whose checkout is shown as a QR code (paymentchannel behind the portal) and polled
// until paid. onDone runs once a licence exists, so the card switches to 下载 without a reload.
export function PurchaseModal({ plugin, plans, token, onClose, onDone }: {
  plugin: MarketPlugin; plans: MarketPricePlan[]; token: string; onClose: () => void; onDone: () => void
}) {
  const { t } = useTranslation('marketStore')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const onSale = activePlans(plans)
  const [planID, setPlanID] = useState(onSale[0]?.id)
  const [method, setMethod] = useState<Method>('balance')
  const [order, setOrder] = useState<{ order: MarketOrder; checkout: string | null } | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const plan = onSale.find((p) => p.id === planID)
  const revision = plan ? saleRevision(plan) ?? plan.revision : 0
  // One key per attempt (market-buy-idem): a retry of the same plan replays on the
  // market instead of charging the balance or opening a second order.
  const orderKey = useIdempotencyKey('plugin-order')
  const prepaidKey = useIdempotencyKey('plugin-prepaid')
  // The attempt whose answer was lost; "check result" replays exactly it.
  const [unknown, setUnknown] = useState<'trial' | 'order' | 'prepaid' | null>(null)
  const failed = (error: unknown, kind: 'trial' | 'order' | 'prepaid') => {
    setUnknown(outcomeUnknown(error) || inProgress(error) ? kind : null)
    if (outcomeUnknown(error)) return
    if (inProgress(error)) return void feedback.warning(t('pay.inProgress'))
    const conflict = error instanceof ApiError && error.status === 409 ? error.code : ''
    if (conflict === 'already_licensed') return void message.info(t('pay.already'))
    // Only a changed plan revision means the price moved (market plugin_seller.go / finance_admin.go).
    if (conflict === 'plan_revision_changed' || conflict === 'price_changed') return void feedback.warning(t('pay.priceChanged'))
    if (conflict in conflictMessages) return void feedback.warning(t(conflictMessages[conflict]))
    void feedback.error(t('errors.failed', { code: error instanceof ApiError ? error.code : 'request_failed' }))
  }
  const createOrder = useMutation({
    mutationFn: (trial: boolean) => marketApi.createOrder(token, { market: 'plugin', price_plan_id: plan!.id, plan_revision: revision,
      ...(trial ? { trial: true } : {}) }, orderKey.keyFor({ plan: plan!.id, revision, trial })),
    onSuccess: (created) => {
      orderKey.complete()
      setUnknown(null)
      const url = checkoutURL(created.checkout_url)
      if (created.checkout_url && !url) return void feedback.error(t('pay.blocked'))
      if (!url) {
        onDone()
        return
      }
      setMethod('qr')
      setOrder({ order: created.order, checkout: url })
    },
    onError: (error, trial) => { if (!outcomeUnknown(error) && !inProgress(error)) orderKey.complete(); failed(error, trial ? 'trial' : 'order') },
  })
  const prepaid = useMutation({
    mutationFn: () => marketApi.purchaseFromPrepaid(token, { price_plan_id: plan!.id, plan_revision: revision }, prepaidKey.keyFor({ plan: plan!.id, revision })),
    onSuccess: () => { prepaidKey.complete(); setUnknown(null); onDone() },
    onError: (error) => {
      if (!outcomeUnknown(error) && !inProgress(error)) prepaidKey.complete()
      if (error instanceof ApiError && error.status === 402) {
        setNotice(t('pay.insufficient'))
        createOrder.mutate(false)
      } else failed(error, 'prepaid')
    },
  })
  const polled = useQuery({
    queryKey: ['marketStore', 'order', order?.order.id], enabled: !!order, initialData: order?.order,
    queryFn: () => marketApi.order(token, order!.order.id),
    refetchInterval: (q) => (terminalOrderStates.has(q.state.data?.status ?? '') ? false : 3000),
  })
  const status = polled.data?.status
  const fulfilled = !!order && status === 'fulfilled'
  useEffect(() => { if (fulfilled) onDone() }, [fulfilled, onDone])
  const pay = () => (unknown ? (unknown === 'prepaid' ? prepaid.mutate() : createOrder.mutate(unknown === 'trial'))
    : plan?.kind === 'free' ? createOrder.mutate(false) : method === 'balance' ? prepaid.mutate() : createOrder.mutate(false))
  return (
    <Modal open title={t('pay.title', { name: plugin.title })} onCancel={onClose} destroyOnHidden
      okText={unknown ? t('pay.checkResult') : t('pay.confirm')} cancelText={t('actions.cancel')} okButtonProps={{ disabled: !plan || !!order, loading: prepaid.isPending || createOrder.isPending }}
      onOk={pay}>
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <div>
          <Typography.Text strong>{t('pay.plan')}</Typography.Text>
          <Radio.Group value={planID} onChange={(e) => setPlanID(e.target.value as string)} disabled={!!order || !!unknown}
            style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}
            options={onSale.map((p) => ({ value: p.id, label: planPrice(t, p) }))} />
        </div>
        {plan && plan.kind !== 'free' ? <div>
          <Radio.Group value={method} onChange={(e) => setMethod(e.target.value as Method)} disabled={!!order || !!unknown} optionType="button"
            options={[{ value: 'balance', label: t('pay.balance') }, { value: 'qr', label: t('pay.qr') }]} />
          <Typography.Paragraph type="secondary" style={{ marginTop: 6, marginBottom: 0 }}>
            {method === 'balance' ? t('pay.balanceHint') : t('pay.qrHint')}
          </Typography.Paragraph>
        </div> : null}
        {plan && plan.trial_days > 0 && !order && !unknown ? <Button loading={createOrder.isPending} onClick={() => createOrder.mutate(true)}>
          {t('pay.trial', { days: plan.trial_days })}</Button> : null}
        {notice ? <Alert type="info" showIcon message={notice} /> : null}
        {unknown ? <Alert type="warning" showIcon message={t('pay.unknownTitle')} description={t('pay.unknownDetail')} /> : null}
        {order?.checkout ? <div className="market-store-qr">
          <Typography.Text strong>{t('pay.scan')}</Typography.Text>
          <QRCode type="svg" value={order.checkout} size={184} />
          {status === 'fulfilled' ? <Alert type="success" showIcon message={t('pay.paid')} />
            : status && terminalOrderStates.has(status) ? <Alert type="warning" showIcon message={t('pay.expired')} />
              : <Typography.Text type="secondary">{t('pay.waiting', { no: order.order.order_no })}</Typography.Text>}
          <Button type="link" href={order.checkout} target="_blank" rel="noopener noreferrer">{t('pay.openPage')}</Button>
        </div> : null}
      </Space>
    </Modal>
  )
}
