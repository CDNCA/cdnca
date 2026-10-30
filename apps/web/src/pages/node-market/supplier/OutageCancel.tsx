import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../../api/auth'
import { newIdempotencyKey } from '../../../api/market'
import { marketSupplierApi, type SupplyOutage } from '../../../api/marketSupplier'
import { useErrorText, useTime, useToken } from './hooks'
import { remaining } from './model'
import { useFeedback } from '@cdnca/ui'

const meteredModels = new Set(['traffic', 'bandwidth_95', 'bandwidth_daily_peak'])

// ADR 0012 §24 (ML-31): while every node of a direct subscription is offline
// the subscriber sees since when; after T1 a liability-free cancel. Before
// cancel_available_at the market does not set it yet, so the countdown
// shows only when outage_cancel_after_minutes is known (T1 from the policy).
export function OutageCancel({ subscriptionID, outage, cancelAfterMinutes, canBuy }: {
  subscriptionID: string
  outage?: SupplyOutage | null
  cancelAfterMinutes?: number
  canBuy: boolean
}) {
  const { t } = useTranslation('marketSupplier')
  const { message, modal } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const time = useTime()
  const errorText = useErrorText()
  const client = useQueryClient()
  const [now, setNow] = useState(() => Date.now())
  const readyAt = outage?.cancel_available_at ? Date.parse(outage.cancel_available_at)
    : outage && cancelAfterMinutes ? Date.parse(outage.since) + cancelAfterMinutes * 60_000 : NaN
  const ready = !!outage?.cancel_available_at && readyAt <= now
  useEffect(() => {
    if (!outage || ready) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [outage, ready])
  const cancel = useMutation({
    mutationFn: () => marketSupplierApi.outageCancel(token, subscriptionID, newIdempotencyKey('outage-cancel')),
    onSuccess: (view) => {
      // B26: what the market booked, not an estimate.
      const s = view.outage_settlement
      const money = (minor: number) => `${(minor / 100).toFixed(2)} ${s?.currency ?? ''}`.trim()
      if (!s) void message.success(t('outage.cancelled'))
      else if (meteredModels.has(s.billing_model)) void message.success(t('outage.cancelledMetered', { credit: money(s.credit_minor) }))
      else void message.success(t('outage.cancelledBundle', { refund: money(s.refund_minor), credit: money(s.credit_minor) }))
      void client.invalidateQueries({ queryKey: ['nodeMarket'] })
    },
    onError: (error) => void feedback.error(error instanceof ApiError && error.code === 'outage_not_eligible' ? t('outage.notEligible') : errorText(error)),
  })
  if (!outage) return null
  return (
    <Alert type="error" showIcon message={t('outage.banner', { since: time(outage.since) })}
      description={ready ? t('outage.cancelReady') : Number.isFinite(readyAt) ? t('outage.cancelIn', { time: remaining(readyAt - now) }) : null}
      action={canBuy && ready ? <Button danger size="small" loading={cancel.isPending}
        onClick={() => modal.confirm({ title: t('outage.cancelConfirm'), onOk: () => cancel.mutateAsync().catch(() => undefined) })}>{t('outage.cancel')}</Button> : null} />
  )
}
