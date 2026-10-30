import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Descriptions, Form, Input, InputNumber, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { checkoutURL } from '../../../api/market'
import { marketSupplierApi, supplierPageSize, type CommissionDeduction } from '../../../api/marketSupplier'
import { useErrorText, useTime, useToken, useWrite } from './hooks'
import { commissionDaysLeft } from './model'
import { CursorPager, LoadFailure, useCursorPages } from './shared'
import { useFeedback, OutcomeUnknown } from '@cdnca/ui'
import { outcomeUnknown, useIdempotencyKey } from '../../market/idempotency'
import { formatYuan, minorToYuan, yuanToMinor } from '@cdnca/ui/offer-terms'

// ADR 0012 §21.2–21.3 (ML-27, U12): direct-settlement commission prepaid:
// balance, top-up, alert line, deductions, switch on/leave (balance stays).
export function CommissionPanel() {
  const { t } = useTranslation('marketSupplier')
  const { modal } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const time = useTime()
  const errorText = useErrorText()
  const [currency, setCurrency] = useState('CNY')
  const [created, setCreated] = useState<{ no: number; url: string | null } | null>(null)
  const account = useQuery({ queryKey: ['nodeMarket', 'commissionPrepaid'], enabled: !!token, retry: false,
    queryFn: () => marketSupplierApi.commissionPrepaid(token) })
  const pages = useCursorPages()
  const deductions = useQuery({ queryKey: ['nodeMarket', 'commissionDeductions', pages.cursor], enabled: !!token && !!account.data?.enabled, retry: false,
    queryFn: () => marketSupplierApi.commissionDeductions(token, pages.cursor) })
  const toggle = useWrite((v: { enabled: boolean; currency: string }) => marketSupplierApi.setCommissionPrepaid(token, v.enabled, v.currency), 'common.saved')
  const alert = useWrite((v: number) => marketSupplierApi.setCommissionAlert(token, account.data!.currency, v), 'common.saved')
  // One key per top-up attempt (market-buy-idem): a lost answer is replayed with it, not re-created.
  const idempotency = useIdempotencyKey('commission-topup')
  const [pending, setPending] = useState<{ amount: number; currency: string; key: string } | null>(null)
  const topup = useMutation({
    mutationFn: (v: { amount: number; currency: string; key: string }) => marketSupplierApi.commissionTopup(token, v.amount, v.currency, v.key),
    onSuccess: (result) => {
      idempotency.complete()
      setPending(null)
      const url = checkoutURL(result.checkout_url)
      if (url) window.open(url, '_blank', 'noopener,noreferrer')
      else void feedback.error(t('commission.checkoutBlocked'))
      setCreated({ no: result.order.order_no, url })
    },
    onError: (error, v) => {
      if (outcomeUnknown(error)) return setPending(v)
      idempotency.complete()
      setPending(null)
      void feedback.error(errorText(error))
    },
  })
  const a = account.data
  const days = a ? commissionDaysLeft(a.balance_minor, a.last_7_days_minor) : null
  const exhausted = !!a?.enabled && (a.balance_minor <= 0 || !!a.exhausted_since)
  return (
    <Space direction="vertical" style={{ width: '100%', maxWidth: 820 }}>
      <Typography.Title level={5}>{t('commission.title')}</Typography.Title>
      <Typography.Text type="secondary">{t('commission.help')}</Typography.Text>
      {account.error ? <LoadFailure scope="sell" error={account.error} title={errorText(account.error)} /> : null}
      {a && !a.enabled ? <Space wrap>
        <Tag>{t('commission.disabled')}</Tag>
        <Input style={{ width: 90 }} aria-label={t('commission.currency')} value={currency} maxLength={3}
          onChange={(e) => setCurrency(e.target.value.toUpperCase())} />
        <Button type="primary" disabled={!/^[A-Z]{3}$/.test(currency)} loading={toggle.isPending}
          onClick={() => toggle.mutate({ enabled: true, currency })}>{t('commission.enable')}</Button>
      </Space> : null}
      {a?.enabled ? <>
        {exhausted ? <Alert type="error" showIcon message={t('commission.exhausted', { since: time(a.exhausted_since ?? null) })} /> : null}
        <Descriptions bordered size="small" column={2}>
          <Descriptions.Item label={t('commission.balance')}>
            <Typography.Text type={a.balance_minor <= 0 ? 'danger' : undefined} strong data-testid="commission-balance">
              {formatYuan(a.balance_minor)} {a.currency}</Typography.Text>
            {days !== null ? <Typography.Text type="secondary"> · {t('commission.daysLeft', { days })}</Typography.Text> : null}
          </Descriptions.Item>
          <Descriptions.Item label={t('commission.due')}>{formatYuan(a.due_minor)}</Descriptions.Item>
          <Descriptions.Item label={t('commission.last7')}>{formatYuan(a.last_7_days_minor)}</Descriptions.Item>
          <Descriptions.Item label={t('commission.alert')}>{formatYuan(a.threshold_minor)}</Descriptions.Item>
        </Descriptions>
        <Form layout="inline" disabled={!!pending} onFinish={(v: { amount: number }) => {
          const body = { amount: yuanToMinor(v.amount) ?? 0, currency: a.currency }
          topup.mutate({ ...body, key: idempotency.keyFor(body) })
        }}>
          <Form.Item name="amount" rules={[{ required: true }]}>
            <InputNumber min={0.01} max={1000000} precision={2} placeholder={t('commission.amount')} aria-label={t('commission.amount')} style={{ width: 180 }} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={topup.isPending}>{t('commission.topupSubmit')}</Button>
        </Form>
        {pending ? <OutcomeUnknown title={t('commission.unknownTitle')} detail={t('commission.unknownDetail')} action={<Space wrap>
          <Button size="small" loading={topup.isPending} onClick={() => topup.mutate(pending)}>{t('commission.checkResult')}</Button>
          <Button size="small" onClick={() => { idempotency.complete(); setPending(null) }}>{t('commission.abandon')}</Button>
        </Space>} /> : null}
        {created ? <Alert type="success" showIcon message={t('commission.topupCreated', { no: created.no })} /> : null}
        <Form layout="inline" key={a.threshold_minor} initialValues={{ threshold: minorToYuan(a.threshold_minor) }}
          onFinish={(v: { threshold: number }) => alert.mutate(yuanToMinor(v.threshold) ?? 0)}>
          <Form.Item name="threshold" label={t('commission.alert')} extra={t('commission.alertHelp')} rules={[{ required: true }]}>
            <InputNumber min={0} precision={2} aria-label={t('commission.alert')} />
          </Form.Item>
          <Button htmlType="submit" loading={alert.isPending}>{t('commission.alertSave')}</Button>
        </Form>
        <Typography.Title level={5}>{t('commission.deductions')}</Typography.Title>
        <Table<CommissionDeduction> size="small" rowKey="id" loading={deductions.isLoading} dataSource={deductions.data?.items ?? []}
          pagination={false} locale={{ emptyText: t('common.empty') }}
          columns={[
            { title: t('commission.at'), dataIndex: 'created_at', render: time },
            { title: t('commission.deducted'), dataIndex: 'amount_minor', render: (v: number) => formatYuan(v) },
            { title: t('commission.remainingDue'), dataIndex: 'due_minor', render: (v: number) => formatYuan(v) },
          ]} />
        <CursorPager pages={pages} pageSize={supplierPageSize} count={deductions.data?.items.length ?? 0}
          next={deductions.data?.next_cursor} busy={deductions.isFetching} />
        <Button danger loading={toggle.isPending} onClick={() => modal.confirm({ title: t('commission.disableConfirm'),
          onOk: () => toggle.mutateAsync({ enabled: false, currency: a.currency }).catch(() => undefined) })}>{t('commission.disable')}</Button>
      </> : null}
    </Space>
  )
}
