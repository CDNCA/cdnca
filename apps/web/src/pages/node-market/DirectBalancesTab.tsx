import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, InputNumber, Modal, QRCode, Radio, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  checkoutURL, marketApi, marketUnavailable, type MarketDirectMethod, type MarketDirectSeller, type MarketDirectTopup,
  type MarketPrepaidSeller, type MarketSellerCredit,
} from '../../api/market'
import { marketAccess } from '../../api/marketAccess'
import { useSessionStore } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/nodeMarket'
import { OutcomeUnknown } from '@cdnca/ui'
import { outcomeUnknown, useIdempotencyKey } from '../market/idempotency'
import { CursorPager, LoadFailure, useCursorPages } from './supplier/shared'

type DirectTopupAttempt = { seller: string; amount_minor: number; method: MarketDirectMethod; key: string }

// ADR 0015 §3.4 / §12: the subscriber's balance with every direct seller in
// one table, with the seller's deposit and record and a top-up button that
// pays the seller's own merchant account. Sellers also see the top-ups they
// received.

function useToken() {
  return useSessionStore((state) => state.accessToken) ?? ''
}

function errorCode(error: unknown): string {
  return error instanceof ApiError ? error.code : 'request_failed'
}

export function money(minor: number, currency = 'CNY'): string {
  return `${(minor / 100).toFixed(2)} ${currency}`
}

// SellerCreditTags is the deposit and record of a seller (§11.4).
export function SellerCreditTags({ credit }: { credit?: MarketSellerCredit }) {
  const { t } = useTranslation('nodeMarket')
  if (!credit) return <Typography.Text type="secondary">—</Typography.Text>
  return (
    <Space size={4} wrap>
      {credit.deposit_effective && credit.deposit_minor !== undefined ? (
        <Tag color={credit.sufficient ? 'success' : 'warning'}>
          {t('direct.credit.deposit', { value: money(credit.deposit_minor) })}
          {credit.sufficient ? '' : ` · ${t('direct.credit.short')}`}
        </Tag>
      ) : <Tag>{t('direct.credit.noDeposit')}</Tag>}
      {credit.absconded ? <Tag color="error">{t('direct.credit.absconded', { count: credit.defaults_count })}</Tag> : null}
      {credit.faults_30d > 0 ? <Tag color="orange">{t('direct.credit.faults', { count: credit.faults_30d })}</Tag> : null}
    </Space>
  )
}

const finalStates = new Set(['paid', 'refused'])
// The market still credits a payment the seller reports after the checkout
// expired or the seller was marked unreachable (RecordDirectPaid), so these
// keep polling, slower, and can be checked by hand; they never suggest a new top-up.
const lateStates = new Set(['unreachable', 'expired'])

// TopupModal: method and amount → the seller's checkout (QR code or link) →
// polls every 3 seconds until paid.
export function TopupModal({ seller, onClose }: { seller: MarketDirectSeller | null; onClose: () => void }) {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const client = useQueryClient()
  const [form] = Form.useForm<{ method: MarketDirectMethod; amount: number }>()
  const [topup, setTopup] = useState<MarketDirectTopup | null>(null)
  const [error, setError] = useState<string | null>(null)
  const method = Form.useWatch('method', form) ?? seller?.methods[0]?.method
  const limits = seller?.methods.find((m) => m.method === method)
  // One key per top-up attempt: fixed for the same seller, method and amount
  // while this dialog is open, so a retry replays the same top-up (market-buy-idem).
  const idempotency = useIdempotencyKey('direct-topup')
  const [pending, setPending] = useState<DirectTopupAttempt | null>(null)
  useEffect(() => { setTopup(null); setError(null) }, [seller?.seller_id])
  // Closing the dialog keeps an unknown top-up: reopening that seller still
  // offers only "check result" with its key.
  const unknownHere = pending && pending.seller === seller?.seller_id ? pending : null
  const create = useMutation({
    mutationFn: (a: DirectTopupAttempt) => marketApi.createDirectTopup(token, a.seller, a.amount_minor, a.method, a.key),
    onSuccess: (created) => { idempotency.complete(); setPending(null); setTopup(created); setError(null) },
    onError: (err, a) => {
      if (outcomeUnknown(err)) { setPending(a); setError(null); return }
      idempotency.complete()
      setPending(null)
      setError(t(`direct.errors.${errorCode(err)}`, { defaultValue: t('errors.failed', { code: errorCode(err) }) }))
    },
  })
  const submit = (v: { method: MarketDirectMethod; amount: number }) => {
    const body = { seller: seller!.seller_id, amount_minor: Math.round(v.amount * 100), method: v.method }
    create.mutate({ ...body, key: idempotency.keyFor(body) })
  }
  const poll = useQuery({
    queryKey: ['nodeMarket', 'directTopup', topup?.id], enabled: !!token && !!topup && !finalStates.has(topup.state),
    queryFn: () => marketApi.directTopup(token, topup!.id), retry: false,
    refetchInterval: (q) => {
      const state = q.state.data?.state ?? topup?.state ?? ''
      return finalStates.has(state) ? false : lateStates.has(state) ? 15000 : 3000
    },
  })
  const current = poll.data ?? topup
  useEffect(() => {
    if (current?.state === 'paid') void client.invalidateQueries({ queryKey: ['nodeMarket'] })
  }, [current?.state, client])
  const link = checkoutURL(current?.action?.url)
  return (
    <Modal open={!!seller} onCancel={onClose} footer={null} destroyOnHidden title={t('direct.topupTitle', { name: seller?.display_name ?? '' })}>
      <Space direction="vertical" style={{ width: '100%' }}>
        <Alert type="info" showIcon message={t('direct.topupNotice', { name: seller?.display_name ?? '' })} />
        {error ? <Alert type="error" showIcon message={error} /> : null}
        {unknownHere && !current ? <OutcomeUnknown title={t('buy.unknownTitle')} detail={t('direct.unknownDetail')}
          action={<Button size="small" loading={create.isPending} onClick={() => create.mutate(unknownHere)}>{t('buy.checkResult')}</Button>} /> : null}
        {poll.error ? <Alert type="warning" showIcon message={t('direct.pollFailed', { code: errorCode(poll.error) })}
          action={<Button size="small" loading={poll.isFetching} onClick={() => void poll.refetch()}>{t('direct.checkNow')}</Button>} /> : null}
        {!current ? (
          <Form form={form} layout="vertical" initialValues={{ method: seller?.methods[0]?.method, amount: 10 }}
            disabled={!!unknownHere} onFinish={submit}>
            <Form.Item name="method" label={t('direct.method')}>
              <Radio.Group optionType="button" options={(seller?.methods ?? []).map((m) => ({ value: m.method, label: m.display_name || m.method }))} />
            </Form.Item>
            <Form.Item name="amount" label={t('direct.amount')} extra={limits ? t('direct.range', { min: money(limits.min_minor), max: money(limits.max_minor) }) : null}
              rules={[{ required: true }, {
                validator: (_, v: number) => !limits || (v * 100 >= limits.min_minor && v * 100 <= limits.max_minor) ? Promise.resolve()
                  : Promise.reject(new Error(t('direct.outOfRange'))),
              }]}>
              <InputNumber min={1} precision={2} addonAfter="CNY" aria-label={t('direct.amount')} />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={create.isPending}>{t('direct.createTopup')}</Button>
          </Form>
        ) : current.state === 'requested' ? <Typography.Text type="secondary">{t('direct.waitingSeller')}</Typography.Text>
          : current.state === 'awaiting_payment' ? <Space direction="vertical" align="center" style={{ width: '100%' }}>
            {current.action?.qr_content ? <QRCode type="svg" value={current.action.qr_content} size={184} /> : null}
            {link ? <Button type="primary" href={link} target="_blank" rel="noopener noreferrer">{t('direct.goPay')}</Button> : null}
            <Typography.Text type="secondary">{t('direct.waitingPayment', { channel: current.channel_display_name ?? '' })}</Typography.Text>
          </Space>
            : current.state === 'paid' ? <Alert type="success" showIcon message={t('direct.paid', { value: money(current.paid_minor) })} />
              : lateStates.has(current.state) ? <Alert type="warning" showIcon message={t(`direct.states.${current.state}`)}
                description={t('direct.latePayment')}
                action={<Button size="small" loading={poll.isFetching} onClick={() => void poll.refetch()}>{t('direct.checkNow')}</Button>} />
                : <Alert type="warning" showIcon message={t(`direct.states.${current.state}`)} />}
      </Space>
    </Modal>
  )
}

function SpendBars({ days }: { days: number[] }) {
  const peak = Math.max(1, ...days)
  return (
    <span className="node-market-spark" aria-hidden="true">
      {days.map((v, i) => <span key={i} style={{ height: `${Math.max(2, Math.round((v / peak) * 18))}px` }} />)}
    </span>
  )
}

export function DirectBalancesTab() {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const access = marketAccess(useSessionStore((state) => state.principal))
  const summary = useQuery({ queryKey: ['nodeMarket', 'prepaid', 'CNY'], queryFn: () => marketApi.prepaid(token, 'CNY'), enabled: !!token, retry: false })
  const sellers = useQuery({ queryKey: ['nodeMarket', 'directSellers'], queryFn: () => marketApi.directSellers(token), enabled: !!token, retry: false })
  const [paying, setPaying] = useState<MarketDirectSeller | null>(null)
  const bySeller = new Map((sellers.data ?? []).map((s) => [s.seller_id, s]))
  const ledgerRows: MarketPrepaidSeller[] = summary.data?.sellers ?? []
  // Sellers the buyer can top up but has no ledger row with yet; a new array,
  // the query cache stays as fetched.
  const rows: MarketPrepaidSeller[] = [...ledgerRows, ...(sellers.data ?? [])
    .filter((s) => !ledgerRows.some((r) => r.seller_member_id === s.seller_id))
    .map((s) => ({ seller_member_id: s.seller_id, display_name: s.display_name, balance_minor: s.balance_minor, overdraft_minor: 0,
      credit_limit_minor: s.credit_limit_minor, below_alert: false, spent_24h_minor: 0, spent_by_day: [], by_subscription: [],
      seller_credit: s.seller_credit ?? { deposit_effective: false, defaults_count: 0, absconded: false, faults_30d: 0 } }))]
  const failure = summary.error ?? sellers.error
  return (
    <Space direction="vertical" style={{ width: '100%' }} size="middle">
      <TopupModal seller={paying} onClose={() => setPaying(null)} />
      <Typography.Title level={5} style={{ margin: 0 }}>{t('direct.title')}</Typography.Title>
      <Typography.Text type="secondary">{t('direct.help')}</Typography.Text>
      {failure ? (marketUnavailable(failure) ? <Alert type="info" showIcon message={t('unavailable')} />
        : <LoadFailure error={failure} title={t('errors.failed', { code: errorCode(failure) })} />) : null}
      {summary.data ? <Typography.Text>{t('direct.platformBalance', { value: money(summary.data.balance_minor) })}</Typography.Text> : null}
      <Table<MarketPrepaidSeller> rowKey="seller_member_id" size="small" loading={summary.isLoading || sellers.isLoading} dataSource={rows}
        pagination={false} locale={{ emptyText: t('direct.empty') }}
        rowClassName={(r) => (r.below_alert ? 'node-market-row-alert' : '')}
        expandable={{
          rowExpandable: (r) => r.by_subscription.length > 0,
          expandedRowRender: (r) => <Table size="small" rowKey="subscription_id" pagination={false} dataSource={r.by_subscription}
            columns={[
              { title: t('direct.subscription'), dataIndex: 'offer_name', render: (v: string, s) => v || s.subscription_id.slice(0, 8) },
              { title: t('direct.spent7d'), dataIndex: 'spent_7d_minor', render: (v: number) => money(v) },
            ]} />,
        }}
        columns={[
          { title: t('direct.seller'), dataIndex: 'display_name', render: (v: string, r) => <Space size={4}>
            <span>{v}</span>{r.below_alert ? <Tag color="warning">{t('direct.belowAlert')}</Tag> : null}</Space> },
          { title: t('direct.balance'), dataIndex: 'balance_minor', render: (v: number) =>
            <Typography.Text type={v < 0 ? 'danger' : undefined}>{money(v)}</Typography.Text> },
          { title: t('direct.creditLimit'), dataIndex: 'credit_limit_minor', render: (v: number) => money(v) },
          { title: t('direct.spent7dTotal'), key: 'spent', render: (_: unknown, r) => <Space size={6}>
            <SpendBars days={r.spent_by_day} /><span>{money(r.spent_by_day.reduce((a, b) => a + b, 0))}</span></Space> },
          { title: t('direct.credit.title'), key: 'credit', render: (_: unknown, r) => <SellerCreditTags credit={r.seller_credit} /> },
          { title: t('direct.status'), key: 'online', render: (_: unknown, r) => {
            const s = bySeller.get(r.seller_member_id)
            return s?.online ? <Tag color="success">{t('direct.online')}</Tag> : <Tag>{t('direct.offline')}</Tag>
          } },
          { key: 'topup', render: (_: unknown, r) => {
            if (!access.purchase) return null
            const s = bySeller.get(r.seller_member_id)
            const reason = !s ? 'not_enabled' : s.unavailable
            return <Space direction="vertical" size={0}>
              <Button size="small" type="primary" disabled={!!reason} onClick={() => s && setPaying(s)}>{t('direct.topup')}</Button>
              {reason ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t(`direct.unavailable.${reason}`)}</Typography.Text> : null}
            </Space>
          } },
        ]} />
    </Space>
  )
}

// ReceivedTopupsPanel: what subscribers topped up with me, under the selling
// section (MC12 E4): a buyer's balances page shows only what I hold at sellers.
export function ReceivedTopupsPanel() {
  const { t } = useTranslation('nodeMarket')
  const token = useToken()
  const access = marketAccess(useSessionStore((state) => state.principal))
  const receivedPages = useCursorPages()
  const received = useQuery({ queryKey: ['nodeMarket', 'directTopups', 'seller', receivedPages.cursor],
    queryFn: () => marketApi.directTopups(token, 'seller', receivedPages.cursor), enabled: !!token && access.sell, retry: false })
  return (
    <Space direction="vertical" style={{ width: '100%' }} size="middle">
      {received.error ? <LoadFailure error={received.error} scope="sell" title={t('errors.failed', { code: errorCode(received.error) })} /> : null}
      <>
        <Typography.Text type="secondary">{t('direct.receivedHelp')}</Typography.Text>
        <Table<MarketDirectTopup> rowKey="id" size="small" loading={received.isLoading} dataSource={received.data?.items ?? []}
          pagination={false} locale={{ emptyText: t('direct.receivedEmpty') }}
          columns={[
            { title: t('direct.buyer'), dataIndex: 'peer_display_name' },
            { title: t('direct.amount'), dataIndex: 'amount_minor', render: (v: number) => money(v) },
            { title: t('direct.method'), dataIndex: 'method', render: (v: string) => t(`direct.methods.${v}`, { defaultValue: v }) },
            { title: t('direct.status'), dataIndex: 'state', render: (v: string) => <Tag color={v === 'paid' ? 'success' : 'default'}>{t(`direct.states.${v}`)}</Tag> },
            { title: t('direct.paidMinor'), dataIndex: 'paid_minor', render: (v: number) => money(v) },
            { title: t('direct.createdAt'), dataIndex: 'created_at', render: (v: string) => formatDateTime(v) },
          ]} />
        <CursorPager pages={receivedPages} pageSize={50} count={received.data?.items.length ?? 0} next={received.data?.next_cursor} busy={received.isFetching} />
      </>
    </Space>
  )
}
