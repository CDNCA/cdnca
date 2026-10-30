import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import dayjs from 'dayjs'
import { TimeRangeFilter, type TimeRangeValue } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../../api/auth'
import { marketApi } from '../../../api/market'
import { complaintCategories, marketSupplierApi, supplierPageSize, type ComplaintCategory, type SupplierSubscriber } from '../../../api/marketSupplier'
import { CursorPager, LoadFailure, Short, SupplyStateTag, useCursorPages } from './shared'
import { formatBytes, useErrorText, useTime, useToken, useWrite } from './hooks'

const targetOf = (row: SupplierSubscriber) => (row.relation === 'direct' ? row.subscription_id : row.downstream_ref ?? '')
const rowKey = (row: SupplierSubscriber) => `${row.subscription_id}/${row.downstream_ref ?? ''}`

interface ComplaintValues {
  category: ComplaintCategory
  detail: string
  domains?: string
  window?: TimeRangeValue
  links?: string
}

function ComplaintWindow({ value = { preset: 'custom', range: null }, onChange, label }: { value?: TimeRangeValue; onChange?: (value: TimeRangeValue) => void; label: string }) {
  return <TimeRangeFilter maxDate={dayjs()} label={label} value={value} onChange={(next) => onChange?.(next)} />
}

function ComplaintModal({ row, onClose }: { row: SupplierSubscriber | null; onClose: () => void }) {
  const { t } = useTranslation('marketSupplier')
  const token = useToken()
  const [form] = Form.useForm<ComplaintValues>()
  const errorText = useErrorText()
  const [failure, setFailure] = useState('')
  const file = useWrite((v: ComplaintValues) => {
    const domains = (v.domains ?? '').split(/[,，\s]+/).map((d) => d.trim()).filter(Boolean)
    const attachments = (v.links ?? '').split('\n').map((l) => l.trim()).filter(Boolean).map((url, i) => ({ name: `evidence-${i + 1}`, url }))
    return marketSupplierApi.fileComplaint(token, {
      offer_id: row!.offer_id, target_ref: targetOf(row!), category: v.category, detail: v.detail.trim(),
      evidence: {
        ...(domains.length ? { domains } : {}),
        ...(v.window?.range ? { from: v.window.range[0].toISOString(), to: v.window.range[1].toISOString() } : {}),
        ...(attachments.length ? { attachments } : {}),
      },
    })
  }, 'complaints.submitted', () => { form.resetFields(); onClose() })
  const submit = (v: ComplaintValues) => {
    setFailure('')
    file.mutate(v, { onError: (error) => setFailure(error instanceof ApiError && error.status === 409 ? t('complaints.duplicate') : errorText(error)) })
  }
  return (
    <Modal open={!!row} title={t('complaints.file')} onCancel={onClose} okText={t('complaints.submit')} confirmLoading={file.isPending}
      onOk={() => form.submit()} destroyOnHidden>
      {row ? <Typography.Paragraph type="secondary">{t('complaints.target')}：
        {row.relation === 'direct' ? row.buyer_name ?? row.subscription_id : row.downstream_ref}</Typography.Paragraph> : null}
      {failure ? <Alert type="error" showIcon message={failure} style={{ marginBottom: 12 }} /> : null}
      <Form form={form} layout="vertical" onFinish={submit} initialValues={{ category: 'abuse_complaint', window: { preset: 'custom', range: null } }}>
        <Form.Item name="category" label={t('complaints.category')} rules={[{ required: true }]}>
          <Select aria-label={t('complaints.category')} options={complaintCategories.map((value) => ({ value, label: t(`complaints.categories.${value}`) }))} />
        </Form.Item>
        <Form.Item name="detail" label={t('complaints.detail')} rules={[{ required: true, whitespace: true }, { max: 4000 }]}>
          <Input.TextArea rows={4} aria-label={t('complaints.detail')} maxLength={4000} />
        </Form.Item>
        <Form.Item name="domains" label={t('complaints.domains')}><Input aria-label={t('complaints.domains')} /></Form.Item>
        {/* 可选：默认不填；快捷项取选中时的窗口，发生时间不晚于当前。 */}
        <Form.Item name="window" label={t('complaints.window')}>
          <ComplaintWindow label={t('complaints.window')} />
        </Form.Item>
        <Form.Item name="links" label={t('complaints.attachments')} rules={[{
          validator: (_, value?: string) => (value ?? '').split('\n').map((l) => l.trim()).filter(Boolean)
            .every((l) => /^https:\/\/[^\s/@]+\/?\S*$/.test(l)) ? Promise.resolve() : Promise.reject(new Error(t('complaints.badLink'))),
        }]}>
          <Input.TextArea rows={3} aria-label={t('complaints.attachments')} />
        </Form.Item>
      </Form>
    </Modal>
  )
}

// ADR 0012 §18.1–18.3 (ML-16/17): who subscribes to me across offers, my own
// note on a row and the stop request entry. No pause/stop/tighten here (U2).
export function SubscribersPanel() {
  const { t } = useTranslation('marketSupplier')
  const token = useToken()
  const time = useTime()
  const errorText = useErrorText()
  const [offer, setOffer] = useState<string | undefined>()
  const [noteRow, setNoteRow] = useState<SupplierSubscriber | null>(null)
  const [note, setNote] = useState('')
  const [complaintRow, setComplaintRow] = useState<SupplierSubscriber | null>(null)
  const pages = useCursorPages()
  const offers = useQuery({ queryKey: ['nodeMarket', 'myOffers'], queryFn: () => marketApi.myOffers(token), enabled: !!token })
  const query = useQuery({ queryKey: ['nodeMarket', 'supplierSubscribers', offer, pages.cursor], enabled: !!token, retry: false,
    queryFn: () => marketSupplierApi.subscribers(token, offer, pages.cursor) })
  const saveNote = useWrite((v: { row: SupplierSubscriber; note: string }) => marketSupplierApi.setNote(token, v.row, v.note),
    'common.saved', () => setNoteRow(null))
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <ComplaintModal row={complaintRow} onClose={() => setComplaintRow(null)} />
      <Modal open={!!noteRow} title={t('subscribers.noteTitle')} onCancel={() => setNoteRow(null)} confirmLoading={saveNote.isPending}
        onOk={() => noteRow && saveNote.mutate({ row: noteRow, note: note.trim() })}>
        <Input.TextArea aria-label={t('subscribers.note')} placeholder={t('subscribers.notePlaceholder')} maxLength={500} rows={3}
          value={note} onChange={(e) => setNote(e.target.value)} />
      </Modal>
      <Typography.Title level={5}>{t('subscribers.title')}</Typography.Title>
      <Typography.Text type="secondary">{t('subscribers.help')}</Typography.Text>
      <Select allowClear style={{ width: 280 }} aria-label={t('subscribers.offer')} placeholder={t('subscribers.allOffers')} value={offer}
        onChange={(v) => { setOffer(v); pages.reset() }} options={(offers.data ?? []).map((o) => ({ value: o.id, label: o.name }))} />
      {query.error ? <LoadFailure scope="sell" error={query.error} title={errorText(query.error)} /> : null}
      <Table<SupplierSubscriber> size="small" rowKey={rowKey} loading={query.isLoading} dataSource={query.data?.items ?? []}
        pagination={false} scroll={{ x: 1300 }} locale={{ emptyText: t('common.empty') }}
        columns={[
          { title: t('subscribers.relation'), dataIndex: 'relation', render: (v: string) => <Tag color={v === 'direct' ? 'blue' : 'default'}>{t(`common.${v}`)}</Tag> },
          { title: t('subscribers.who'), key: 'who', render: (_: unknown, r) => r.relation === 'direct'
            ? <Space size={4}><span>{r.buyer_name ?? '—'}</span><Short value={r.buyer_id} /></Space>
            : <Space direction="vertical" size={0}><Typography.Text code>{r.downstream_ref}</Typography.Text>
              {r.via_name ? <Typography.Text type="secondary">{t('common.via', { name: r.via_name })}</Typography.Text> : null}</Space> },
          { title: t('subscribers.status'), dataIndex: 'status', render: (v: string) => t(`common.subscriptionStates.${v}`, { defaultValue: v }) },
          { title: t('subscribers.state'), dataIndex: 'supply_state', render: (v: string) => <SupplyStateTag value={v} /> },
          { title: t('subscribers.paidThrough'), dataIndex: 'paid_through', render: time },
          { title: t('subscribers.renewal'), key: 'renewal', render: (_: unknown, r) => r.renewal_stop
            ? <Space direction="vertical" size={0}>
              <Tooltip title={r.renewal_stop.reason === 'upstream_paused' ? t('subscribers.upstreamPausedHelp') : undefined}>
                <Tag color="warning">{t(`subscribers.renewalStops.${r.renewal_stop.reason}`, { defaultValue: r.renewal_stop.reason })}</Tag></Tooltip>
              <Typography.Text type="secondary">{t('subscribers.renewalSince', { time: time(r.renewal_stop.since) })}</Typography.Text>
            </Space> : t('subscribers.renewing') },
          { title: t('subscribers.domains'), key: 'domains', render: (_: unknown, r) => r.domains.length
            ? <Space size={4} wrap>{r.domains.slice(0, 3).map((d) => <Tag key={d}>{d}</Tag>)}{r.domains.length > 3 ? `+${r.domains.length - 3}` : null}</Space> : '—' },
          { title: t('subscribers.pools'), key: 'pools', render: (_: unknown, r) => r.pools.join(', ') || '—' },
          { title: t('subscribers.traffic'), key: 'traffic', render: (_: unknown, r) => `${formatBytes(r.traffic.last_24h_bytes)} / ${formatBytes(r.traffic.month_bytes)}` },
          { title: t('subscribers.holds'), key: 'holds', render: (_: unknown, r) => r.holds.length
            ? <Space size={4} wrap>{r.holds.map((h, i) => <Tag key={i} color={h.action === 'stop' ? 'error' : 'warning'}>
              {t(`holds.reasons.${h.reason}`, { defaultValue: h.reason })} · {t(`holds.actions.${h.action}`)}</Tag>)}</Space> : '—' },
          { title: t('subscribers.note'), dataIndex: 'note', render: (v: string) => v || '—' },
          { key: 'actions', fixed: 'right', render: (_: unknown, r) => <Space size={4}>
            <Button size="small" onClick={() => { setNote(r.note); setNoteRow(r) }}>{t('subscribers.editNote')}</Button>
            <Button size="small" danger onClick={() => setComplaintRow(r)}>{t('subscribers.complain')}</Button>
          </Space> },
        ]} />
      <CursorPager pages={pages} pageSize={supplierPageSize} count={query.data?.items.length ?? 0} next={query.data?.next_cursor} busy={query.isFetching} />
    </Space>
  )
}
