import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Descriptions, Drawer, Form, Input, InputNumber, Modal, Select, Space, Table, Tag, Timeline, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../../api/auth'
import {
  marketApi, marketUnavailable, type MarketFeedbackCategory, type MarketFeedbackRole, type MarketFeedbackState, type MarketFeedbackTicket,
} from '../../../api/market'
import { formatDateTime } from '../../../i18n/formatters'
import { formatMinor } from '../../plugin-market/pluginStoreModel'
import { outcomeUnknown, useIdempotencyKey } from '../../market/idempotency'
import { useErrorText, useToken } from './hooks'
import { useFeedback, useFormSubmitError } from '@cdnca/ui'
import { yuanToMinor } from '@cdnca/ui/offer-terms'

const categories: MarketFeedbackCategory[] = ['outage', 'degraded', 'config', 'billing', 'other']
const stateColor: Record<MarketFeedbackState, string> = { open: 'warning', in_progress: 'processing', resolved: 'success', closed: 'default' }

function feedbackError(t: (key: string, o?: Record<string, unknown>) => string, errorText: (e: unknown) => string, error: unknown): string {
  const code = error instanceof ApiError ? error.code : ''
  if (['feedback_not_due', 'feedback_closed', 'seller_not_onboarded', 'conflict'].includes(code)) return t(`feedback.errors.${code}`)
  return errorText(error)
}

function StateTag({ state }: { state: MarketFeedbackState }) {
  const { t } = useTranslation('marketSupplier')
  return <Tag color={stateColor[state]}>{t(`feedback.states.${state}`)}</Tag>
}

// One ticket: the conversation, a reply box and the side's actions. The seller
// marks in progress / resolved; the buyer closes, reopens by replying, and
// escalates an overdue ticket to a dispute.
function TicketDrawer({ role, ticketID, canWrite, onClose }: { role: MarketFeedbackRole; ticketID: string | null; canWrite: boolean; onClose: () => void }) {
  const { t, i18n } = useTranslation('marketSupplier')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const client = useQueryClient()
  const errorText = useErrorText()
  const lang = i18n.resolvedLanguage ?? 'zh-CN'
  const [reply, setReply] = useState('')
  const [escalating, setEscalating] = useState(false)
  const [amount, setAmount] = useState<number | null>(null)
  const [note, setNote] = useState('')
  const answerKey = useIdempotencyKey('feedback-answer')
  const escalateKey = useIdempotencyKey('feedback-escalate')
  const queryKey = ['nodeMarket', 'feedback', role, ticketID]
  const query = useQuery({ queryKey, enabled: !!token && !!ticketID, queryFn: () => marketApi.feedback(token, role, ticketID!) })
  const done = (key: string) => {
    void message.success(t(key))
    void client.invalidateQueries({ queryKey: ['nodeMarket', 'feedback'] })
  }
  const fail = (error: unknown) => void feedback.error(feedbackError(t, errorText, error))
  // 卡 7/10：键随请求走，结算时只清这次请求的键；结果未知（断网、超时、5xx）保留键，重试按原键重放，不换键重复写。
  const answer = useMutation({
    mutationFn: ({ key, ...input }: { body?: string; state?: MarketFeedbackState; key: string }) =>
      marketApi.answerFeedback(token, role, ticketID!, input, key),
    onSuccess: (_, { key, ...input }) => { answerKey.complete(key); setReply(''); done(input.state ? `feedback.stateDone.${input.state}` : 'feedback.replied') },
    onError: (error, { key }) => { if (!outcomeUnknown(error)) answerKey.complete(key); fail(error) },
  })
  const sendAnswer = (input: { body?: string; state?: MarketFeedbackState }) => answer.mutate({ ...input, key: answerKey.keyFor({ ticketID, ...input }) })
  const escalate = useMutation({
    mutationFn: ({ key, ...input }: { amount_minor: number; note: string; key: string }) =>
      marketApi.escalateFeedback(token, ticketID!, input, key),
    onSuccess: (_, { key }) => { escalateKey.complete(key); setEscalating(false); done('feedback.escalated') },
    onError: (error, { key }) => { if (!outcomeUnknown(error)) escalateKey.complete(key); fail(error) },
  })
  const sendEscalate = (input: { amount_minor: number; note: string }) => escalate.mutate({ ...input, key: escalateKey.keyFor({ ticketID, ...input }) })
  const ticket = query.data
  const open = ticket && ticket.state !== 'closed'
  const time = (v?: string | null) => (v ? formatDateTime(v, lang) || v : '—')
  return (
    <Drawer open={!!ticketID} onClose={onClose} width="min(720px, 100vw)" title={ticket ? ticket.title : t('feedback.title')} destroyOnHidden>
      {query.error ? <Alert type="error" showIcon message={feedbackError(t, errorText, query.error)} /> : null}
      {ticket ? <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Descriptions bordered size="small" column={1}>
          <Descriptions.Item label={t('feedback.offer')}>{ticket.offer_name}</Descriptions.Item>
          <Descriptions.Item label={t('feedback.category')}>{t(`feedback.categories.${ticket.category}`)}</Descriptions.Item>
          <Descriptions.Item label={t('feedback.state')}><StateTag state={ticket.state} /></Descriptions.Item>
          <Descriptions.Item label={t('feedback.respondBy')}>
            {time(ticket.respond_by)}{ticket.seller_responded_at ? ` · ${t('feedback.respondedAt', { time: time(ticket.seller_responded_at) })}` : ''}
          </Descriptions.Item>
          {ticket.dispute_id ? <Descriptions.Item label={t('feedback.dispute')}>
            <Typography.Text code copyable>{ticket.dispute_id}</Typography.Text></Descriptions.Item> : null}
          {ticket.decision ? <Descriptions.Item label={t('feedback.decision')}>
            {t(`feedback.outcomes.${ticket.decision.outcome}`, {
              claim: formatMinor(ticket.decision.amount_minor, ticket.decision.currency),
              share: formatMinor(ticket.decision.buyer_share_minor ?? 0, ticket.decision.currency),
            })} · {t('feedback.decidedAt', { time: time(ticket.decision.decided_at) })}
          </Descriptions.Item> : null}
        </Descriptions>
        {role === 'buyer' && ticket.escalable ? <Alert type="warning" showIcon message={t('feedback.overdue')} /> : null}
        {role === 'seller' && ticket.state === 'open' ? <Alert type="info" showIcon message={t('feedback.sellerDue', { time: time(ticket.respond_by) })} /> : null}
        <Timeline items={(ticket.messages ?? []).map((m) => ({
          key: m.seq,
          color: m.author_role === 'operator' ? 'red' : m.author_role === role ? 'blue' : 'gray',
          children: <Space direction="vertical" size={0}>
            <Typography.Text type="secondary">{t(`feedback.authors.${m.author_role}`)} · {time(m.created_at)}</Typography.Text>
            {m.kind === 'state' && m.to_state ? <span>{t('feedback.changedTo')} <StateTag state={m.to_state} /></span>
              : m.kind === 'escalated' ? <span>{t('feedback.escalatedLine')}{m.body ? `：${m.body}` : ''}</span>
              : <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{m.body}</Typography.Paragraph>}
          </Space>,
        }))} />
        {canWrite && open ? <>
          <Input.TextArea rows={3} maxLength={4000} value={reply} onChange={(e) => setReply(e.target.value)}
            aria-label={t('feedback.reply')} placeholder={t('feedback.replyPlaceholder')} />
          <Space wrap>
            <Button type="primary" disabled={!reply.trim()} loading={answer.isPending && !answer.variables?.state}
              onClick={() => sendAnswer({ body: reply })}>{t('feedback.send')}</Button>
            {role === 'seller' && ticket.state !== 'in_progress' ? <Button loading={answer.isPending && answer.variables?.state === 'in_progress'}
              onClick={() => sendAnswer({ state: 'in_progress', ...(reply.trim() ? { body: reply } : {}) })}>{t('feedback.markInProgress')}</Button> : null}
            {role === 'seller' && ticket.state !== 'resolved' ? <Button loading={answer.isPending && answer.variables?.state === 'resolved'}
              onClick={() => sendAnswer({ state: 'resolved', ...(reply.trim() ? { body: reply } : {}) })}>{t('feedback.markResolved')}</Button> : null}
            {role === 'buyer' ? <Button loading={answer.isPending && answer.variables?.state === 'closed'}
              onClick={() => sendAnswer({ state: 'closed', ...(reply.trim() ? { body: reply } : {}) })}>{t('feedback.close')}</Button> : null}
            {role === 'buyer' && ticket.escalable ? <Button danger onClick={() => setEscalating(true)}>{t('feedback.escalate')}</Button> : null}
          </Space>
          {role === 'buyer' && ticket.state === 'resolved' ? <Typography.Text type="secondary">{t('feedback.reopenHelp')}</Typography.Text> : null}
        </> : null}
      </Space> : null}
      <Modal open={escalating} title={t('feedback.escalate')} onCancel={() => setEscalating(false)} confirmLoading={escalate.isPending}
        okButtonProps={{ disabled: !amount || amount <= 0 }} okText={t('feedback.escalateConfirm')}
        onOk={() => amount && sendEscalate({ amount_minor: yuanToMinor(amount) ?? 0, note: note.trim() })}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Alert type="info" showIcon message={t('feedback.escalateHelp')} />
          <InputNumber min={0.01} precision={2} style={{ width: 240 }} value={amount} onChange={(v) => setAmount(v === null ? null : Number(v))}
            aria-label={t('feedback.claim')} placeholder={t('feedback.claim')} />
          <Input.TextArea rows={3} maxLength={4000} value={note} onChange={(e) => setNote(e.target.value)} aria-label={t('feedback.escalateNote')}
            placeholder={t('feedback.escalateNote')} />
        </Space>
      </Modal>
    </Drawer>
  )
}

// FeedbackList: the buyer's tickets on one subscription (with the "report a
// fault" form) or the seller's tickets on all its subscriptions.
export function FeedbackList({ role, subscriptionID, canWrite }: { role: MarketFeedbackRole; subscriptionID?: string; canWrite: boolean }) {
  const { t, i18n } = useTranslation('marketSupplier')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useToken()
  const client = useQueryClient()
  const errorText = useErrorText()
  const [state, setState] = useState<MarketFeedbackState | undefined>()
  const [cursors, setCursors] = useState<string[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [filing, setFiling] = useState(false)
  const [form] = Form.useForm<{ category: MarketFeedbackCategory; title: string; body: string }>()
  const markSubmitError = useFormSubmitError(form)
  const openKey = useIdempotencyKey('feedback-open')
  const cursor = cursors.at(-1)
  const query = useQuery({ queryKey: ['nodeMarket', 'feedback', role, subscriptionID ?? '', state, cursor], enabled: !!token,
    queryFn: () => marketApi.feedbackList(token, role, { state, subscription: subscriptionID, cursor }) })
  const file = useMutation({
    mutationFn: ({ key, ...v }: { category: MarketFeedbackCategory; title: string; body: string; key: string }) =>
      marketApi.openFeedback(token, subscriptionID!, v, key),
    onSuccess: (ticket, { key }) => {
      openKey.complete(key); setFiling(false); form.resetFields()
      void message.success(t('feedback.opened'))
      void client.invalidateQueries({ queryKey: ['nodeMarket', 'feedback'] })
      setSelected(ticket.id)
    },
    onError: (error, { key }) => { if (!outcomeUnknown(error)) openKey.complete(key); markSubmitError(error, () => void feedback.error(feedbackError(t, errorText, error))) },
  })
  const sendFile = (v: { category: MarketFeedbackCategory; title: string; body: string }) => file.mutate({ ...v, key: openKey.keyFor({ subscriptionID, ...v }) })
  const lang = i18n.resolvedLanguage ?? 'zh-CN'
  const next = query.data?.next_cursor
  if (marketUnavailable(query.error)) return <Alert type="info" showIcon message={t('feedback.unavailable')} />
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Text type="secondary">{t(role === 'buyer' ? 'feedback.buyerHelp' : 'feedback.sellerHelp')}</Typography.Text>
      <Space wrap>
        {role === 'buyer' && subscriptionID && canWrite ? <Button type="primary" onClick={() => setFiling(true)}>{t('feedback.report')}</Button> : null}
        <Select<MarketFeedbackState> allowClear style={{ width: 160 }} placeholder={t('feedback.anyState')} aria-label={t('feedback.state')} value={state}
          onChange={(v) => { setState(v); setCursors([]) }}
          options={(['open', 'in_progress', 'resolved', 'closed'] as const).map((v) => ({ value: v, label: t(`feedback.states.${v}`) }))} />
      </Space>
      {query.error ? <Alert type="error" showIcon message={errorText(query.error)} /> : null}
      <Table<MarketFeedbackTicket> rowKey="id" size="small" loading={query.isLoading} dataSource={query.data?.items ?? []} pagination={false}
        locale={{ emptyText: t('feedback.empty') }}
        columns={[
          { title: t('feedback.titleColumn'), dataIndex: 'title' },
          ...(role === 'seller' ? [{ title: t('feedback.offer'), dataIndex: 'offer_name' }] : []),
          { title: t('feedback.category'), dataIndex: 'category', render: (v: MarketFeedbackCategory) => t(`feedback.categories.${v}`) },
          { title: t('feedback.state'), dataIndex: 'state', render: (v: MarketFeedbackState, f) => <Space size={4} wrap><StateTag state={v} />
            {f.dispute_id ? <Tag color="red">{t('feedback.disputed')}</Tag> : f.escalable && role === 'buyer' ? <Tag color="orange">{t('feedback.overdueTag')}</Tag> : null}</Space> },
          { title: t('feedback.respondBy'), dataIndex: 'respond_by', render: (v: string) => formatDateTime(v, lang) || v },
          { title: t('feedback.updated'), dataIndex: 'updated_at', render: (v: string) => formatDateTime(v, lang) || v },
          { key: 'open', render: (_: unknown, f) => <Button size="small" onClick={() => setSelected(f.id)}>{t('feedback.view')}</Button> },
        ]} />
      <Space>
        <Button disabled={!cursors.length || query.isFetching} onClick={() => setCursors(cursors.slice(0, -1))}>{t('feedback.previous')}</Button>
        <Button disabled={!next || cursors.includes(next) || query.isFetching} onClick={() => next && setCursors([...cursors, next])}>{t('feedback.next')}</Button>
      </Space>
      <TicketDrawer role={role} ticketID={selected} canWrite={canWrite} onClose={() => setSelected(null)} />
      <Modal open={filing} title={t('feedback.report')} onCancel={() => setFiling(false)} confirmLoading={file.isPending} okText={t('feedback.submit')}
        onOk={() => void form.validateFields().then((v) => sendFile({ ...v, title: v.title.trim() })).catch(() => undefined)}>
        <Alert type="info" showIcon style={{ marginBottom: 12 }} message={t('feedback.reportHelp')} />
        <Form form={form} layout="vertical" initialValues={{ category: 'outage' }}>
          <Form.Item name="category" label={t('feedback.category')}>
            <Select options={categories.map((v) => ({ value: v, label: t(`feedback.categories.${v}`) }))} />
          </Form.Item>
          <Form.Item name="title" label={t('feedback.titleColumn')} rules={[{ required: true, whitespace: true, message: t('feedback.titleRequired') }]}>
            <Input maxLength={128} />
          </Form.Item>
          <Form.Item name="body" label={t('feedback.body')} extra={t('feedback.bodyHelp')}
            rules={[{ required: true, whitespace: true, message: t('feedback.bodyRequired') }]}>
            <Input.TextArea rows={5} maxLength={4000} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
