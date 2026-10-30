import { useEffect, useRef, useState, type DragEvent, type KeyboardEvent, type ReactElement } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, App, Button, Card, Checkbox, Drawer, Form, Image, Input, Popconfirm, Result, Select, Space, Table, Tag,
  Typography,
} from 'antd'
import { ArrowLeft, BellRing, Eye, File, FileImage, FileText, Lock, Paperclip, Plus, Send, ShieldOff, Trash2, XCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import {
  maxTicketAttachments, ticketCategories, ticketPriorities, ticketsApi, ticketsManagePermission, ticketsReadPermission,
  ticketStatuses, validateAttachment, type CreateTicketInput, type Ticket, type TicketAttachment, type TicketCategory,
  type ReplyTicketInput, type TicketDetail, type TicketEvent, type TicketFilters, type TicketMessage, type TicketMode, type TicketPriority, type TicketStatus,
} from '../../api/tickets'
import { useSessionStore } from '../../auth/session'
import '../../i18n/tickets'
import { outcomeUnknown, useIdempotencyKey } from '../market/idempotency'
import { AdvancedFilters, FeedbackWhen, useLiveApply } from '@cdnca/ui'
import { filterParam, useFilterUrl } from '../filterUrl'
import { TicketNotifyDrawer } from './TicketNotifyDrawer'
import { TicketStaffCreateDrawer } from './TicketStaffCreateDrawer'
import './TicketsChat.css'

const statusColors: Record<TicketStatus, string> = {
  open: 'blue', processing: 'gold', pending_customer: 'purple', resolved: 'green', closed: 'default',
}
const priorityColors: Record<TicketPriority, string> = { low: 'default', normal: 'blue', high: 'orange', urgent: 'red' }

// The ticket API takes related IDs as canonical lowercase UUIDs (tickets.parseID).
const relatedIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function codeOf(error: unknown): string {
  return error instanceof ApiError ? error.code : 'request_failed'
}

function formatTime(value?: string): string {
  return value ? new Date(value).toLocaleString() : ''
}

function useErrorText() {
  const { t } = useTranslation('tickets')
  return (error: unknown): string => {
    const code = codeOf(error)
    const known: Record<string, string> = {
      ticket_not_found: 'errors.notFound', ticket_invalid_state: 'errors.invalidState',
      ticket_reopen_expired: 'errors.reopenExpired', ticket_revision_conflict: 'errors.revisionConflict',
      ticket_attachments_disabled: 'errors.attachmentsDisabled', ticket_attachment_rejected: 'errors.attachmentRejected',
      ticket_attachment_type: 'errors.attachmentType', ticket_attachment_too_large: 'errors.attachmentSize',
      ticket_attachment_limit: 'errors.attachmentLimit', invalid_ticket: 'errors.invalid', permission_denied: 'errors.forbidden',
    }
    return known[code] ? t(known[code]) : t('errors.failed', { code })
  }
}

// useAttachmentUpload checks and uploads files right away (picker or drop)
// and reports the attachment ids.
function useAttachmentUpload(mode: TicketMode, value: TicketAttachment[], onChange: (next: TicketAttachment[]) => void) {
  const { t } = useTranslation('tickets')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const errorText = useErrorText()
  const [problem, setProblem] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const pick = async (files: FileList | null) => {
    if (!files?.length) return
    setProblem(null)
    const list = Array.from(files)
    if (value.length + list.length > maxTicketAttachments) {
      setProblem(t('attachments.tooMany', { count: maxTicketAttachments }))
      return
    }
    for (const file of list) {
      const invalid = validateAttachment(file)
      if (invalid) {
        setProblem(t(invalid === 'type' ? 'attachments.badType' : 'attachments.badSize', { name: file.name }))
        return
      }
    }
    setBusy(true)
    try {
      const uploaded: TicketAttachment[] = []
      for (const file of list) uploaded.push(await ticketsApi.upload(token, mode, file))
      onChange([...value, ...uploaded])
    } catch (error) {
      setProblem(errorText(error))
    } finally {
      setBusy(false)
    }
  }
  return { pick, busy, problem }
}

// AttachmentPicker uploads files right away and reports the attachment ids.
function AttachmentPicker({ mode, value, onChange }: {
  mode: TicketMode; value: TicketAttachment[]; onChange: (next: TicketAttachment[]) => void
}) {
  const { t } = useTranslation('tickets')
  const { pick, busy, problem } = useAttachmentUpload(mode, value, onChange)
  return (
    <div>
      <Space wrap>
        <label className="ant-btn ant-btn-default" aria-disabled={busy}>
          {busy ? t('attachments.uploading') : t('attachments.add')}
          <input type="file" multiple hidden disabled={busy} aria-label={t('attachments.add')}
            onChange={(event) => { void pick(event.target.files); event.target.value = '' }} />
        </label>
        <Typography.Text type="secondary">{t('attachments.hint', { count: maxTicketAttachments })}</Typography.Text>
      </Space>
      {value.length ? <ul className="ticket-attachments">
        {value.map((item) => <li key={item.id}>{item.file_name}{' '}
          <Button size="small" type="link" onClick={() => onChange(value.filter((other) => other.id !== item.id))}>
            {t('attachments.remove')}</Button></li>)}
      </ul> : null}
      {problem ? <Alert type="error" showIcon style={{ marginTop: 8 }} message={problem} /> : null}
    </div>
  )
}

type IdempotencyKey = ReturnType<typeof useIdempotencyKey>

function CreateDrawer({ open, onClose, onCreated, createKey, initialSiteID }: {
  open: boolean; onClose: () => void; onCreated: (detail: TicketDetail) => void; createKey: IdempotencyKey
  // 第七节“普通用户求助”：从网站失败处进入时预填关联网站，用户不必记 UUID。
  initialSiteID?: string
}) {
  const { t } = useTranslation('tickets')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const errorText = useErrorText()
  const [form] = Form.useForm<CreateTicketInput>()
  const [attachments, setAttachments] = useState<TicketAttachment[]>([])
  const [error, setError] = useState<string | null>(null)
  // One Idempotency-Key per submission (createKey lives on the page, so
  // closing the drawer keeps it): an unknown outcome (network error, 5xx)
  // keeps it so "check result / retry" replays the same create; changed
  // content gets a new key, a success or a definite refusal drops it.
  const [unknown, setUnknown] = useState(false)
  // isPending lags a render behind, so a second click in the same tick would
  // still send; the ref closes that gap.
  const inFlight = useRef(false)
  const create = useMutation({
    mutationFn: ({ input, key }: { input: CreateTicketInput; key: string }) => ticketsApi.create(token, input, key),
    onSettled: () => { inFlight.current = false },
    onSuccess: (detail, { key }) => {
      createKey.complete(key)
      setUnknown(false)
      void message.success(t('create.created', { no: detail.ticket.ticket_no }))
      onCreated(detail)
    },
    onError: (err, { input, key }) => {
      if (outcomeUnknown(err)) {
        setUnknown(true)
        setError(t('create.unknown'))
        return
      }
      createKey.complete(key)
      setUnknown(false)
      // invalid_ticket carries no field details. The form already checks every
      // other field, so a refusal with related IDs points at those IDs (unknown
      // or another account's site/order).
      const related = (['site_id', 'order_id'] as const).filter((name) => input[name])
      if (codeOf(err) === 'invalid_ticket' && related.length) {
        form.setFields(related.map((name) => ({ name, errors: [t('create.relatedNotFound')] })))
      }
      setError(errorText(err))
    },
  })
  const relatedIDRule = { pattern: relatedIDPattern, message: t('create.badID'), transform: (value?: string) => value?.trim() }
  return (
    <Drawer open={open} onClose={onClose} width="min(640px, 100vw)" title={t('create.title')} destroyOnHidden>
      {error ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message={error} /> : null}
      <Form<CreateTicketInput> form={form} layout="vertical" initialValues={{ category: 'technical', priority: 'normal', ...(initialSiteID ? { site_id: initialSiteID } : {}) }}
        onValuesChange={() => setUnknown(false)}
        onFinish={(values) => {
          if (inFlight.current) return
          inFlight.current = true
          setError(null)
          const input: CreateTicketInput = {
            category: values.category, priority: values.priority, subject: values.subject.trim(), body: values.body,
            ...(values.site_id?.trim() ? { site_id: values.site_id.trim() } : {}),
            ...(values.order_id?.trim() ? { order_id: values.order_id.trim() } : {}),
            ...(attachments.length ? { attachment_ids: attachments.map((item) => item.id) } : {}),
          }
          create.mutate({ input, key: createKey.keyFor(input) })
        }}>
        <Space wrap>
          <Form.Item name="category" label={t('create.category')}>
            <Select<TicketCategory> style={{ width: 160 }} aria-label={t('create.category')}
              options={ticketCategories.map((value) => ({ value, label: t(`categories.${value}`) }))} />
          </Form.Item>
          <Form.Item name="priority" label={t('create.priority')}>
            <Select<TicketPriority> style={{ width: 120 }} aria-label={t('create.priority')}
              options={ticketPriorities.map((value) => ({ value, label: t(`priorities.${value}`) }))} />
          </Form.Item>
        </Space>
        <Form.Item name="subject" label={t('create.subject')} rules={[{ required: true, whitespace: true, max: 200 }]}>
          <Input maxLength={200} />
        </Form.Item>
        <Form.Item name="body" label={t('create.body')} rules={[{ required: true, whitespace: true, max: 20000 }]}>
          <Input.TextArea rows={8} maxLength={20000} />
        </Form.Item>
        <Space wrap>
          <Form.Item name="site_id" label={t('create.site')} rules={[relatedIDRule]}><Input style={{ width: 300 }} /></Form.Item>
          <Form.Item name="order_id" label={t('create.order')} rules={[relatedIDRule]}><Input style={{ width: 300 }} /></Form.Item>
        </Space>
        <Form.Item><AttachmentPicker mode="user" value={attachments}
          onChange={(next) => { setUnknown(false); setAttachments(next) }} /></Form.Item>
        <Space>
          <Button type="primary" htmlType="submit" loading={create.isPending}>
            {unknown ? t('create.checkResult') : t('create.submit')}</Button>
          <Button onClick={onClose}>{t('create.cancel')}</Button>
        </Space>
      </Form>
    </Drawer>
  )
}

// 平台端改状态/关闭/删除要 tickets.manage 或 platform.admin（后端 authStaff 同一规则）。
function useStaffManage(mode: TicketMode): boolean {
  const permissions = useSessionStore((state) => state.principal?.permissions) ?? []
  return mode === 'admin' && (permissions.includes(ticketsManagePermission) || permissions.includes('platform.admin'))
}

// 危险操作的二次确认：标题写对象，描述写影响。
function ConfirmAction({ title, impact, onConfirm, children }: {
  title: string; impact: string; onConfirm: () => void; children: ReactElement
}) {
  const { t } = useTranslation('tickets')
  return <Popconfirm title={title} description={<span className="ticket-ops-impact">{impact}</span>}
    okText={t('ops.confirmOk')} cancelText={t('ops.confirmCancel')} okButtonProps={{ danger: true }} onConfirm={onConfirm}>
    {children}
  </Popconfirm>
}

function StatusTag({ status }: { status: TicketStatus }) {
  const { t } = useTranslation('tickets')
  return <Tag color={statusColors[status]}>{t(`status.${status}`)}</Tag>
}

function PriorityTag({ priority }: { priority: TicketPriority }) {
  const { t } = useTranslation('tickets')
  return <Tag color={priorityColors[priority]}>{t(`priorities.${priority}`)}</Tag>
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1 << 20) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1 << 20)).toFixed(1)} MB`
}

function formatClock(value: string): string {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function formatRelative(value: string, t: (key: string, values?: Record<string, number>) => string): string {
  const minutes = Math.floor((Date.now() - Date.parse(value)) / 60000)
  if (minutes < 1) return t('chat.justNow')
  if (minutes < 60) return t('chat.minutesAgo', { count: minutes })
  if (minutes < 24 * 60) return t('chat.hoursAgo', { count: Math.floor(minutes / 60) })
  if (minutes < 7 * 24 * 60) return t('chat.daysAgo', { count: Math.floor(minutes / 1440) })
  return formatTime(value)
}

function formatDay(value: string): string {
  return new Date(value).toLocaleDateString([], { year: 'numeric', month: 'long', day: 'numeric' })
}

// One avatar letter from the display name (staff names reach customers as "客服 名字").
function initialOf(name: string): string {
  const plain = name.replace(/^客服\s+/, '').trim()
  return Array.from(plain)[0]?.toUpperCase() ?? '?'
}

function attachmentIcon(mime: string) {
  if (mime.startsWith('image/')) return FileImage
  if (mime === 'text/plain' || mime === 'application/pdf') return FileText
  return File
}

// Chat stream items: consecutive messages of one author with the same
// visibility within 5 minutes share one header; system lines are the date
// change, "filed", and the ticket's events (migration 543: status, priority,
// assignee, closed, reopened). A ticket from before 543 has no events, so its
// resolved / closed timestamps still give a line.
type ChatItem =
  | { kind: 'system'; key: string; text: string }
  | { kind: 'group'; key: string; side: 'customer' | 'staff'; internal: boolean; author: string; at: string; messages: TicketMessage[] }

const groupWindowMs = 5 * 60 * 1000

function eventText(event: TicketEvent, t: (key: string, values?: Record<string, string>) => string): string {
  const name = event.actor_name
  switch (event.kind) {
    case 'status':
      return t('chat.statusChanged', { name, from: t(`status.${event.from}`), to: t(`status.${event.to}`) })
    case 'priority':
      return t('chat.priorityChanged', { name, from: t(`priorities.${event.from}`), to: t(`priorities.${event.to}`) })
    case 'assignee':
      return event.to ? t('chat.assigneeChanged', { name, to: event.to }) : t('chat.assigneeCleared', { name })
    case 'closed':
      return t('chat.closedBy', { name })
    case 'reopened':
      return t('chat.reopenedBy', { name })
  }
}

function buildChat(ticket: Ticket, messages: TicketMessage[], ticketEvents: TicketEvent[],
  t: (key: string, values?: Record<string, string>) => string): ChatItem[] {
  const recorded = (kind: TicketEvent['kind'], to: string) =>
    ticketEvents.some((event) => event.to === to && (event.kind === kind || event.kind === 'status'))
  const events: Array<{ at: string; system?: string; message?: TicketMessage }> = [
    { at: ticket.created_at, system: t('chat.filed', { name: ticket.username || messages[0]?.author_name || t('detail.customer') }) },
    ...messages.map((message) => ({ at: message.created_at, message })),
    ...ticketEvents.map((event) => ({ at: event.created_at, system: eventText(event, t) })),
    ...(ticket.resolved_at && !recorded('status', 'resolved') ? [{ at: ticket.resolved_at, system: t('chat.resolved') }] : []),
    ...(ticket.closed_at && !recorded('closed', 'closed') ? [{ at: ticket.closed_at, system: t('chat.closed') }] : []),
  ]
  // Stable sort keeps "filed" ahead of the first message at the same instant.
  events.sort((a, b) => Date.parse(a.at) - Date.parse(b.at))
  const items: ChatItem[] = []
  let day = ''
  for (const [index, event] of events.entries()) {
    const nextDay = new Date(event.at).toDateString()
    if (nextDay !== day) {
      day = nextDay
      items.push({ kind: 'system', key: `day-${index}`, text: formatDay(event.at) })
    }
    if (event.system) {
      items.push({ kind: 'system', key: `sys-${index}`, text: `${event.system} · ${formatClock(event.at)}` })
      continue
    }
    const message = event.message!
    const last = items[items.length - 1]
    if (last?.kind === 'group' && last.side === message.author_kind && last.author === message.author_name &&
      last.internal === Boolean(message.internal) &&
      Date.parse(message.created_at) - Date.parse(last.messages[last.messages.length - 1].created_at) <= groupWindowMs) {
      last.messages.push(message)
      continue
    }
    items.push({ kind: 'group', key: message.id, side: message.author_kind, internal: Boolean(message.internal),
      author: message.author_name, at: message.created_at, messages: [message] })
  }
  return items
}

function AttachmentCard({ attachment, onDownload, onPreview }: {
  attachment: TicketAttachment; onDownload: () => void; onPreview?: () => void
}) {
  const { t } = useTranslation('tickets')
  const Icon = attachmentIcon(attachment.mime_type)
  return (
    <div className="ticket-chat-file">
      <button type="button" className="ticket-chat-file-main" onClick={onDownload}
        aria-label={`${t('attachments.download')} ${attachment.file_name}`}>
        <Icon size={20} aria-hidden="true" />
        <span className="ticket-chat-file-text">
          <span className="ticket-chat-file-name">{attachment.file_name}</span>
          <span className="ticket-chat-file-size">{formatSize(attachment.size_bytes)}</span>
        </span>
      </button>
      {onPreview ? <Button size="small" type="text" icon={<Eye size={16} aria-hidden="true" />} onClick={onPreview}
        aria-label={`${t('attachments.preview')} ${attachment.file_name}`}>{t('attachments.preview')}</Button> : null}
    </div>
  )
}

function TicketDetailView({ mode, id, onBack, replyKey }: {
  mode: TicketMode; id: string; onBack: () => void; replyKey: IdempotencyKey
}) {
  const { t } = useTranslation('tickets')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const principal = useSessionStore((state) => state.principal)
  const permissions = principal?.permissions ?? []
  const me = principal?.user_id
  const canManage = mode === 'user' || permissions.includes(ticketsManagePermission) || permissions.includes('platform.admin')
  const client = useQueryClient()
  const errorText = useErrorText()
  const [body, setBody] = useState('')
  const [internal, setInternal] = useState(false)
  const [attachments, setAttachments] = useState<TicketAttachment[]>([])
  const [error, setError] = useState<string | null>(null)
  const detail = useQuery({ queryKey: ['tickets', mode, 'detail', id], queryFn: () => ticketsApi.get(token, mode, id) })
  const assignees = useQuery({ queryKey: ['tickets', 'assignees'], queryFn: () => ticketsApi.assignees(token),
    enabled: mode === 'admin' && canManage })
  const refresh = (next: TicketDetail) => {
    client.setQueryData(['tickets', mode, 'detail', id], next)
    void client.invalidateQueries({ queryKey: ['tickets', mode, 'list'] })
    void client.invalidateQueries({ queryKey: ['tickets', mode, 'summary'] })
  }
  // A 409 means the ticket moved on under this page (another writer, or our
  // own earlier write whose response was lost): reload the detail so buttons
  // follow the server. ticket_invalid_state reads "status changed" only when
  // the reload shows a different status; otherwise the action is truly not
  // allowed and keeps its own message.
  const fail = async (err: unknown) => {
    if (!(err instanceof ApiError) || err.status !== 409) {
      setError(errorText(err))
      return
    }
    const before = detail.data?.ticket.status
    setError(errorText(err))
    const next = await detail.refetch()
    if (codeOf(err) === 'ticket_invalid_state' && next.data && next.data.ticket.status !== before) {
      setError(t('errors.stateChanged'))
    }
  }
  // One Idempotency-Key per reply (same ticket, body, note flag, attachments):
  // an unknown outcome keeps it so the retry replays instead of posting twice.
  const [replyUnknown, setReplyUnknown] = useState<string | null>(null)
  const replyInput: ReplyTicketInput = {
    body, ...(internal ? { internal: true } : {}),
    ...(attachments.length ? { attachment_ids: attachments.map((item) => item.id) } : {}),
  }
  const replying = useRef(false)
  const reply = useMutation({
    mutationFn: ({ input, key }: { input: ReplyTicketInput; key: string }) => ticketsApi.reply(token, mode, id, input, key),
    onSettled: () => { replying.current = false },
    onSuccess: (next, { key }) => {
      replyKey.complete(key); setReplyUnknown(null)
      setBody(''); setInternal(false); setAttachments([]); setError(null)
      void message.success(t('detail.sent'))
      refresh(next)
    },
    onError: (err, { input, key }) => {
      if (outcomeUnknown(err)) {
        setReplyUnknown(JSON.stringify(input))
        setError(t('detail.unknown'))
        return
      }
      replyKey.complete(key); setReplyUnknown(null)
      void fail(err)
    },
  })
  const sendReply = () => {
    if (replying.current) return
    replying.current = true
    setError(null)
    reply.mutate({ input: replyInput, key: replyKey.keyFor({ mode, id, input: replyInput }) })
  }
  const transition = useMutation({
    mutationFn: (action: 'close' | 'reopen') => action === 'close' ? ticketsApi.close(token, id) : ticketsApi.reopen(token, id),
    onSuccess: (next) => { setError(null); refresh(next) },
    onError: (err) => { void fail(err) },
  })
  const update = useMutation({
    mutationFn: (change: { status?: TicketStatus; priority?: TicketPriority; assignee_user_id?: string }) =>
      ticketsApi.update(token, id, { expected_revision: detail.data!.ticket.revision, ...change }),
    onSuccess: (next) => { setError(null); void message.success(t('detail.updated')); refresh(next) },
    onError: (err) => { void fail(err) },
  })
  const remove = useMutation({
    mutationFn: () => ticketsApi.remove(token, id),
    onSuccess: () => {
      void message.success(t('ops.deleted'))
      client.removeQueries({ queryKey: ['tickets', mode, 'detail', id] })
      void client.invalidateQueries({ queryKey: ['tickets', mode] })
      onBack()
    },
    onError: (err) => { setError(errorText(err)) },
  })
  const download = async (attachment: TicketAttachment) => {
    try {
      const blob = await ticketsApi.download(token, mode, attachment)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = attachment.file_name
      link.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(errorText(err))
    }
  }
  const upload = useAttachmentUpload(mode, attachments, setAttachments)
  const [dragging, setDragging] = useState(false)
  const [preview, setPreview] = useState<{ url: string; name: string } | null>(null)
  const openPreview = async (attachment: TicketAttachment) => {
    try {
      const blob = await ticketsApi.download(token, mode, attachment)
      setPreview({ url: URL.createObjectURL(blob), name: attachment.file_name })
    } catch (err) {
      setError(errorText(err))
    }
  }
  const closePreview = () => setPreview((current) => {
    if (current) URL.revokeObjectURL(current.url)
    return null
  })
  // Keep the newest message in view, like a chat app.
  const stream = useRef<HTMLDivElement>(null)
  const messageCount = detail.data?.messages.length ?? 0
  useEffect(() => {
    const node = stream.current
    if (node) node.scrollTop = node.scrollHeight
  }, [messageCount])
  if (detail.isLoading) return <Card loading />
  if (detail.error || !detail.data) {
    return <Space direction="vertical"><Button onClick={onBack}>{t('detail.back')}</Button>
      <FeedbackWhen title={errorText(detail.error)} /></Space>
  }
  const { ticket, messages, events = [] } = detail.data
  const finished = ticket.status === 'resolved' || ticket.status === 'closed'
  const canReply = mode === 'user' ? !finished : canManage && (ticket.status !== 'closed' || internal)
  const showComposer = canManage && (mode !== 'user' || !finished)
  const editable = mode === 'admin' && canManage
  const chat = buildChat(ticket, messages, events, t)
  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== 'Enter' || !(event.ctrlKey || event.metaKey)) return
    event.preventDefault()
    if (body.trim() && canReply && !reply.isPending && !upload.busy) sendReply()
  }
  const dropProps = showComposer ? {
    onDragOver: (event: DragEvent) => { if (event.dataTransfer.types.includes('Files')) { event.preventDefault(); setDragging(true) } },
    onDragLeave: (event: DragEvent) => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false) },
    onDrop: (event: DragEvent) => { event.preventDefault(); setDragging(false); void upload.pick(event.dataTransfer.files) },
  } : {}
  return (
    <div className="ticket-chat">
      <header className="ticket-chat-head">
        <Button onClick={onBack} icon={<ArrowLeft size={16} aria-hidden="true" />}>{t('detail.back')}</Button>
        <div className="ticket-chat-head-text">
          <Typography.Title level={4}>{ticket.subject}</Typography.Title>
          <div className="ticket-chat-head-meta">
            <StatusTag status={ticket.status} />
            <PriorityTag priority={ticket.priority} />
            {ticket.sla_breached ? <Tag color="red">{t('badges.sla')}</Tag> : null}
            <Typography.Text type="secondary">{t('detail.meta', { no: ticket.ticket_no, category: t(`categories.${ticket.category}`),
              created: formatTime(ticket.created_at) })}</Typography.Text>
          </div>
        </div>
        {editable ? <Space className="ticket-chat-head-ops">
          {ticket.status !== 'closed' ? <ConfirmAction title={t('ops.closeConfirm', { no: ticket.ticket_no })}
            impact={t('ops.closeImpact')} onConfirm={() => update.mutate({ status: 'closed' })}>
            <Button icon={<XCircle size={14} aria-hidden="true" />} loading={update.isPending}>{t('ops.closeTicket')}</Button>
          </ConfirmAction> : null}
          <ConfirmAction title={t('ops.deleteConfirm', { no: ticket.ticket_no })} impact={t('ops.deleteImpact')}
            onConfirm={() => remove.mutate()}>
            <Button danger icon={<Trash2 size={14} aria-hidden="true" />} loading={remove.isPending}>{t('ops.deleteTicket')}</Button>
          </ConfirmAction>
        </Space> : null}
      </header>
      {error ? <FeedbackWhen title={error} /> : null}
      <div className="ticket-chat-body">
        <section className={`ticket-chat-panel${dragging ? ' is-dragging' : ''}`} aria-label={t('chat.timeline')} {...dropProps}>
          <div className="ticket-chat-stream" ref={stream} role="log" aria-label={ticket.subject}>
            {messages.length === 0 ? <p className="ticket-chat-system"><span>{t('detail.empty')}</span></p> : null}
            {chat.map((item) => item.kind === 'system'
              ? <p key={item.key} className="ticket-chat-system"><span>{item.text}</span></p>
              : <div key={item.key} className={`ticket-chat-group ticket-chat-group--${item.side}${item.internal ? ' ticket-chat-group--internal' : ''}`}>
                <span className="ticket-chat-avatar" aria-hidden="true">{initialOf(item.author)}</span>
                <div className="ticket-chat-group-main">
                  <div className="ticket-chat-who">
                    <strong>{item.author}</strong>
                    <span className="ticket-chat-role">{item.side === 'staff' ? t('detail.staff') : t('detail.customer')}</span>
                    <time dateTime={item.at} title={formatTime(item.at)}>{formatClock(item.at)}</time>
                  </div>
                  {item.messages.map((entry) => (
                    <div key={entry.id} className="ticket-chat-bubble" title={formatTime(entry.created_at)}>
                      {entry.internal ? <span className="ticket-chat-internal">
                        <Lock size={12} aria-hidden="true" />{t('detail.internal')} · {t('chat.internalOnly')}</span> : null}
                      <p className="ticket-chat-text">{entry.body}</p>
                      {entry.attachments.length ? <div className="ticket-chat-files">
                        {entry.attachments.map((attachment) => <AttachmentCard key={attachment.id} attachment={attachment}
                          onDownload={() => { void download(attachment) }}
                          onPreview={attachment.mime_type.startsWith('image/') ? () => { void openPreview(attachment) } : undefined} />)}
                      </div> : null}
                    </div>
                  ))}
                </div>
              </div>)}
          </div>
          {mode === 'user' && finished ? <Alert className="ticket-chat-notice" type="info" showIcon
            message={t('detail.closedHint')}
            description={ticket.reopenable_until ? t('detail.reopenUntil', { until: formatTime(ticket.reopenable_until) }) : undefined}
            action={ticket.reopenable_until ? <Button loading={transition.isPending}
              onClick={() => transition.mutate('reopen')}>{t('detail.reopen')}</Button> : undefined} /> : null}
          {mode !== 'user' && ticket.status === 'closed' && !internal ? <Alert className="ticket-chat-notice" type="info" showIcon
            message={t('detail.staffClosedHint')} /> : null}
          {showComposer ? <div className={`ticket-chat-composer${internal ? ' is-internal' : ''}`}>
            {dragging ? <div className="ticket-chat-drop" aria-hidden="true">{t('chat.drop')}</div> : null}
            {mode === 'admin' ? <Checkbox checked={internal} onChange={(event) => setInternal(event.target.checked)}>
              {t('detail.note')}</Checkbox> : null}
            <Input.TextArea autoSize={{ minRows: 2, maxRows: 8 }} maxLength={20000} value={body} aria-label={t('detail.reply')}
              placeholder={internal ? t('chat.notePlaceholder') : t('detail.replyPlaceholder')} onKeyDown={onKeyDown}
              onChange={(event) => setBody(event.target.value)} />
            {attachments.length ? <ul className="ticket-chat-pending">
              {attachments.map((item) => <li key={item.id}><Paperclip size={14} aria-hidden="true" />
                <span>{item.file_name}</span><span className="ticket-chat-file-size">{formatSize(item.size_bytes)}</span>
                <Button size="small" type="link" onClick={() => setAttachments(attachments.filter((other) => other.id !== item.id))}>
                  {t('attachments.remove')}</Button></li>)}
            </ul> : null}
            {upload.problem ? <Alert type="error" showIcon message={upload.problem} /> : null}
            <div className="ticket-chat-actions">
              <label className="ant-btn ant-btn-default ant-btn-sm ticket-chat-attach" aria-disabled={upload.busy}
                title={t('attachments.hint', { count: maxTicketAttachments })}>
                <Paperclip size={14} aria-hidden="true" />{upload.busy ? t('attachments.uploading') : t('attachments.add')}
                <input type="file" multiple hidden disabled={upload.busy} aria-label={t('attachments.add')}
                  onChange={(event) => { void upload.pick(event.target.files); event.target.value = '' }} />
              </label>
              <span className="ticket-chat-hint">{t('chat.shortcut')}</span>
              <span className="ticket-chat-actions-end">
                {mode === 'user' && !finished ? <Popconfirm title={t('detail.closeConfirm')} onConfirm={() => transition.mutate('close')}>
                  <Button danger loading={transition.isPending}>{t('detail.close')}</Button>
                </Popconfirm> : null}
                <Button type="primary" icon={<Send size={14} aria-hidden="true" />} disabled={!body.trim() || !canReply || upload.busy}
                  loading={reply.isPending} onClick={sendReply}>
                  {replyUnknown === JSON.stringify(replyInput) ? t('detail.checkResult') : t('detail.send')}</Button>
              </span>
            </div>
          </div> : null}
        </section>
        <aside className="ticket-chat-side" aria-label={t('chat.info')}>
          {mode !== 'user' ? <section className="ticket-chat-card ticket-chat-user">
            <span className="ticket-chat-avatar" aria-hidden="true">{initialOf(ticket.username || '?')}</span>
            <div>
              <span className="ticket-chat-label">{t('columns.user')}</span>
              <strong>{ticket.username || '-'}</strong>
              {mode === 'admin' && ticket.username ? <Link to={`/sys/user?username=${encodeURIComponent(ticket.username)}`}>
                {t('chat.viewUser')}</Link> : null}
            </div>
          </section> : null}
          <section className="ticket-chat-card">
            <h3>{t('chat.info')}</h3>
            <dl className="ticket-chat-fields">
              <dt>{t('detail.status')}</dt>
              <dd>{editable ? <Select<TicketStatus> value={ticket.status} aria-label={t('detail.status')} disabled={update.isPending}
                onChange={(status) => update.mutate({ status })}
                options={ticketStatuses.map((value) => ({ value, label: t(`status.${value}`) }))} /> : <StatusTag status={ticket.status} />}</dd>
              <dt>{t('detail.priority')}</dt>
              <dd>{editable ? <Select<TicketPriority> value={ticket.priority} aria-label={t('detail.priority')} disabled={update.isPending}
                onChange={(priority) => update.mutate({ priority })}
                options={ticketPriorities.map((value) => ({ value, label: t(`priorities.${value}`) }))} /> : <PriorityTag priority={ticket.priority} />}</dd>
              {mode === 'admin' ? <>
                <dt>{t('detail.assignee')}</dt>
                <dd>{editable ? <>
                  <Select<string> value={ticket.assignee_user_id ?? ''} aria-label={t('detail.assignee')}
                    disabled={update.isPending} onChange={(assignee) => update.mutate({ assignee_user_id: assignee })}
                    options={[{ value: '', label: t('detail.unassigned') }, ...(assignees.data ?? []).map((item) => ({
                      value: item.user_id, label: item.display_name || item.username }))]} />
                  {me && ticket.assignee_user_id !== me ? <Button size="small" type="link" disabled={update.isPending}
                    onClick={() => update.mutate({ assignee_user_id: me })}>{t('detail.claim')}</Button> : null}
                </> : ticket.assignee_name || t('detail.unassigned')}</dd>
              </> : null}
              <dt>{t('columns.category')}</dt><dd>{t(`categories.${ticket.category}`)}</dd>
              {ticket.site_domain ? <><dt>{t('chat.site')}</dt><dd>{ticket.site_domain}</dd></> : null}
              {ticket.order_id ? <><dt>{t('chat.order')}</dt><dd className="ticket-chat-mono">{ticket.order_id}</dd></> : null}
              <dt>{t('chat.created')}</dt><dd>{formatTime(ticket.created_at)}</dd>
              {mode === 'admin' && ticket.first_response_at ? <>
                <dt>{t('chat.firstResponse')}</dt><dd>{formatTime(ticket.first_response_at)}</dd></> : null}
            </dl>
            {mode === 'admin' && ticket.sla_breached ? <Alert type="error" showIcon message={t('detail.sla')} /> : null}
          </section>
        </aside>
      </div>
      {preview ? <Image className="visually-hidden" src={preview.url} alt={preview.name}
        preview={{ visible: true, src: preview.url, onVisibleChange: (visible) => { if (!visible) closePreview() } }} /> : null}
    </div>
  )
}

function TicketList({ mode, onOpen, createKey, initialCreate }: {
  mode: TicketMode; onOpen: (id: string) => void; createKey: IdempotencyKey
  initialCreate?: { siteID?: string }
}) {
  const { t } = useTranslation('tickets')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  // 编号/标题搜索边输入边生效（400ms 防抖），写进 URL（q）可分享。
  const [initialParams] = useSearchParams()
  const [filters, setFilters] = useState<TicketFilters>(() => ({ limit: 20, offset: 0, ...(filterParam(initialParams, 'q') ? { q: filterParam(initialParams, 'q') } : {}) }))
  const [search, setSearch] = useState(() => filterParam(initialParams, 'q'))
  const [creating, setCreating] = useState(mode === 'user' && Boolean(initialCreate))
  const [notifying, setNotifying] = useState(false)
  const { message } = App.useApp()
  const errorText = useErrorText()
  const manage = useStaffManage(mode)
  const [selected, setSelected] = useState<Ticket[]>([])
  const list = useQuery({ queryKey: ['tickets', mode, 'list', filters], queryFn: () => ticketsApi.list(token, mode, filters) })
  const summary = useQuery({ queryKey: ['tickets', mode, 'summary'], queryFn: () => ticketsApi.summary(token, mode) })
  const unavailable = list.error instanceof ApiError && (list.error.status === 404 || list.error.status === 501)
  const set = (change: TicketFilters) => setFilters((current) => ({ ...current, ...change, offset: 0 }))
  useLiveApply(search.trim(), filters.q ?? '', (next) => set({ q: next || undefined }))
  useFilterUrl({ q: filters.q })
  const categorySelect = (allLabel: string) => <Select<TicketCategory | ''> style={mode === 'admin' ? undefined : { width: 140 }} value={filters.category ?? ''}
    aria-label={t('filters.category')} onChange={(value) => set({ category: value || undefined })}
    options={[{ value: '', label: allLabel }, ...ticketCategories.map((value) => ({ value, label: t(`categories.${value}`) }))]} />
  // 行内改状态/关闭/删除与批量关闭/删除。每个工单按自己的 revision 单独提交，
  // 部分失败时列出失败码，成功的不回滚；完成后刷新列表与汇总。
  const ops = useMutation({
    mutationFn: async ({ action, tickets }: { action: TicketStatus | 'delete'; tickets: Ticket[] }) => {
      const results = await Promise.allSettled(tickets.map((item) => action === 'delete'
        ? ticketsApi.remove(token, item.id)
        : ticketsApi.update(token, item.id, { expected_revision: item.revision, status: action })))
      return { action, results }
    },
    onSuccess: ({ action, results }) => {
      const failed = results.filter((item): item is PromiseRejectedResult => item.status === 'rejected')
      const ok = results.length - failed.length
      if (failed.length) {
        void message.error(t('ops.batchPartial', { ok, failed: failed.length,
          codes: [...new Set(failed.map((item) => errorText(item.reason)))].join('；') }))
      } else if (results.length > 1) {
        void message.success(t('ops.batchDone', { ok }))
      } else {
        void message.success(action === 'delete' ? t('ops.deleted') : action === 'closed' ? t('ops.closed') : t('detail.updated'))
      }
      setSelected([])
      void client.invalidateQueries({ queryKey: ['tickets', mode] })
    },
  })
  return (
    <>
      {/* tp-b7：用户端不放页内标题（面包屑即标题），只留给读屏；管理端不变。 */}
      <Typography.Title level={4} className={mode === 'admin' ? undefined : 'visually-hidden'}>{mode === 'admin' ? t('adminTitle') : t('title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{mode === 'admin' ? t('adminSubtitle') : t('subtitle')}</Typography.Paragraph>
      {unavailable ? <Alert type="info" showIcon message={t('errors.unavailable')} />
        : list.error ? <FeedbackWhen title={t('errors.load', { code: codeOf(list.error) })} /> : null}
      {!unavailable ? <>
        <div className="ticket-list-head">
          {summary.data ? <ul className="ticket-list-summary" aria-label={t('chat.summary')}>
            <li className={summary.data.unread ? 'is-primary' : undefined}>
              <span>{t('chat.unread')}</span><strong>{summary.data.unread}</strong></li>
            {mode === 'admin' ? <>
              <li><span>{t('chat.pending')}</span><strong>{summary.data.pending ?? 0}</strong></li>
              <li><span>{t('chat.mine')}</span><strong>{summary.data.mine ?? 0}</strong></li>
              <li className={summary.data.sla_breached ? 'is-error' : undefined}>
                <span>{t('chat.sla')}</span><strong>{summary.data.sla_breached ?? 0}</strong></li>
            </> : null}
          </ul> : <span />}
          {/* 工单通知（个人设置，代理商面不提供）与管理端新建工单。 */}
          <Space wrap className="ticket-list-actions">
            {/* 工单提醒只发给能处理工单的平台成员（后端 notifyStaff：tickets.manage / platform.admin）。 */}
            {mode === 'user' || manage ? <Button icon={<BellRing size={14} aria-hidden="true" />} onClick={() => setNotifying(true)}>
              {t('notify.open')}</Button> : null}
            {mode === 'user' ? <Button type="primary" onClick={() => setCreating(true)}>{t('create.open')}</Button> : null}
            {mode === 'admin' && manage ? <Button type="primary" icon={<Plus size={14} aria-hidden="true" />}
              onClick={() => setCreating(true)}>{t('staffCreate.open')}</Button> : null}
          </Space>
        </div>
        {/* 管理端 6 个条件时常显 状态+搜索，分类/优先级/处理人/只看超时进高级筛选；用户/代理商只有 3 个，全部常显。
            下拉与勾选仍是选中即生效；查询提交搜索框。 */}
        <AdvancedFilters
          className="ticket-list-advfilters"
          storageKey={`tickets-${mode}`}
          columns={4}
          primary={<>
            <Select<TicketStatus | ''> style={{ width: 140 }} value={filters.status ?? ''} aria-label={t('filters.status')}
              onChange={(value) => set({ status: value || undefined })}
              options={[{ value: '', label: `${t('filters.status')}：${t('filters.all')}` },
                ...ticketStatuses.map((value) => ({ value, label: t(`status.${value}`) }))]} />
            {mode === 'admin' ? null : categorySelect(`${t('filters.category')}：${t('filters.all')}`)}
            <Input allowClear style={{ width: 220 }} placeholder={t('filters.search')} aria-label={t('filters.search')}
              value={search} onChange={(event) => setSearch(event.target.value)} onPressEnter={() => set({ q: search.trim() || undefined })} />
          </>}
          items={mode === 'admin' ? [
            { key: 'category', label: t('filters.category'), applied: filters.category ? t(`categories.${filters.category}`) : undefined,
              field: categorySelect(t('filters.all')) },
            { key: 'priority', label: t('filters.priority'), applied: filters.priority ? t(`priorities.${filters.priority}`) : undefined,
              field: <Select<TicketPriority | ''> value={filters.priority ?? ''} aria-label={t('filters.priority')}
                onChange={(value) => set({ priority: value || undefined })}
                options={[{ value: '', label: t('filters.all') }, ...ticketPriorities.map((value) => ({ value, label: t(`priorities.${value}`) }))]} /> },
            { key: 'assignee', label: t('filters.assignee'), applied: filters.assignee === 'me' ? t('filters.mine') : filters.assignee === 'none' ? t('filters.unassigned') : undefined,
              field: <Select<string> value={filters.assignee ?? ''} aria-label={t('filters.assignee')}
                onChange={(value) => set({ assignee: value || undefined })}
                options={[{ value: '', label: t('filters.all') }, { value: 'me', label: t('filters.mine') }, { value: 'none', label: t('filters.unassigned') }]} /> },
            { key: 'sla_breached', label: t('filters.slaBreached'), applied: filters.sla_breached ? t('filters.on') : undefined,
              field: <Checkbox checked={Boolean(filters.sla_breached)} onChange={(event) => set({ sla_breached: event.target.checked || undefined })}>
                {t('filters.slaBreached')}</Checkbox> },
          ] : []}
          onQuery={() => { if (search.trim() === (filters.q ?? '')) void list.refetch(); else set({ q: search.trim() || undefined }) }}
          onReset={() => { setSearch(''); setFilters({ limit: 20, offset: 0 }) }}
          onClearAdvanced={() => set({ category: undefined, priority: undefined, assignee: undefined, sla_breached: undefined })}
          onRemove={(key) => set({ [key]: undefined })}
        />
        {manage && selected.length ? <div className="ticket-list-batch" role="region" aria-label={t('ops.selected', { count: selected.length })}>
          <span>{t('ops.selected', { count: selected.length })}</span>
          <ConfirmAction title={t('ops.batchCloseConfirm', { count: selected.length })} impact={t('ops.closeImpact')}
            onConfirm={() => ops.mutate({ action: 'closed', tickets: selected.filter((item) => item.status !== 'closed') })}>
            <Button size="small" loading={ops.isPending}>{t('ops.batchClose')}</Button>
          </ConfirmAction>
          <ConfirmAction title={t('ops.batchDeleteConfirm', { count: selected.length })} impact={t('ops.deleteImpact')}
            onConfirm={() => ops.mutate({ action: 'delete', tickets: selected })}>
            <Button size="small" danger loading={ops.isPending}>{t('ops.batchDelete')}</Button>
          </ConfirmAction>
          <Button size="small" type="link" onClick={() => setSelected([])}>{t('ops.clearSelection')}</Button>
        </div> : null}
        <Table<Ticket> className="ticket-list-table" rowKey="id" size="small" loading={list.isLoading} dataSource={list.data?.items ?? []}
          scroll={{ x: manage ? 1100 : 900 }}
          rowSelection={manage ? { selectedRowKeys: selected.map((item) => item.id),
            onChange: (_keys, rows) => setSelected(rows) } : undefined}
          pagination={{ current: Math.floor((filters.offset ?? 0) / (filters.limit ?? 20)) + 1, pageSize: filters.limit ?? 20,
            total: list.data?.total ?? 0, showSizeChanger: false,
            onChange: (page) => { setSelected([]); setFilters((current) => ({ ...current, offset: (page - 1) * (current.limit ?? 20) })) } }}
          columns={[
            { title: t('columns.number'), dataIndex: 'ticket_no', width: 90, render: (value: number) => `#${value}` },
            { title: t('columns.subject'), key: 'subject', ...(manage ? { width: 240 } : {}), render: (_: unknown, ticket) => <div className="ticket-list-subject">
              <span className={`ticket-list-dot${ticket.unread ? ' is-unread' : ''}`} aria-hidden="true" />
              <div>
                <Button type="link" className={ticket.unread ? 'is-unread' : undefined} onClick={() => onOpen(ticket.id)}>{ticket.subject}</Button>
                {ticket.unread ? <span className="visually-hidden">{t('badges.unread')}</span> : null}
                {ticket.sla_breached ? <Tag color="red">{t('badges.sla')}</Tag> : null}
                {ticket.site_domain ? <div className="ticket-list-sub">{ticket.site_domain}</div> : null}
              </div>
            </div> },
            { title: t('columns.category'), dataIndex: 'category', render: (value: TicketCategory) => t(`categories.${value}`) },
            { title: t('columns.status'), dataIndex: 'status', render: (value: TicketStatus) => <StatusTag status={value} /> },
            { title: t('columns.priority'), dataIndex: 'priority',
              render: (value: TicketPriority) => <PriorityTag priority={value} /> },
            ...(mode === 'admin' ? [
              { title: t('columns.user'), dataIndex: 'username' },
              { title: t('columns.assignee'), key: 'assignee', render: (_: unknown, ticket: Ticket) => ticket.assignee_name || t('detail.unassigned') },
            ] : []),
            { title: t('columns.lastReply'), key: 'lastReply', render: (_: unknown, ticket: Ticket) => ticket.last_reply_author || '-' },
            { title: t('columns.updated'), dataIndex: 'last_message_at',
              render: (value: string) => <time dateTime={value} title={formatTime(value)}>{formatRelative(value, t)}</time> },
            ...(manage ? [{ title: t('columns.actions'), key: 'actions', fixed: 'right' as const, width: 224,
              render: (_: unknown, item: Ticket) => <Space size={4}>
                <Select<TicketStatus> size="small" style={{ width: 108 }} value={item.status} disabled={ops.isPending}
                  aria-label={t('ops.changeStatus') + ' #' + item.ticket_no}
                  onChange={(status) => ops.mutate({ action: status, tickets: [item] })}
                  options={ticketStatuses.map((value) => ({ value, label: t(`status.${value}`) }))} />
                {item.status !== 'closed' ? <ConfirmAction title={t('ops.closeConfirm', { no: item.ticket_no })} impact={t('ops.closeImpact')}
                  onConfirm={() => ops.mutate({ action: 'closed', tickets: [item] })}>
                  <Button size="small" type="link" aria-label={t('ops.closeTicket') + ' #' + item.ticket_no}>{t('ops.close')}</Button>
                </ConfirmAction> : null}
                <ConfirmAction title={t('ops.deleteConfirm', { no: item.ticket_no })} impact={t('ops.deleteImpact')}
                  onConfirm={() => ops.mutate({ action: 'delete', tickets: [item] })}>
                  <Button size="small" type="link" danger aria-label={t('ops.deleteTicket') + ' #' + item.ticket_no}>{t('ops.delete')}</Button>
                </ConfirmAction>
              </Space> }] : []),
          ]} />
      </> : null}
      {creating && mode === 'user' ? <CreateDrawer open createKey={createKey} initialSiteID={initialCreate?.siteID} onClose={() => setCreating(false)} onCreated={(detail) => {
        setCreating(false)
        void client.invalidateQueries({ queryKey: ['tickets', mode] })
        onOpen(detail.ticket.id)
      }} /> : null}
      {creating && mode === 'admin' ? <TicketStaffCreateDrawer errorText={errorText} onClose={() => setCreating(false)}
        onCreated={(detail) => {
          setCreating(false)
          void client.invalidateQueries({ queryKey: ['tickets', mode] })
          onOpen(detail.ticket.id)
        }} /> : null}
      {notifying ? <TicketNotifyDrawer staff={mode === 'admin'} onClose={() => setNotifying(false)} /> : null}
    </>
  )
}

export default function TicketsPage({ mode }: { mode: TicketMode }) {
  const { t } = useTranslation('tickets')
  const principal = useSessionStore((state) => state.principal)
  const [params, setParams] = useSearchParams()
  // Kept above the drawer and the detail view so leaving and coming back with
  // the same content still replays an attempt whose outcome was unknown.
  const createKey = useIdempotencyKey('ticket-create')
  const replyKey = useIdempotencyKey('ticket-reply')
  const permissions = principal?.permissions ?? []
  const allowed = mode === 'user' ? principal?.scope_kind === 'tenant'
    : principal?.scope_kind === 'platform' && [ticketsReadPermission, ticketsManagePermission, 'platform.admin']
      .some((permission) => permissions.includes(permission))
  if (!allowed) return <Result status="error" icon={<ShieldOff size={72} aria-hidden="true" />} title={t('errors.forbidden')} />
  const id = params.get('id')
  const newSite = params.get('site_id')?.toLowerCase()
  const initialCreate = params.get('new') === '1'
    ? { siteID: newSite && relatedIDPattern.test(newSite) ? newSite : undefined } : undefined
  return (
    <div className="page">
      {id ? <TicketDetailView mode={mode} id={id} replyKey={replyKey} onBack={() => setParams({})} />
        : <TicketList mode={mode} createKey={createKey} initialCreate={initialCreate} onOpen={(next) => setParams({ id: next })} />}
    </div>
  )
}
