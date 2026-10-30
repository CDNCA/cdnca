// Error / warning feedback that the user must acknowledge (usage: ../COMPONENTS.md
// "错误与警告反馈"). A centered dialog with the reason, optional next-step
// buttons and an always-present 「知道了」; ×, Esc and the mask close it too.
// The same feedback raised again while its dialog is open does not stack a
// second one. Success hints stay message.success (no acknowledgement needed).
import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import { Alert, Button, ConfigProvider, Modal, Space, Typography } from 'antd'

export interface FeedbackAction {
  label: ReactNode
  onClick: () => void
  /** Primary look (the suggested next step). At most one per dialog. */
  primary?: boolean
}

export interface FeedbackOptions {
  /** Reason / detail under the title. */
  detail?: ReactNode
  /** Next-step buttons, shown left of 「知道了」. Clicking one closes the dialog first. */
  actions?: FeedbackAction[]
  /** Dedupe key; defaults to the type, title and detail text. */
  key?: string
}

export type FeedbackFn = (title: ReactNode, detailOrOptions?: ReactNode | FeedbackOptions, actions?: FeedbackAction[]) => void

export interface Feedback {
  error: FeedbackFn
  warning: FeedbackFn
}

type FeedbackType = keyof Feedback

interface Item { id: number; key: string; type: FeedbackType; title: ReactNode; detail?: ReactNode; actions: FeedbackAction[]; open: boolean }

const ackText = { 'zh-CN': '知道了', 'zh-TW': '知道了', 'en-US': 'Got it' }

function useAckText() {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  return ackText[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
}

function isOptions(value: unknown): value is FeedbackOptions {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !('$$typeof' in value)
    && ('detail' in value || 'actions' in value || 'key' in value)
}

const textOf = (node: ReactNode) => (typeof node === 'string' || typeof node === 'number' ? String(node) : '')

// Pages append the request ID to their error text: 「原因（请求 ID：xxx）」 /
// "reason (Request ID: xxx)". The dialog shows it as a small copyable line in
// the body instead (fix-feedbackui: a long ID made the title three lines).
const requestIdSuffix = /\s*[（(]\s*(?:请求\s?ID|[Rr]equest\s?ID)\s*[：:]\s*([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*[）)]\s*[。.]?\s*$/

function splitRequestId(node: ReactNode): { text: ReactNode; requestId?: string } {
  if (typeof node !== 'string') return { text: node }
  const match = requestIdSuffix.exec(node)
  return match ? { text: node.slice(0, match.index), requestId: match[1] } : { text: node }
}

// A sentence used as the title keeps only its first clause there (「请求内容无效」);
// the rest of the sentence goes to the body (「请检查输入」).
function splitTitle(title: ReactNode): { title: ReactNode; rest?: string } {
  if (typeof title !== 'string') return { title }
  // First clause break outside brackets (「（如 a，b）」 stays whole).
  let depth = 0
  let at = -1
  for (let index = 0; index < title.length && at < 0; index += 1) {
    const char = title[index]
    if (char === '（' || char === '(') depth += 1
    else if ((char === '）' || char === ')') && depth > 0) depth -= 1
    else if (depth === 0 && (char === '，' || char === '；' || char === '。')) at = index
  }
  if (at <= 0) return { title }
  const rest = title.slice(at + 1).trim()
  return rest ? { title: title.slice(0, at), rest } : { title: title.slice(0, at) }
}

const empty = (node: ReactNode) => node === undefined || node === null || node === '' || node === false

const FeedbackContext = createContext<Feedback | null>(null)

// FeedbackWhen instances showing the same failure: the first one mounted owns
// the dialog, the others stay closed (signature -> owner id).
const WhenOwners = createContext<Map<string, string> | null>(null)

// Exclamation in a circle (decorative: the title carries the meaning).
function FeedbackIcon({ type }: { type: FeedbackType }) {
  return (
    <svg className={`cdnca-feedback-icon cdnca-feedback-icon-${type}`} viewBox="0 0 24 24" width="28" height="28" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="11" fill="currentColor" />
      <rect x="11" y="6" width="2" height="8" rx="1" fill="#fff" />
      <circle cx="12" cy="17.5" r="1.25" fill="#fff" />
    </svg>
  )
}

/**
 * One error / warning dialog, controlled. useFeedback() renders it for you;
 * render it yourself only when the detail needs the page's context (router,
 * query client), e.g. a status mark that opens its reason on click.
 */
export function FeedbackDialog({ open, type, title, detail, actions = [], extra, hint, onClose, afterClose }: {
  open: boolean
  type: FeedbackType
  title: ReactNode
  detail?: ReactNode
  actions?: FeedbackAction[]
  /** Page-made buttons for the bottom row, left of 「知道了」 (FeedbackWhen / OutcomeUnknown `action`). They do not close the dialog: it closes when the page drops the failure. */
  extra?: ReactNode
  /** Small secondary line under the detail. */
  hint?: ReactNode
  onClose: () => void
  afterClose?: () => void
}) {
  const ok = useAckText()
  const requestIdLabel = useContext(ConfigProvider.ConfigContext).locale?.locale === 'en' ? 'Request ID: ' : '请求 ID：'
  // Short reason in the title; the rest of the sentence and the request ID go to the body.
  const fromTitle = splitRequestId(title)
  const fromDetail = splitRequestId(detail)
  // Only a server error sentence (it carried a request ID) is cut down; page-written titles stay as written.
  const split = fromTitle.requestId && empty(fromDetail.text) ? splitTitle(fromTitle.text) : { title: fromTitle.text }
  const body = empty(fromDetail.text) ? split.rest : fromDetail.text
  const requestId = fromTitle.requestId ?? fromDetail.requestId
  const primary = actions.filter((action) => action.primary)
  const secondary = actions.filter((action) => !action.primary)
  const button = (action: FeedbackAction, index: number) => (
    <Button key={index} type={action.primary ? 'primary' : 'default'} onClick={() => { onClose(); action.onClick() }}>{action.label}</Button>
  )
  // One bottom row, right-aligned, the primary button last (iView Modal.confirm).
  const ack = <Button key="ack" type={primary.length ? 'default' : 'primary'} autoFocus={!primary.length} onClick={onClose}>{ok}</Button>
  return (
    <Modal
      open={open}
      centered
      width={416}
      className={`cdnca-feedback cdnca-feedback-${type}`}
      title={<span className="cdnca-feedback-title"><FeedbackIcon type={type} /><span>{split.title}</span></span>}
      onCancel={onClose}
      afterClose={afterClose}
      footer={(
        <div className="cdnca-feedback-footer">
          {extra ? <span className="cdnca-feedback-actions">{extra}</span> : null}
          {primary.length ? [ack, ...secondary.map(button), ...primary.map(button)] : [...secondary.map(button), ack]}
        </div>
      )}
    >
      {empty(body) ? null : <div className="cdnca-feedback-detail">{body}</div>}
      {empty(hint) ? null : <div className="cdnca-feedback-hint">{hint}</div>}
      {requestId ? (
        <div className="cdnca-feedback-request-id">
          <Typography.Text type="secondary" copyable={{ text: requestId }}>{requestIdLabel}{requestId}</Typography.Text>
        </div>
      ) : null}
    </Modal>
  )
}

/**
 * A failure held in page state (mutation error, submit error) shown as a
 * dialog instead of an in-page Alert: render it where the Alert was, under the
 * same condition. It opens when mounted and again when the title/detail text
 * changes; 「知道了」/×/Esc close it and call onClose (e.g. clear the error).
 * `action` (retry buttons) is shown under the detail.
 */
export function FeedbackWhen({ type = 'error', title, detail, action, onClose }: {
  type?: FeedbackType
  title: ReactNode
  detail?: ReactNode
  action?: ReactNode
  onClose?: () => void
}) {
  const signature = `${type}\u0000${textOf(title)}\u0000${textOf(detail)}`
  const [dismissed, setDismissed] = useState<string | null>(null)
  const owners = useContext(WhenOwners)
  const id = useId()
  const [owner, setOwner] = useState(!owners)
  useEffect(() => {
    if (!owners) return
    const current = owners.get(signature)
    if (current === undefined) owners.set(signature, id)
    setOwner(owners.get(signature) === id)
    return () => { if (owners.get(signature) === id) owners.delete(signature) }
  }, [owners, signature, id])
  return (
    <FeedbackDialog open={owner && dismissed !== signature} type={type} title={title} detail={detail} extra={action}
      onClose={() => { setDismissed(signature); onClose?.() }} />
  )
}

const outcomeText = {
  'zh-CN': { details: '查看说明', hint: '关闭后，可在该区域旁的提示条中继续处理。' },
  'zh-TW': { details: '查看說明', hint: '關閉後，可在該區域旁的提示條中繼續處理。' },
  'en-US': { details: 'Details', hint: 'After closing, continue from the notice next to this section.' },
}

/**
 * A write whose result is unknown, locking a block of the page until the user
 * retries the exact request or abandons it. Render it next to the block it
 * locks (not at the page top/bottom): it opens a warning dialog with the
 * explanation (closable), and keeps a compact bar with `action` (「按原请求重试 /
 * 放弃并刷新」) in place so the user can still recover after closing it.
 */
export function OutcomeUnknown({ type = 'warning', title, detail, action, className }: {
  type?: FeedbackType
  title: ReactNode
  detail?: ReactNode
  action?: ReactNode
  className?: string
}) {
  const signature = `${textOf(title)}\u0000${textOf(detail)}`
  const [dismissed, setDismissed] = useState<string | null>(null)
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  const text = outcomeText[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
  const open = dismissed !== signature
  // The recovery buttons live in one place at a time: the dialog's bottom row
  // while it is open, the bar once it is closed.
  return (
    <>
      <Alert className={className ? `cdnca-outcome-bar ${className}` : 'cdnca-outcome-bar'} type={type} showIcon role="status" message={title}
        action={<Space size={4} wrap><Button size="small" type="link" onClick={() => setDismissed(null)}>{text.details}</Button>{open ? null : action}</Space>} />
      <FeedbackDialog open={open} type={type} title={title} detail={detail} hint={text.hint} extra={open ? action : undefined}
        onClose={() => setDismissed(signature)} />
    </>
  )
}

/** Renders the feedback dialogs; CdncaProvider mounts it, pages call useFeedback(). */
export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Item[]>([])
  // Keys on screen, kept in a ref so calls in one batch dedupe synchronously.
  const shown = useRef(new Map<string, number>())
  const [whenOwners] = useState(() => new Map<string, string>())
  const nextId = useRef(0)
  const close = useCallback((id: number) => {
    for (const [key, value] of shown.current) if (value === id) shown.current.delete(key)
    setItems((list) => list.map((item) => (item.id === id ? { ...item, open: false } : item)))
  }, [])
  const remove = useCallback((id: number) => setItems((list) => list.filter((item) => item.id !== id)), [])

  const api = useMemo<Feedback>(() => {
    const show = (type: FeedbackType): FeedbackFn => (title, detailOrOptions, extraActions) => {
      const options: FeedbackOptions = isOptions(detailOrOptions) ? detailOrOptions : { detail: detailOrOptions, actions: extraActions }
      const texted = textOf(title) || textOf(options.detail)
      const key = options.key ?? (texted ? `${type}\u0000${textOf(title)}\u0000${textOf(options.detail)}` : `${type}\u0000#${nextId.current}`)
      if (shown.current.has(key)) return
      const id = ++nextId.current
      shown.current.set(key, id)
      setItems((list) => [...list, { id, key, type, title, detail: options.detail, actions: options.actions ?? [], open: true }])
    }
    return { error: show('error'), warning: show('warning') }
  }, [])

  return (
    <FeedbackContext.Provider value={api}>
      <WhenOwners.Provider value={whenOwners}>{children}</WhenOwners.Provider>
      {items.map((item) => (
        <FeedbackDialog key={item.id} open={item.open} type={item.type} title={item.title} detail={item.detail} actions={item.actions}
          onClose={() => close(item.id)} afterClose={() => remove(item.id)} />
      ))}
    </FeedbackContext.Provider>
  )
}

/**
 * Error / warning dialogs. Under CdncaProvider (every end and test wrapper)
 * they come from its FeedbackProvider; elsewhere antd's static Modal is used.
 */
export function useFeedback(): Feedback {
  const context = useContext(FeedbackContext)
  const ok = useAckText()
  return useMemo(() => context ?? {
    error: (title, detail) => { Modal.error({ title, content: isOptions(detail) ? detail.detail : detail, centered: true, closable: true, okText: ok }) },
    warning: (title, detail) => { Modal.warning({ title, content: isOptions(detail) ? detail.detail : detail, centered: true, closable: true, okText: ok }) },
  }, [context, ok])
}
