// Error / warning feedback that the user must acknowledge (usage: ../COMPONENTS.md
// "错误与警告反馈"). A centered dialog with the reason, optional next-step
// buttons and an always-present 「知道了」; ×, Esc and the mask close it too.
// The same feedback raised again while its dialog is open does not stack a
// second one. Success hints stay message.success (no acknowledgement needed).
import { createContext, lazy, Suspense, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import { ConfigProvider } from 'antd'

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

export type FeedbackType = keyof Feedback

interface Item { id: number; key: string; type: FeedbackType; title: ReactNode; detail?: ReactNode; actions: FeedbackAction[]; open: boolean }

const ackText = { 'zh-CN': '知道了', 'zh-TW': '知道了', 'en-US': 'Got it' }

/** 「知道了」 in the antd locale of the nearest ConfigProvider (Chinese without one). */
export function useAckText() {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  return ackText[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
}

function isOptions(value: unknown): value is FeedbackOptions {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !('$$typeof' in value)
    && ('detail' in value || 'actions' in value || 'key' in value)
}

export const textOf = (node: ReactNode) => (typeof node === 'string' || typeof node === 'number' ? String(node) : '')


const FeedbackContext = createContext<Feedback | null>(null)

// FeedbackWhen instances showing the same failure: the first one mounted owns
// the dialog, the others stay closed (signature -> owner id).
const WhenOwners = createContext<Map<string, string> | null>(null)

export interface FeedbackDialogProps {
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
}

type DialogBody = typeof import('./feedbackDialog').default
// Once loaded, render the body directly: React.lazy suspends again on every
// fresh mount, so a second dialog (or a retry action inside it) would appear a
// tick late and the "same request retry" button would not be there yet.
let loadedDialogBody: DialogBody | undefined
const loadDialogBody = () => import('./feedbackDialog').then((module) => { loadedDialogBody = module.default; return module })
const FeedbackDialogBody = lazy(loadDialogBody)
/** Loads the dialog body ahead of the first error (tests, idle prefetch). */
export function preloadFeedbackDialog(): Promise<unknown> { return loadDialogBody() }

/**
 * One error / warning dialog, controlled. useFeedback() renders it for you;
 * render it yourself only when the detail needs the page's context (router,
 * query client), e.g. a status mark that opens its reason on click.
 * The dialog body loads the first time it opens; once shown it
 * stays mounted so closing still animates.
 */
export function FeedbackDialog(props: FeedbackDialogProps) {
  const [shown, setShown] = useState(props.open)
  if (props.open && !shown) setShown(true)
  if (!shown) return null
  const Loaded = loadedDialogBody
  if (Loaded) return <Loaded {...props} />
  return <Suspense fallback={null}><FeedbackDialogBody {...props} /></Suspense>
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
  // The Modal module is loaded with the dialog body, so the static fallback waits for it.
  return useMemo(() => context ?? {
    error: (title, detail) => { void import('antd/es/modal').then(({ default: Modal }) => Modal.error({ title, content: isOptions(detail) ? detail.detail : detail, centered: true, closable: true, okText: ok })) },
    warning: (title, detail) => { void import('antd/es/modal').then(({ default: Modal }) => Modal.warning({ title, content: isOptions(detail) ? detail.detail : detail, centered: true, closable: true, okText: ok })) },
  }, [context, ok])
}
