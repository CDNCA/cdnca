import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useApp } from '@cdnca/ui'

import i18n from '../i18n'
import { createApprovalFetch } from './approvalFetch'

// The dialog and its approvalCenter texts load on the first prompt, not with
// the first page: the host itself is on every page.
const loadDialog = () => import('./ApprovalPromptDialog')
const ApprovalPromptDialog = lazy(loadDialog)

// ApprovalPromptHost installs the 428 approval_required fetch wrapper once and
// renders the reason dialog it asks for. Mounted inside the antd App context.
export function ApprovalPromptHost() {
  const { message } = useApp()
  const [rule, setRule] = useState<string | null>(null)
  // Once shown, the dialog stays mounted so the close animation still plays.
  const [shown, setShown] = useState(false)
  const [reason, setReason] = useState('')
  const resolver = useRef<((value: string | null) => void) | null>(null)
  const notify = useRef(message)
  notify.current = message

  useEffect(() => {
    const original = globalThis.fetch
    globalThis.fetch = createApprovalFetch(original, (next) => new Promise((resolve) => {
      resolver.current = resolve
      setReason('')
      setRule(next)
      setShown(true)
    }), (result) => {
      // The dialog module registers the approvalCenter namespace; a notice
      // always follows a prompt, so this only waits when the load is still running.
      void loadDialog().then(() => {
        const api = notify.current
        if (result === 'submitted') void api.success(i18n.t('notices.submitted', { ns: 'approvalCenter' }))
        else void api.info(i18n.t('notices.cancelled', { ns: 'approvalCenter' }))
      })
    })
    return () => { globalThis.fetch = original }
  }, [])

  const close = (value: string | null) => {
    resolver.current?.(value)
    resolver.current = null
    setRule(null)
  }
  if (!shown) return null
  return (
    <Suspense fallback={null}>
      <ApprovalPromptDialog rule={rule} reason={reason} onReasonChange={setReason} onClose={close} />
    </Suspense>
  )
}
