import { useEffect, useRef, useState } from 'react'
import { App, Input, Modal, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import '../i18n/approvalCenter'
import { createApprovalFetch } from './approvalFetch'

// ApprovalPromptHost installs the 428 approval_required fetch wrapper once and
// renders the reason dialog it asks for. Mounted inside the antd App context.
export function ApprovalPromptHost() {
  const { t } = useTranslation('approvalCenter')
  const { message } = App.useApp()
  const [rule, setRule] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  const resolver = useRef<((value: string | null) => void) | null>(null)
  const notify = useRef({ t, message })
  notify.current = { t, message }

  useEffect(() => {
    const original = globalThis.fetch
    globalThis.fetch = createApprovalFetch(original, (next) => new Promise((resolve) => {
      resolver.current = resolve
      setReason('')
      setRule(next)
    }), (result) => {
      const { t: translate, message: api } = notify.current
      if (result === 'submitted') void api.success(translate('notices.submitted'))
      else void api.info(translate('notices.cancelled'))
    })
    return () => { globalThis.fetch = original }
  }, [])

  const close = (value: string | null) => {
    resolver.current?.(value)
    resolver.current = null
    setRule(null)
  }
  const trimmed = reason.trim()
  return (
    <Modal open={rule !== null} title={t('prompt.title')} okText={t('prompt.submit')} cancelText={t('prompt.cancel')}
      okButtonProps={{ disabled: trimmed.length === 0 || trimmed.length > 500 }} onOk={() => close(trimmed)} onCancel={() => close(null)} destroyOnHidden>
      <Typography.Paragraph>{t('prompt.description', { rule: rule ? t(`rules.${rule}`, { defaultValue: rule }) : '' })}</Typography.Paragraph>
      <Input.TextArea aria-label={t('prompt.reason')} placeholder={t('prompt.reasonPlaceholder')} maxLength={500} rows={3} value={reason} onChange={(event) => setReason(event.target.value)} />
    </Modal>
  )
}
