import { Input, Modal, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import '../i18n/approvalCenter'

// The reason dialog of ApprovalPromptHost. Loaded on the first 428
// approval_required: its antd fields and the approvalCenter namespace stay out
// of the first load.
export default function ApprovalPromptDialog({ rule, reason, onReasonChange, onClose }: {
  rule: string | null
  reason: string
  onReasonChange: (value: string) => void
  onClose: (value: string | null) => void
}) {
  const { t } = useTranslation('approvalCenter')
  const trimmed = reason.trim()
  return (
    <Modal open={rule !== null} title={t('prompt.title')} okText={t('prompt.submit')} cancelText={t('prompt.cancel')}
      okButtonProps={{ disabled: trimmed.length === 0 || trimmed.length > 500 }} onOk={() => onClose(trimmed)} onCancel={() => onClose(null)} destroyOnHidden>
      <Typography.Paragraph>{t('prompt.description', { rule: rule ? t(`rules.${rule}`, { defaultValue: rule }) : '' })}</Typography.Paragraph>
      <Input.TextArea aria-label={t('prompt.reason')} placeholder={t('prompt.reasonPlaceholder')} maxLength={500} rows={3} value={reason} onChange={(event) => onReasonChange(event.target.value)} />
    </Modal>
  )
}
