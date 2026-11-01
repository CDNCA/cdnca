// The error / warning dialog body of FeedbackDialog (feedback.tsx). Loaded the
// first time a dialog opens, so its antd Modal / Typography / Button stay out of
// every front end's first load.
import { useContext, type ReactNode } from 'react'
import { Button, ConfigProvider, Modal, Typography } from 'antd'

import { useAckText, type FeedbackAction, type FeedbackDialogProps, type FeedbackType } from './feedback'

// Pages append the request ID to their error text: 「原因（请求 ID：xxx）」 /
// "reason (Request ID: xxx)". The dialog shows it as a small copyable line in
// the body instead.
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

export default function FeedbackDialogBody({ open, type, title, detail, actions = [], extra, hint, onClose, afterClose }: FeedbackDialogProps) {
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

