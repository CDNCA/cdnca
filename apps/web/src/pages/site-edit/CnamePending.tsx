import { useState } from 'react'
import { FeedbackDialog, type FeedbackAction } from '@cdnca/ui'
import { Tag } from 'antd'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import '../../i18n/siteCnameRegeneration'

// CNAME 仍是 pending 时的展示，列表 CNAME 列与网站详情 CNAME 字段共用。
// 服务端 cname_pending_code 说明任务停滞的原因（任务不存在 / 已结束未写回 / 排队无人处理 / 超时仍在重试），
// 有原因时显示“生成中（已停滞）”并可点开看原因、重新生成、去任务中心；没有原因就是正常生成中。
function cnamePendingReason(code: string | null | undefined, t: (key: string) => string,
  exists: (key: string) => boolean): string | null {
  if (!code) return null
  const key = `pending.${code}`
  return exists(`siteCnameRegeneration:${key}`) ? t(key) : null
}

export default function CnamePending({ code, taskID, admin, onRegenerate, regenerateDisabled }: {
  code: string | null | undefined
  taskID?: string | null
  admin: boolean
  onRegenerate?: () => void
  regenerateDisabled?: boolean
}) {
  const { t, i18n } = useTranslation('siteCnameRegeneration')
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const reason = cnamePendingReason(code, t, (key) => i18n.exists(key))
  if (!reason) return <Tag color="processing" data-testid="site-cname-pending">{t('cell.pending')}</Tag>
  const actions: FeedbackAction[] = []
  if (onRegenerate && !regenerateDisabled) actions.push({ label: t('action'), primary: true, onClick: () => { setOpen(false); onRegenerate() } })
  if (taskID) {
    const path = `${admin ? '/sys/task' : '/task'}?task_id=${encodeURIComponent(taskID)}`
    actions.push({ label: t('pending.taskCenter'), onClick: () => navigate(path) })
  }
  return (
    <>
      <button type="button" className="site-cname-pending-mark" aria-haspopup="dialog" title={reason}
        aria-label={`${t('pending.stuck')}：${reason}`} data-testid="site-cname-stalled" onClick={() => setOpen(true)}>
        <Tag color="warning">{t('pending.stuck')}</Tag>
      </button>
      <FeedbackDialog
        open={open}
        type="warning"
        title={t('pending.stuck')}
        detail={<div data-testid="cname-pending-reason">{reason}</div>}
        actions={actions}
        onClose={() => setOpen(false)}
      />
    </>
  )
}
