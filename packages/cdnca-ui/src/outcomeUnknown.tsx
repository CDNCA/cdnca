// OutcomeUnknown (usage: ../COMPONENTS.md "错误与警告反馈"). Its own module so a
// front end that never shows it keeps antd Alert / Space out of the first load.
import { useContext, useState, type ReactNode } from 'react'
import { Alert, Button, ConfigProvider, Space } from 'antd'

import { FeedbackDialog, textOf, type FeedbackType } from './feedback'

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
