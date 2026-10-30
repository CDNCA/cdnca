import { useId, useState } from 'react'
import { Button } from 'antd'
import { useTranslation } from 'react-i18next'
import { certificateOrderFailureReason, certificateOrderFailureText } from '../i18n/certificateFailureCodes'
import './CertificateFailureReason.css'

type Order = Parameters<typeof certificateOrderFailureReason>[0]

// 约两行（失败原因列 428px、12px 字号）能放下的字符数；更短的原因不需要展开按钮。
const expandableReasonLength = 120

// 申请记录“失败原因”先给分类文案，下面跟证书签发机构返回的具体原因
// （服务端已脱敏、≤512 字符）。原因默认两行，悬停看全文，按钮展开/收起。
export function CertificateFailureReason({ order, fallback }: { order: Order, fallback: string }) {
  const { t } = useTranslation('certificateFailureCodes')
  const [expanded, setExpanded] = useState(false)
  const reasonID = useId()
  const category = certificateOrderFailureText(order, t)
  const reason = certificateOrderFailureReason(order)
  if (!category) return <>{fallback}</>
  return (
    <div className="certificate-failure">
      <span className="certificate-failure-cell" title={category}>{category}</span>
      {reason && (
        <>
          <span id={reasonID} className={`certificate-failure-reason${expanded ? ' is-expanded' : ''}`} title={reason}>{reason}</span>
          {reason.length > expandableReasonLength && <Button type="link" size="small" className="certificate-failure-toggle" aria-controls={reasonID}
            aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}>
            {expanded ? t('collapseReason') : t('expandReason')}
          </Button>}
        </>
      )}
    </div>
  )
}
