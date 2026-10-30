import { useState, type ReactNode } from 'react'
import { FeedbackDialog, type FeedbackAction } from '@cdnca/ui'
import { CircleAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import '../../i18n/siteCnameRegeneration'
import { cnameFailureNeedsDnsConfig, cnameFailureNeedsLine, cnameFailureNeedsPlatform, dnsConfigPath, lineGroupsPath, tenantTicketPathFor } from './cnameFailureText'

// The CNAME failure in place, shared by the site list (CNAME column) and the
// site edit page (CNAME field): a 「生成失败」 mark that opens a dialog with
// the reason, 去 DNS 配置 (platform admins, DNS configuration codes), 去线路组
// (platform admins, missing line), 联系管理员 (tenants, platform-side gaps),
// 重新生成 and 知道了. The reason code (as a short Chinese label, 10-27 用户) and
// extra detail sit in the dialog.
export default function CnameFailureActions({ code, reason, admin, onRegenerate, regenerateDisabled, extraDetail, siteID }: {
  code: string | null | undefined
  /** The one-sentence reason (cnameFailureText). */
  reason: string
  admin: boolean
  onRegenerate?: () => void
  regenerateDisabled?: boolean
  extraDetail?: ReactNode
  /** 普通用户“联系管理员”时预填到工单的网站。 */
  siteID?: string
}) {
  const { t } = useTranslation('siteCnameRegeneration')
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const actions: FeedbackAction[] = []
  if (admin && cnameFailureNeedsDnsConfig(code)) actions.push({ label: t('cell.goDnsConfig'), primary: true, onClick: () => navigate(dnsConfigPath) })
  // FLOW001：缺线路时管理员去线路组；普通用户遇到平台侧缺失只给工单入口，不指向他没有的菜单。
  if (admin && cnameFailureNeedsLine(code)) actions.push({ label: t('cell.goLineGroups'), primary: true, onClick: () => navigate(lineGroupsPath) })
  if (!admin && (cnameFailureNeedsLine(code) || cnameFailureNeedsPlatform(code))) actions.push({ label: t('cell.contactAdmin'), primary: true, onClick: () => navigate(tenantTicketPathFor(siteID)) })
  if (onRegenerate && !regenerateDisabled) actions.push({ label: t('cell.regenerate'), onClick: onRegenerate })
  return (
    <>
      <button
        type="button"
        className="site-cname-failure-mark"
        aria-haspopup="dialog"
        aria-label={t('cell.failedMarkLabel', { reason })}
        title={reason}
        onClick={() => setOpen(true)}
      >
        <CircleAlert size={14} aria-hidden="true" />
        <span>{t('cell.failedMark')}</span>
      </button>
      <FeedbackDialog
        open={open}
        type="error"
        title={t('cell.failedTitle')}
        detail={<div data-testid="cname-failure-details">
          <div data-testid="cname-failure-text">{reason}</div>
          <div className="site-cname-failure-code" data-testid="cname-failure-code">{t('cell.code', { label: t(`codes.${code || 'unknown'}`, { defaultValue: t('codes.unknown') }) })}</div>
          {extraDetail}
        </div>}
        actions={actions}
        onClose={() => setOpen(false)}
      />
    </>
  )
}
