import { Tag, Tooltip } from 'antd'
import { useTranslation } from 'react-i18next'
import type { NodeTicket } from '../api/nodeInstallationTickets'
import { nodeTicketFrozen } from '../api/nodeInstallationTickets'
import { formatDateTime } from '../i18n/formatters'
import i18n from '../i18n'
import './NodeFrozenTag.css'

// fix-stoppolicy2: a frozen node (its service ticket ended -- authorization
// expired or the controller lost its license center) keeps serving its
// existing sites but takes no new publications, scaling or upgrades.
const zhCN = {
  tag: '已冻结',
  reason: '原因：服务票据过期（授权到期或主控与授权中心失联）。已有站点继续服务，暂停新发布、扩容与升级。',
  recovery: '恢复条件：续期授权或恢复主控与授权中心连接后，节点拿到新票据自动解冻，冻结期间被拒的发布由系统自动补发。',
  notAfter: '最近票据到期时间：{{time}}',
  noTicketTime: '最近票据到期时间：节点未上报',
}
const enUS: typeof zhCN = {
  tag: 'Frozen',
  reason: 'Reason: the service ticket expired (authorization ended or the controller lost the license center). Existing sites keep serving; new publications, scaling and upgrades wait.',
  recovery: 'Recovers when the authorization is renewed or the controller reaches the license center again: the node gets a new ticket and unfreezes, and the publications it refused are redelivered automatically.',
  notAfter: 'Last ticket expired at: {{time}}',
  noTicketTime: 'Last ticket expiry: not reported by the node',
}
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'nodeFrozen', messages, true, true)
}

export function useNodeFrozenText(ticket: NodeTicket | undefined): string[] {
  const { t, i18n: active } = useTranslation('nodeFrozen')
  if (!nodeTicketFrozen(ticket)) return []
  const time = ticket?.not_after ? formatDateTime(ticket.not_after, active.resolvedLanguage) : ''
  return [t('reason'), t('recovery'), time ? t('notAfter', { time }) : t('noTicketTime')]
}

/** The 已冻结 tag with reason, recovery and last ticket expiry on hover/focus; nothing for a node that is not frozen. */
export function NodeFrozenTag({ ticket }: { ticket: NodeTicket | undefined }) {
  const { t } = useTranslation('nodeFrozen')
  const details = useNodeFrozenText(ticket)
  if (details.length === 0) return null
  const title = details.join('\n')
  return (
    <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{title}</span>} trigger={['hover', 'focus', 'click']}>
      <Tag color="warning" className="node-frozen-tag" tabIndex={0} aria-label={`${t('tag')}。${details.join(' ')}`}>
        {t('tag')}
      </Tag>
    </Tooltip>
  )
}
