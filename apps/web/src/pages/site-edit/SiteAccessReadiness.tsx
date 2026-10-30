import { useState } from 'react'
import { Button, Tooltip } from 'antd'
import { CircleCheck, CircleX, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearchParams } from 'react-router-dom'

import type { SiteAccessCheckCode, SiteAccessReadiness as Readiness } from '../../api/sites'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/siteAccessReadiness'
import { accessStatusLabel, firstFailing, lookup, type Check, type Translate } from './accessReadinessText'
import { lineGroupsPath, tenantTicketPathFor } from './cnameFailureText'

// fix-readiness：服务端 access_readiness 的两种呈现——列表状态列的一行（第一个未通过项），
// 详情“接入状态”卡逐项列出通过/未通过、原因与按角色的下一步（普通用户只给工单入口）。

/** 列表状态列：第一个未通过项；悬停/读屏给出原因。 */
export function SiteAccessStatus({ readiness }: { readiness: Readiness }) {
  const { t, i18n } = useTranslation('siteAccessReadiness')
  const exists = (key: string) => i18n.exists(key)
  const failing = firstFailing(readiness)
  const label = accessStatusLabel(readiness, t, exists)
  const reason = failing ? lookup(t, exists, 'reasons', failing) : ''
  const node = (
    <span data-testid="site-access-status" className={`site-access-status is-${readiness.state}`}
      aria-label={reason ? `${label}，${reason}` : label}>
      {label}
    </span>
  )
  return reason ? <Tooltip title={reason}>{node}</Tooltip> : node
}

const nodesPath = '/node/list'
const publicationsPath = '/site/publications'

interface Advice {
  text: string
  action?: { label: string; onClick: () => void }
}

function adviceFor(check: Check, admin: boolean, cname: string, t: Translate, go: {
  navigate: (path: string) => void
  https: () => void
  siteID: string
}): Advice | null {
  const ticket = { label: t('actions.contactAdmin'), onClick: () => go.navigate(tenantTicketPathFor(go.siteID)) }
  switch (check.code) {
    case 'package':
      // 社区版不绑定套餐：服务端若仍报告套餐检查项，不给去套餐页面的入口。
      return null
    case 'line_group':
      if (!admin) return { text: t('advice.tenantPlatform'), action: ticket }
      return check.detail === 'no_online_nodes'
        ? { text: t('advice.adminNodes'), action: { label: t('actions.goNodes'), onClick: () => go.navigate(nodesPath) } }
        : { text: t('advice.adminLineGroup'), action: { label: t('actions.goLineGroups'), onClick: () => go.navigate(lineGroupsPath) } }
    case 'cname_generated':
      return null // CNAME 字段旁已有失败原因与重新生成/联系管理员（CnameFailureActions）
    case 'dns_resolved':
      if (check.detail === 'waiting_cname' || check.detail === 'no_domains') return null
      return { text: cname ? `${t('advice.dnsTarget', { cname })}${t('advice.waitDNS')}` : t('advice.waitDNS') }
    case 'https_cert':
      return check.detail === 'certificate_not_active' ? null
        : { text: t('advice.bindCertificate'), action: { label: t('actions.goHttps'), onClick: go.https } }
    case 'published':
      if (check.detail === 'site_disabled') return { text: t('advice.enableSite') }
      if (check.detail === 'publish_failed') {
        return admin
          ? { text: t('advice.adminPublish'), action: { label: t('actions.goPublications'), onClick: () => go.navigate(publicationsPath) } }
          : { text: t('advice.tenantPublish'), action: ticket }
      }
      return { text: t('advice.waitPublish') }
  }
  return null
}

const checkOrder: SiteAccessCheckCode[] = ['package', 'line_group', 'cname_generated', 'dns_resolved', 'https_cert', 'published']

/** 详情“接入状态”卡。onCheckNow 缺省时不显示“立即检查”（无权限或只读预览）。 */
export function SiteAccessReadinessCard({ readiness, siteID, admin, cname, onCheckNow }: {
  readiness: Readiness
  siteID: string
  admin: boolean
  cname: string
  onCheckNow?: () => Promise<unknown>
}) {
  const { t, i18n } = useTranslation('siteAccessReadiness')
  const exists = (key: string) => i18n.exists(key)
  const navigate = useNavigate()
  const [, setSearchParams] = useSearchParams()
  const [checking, setChecking] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const checks = [...readiness.checks].sort((a, b) => checkOrder.indexOf(a.code) - checkOrder.indexOf(b.code))
  const https = () => setSearchParams((current) => {
    const next = new URLSearchParams(current)
    next.set('tab', 'https')
    return next
  })
  const dns = checks.find((check) => check.code === 'dns_resolved')

  const checkNow = async () => {
    if (!onCheckNow) return
    setChecking(true)
    setNotice(null)
    try {
      await onCheckNow()
    } catch (error) {
      const failure = error as { status?: number; retryAfter?: number }
      setNotice(failure.status === 429 && failure.retryAfter
        ? t('throttled', { seconds: failure.retryAfter }) : t('checkFailed'))
    } finally {
      setChecking(false)
    }
  }

  const detailed = checks.map((check) => ({
    check,
    reason: lookup(t, exists, 'reasons', check),
    advice: check.ok ? null : adviceFor(check, admin, cname, t, { navigate, https, siteID }),
  }))
  return (
    <section className={`site-access-card is-${readiness.state}`} aria-labelledby="site-access-card-title" data-testid="site-access-card">
      <header className="site-access-card-head">
        <h3 id="site-access-card-title">{t('title')}</h3>
        <span className={`site-access-status is-${readiness.state}`}>{accessStatusLabel(readiness, t, exists)}</span>
        <span className="site-access-card-time">
          {dns?.checked_at ? t('checkedAt', { time: formatDateTime(dns.checked_at, i18n.resolvedLanguage) }) : t('notChecked')}
        </span>
        <ul className="site-access-checks">
          {detailed.map(({ check, reason }) => (
            <li key={check.code} className={`site-access-check ${check.ok ? 'is-ok' : 'is-failed'}`}
              title={reason ?? undefined}>
              {check.ok
                ? <CircleCheck size={13} aria-hidden="true" className="site-access-check-icon" />
                : <CircleX size={13} aria-hidden="true" className="site-access-check-icon" />}
              <span className="site-access-check-title">{t(`checks.${check.code}`)}</span>
              <span className="site-access-check-result">{check.ok ? t('pass') : t('fail')}</span>
            </li>
          ))}
        </ul>
        {onCheckNow ? (
          <Button size="small" className="site-access-check-now" icon={<RefreshCw size={13} aria-hidden="true" />} loading={checking}
            onClick={() => void checkNow()}>
            {t('checkNow')}
          </Button>
        ) : null}
      </header>
      {notice ? <p className="site-access-card-notice" role="status">{notice}</p> : null}
      {detailed.some(({ check, reason }) => !check.ok || (check.detail && reason)) ? (
        <ul className="site-access-check-details">
          {detailed.filter(({ check, reason }) => !check.ok || (check.detail && reason)).map(({ check, reason, advice }) => (
            <li key={check.code} className={`site-access-check-detail ${check.ok ? 'is-ok' : 'is-failed'}`}>
              <strong>{t(`checks.${check.code}`)}</strong>
              {reason ? <span className="site-access-check-reason">{reason}</span> : null}
              {advice ? (
                <span className="site-access-check-advice">
                  <span>{advice.text}</span>
                  {advice.action ? <Button type="link" size="small" onClick={advice.action.onClick}>{advice.action.label}</Button> : null}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  )
}
