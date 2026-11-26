import { useId, useState } from 'react'
import { Button, Tooltip } from 'antd'
import { CircleCheck, CircleX, Clipboard, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearchParams } from 'react-router-dom'

import type { SiteAccessCheckCode, SiteAccessReadiness as Readiness, SitePackageSuspension } from '../../api/sites'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/siteAccessReadiness'
import { accessStatusLabel, checkReason, firstFailing, type Check, type Translate } from './accessReadinessText'
import {
  cnameFailureNeedsDnsConfig, cnameFailureNeedsLine, cnameFailureNeedsPackage, cnameFailureNeedsPlatform, cnameFailureText,
  dnsConfigPath, lineGroupsPath, tenantTicketPathFor,
} from './cnameFailureText'

// 服务端 access_readiness 的两种呈现——列表状态列的一行（第一个未通过项），
// 详情“接入状态”卡逐项列出通过/未通过、原因与按角色的下一步（普通用户只给工单入口）。

/**
 * 列表状态列：第一个未通过项；悬停给出原因。/53 补充：名称只是状态，不再拼原因；
 * 传 reasonID 时原因放进这个 id 的隐藏节点，由外层按钮 aria-describedby 引用
 * （Tooltip 会把子元素的 aria-describedby 换成浮层 id，不能挂在这里的 span 上）。
 */
export function SiteAccessStatus({ readiness, reasonID }: { readiness: Readiness; reasonID?: string }) {
  const { t, i18n } = useTranslation('siteAccessReadiness')
  const exists = (key: string) => i18n.exists(key)
  const failing = firstFailing(readiness)
  const label = accessStatusLabel(readiness, t, exists)
  const reason = failing ? checkReason(t, exists, failing) : ''
  const node = (
    <span data-testid="site-access-status" className={`site-access-status is-${readiness.state}`}>
      {label}
    </span>
  )
  if (!reason) return node
  return <><Tooltip title={reason}>{node}</Tooltip>{reasonID ? <span id={reasonID} hidden>{reason}</span> : null}</>
}

const nodesPath = '/node/list'
const publicationsPath = '/site/publications'

interface Advice {
  /** 53 补充：普通用户遇到平台侧原因只给工单入口，不再加“需要平台处理”“网站配置已保存”这类通用句。 */
  text?: string
  action?: { label: string; onClick: () => void }
}

function adviceFor(check: Check, admin: boolean, cname: string, t: Translate, go: {
  navigate: (path: string) => void
  https: () => void
  basic: () => void
  siteID: string
  cnameFailureCode?: string | null
  packageSuspension?: SitePackageSuspension | null
}): Advice | null {
  const ticket = { label: t('actions.contactAdmin'), onClick: () => go.navigate(tenantTicketPathFor(go.siteID)) }
  switch (check.code) {
    case 'package':
      // 社区版不绑定套餐：服务端若仍报告套餐检查项，不给去套餐页面的入口。
      return null
    case 'line_group':
      if (!admin) return { action: ticket }
      return check.detail === 'no_online_nodes'
        ? { text: t('advice.adminNodes'), action: { label: t('actions.goNodes'), onClick: () => go.navigate(nodesPath) } }
        : { text: t('advice.adminLineGroup'), action: { label: t('actions.goLineGroups'), onClick: () => go.navigate(lineGroupsPath) } }
    case 'cname_generated': {
      if (check.detail === 'cname_pending') return null
      // autodefense-ux / 管理员按原因去 DNS 配置或线路组，用户提交工单；其余看 CNAME 字段旁的原因与“重新生成”。
      const code = go.cnameFailureCode ?? check.detail
      if (!admin && (cnameFailureNeedsPlatform(code) || cnameFailureNeedsLine(code))) return { action: ticket }
      if (admin && cnameFailureNeedsPackage(code)) {
        return { text: t('advice.adminPackageCname') }
      }
      if (admin && cnameFailureNeedsDnsConfig(code)) {
        return { text: t('advice.adminDnsConfig'), action: { label: t('actions.goDnsConfig'), onClick: () => go.navigate(dnsConfigPath) } }
      }
      if (admin && cnameFailureNeedsLine(code)) {
        return { text: t('advice.adminLineGroup'), action: { label: t('actions.goLineGroups'), onClick: () => go.navigate(lineGroupsPath) } }
      }
      return { text: t('advice.cnameRegenerate'), action: { label: t('actions.viewCname'), onClick: go.basic } }
    }
    case 'dns_resolved':
      if (check.detail === 'waiting_cname' || check.detail === 'no_domains') return null
      // 原因里已写明改成哪个 CNAME，这里只提示生效时间。
      if (check.dns_mismatch?.observed.length) return { text: t('advice.waitDNS') }
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

// 重新发布：发布失败、最近一次发布不含本站或还没发布过时可用（发布中、网站停用时不给）。
const republishable = new Set(['publish_failed', 'site_not_in_publication', 'not_published'])

// 未通过项的标题是「字段名：状态」，状态按原因码分等待（会自动推进）与未通过。
const waitingDetails = new Set(['cname_pending', 'waiting_cname', 'not_checked', 'dns_lookup_failed', 'certificate_not_active', 'publishing', 'market_delivering'])

const checkOrder: SiteAccessCheckCode[] = ['package', 'line_group', 'cname_generated', 'dns_resolved', 'https_cert', 'published']

/**
 * 详情“接入状态”卡。onCheckNow 缺省时不显示“立即检查”（无权限或只读预览）；
 * onRepublish 缺省时“已发布到节点”旁不显示“重新发布”（无 sites.manage）。
 */
export function SiteAccessReadinessCard({ readiness, siteID, admin, cname, cnameFailureCode, cnameDomain, packageSuspension, onCheckNow, onRepublish }: {
  readiness: Readiness
  siteID: string
  admin: boolean
  cname: string
  /** basic.cname_failure_code：区分 DNS 未配置（去 DNS 配置/工单）与其他失败（看 CNAME 字段、重新生成）。 */
  cnameFailureCode?: string | null
  /** basic.cname_domain：失败原因里写出的 CNAME 域名。 */
  cnameDomain?: string | null
  /** package_suspension：订阅暂停的来源与原因。 */
  packageSuspension?: SitePackageSuspension | null
  onCheckNow?: () => Promise<unknown>
  onRepublish?: () => Promise<unknown>
}) {
  const { t, i18n } = useTranslation('siteAccessReadiness')
  const { t: tCname } = useTranslation('siteCnameRegeneration')
  const exists = (key: string) => i18n.exists(key)
  const idPrefix = useId()
  const navigate = useNavigate()
  const [, setSearchParams] = useSearchParams()
  const [checking, setChecking] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [republishing, setRepublishing] = useState(false)
  const [republishNotice, setRepublishNotice] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  // 订阅暂停或终止时套餐项已说明不下发、配置保留，发布项的同一原因不再重复一行。
  const packageOut = readiness.checks.find((check) => check.code === 'package' && !check.ok &&
    (check.detail === 'package_suspended' || check.detail === 'package_cancelled'))?.detail
  const checks = readiness.checks
    .filter((check) => !(packageOut && check.code === 'published' && !check.ok && check.detail === packageOut))
    .sort((a, b) => checkOrder.indexOf(a.code) - checkOrder.indexOf(b.code))
  const https = () => setSearchParams((current) => {
    const next = new URLSearchParams(current)
    next.set('tab', 'https')
    return next
  })
  const dns = checks.find((check) => check.code === 'dns_resolved')
  const basic = () => {
    setSearchParams(new URLSearchParams())
    document.querySelector<HTMLElement>('.site-basic-cname button, .site-basic-cname')?.scrollIntoView?.({ block: 'center' })
  }

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

  const republish = async () => {
    if (!onRepublish) return
    setRepublishing(true)
    setRepublishNotice(null)
    try {
      await onRepublish()
      setRepublishNotice(t('republishQueued'))
    } catch (error) {
      const failure = error as { status?: number; code?: string }
      setRepublishNotice(failure.status === 409 && failure.code === 'publish_in_flight' ? t('republishInFlight')
        : failure.status === 409 && failure.code === 'package_subscription_suspended' ? t('republishSuspended') : t('republishFailed'))
    } finally {
      setRepublishing(false)
    }
  }

  // CNAME 生成失败写出失败码对应的那一句原因（与 CNAME 字段旁一致），不再只说“原因见基本设置”。
  const reasonOf = (check: Check) => check.code === 'cname_generated' && !check.ok && cnameFailureCode
    ? cnameFailureText(cnameFailureCode, cnameDomain, tCname, exists, admin) : checkReason(t, exists, check)
  const detailed = checks.map((check) => ({
    check,
    reason: reasonOf(check),
    advice: check.ok ? null : adviceFor(check, admin, cname, t, { navigate, https, basic, siteID, cnameFailureCode, packageSuspension }),
  }))
  const failed = detailed.filter(({ check }) => !check.ok)
  const passed = detailed.filter(({ check }) => check.ok)
  return (
    <section id="site-access-card" className={`site-access-card is-${readiness.state}`} aria-labelledby="site-access-card-title" data-testid="site-access-card">
      {/* 整体状态只在页头说一次；卡里列出要处理的未通过项与动作，已通过项默认收起。 */}
      <header className="site-access-card-head">
        <h3 id="site-access-card-title">{t('title')}</h3>
        <span className="site-access-card-time">
          {dns?.checked_at ? t('checkedAt', { time: formatDateTime(dns.checked_at, i18n.resolvedLanguage) }) : t('notChecked')}
        </span>
        {onCheckNow ? (
          <Button size="small" className="site-access-check-now" icon={<RefreshCw size={13} aria-hidden="true" />} loading={checking}
            onClick={() => void checkNow()}>
            {t('checkNow')}
          </Button>
        ) : null}
      </header>
      {notice ? <p className="site-access-card-notice" role="status">{notice}</p> : null}
      {failed.length ? (
        <ul className="site-access-check-details">
          {failed.map(({ check, reason, advice }) => {
            // 53 补充：这一行的按钮名称只说动作，原因经 aria-describedby 关联同一行的说明。
            const reasonID = reason ? `${idPrefix}-${check.code}-reason` : undefined
            return (
            <li key={check.code} id={`site-access-check-${check.code}`} className="site-access-check-detail is-failed">
              <CircleX size={13} aria-hidden="true" className="site-access-check-icon" />
              <strong>{t('checkTitle', { name: t(`checks.${check.code}`), status: t(waitingDetails.has(check.detail) ? 'status.waiting' : 'status.failed') })}</strong>
              {reason ? <span id={reasonID} className="site-access-check-reason">{reason}</span> : null}
              {check.dns_mismatch?.observed.length ? (
                <Button type="link" size="small" className="site-access-copy-cname" icon={<Clipboard size={13} aria-hidden="true" />}
                  onClick={() => {
                    if (!navigator.clipboard) return
                    void navigator.clipboard.writeText(check.dns_mismatch!.expected_cname).then(() => setCopied(true), () => undefined)
                  }}>
                  {copied ? t('dnsMismatch.copied') : t('dnsMismatch.copy')}
                </Button>
              ) : null}
              {advice ? (
                <span className="site-access-check-advice">
                  {advice.text ? <span>{advice.text}</span> : null}
                  {advice.action ? <Button type="link" size="small" aria-describedby={reasonID} onClick={advice.action.onClick}>{advice.action.label}</Button> : null}
                </span>
              ) : null}
              {check.code === 'published' && onRepublish && republishable.has(check.detail) ? (
                <span className="site-access-check-advice">
                  <Button size="small" className="site-access-republish" icon={<RefreshCw size={13} aria-hidden="true" />}
                    loading={republishing} aria-describedby={reasonID} onClick={() => void republish()}>
                    {t('republish')}
                  </Button>
                  {republishNotice ? <span role="status">{republishNotice}</span> : null}
                </span>
              ) : null}
            </li>
            )
          })}
        </ul>
      ) : null}
      {passed.length ? (
        <details className="site-access-passed">
          <summary>{t('passedCount', { count: passed.length })}</summary>
          <ul className="site-access-checks">
            {passed.map(({ check, reason }) => (
              <li key={check.code} id={`site-access-check-${check.code}`} className="site-access-check is-ok">
                <CircleCheck size={13} aria-hidden="true" className="site-access-check-icon" />
                <span className="site-access-check-title">{t(`checks.${check.code}`)}</span>
                <span className="site-access-check-result">{check.detail && reason ? reason : t('pass')}</span>
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </section>
  )
}
