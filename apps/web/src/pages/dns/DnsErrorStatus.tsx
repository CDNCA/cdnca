import { useTranslation } from 'react-i18next'

import type { PlatformDNSError } from '../../api/dnsPlatform'
import '../../i18n/dnsConfig'

// A failed 记录修复 / 清除CDN无关解析 item arrives as "<item id> (<code>)":
// "修复记录 <owner> [A ..] [AAAA ..]" or "删除记录 <name> <type> <value> #<zone>/<id>".
const itemPattern = /^(修复记录|删除记录) (\S+).*\(([a-z][a-z0-9_.-]*)\)$/

// DNS错误: the newest DNS write outcome when it failed (CNAME allocation,
// retarget, 记录修复, 清除CDN无关解析 or the configuration sync). A later
// successful outcome clears it (the API returns no error then).
export default function DnsErrorStatus({ error }: { error: PlatformDNSError | null }) {
  const { t } = useTranslation('dnsConfig')
  if (!error) {
    return <span className="dns-status is-ok" role="status"><i aria-hidden="true" />{t('status.ok')}</span>
  }
  const describe = (code: string) => t(`errors.codes.${code}`, { defaultValue: '' }) || t('errors.codes.dns_reconcile_failed')
  const source = t(`errorSources.${error.source}`, { defaultValue: error.source })
  let detail = error.message ? `：${error.message}` : ''
  const item = error.message ? itemPattern.exec(error.message) : null
  if (item) {
    const [, kind, name, code] = item
    const advice = t(`advice.${code}`, { defaultValue: '' })
    detail = `。${t(kind === '修复记录' ? 'itemError.repair' : 'itemError.cleanup', { name, reason: describe(code) })}${advice ? `，${advice}` : ''}`
  }
  const text = `${source}：${describe(error.code)}${detail}`
  const at = new Date(error.at)
  const when = Number.isNaN(at.getTime()) ? '' : ` ${at.toLocaleString('zh-CN', { hour12: false })}`
  return <span className="dns-status is-error" role="status" title={`${text}${when}`}>
    <i aria-hidden="true" />{text}
  </span>
}
