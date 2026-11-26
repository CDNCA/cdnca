import { useTranslation } from 'react-i18next'

import type { SiteAccessReadiness as Readiness } from '../../api/sites'
import '../../i18n/siteAccessReadiness'
import './SiteCreatedProgress.css'

// 53 补充：创建网站后的横幅分三项说进度——保存、节点发布（access_readiness 的 published）、
// DNS 接入（cname_generated / dns_resolved）。不断言公网能否访问：网站可能已用自己的解析指到节点。

type Tone = 'ok' | 'pending' | 'failed'

const publishFailed = new Set(['publish_failed', 'market_delivery_failed'])
const publishInFlight = new Set(['publishing', 'market_delivering'])

function publishState(readiness: Readiness | null | undefined): { key: string; tone: Tone } {
  const check = readiness?.checks.find((item) => item.code === 'published')
  if (!check) return { key: 'unknown', tone: 'pending' }
  if (check.ok) return { key: 'published', tone: 'ok' }
  if (publishFailed.has(check.detail)) return { key: 'publishFailed', tone: 'failed' }
  return { key: publishInFlight.has(check.detail) ? 'publishing' : 'notPublished', tone: 'pending' }
}

function dnsState(readiness: Readiness | null | undefined): { key: string; tone: Tone } {
  if (!readiness) return { key: 'unknown', tone: 'pending' }
  const cname = readiness.checks.find((item) => item.code === 'cname_generated')
  // CNAME 没生成时只提示去看 DNS 接入（原因在网站详情的接入状态卡），不当作失败。
  if (cname && !cname.ok) return { key: cname.detail === 'cname_pending' ? 'cnamePending' : 'checkDns', tone: 'pending' }
  const dns = readiness.checks.find((item) => item.code === 'dns_resolved')
  return dns && !dns.ok ? { key: 'dnsWaiting', tone: 'pending' } : { key: 'dnsReady', tone: 'ok' }
}

/** readiness 缺省（新网站还不在当前列表页里）时发布与 DNS 两项显示“待确认”。 */
export default function SiteCreatedProgress({ readiness }: { readiness?: Readiness | null }) {
  const { t } = useTranslation('siteAccessReadiness')
  const publish = publishState(readiness)
  const dns = dnsState(readiness)
  const items = [
    { name: 'saved', label: t('created.saved'), value: t('created.savedDone'), tone: 'ok' as Tone },
    { name: 'publish', label: t('created.publish'), value: t(`created.publishStates.${publish.key}` as 'created.saved'), tone: publish.tone },
    { name: 'dns', label: t('created.dns'), value: t(`created.dnsStates.${dns.key}` as 'created.saved'), tone: dns.tone },
  ]
  return (
    <ul className="site-created-progress" aria-label={t('created.label')} data-testid="site-created-progress">
      {items.map((item) => (
        <li key={item.name} className={`is-${item.tone}`} data-testid={`site-created-${item.name}`}>
          {t('created.item', { label: item.label, value: item.value })}
        </li>
      ))}
    </ul>
  )
}
