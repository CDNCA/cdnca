import type { TFunction } from 'i18next'

import '../../i18n/siteCnameRegeneration'

// Explains a CNAME failure code from the site (cname_failure_code) in words,
// naming the CNAME domain where it matters.
export function cnameFailureText(
  code: string | null | undefined,
  domain: string | null | undefined,
  t: TFunction<'siteCnameRegeneration'>,
  exists: (key: string) => boolean,
  // FLOW001：普通用户没有“节点管理”菜单，平台侧缺失只告诉他联系管理员（默认按管理员）。
  admin = true,
): string {
  if (!admin && cnameFailureNeedsLine(code)) return t('tenantFailures.line')
  // 原文指向“节点管理 → DNS配置”的平台侧原因；其余原因不含菜单路径，照常显示具体原因。
  if (!admin && (code === 'dns_provider_not_configured' || code === 'cname_no_default_zone' ||
    (code === 'cname_zone_not_configured' && !domain))) return t('tenantFailures.platform')
  if (!code) return t('failures.unknown')
  if (code === 'cname_zone_not_configured' && !domain) return t('failures.cname_zone_not_configured_default')
  const key = `failures.${code}`
  return exists(`siteCnameRegeneration:${key}`) ? t(key as 'failures.unknown', { domain: domain ?? '' }) : t('failures.unknown')
}

// Failure codes fixed under 节点管理 > DNS配置 (/node/dns).
const dnsConfigCodes = new Set(['dns_provider_not_configured', 'cname_zone_not_configured', 'cname_zone_provider_mismatch'])

export function cnameFailureNeedsDnsConfig(code: string | null | undefined): boolean {
  return !!code && dnsConfigCodes.has(code)
}

export const dnsConfigPath = '/node/dns'

// FLOW001：缺可用线路（平台默认线路组 / 套餐线路组或其节点）——管理员去线路组处理。
const lineCodes = new Set(['cname_no_default_line_group', 'node_group_unavailable', 'node_targets_unavailable'])
// 平台侧 DNS / CNAME 域名缺失——普通用户只能联系管理员。
const platformCodes = new Set([...dnsConfigCodes, 'cname_no_default_zone', 'platform_dns_sync_failed', 'domain_blocked'])

export function cnameFailureNeedsLine(code: string | null | undefined): boolean {
  return !!code && lineCodes.has(code)
}

export function cnameFailureNeedsPlatform(code: string | null | undefined): boolean {
  return !!code && platformCodes.has(code)
}

export const lineGroupsPath = '/node/line-group'
export const tenantTicketsPath = '/account/tickets'
/** 普通用户就当前网站提交工单：打开新建并预填网站。 */
export const tenantTicketPathFor = (siteID?: string) => `${tenantTicketsPath}?new=1${siteID ? `&site_id=${encodeURIComponent(siteID)}` : ''}`

export type SiteAccessGap = 'line' | 'cname' | 'certificate'

/**
 * FLOW001：接入是否就绪（与“配置已保存”“节点同步”分开）。列表与详情共用这一判定：
 * CNAME 失败按原因归到缺线路或缺 CNAME，生成中/未生成算缺 CNAME，HTTPS 开着但没绑证书算缺证书。
 */
export function siteAccessGap(site: {
  cname: string
  cname_state?: 'pending' | 'failed' | 'done' | null
  cname_failure_code?: string | null
  https_enabled: boolean
  https_certificate_bound?: boolean
}): SiteAccessGap | null {
  if (site.cname_state === 'failed') return cnameFailureNeedsLine(site.cname_failure_code) ? 'line' : 'cname'
  if (site.cname_state === 'pending' || !site.cname) return 'cname'
  if (site.https_enabled && site.https_certificate_bound === false) return 'certificate'
  return null
}
