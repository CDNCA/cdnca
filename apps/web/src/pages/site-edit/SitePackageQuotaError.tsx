
import { ApiError } from '../../api/auth'
import type { SiteBasicConfig } from '../../api/sites'
import i18n from '../../i18n'
import '../../i18n/sitePackageQuota'

// 套餐额度拒绝（409 package_resource_quota_exceeded，details 写明资源）
// 标在被拒的字段下：网站数标在套餐选择，域名 / 根域名标在域名组，非标准端口标在本次改动的端口框。
export type SitePackageQuotaField = 'package' | 'domains' | 'http_listen_ports' | 'https_listen_ports'

const quotaResources = new Set(['sites', 'domains', 'root_domains', 'http_ports', 'stream_ports'])

/** 「…数量已达上限（已用/上限）」 of a package quota refusal that names its resource, or null for any other error. */
export function packageQuotaText(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.code !== 'package_resource_quota_exceeded' || !error.packageQuota) return null
  const { resource, used, limit } = error.packageQuota
  return quotaResources.has(resource) ? i18n.t(`sitePackageQuota:reached.${resource}`, { used, limit }) : null
}

export interface SitePackageQuotaNotice {
  field: SitePackageQuotaField
  text: string
}

const sameList = (left: string[], right: string[]) => JSON.stringify(left) === JSON.stringify(right)

/** The in-place notice of a basic-section save refused by the package quota, or null for any other error. */
export function sitePackageQuotaNotice(error: unknown, sent: SiteBasicConfig, stored: SiteBasicConfig): SitePackageQuotaNotice | null {
  const text = packageQuotaText(error)
  if (!text) return null
  const resource = (error as ApiError).packageQuota!.resource
  let field: SitePackageQuotaField
  if (resource === 'sites') field = 'package'
  else if (resource === 'domains' || resource === 'root_domains') field = 'domains'
  else if (resource === 'http_ports') {
    field = !sameList(sent.https_listen_ports, stored.https_listen_ports) && sameList(sent.http_listen_ports, stored.http_listen_ports)
      ? 'https_listen_ports' : 'http_listen_ports'
  } else return null
  return { field, text }
}

/** The notice under its field. */
export function SitePackageQuotaError({ notice }: { notice: SitePackageQuotaNotice; admin: boolean }) {
  return (
    <span className="site-field-error site-package-quota-error" data-testid="site-package-quota-error">
      {notice.text}
    </span>
  )
}
