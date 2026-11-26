import { describe, expect, it } from 'vitest'

import i18n from '../../i18n'
import { cnameFailureText, cnameRegenerateBlockedForTenant, siteAccessGap } from './cnameFailureText'

describe('cnameFailureText (cname-retry)', () => {
  const t = i18n.getFixedT('zh-CN', 'siteCnameRegeneration')
  const exists = (key: string) => i18n.exists(key, { lng: 'zh-CN' })

  it('names the package CNAME domain missing from the DNS configuration', () => {
    expect(cnameFailureText('cname_zone_not_configured', 'cdn.cdnca.com', t, exists))
      .toBe('套餐 CNAME 域名 cdn.cdnca.com 未在 DNS 配置的 CNAME 域名里')
    expect(cnameFailureText('cname_zone_not_configured', '', t, exists))
      .toBe('未配置默认 CNAME 域名（节点管理 → DNS配置 → CNAME域名）')
    expect(cnameFailureText('dns_provider_not_configured', null, t, exists)).toBe('尚未配置 DNS 服务商（节点管理 → DNS配置）')
  })

  it('explains a DNS permission refusal instead of a provider failure', () => {
    expect(cnameFailureText('dns_permission_denied', null, t, exists)).toBe('操作人没有该租户的 DNS 权限')
    const en = i18n.getFixedT('en-US', 'siteCnameRegeneration')
    expect(cnameFailureText('dns_permission_denied', null, en, (key) => i18n.exists(key, { lng: 'en-US' })))
      .toBe('The operator has no DNS permission for this tenant')
  })

  it('fix-nopkg: tells a site without a package to set a platform default line group', () => {
    expect(cnameFailureText('cname_no_default_line_group', '', t, exists))
      .toBe('网站未绑定套餐且没有平台默认线路组，请在节点管理 → 线路组设一个平台默认线路组')
    expect(cnameFailureText('cname_no_default_zone', '', t, exists))
      .toBe('网站未绑定套餐，且没有参与随机分配的 CNAME 域名，也没有默认 CNAME 域名（节点管理 → DNS配置 → CNAME域名）')
  })

  it('fix-cnamerand: a CNAME domain may sit at any DNS provider; only its own must be enabled', () => {
    expect(cnameFailureText('cname_zone_provider_mismatch', 'b.cdn.example', t, exists))
      .toBe('CNAME 域名 b.cdn.example 所在的 DNS 服务商已停用（节点管理 → DNS配置）')
    expect(cnameFailureText('cname_zone_not_configured', '', t, exists))
      .toBe('未配置默认 CNAME 域名（节点管理 → DNS配置 → CNAME域名）')
  })

  it('FLOW001: gives a tenant one platform-side reason (the ticket button sits next to it)', () => {
    for (const code of ['cname_no_default_line_group', 'node_group_unavailable', 'node_targets_unavailable']) {
      expect(cnameFailureText(code, '', t, exists, false)).toBe('平台尚未配置可用线路，请联系管理员。网站配置已保存，管理员配置后可重新生成。')
    }
    // 其余平台侧原因一句具体说明，不写管理员菜单路径。
    expect(cnameFailureText('dns_provider_not_configured', '', t, exists, false))
      .toBe('平台 DNS 服务商未配置，管理员处理后会自动重新生成。')
    expect(cnameFailureText('cname_zone_not_configured', '', t, exists, false))
      .toBe('平台没有可用的 CNAME 域名，管理员处理后会自动重新生成。')
    expect(cnameFailureText('cname_no_default_zone', '', t, exists, false))
      .toBe('平台没有可用的 CNAME 域名，管理员处理后可重新生成。')
    expect(cnameFailureText('cname_zone_not_configured', 'cdn.cdnca.com', t, exists, false))
      .toBe('套餐的 CNAME 域名 cdn.cdnca.com 找不到对应的 DNS 区域，管理员处理后会自动重新生成。')
    for (const code of ['dns_provider_not_configured', 'cname_package_domain_missing', 'cname_zone_not_configured',
      'cname_zone_provider_mismatch', 'cname_no_default_zone', 'platform_dns_sync_failed', 'domain_blocked']) {
      expect(cnameFailureText(code, 'cdn.cdnca.com', t, exists, false)).not.toMatch(/节点管理|DNS配置|套餐管理|网站配置已保存|请联系管理员/)
    }
    // the administrator keeps the menu path
    expect(cnameFailureText('cname_no_default_line_group', '', t, exists, true)).toMatch(/节点管理 → 线路组/)
    // tenant-side reasons stay as they are
    expect(cnameFailureText('dns_permission_denied', null, t, exists, false)).toBe('操作人没有该租户的 DNS 权限')
  })

  it('a package without a CNAME domain and a missing DNS provider read differently', () => {
    expect(cnameFailureText('cname_package_domain_missing', '', t, exists))
      .toBe('所选套餐未绑定 CNAME 域名，请在套餐管理里为该套餐选择 CNAME 域名')
    expect(cnameFailureText('cname_package_domain_missing', '', t, exists, false))
      .toBe('所选套餐未绑定 CNAME 域名，管理员处理后会自动重新生成。')
    const en = i18n.getFixedT('en-US', 'siteCnameRegeneration')
    const enExists = (key: string) => i18n.exists(key, { lng: 'en-US' })
    expect(cnameFailureText('cname_package_domain_missing', '', en, enExists, false)).toMatch(/^The selected package has no CNAME domain\. The CNAME is regenerated automatically/)
    expect(cnameFailureText('dns_provider_not_configured', '', en, enExists, false)).toMatch(/^The platform has no DNS provider configured\. The CNAME is regenerated automatically/)
  })

  it('a tenant does not retry what only the platform can fix', () => {
    for (const code of ['dns_provider_not_configured', 'cname_package_domain_missing', 'cname_zone_not_configured', 'cname_zone_provider_mismatch', 'platform_dns_sync_failed']) {
      expect(cnameRegenerateBlockedForTenant(code)).toBe(true)
    }
    for (const code of ['cname_no_default_line_group', 'dns_reconcile_failed', 'cname_label_exhausted', null]) {
      expect(cnameRegenerateBlockedForTenant(code)).toBe(false)
    }
  })

  it('FLOW001: siteAccessGap names the missing line, CNAME or certificate', () => {
    const base = { cname: 'a.cdn.example.net', cname_state: 'done' as const, https_enabled: false }
    expect(siteAccessGap(base)).toBeNull()
    expect(siteAccessGap({ ...base, cname_state: 'failed', cname_failure_code: 'cname_no_default_line_group' })).toBe('line')
    expect(siteAccessGap({ ...base, cname_state: 'failed', cname_failure_code: 'dns_reconcile_failed' })).toBe('cname')
    expect(siteAccessGap({ ...base, cname: '', cname_state: 'pending' })).toBe('cname')
    expect(siteAccessGap({ ...base, https_enabled: true, https_certificate_bound: false })).toBe('certificate')
    expect(siteAccessGap({ ...base, https_enabled: true, https_certificate_bound: true })).toBeNull()
  })

  it('falls back for unknown or missing codes', () => {
    expect(cnameFailureText('some_future_code', 'x.example.com', t, exists)).toBe('原因未知')
    expect(cnameFailureText(null, null, t, exists)).toBe('原因未知')
  })
})
