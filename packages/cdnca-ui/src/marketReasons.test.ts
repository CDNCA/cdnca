import { describe, expect, it } from 'vitest'

import { closeReason, marketReason, marketReasonCodes, marketReasonDetail } from './marketReasons'

describe('marketReason (MC12 E3)', () => {
  it('explains known codes in Chinese with who acts next', () => {
    const r = marketReason('offer_quota_exceeded', 'zh-CN')
    expect(r.known).toBe(true)
    expect(r.reason).toContain('报价')
    expect(r.next).not.toBe('')
    expect(marketReason('no_supply').reason).toContain('有效供给')
  })

  it('reads the seller site market_ prefix', () => {
    expect(marketReason('market_offer_quota_exceeded', 'zh-CN')).toMatchObject({ known: true, code: 'market_offer_quota_exceeded' })
  })

  it('keeps an unknown code visible with a generic next step', () => {
    const r = marketReason('brand_new_code', 'zh-CN')
    expect(r.known).toBe(false)
    expect(r.reason).toContain('brand_new_code')
    expect(r.next).toContain('请求 ID')
  })

  it('maps close codes exactly, then by range', () => {
    expect(closeReason(20002, 'zh-CN')).toMatchObject({ known: true, reason: '连续违反 SLA' })
    expect(closeReason(10099, 'zh-CN')).toMatchObject({ known: false, reason: '卖方关闭（10099）' })
    expect(closeReason(1, 'en-US').reason).toBe('Cancelled by the buyer')
  })

  it('explains a push refused for a site without a valid package (fix-nopkgpub4)', () => {
    const r = marketReason('site_package_unavailable', 'zh-CN')
    expect(r).toMatchObject({ known: true, code: 'site_package_unavailable' })
    expect(r.reason).toContain('有效套餐')
    expect(r.next).toContain('套餐')
  })

  it('has the same codes in both languages', () => {
    expect([...marketReasonCodes['en-US']].sort()).toEqual([...marketReasonCodes['zh-CN']].sort())
  })

  // fix-mktsiteconf: what the leaf now serves no longer has a blocker; what
  // still blocks or degrades says why, in Chinese.
  it('explains the market site rollout codes', () => {
    expect(marketReason('http3_unavailable', 'zh-CN').reason).toContain('HTTP/2')
    expect(marketReason('origin_route_geo_unmatched', 'zh-CN').reason).toBe('该供给没有对应地区的节点，此条件回源规则在该供给上不生效')
    for (const code of ['site_acl_rule', 'site_cc_rule', 'site_waf_policy', 'site_origin_routes', 'origin_routes_invalid',
      'site_l2_custom', 'site_basic_auth', 'site_http_policy', 'site_origin_auth', 'site_access_invalid', 'unsupported_site_access',
      'waf_invalid', 'unsupported_waf', 'cc_invalid', 'unsupported_cc', 'http_policy_invalid', 'unsupported_http_policy',
      'origin_auth_sealed', 'origin_auth_invalid', 'unsupported_origin_auth']) {
      expect(marketReason(code, 'zh-CN').known).toBe(true)
    }
    for (const code of ['unsupported_protocol_switch', 'unsupported_origin_scheme', 'unsupported_backup_origin', 'force_https',
      'tls_client_auth', 'balance_method', 'site_cache_policy', 'site_security_policy', 'origin_max_conns']) {
      expect(marketReason(code, 'zh-CN').known).toBe(false)
    }
  })

  it('names the sub-reason of a rule that cannot be carried', () => {
    expect(marketReasonDetail('unsupported_cc', 'activation_pending', 'zh-CN')).toContain('安全策略激活')
    expect(marketReasonDetail('site_origin_routes', 'node_region_geo', 'zh-CN')).toContain('请在区域管理为该区域设置国家/省份')
    expect(marketReasonDetail('site_waf_policy', '我的 WAF', 'zh-CN')).toBe('我的 WAF')
    expect(marketReasonDetail('unsupported_cc', 'activation_pending', 'en-US')).toContain('security activation')
  })

  // fix-mktsiteconf5: origin auth is carried sealed per leaf; what still
  // stops it names why.
  it('explains why site origin auth cannot be carried', () => {
    expect(marketReason('site_origin_auth', 'zh-CN').reason).not.toContain('无法带到供货方，凭据以本平台密钥加密')
    expect(marketReasonDetail('site_origin_auth', 'credential', 'zh-CN')).toContain('重新校验')
    expect(marketReasonDetail('site_origin_auth', 'no_leaf', 'zh-CN')).toContain('供给')
    expect(marketReasonDetail('site_origin_auth', 'origin_auth_off', 'en-US')).toContain('origin auth')
    expect(marketReason('origin_auth_sealed', 'zh-CN').reason).toContain('解开')
  })

  // fix-mktsiteconf6: the leaf sends the credentials to its nodes by itself;
  // a delivery that has not reached them is advisory with its reason.
  it('explains an origin auth delivery that has not reached the supplier nodes', () => {
    const delivery = marketReason('origin_auth_delivery', 'zh-CN')
    expect(delivery.known).toBe(true)
    expect(delivery.reason).toContain('节点')
    expect(delivery.next).toContain('自动重试')
    expect(marketReasonDetail('origin_auth_delivery', 'waiting_nodes', 'zh-CN')).toContain('离线')
    expect(marketReasonDetail('origin_auth_delivery', 'credential_unreadable', 'zh-CN')).toContain('凭据')
    expect(marketReasonDetail('origin_auth_delivery', 'node_rejected', 'zh-CN')).toContain('节点')
    expect(marketReasonDetail('origin_auth_delivery', 'failed', 'en-US')).toContain('gave up')
    for (const detail of ['no_nodes', 'publication_invalid', 'delivery_unavailable', 'retrying']) {
      expect(marketReasonDetail('origin_auth_delivery', detail, 'zh-CN')).not.toBe(detail)
    }
  })

  // fix-mktsiteconf7: the node delivery of an applied leaf (subscriber check).
  it('explains the node delivery of an applied leaf', () => {
    for (const code of ['site_syncing', 'site_sync_failed', 'security_activating', 'security_failed', 'origin_auth_delivering',
      'origin_auth_failed', 'node_delivery_timeout', 'status_unavailable', 'node_reason_unknown']) {
      expect(marketReason(code, 'zh-CN').known).toBe(true)
      expect(marketReason(code, 'en-US').known).toBe(true)
    }
    expect(marketReason('node_delivery_timeout', 'zh-CN').next).toContain('重新下发')
    expect(marketReasonDetail('origin_auth_failed', 'credential_unreadable', 'zh-CN')).toContain('凭据')
    // A policy kind:reason detail is shown as sent.
    expect(marketReasonDetail('security_failed', 'waf:candidate_rejected', 'zh-CN')).toBe('waf:candidate_rejected')
  })

  it('explains why a site WAF cannot be carried', () => {
    expect(marketReasonDetail('site_waf_policy', 'waf_ip_list', 'zh-CN')).toContain('IP 名单')
    expect(marketReasonDetail('unsupported_waf', 'system/crs-pl3', 'zh-CN')).toBe('system/crs-pl3')
  })
})
