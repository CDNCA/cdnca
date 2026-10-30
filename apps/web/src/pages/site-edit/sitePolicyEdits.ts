import { ApiError } from '../../api/auth'
import {
  newSecurityActivationWriteMetadata,
  securityPoliciesApi,
  type SecurityActivationStatus,
  type SecurityPolicy,
  type SecurityPolicyFields,
  type SecurityPolicyManagedWAF,
  type SecurityPolicyRule,
} from '../../api/securityPolicies'

// fix-siteprot：网站管理 CC/WAF 标签页就地修改本站绑定的规则库。全部复用规则页的接口：
// 目录展开 GET /v1/security-policies/catalog-rules，写规则库 PATCH/POST /v1/security-policies，
// 下发 POST /v1/site-publications/security-activations（与规则页 ?site_id 保存即下发同一请求）。

/** CC 默认防护档位 → 系统 CC 规则组（license-service 050 种子 cc_rule:*）。 */
export const ccPresetGroups = {
  off: 'cc_rule:10002', loose: 'cc_rule:6', js: 'cc_rule:1', fiveSecond: 'cc_rule:10001', click: 'cc_rule:10000',
  slider: 'cc_rule:2', captcha: 'cc_rule:4', rotate: 'cc_rule:10003', simpleClick: 'cc_rule:10004', simpleSlider: 'cc_rule:10005',
} as const
export type CCPreset = keyof typeof ccPresetGroups

/** Names of the rules this page manages in the site's library (one rule each). */
export const managedRuleNames = { whitelist: '本站白名单 IP', blacklist: '本站黑名单 IP', crawlerBlock: '搜索引擎爬虫 拦截' } as const

/** Catalog expansion names rules "<group or set name> · <part>" (securitypolicy.ExpandCCRuleGroup / ExpandWAFRuleSets). */
export function fromCatalogSet(rule: SecurityPolicyRule, setName: string): boolean {
  return rule.name.startsWith(`${setName} · `)
}

/** The preset whose catalog group the library's enabled rules came from; undefined when none did. */
export function currentCCPreset(policy: SecurityPolicy | undefined, groupNames: Partial<Record<CCPreset, string>>): CCPreset | undefined {
  const rules = (policy?.rules ?? []).filter((rule) => rule.enabled)
  return (Object.keys(ccPresetGroups) as CCPreset[]).find((preset) => preset !== 'off' && groupNames[preset] &&
    rules.some((rule) => fromCatalogSet(rule, groupNames[preset]!)))
}

/** IP list text: one IP/CIDR per line, "#" starts a comment. */
export function ipLines(text: string): string[] {
  return [...new Set(text.split('\n').map((line) => line.replace(/#.*$/, '').trim()).filter(Boolean))]
}

export function managedRuleValues(policy: SecurityPolicy | undefined, name: string): string[] {
  return (policy?.rules ?? []).find((rule) => rule.name === name)?.conditions.flatMap((condition) => condition.values) ?? []
}

export interface CCEdit {
  /** Rules of the new default protection (expanded catalog group; [] for 关闭). */
  presetRules?: SecurityPolicyRule[]
  /** Catalog group names whose rules are replaced by presetRules. */
  presetNames?: string[]
  crawler?: { mode: 'none' | 'allow' | 'block'; tokens: string[] }
  whitelist?: string[]
  blacklist?: string[]
}

function ipRule(name: string, action: 'allow' | 'block', values: string[]): SecurityPolicyRule {
  return { name, priority: 1, enabled: true, action, flow: 'stop', action_config: {},
    conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values }] }
}

/**
 * The CC library rules after an edit, in run order: whitelist, crawler block, blacklist, the user's own rules
 * (their order kept), then the default protection (runs when nothing else matched). Priorities are renumbered.
 */
export function editCCRules(rules: SecurityPolicyRule[], edit: CCEdit): SecurityPolicyRule[] {
  const keep = (name: string, values: string[] | undefined) => values === undefined
    ? rules.filter((rule) => rule.name === name) : values.length ? [ipRule(name, name === managedRuleNames.whitelist ? 'allow' : 'block', values)] : []
  const managed = new Set<string>(Object.values(managedRuleNames))
  const presetNames = edit.presetRules ? edit.presetNames ?? [] : []
  const isPreset = (rule: SecurityPolicyRule) => presetNames.some((name) => fromCatalogSet(rule, name))
  const crawler = edit.crawler === undefined ? rules.filter((rule) => rule.name === managedRuleNames.crawlerBlock)
    : edit.crawler.mode === 'block' && edit.crawler.tokens.length ? [{ name: managedRuleNames.crawlerBlock, priority: 1, enabled: true,
      action: 'block' as const, flow: 'stop' as const, action_config: {},
      conditions: [{ field: 'header' as const, key: 'user-agent', operator: 'contains', values: edit.crawler.tokens.slice(0, 64) }] }] : []
  const own = rules.filter((rule) => !managed.has(rule.name) && !isPreset(rule)).sort((left, right) => left.priority - right.priority)
  const ordered = [...keep(managedRuleNames.whitelist, edit.whitelist), ...crawler, ...keep(managedRuleNames.blacklist, edit.blacklist),
    ...own, ...(edit.presetRules ?? [])]
  return ordered.map((rule, index) => ({ ...rule, priority: index + 1 }))
}

/**
 * 屏蔽透明代理 / 区域屏蔽 as WAF rules, the same rules 网站默认设置 copies into a new site's WAF library
 * (securitypolicy.ProxyBlockRules / RegionBlockRules: names, operators and values identical).
 */
export const proxyHeaders = ['via', 'x-forwarded-for', 'forwarded'] as const
export const regionPresets = {
  abroad: { name: '屏蔽境外（不含港澳台）', operator: 'not_in', values: ['CN', 'HK', 'MO', 'TW'] },
  abroadHmt: { name: '屏蔽境外（含港澳台）', operator: 'not_in', values: ['CN'] },
  chinaHmt: { name: '屏蔽境内（含港澳台）', operator: 'in', values: ['CN', 'HK', 'MO', 'TW'] },
  china: { name: '屏蔽境内（不含港澳台）', operator: 'in', values: ['CN'] },
} as const
export type RegionPreset = keyof typeof regionPresets
const proxyRuleName = (header: string) => `屏蔽透明代理 ${header}`
const regionRuleName = (preset: RegionPreset) => `区域屏蔽 ${regionPresets[preset].name}`

export function proxyBlocked(policy: SecurityPolicy | undefined): boolean {
  return (policy?.rules ?? []).some((rule) => rule.enabled && proxyHeaders.some((header) => rule.name === proxyRuleName(header)))
}

/** The region preset of the WAF library; 'custom' for other country block rules, 'none' without. */
export function regionPreset(policy: SecurityPolicy | undefined): RegionPreset | 'none' | 'custom' {
  const rules = (policy?.rules ?? []).filter((rule) => rule.enabled)
  const preset = (Object.keys(regionPresets) as RegionPreset[]).find((key) => rules.some((rule) => rule.name === regionRuleName(key)))
  if (preset) return preset
  return rules.some((rule) => rule.action === 'block' && rule.conditions.some((condition) => condition.field === 'country')) ? 'custom' : 'none'
}

/** WAF rules after setting 屏蔽透明代理 and/or 区域屏蔽 (undefined leaves it); both run first. */
export function editWAFSourceRules(rules: SecurityPolicyRule[], edit: { proxy?: boolean; region?: RegionPreset | 'none' }): SecurityPolicyRule[] {
  const isProxy = (rule: SecurityPolicyRule) => proxyHeaders.some((header) => rule.name === proxyRuleName(header))
  const isRegion = (rule: SecurityPolicyRule) => (Object.keys(regionPresets) as RegionPreset[]).some((key) => rule.name === regionRuleName(key))
  const proxy = edit.proxy === undefined ? rules.filter(isProxy) : edit.proxy ? proxyHeaders.map((header): SecurityPolicyRule => ({
    name: proxyRuleName(header), priority: 1, enabled: true, action: 'block', flow: 'stop', action_config: {},
    conditions: [{ field: 'header', key: header, operator: 'regex', values: ['.'] }] })) : []
  const region = edit.region === undefined ? rules.filter(isRegion) : edit.region === 'none' ? [] : [{
    name: regionRuleName(edit.region), priority: 1, enabled: true, action: 'block' as const, flow: 'stop' as const, action_config: {},
    conditions: [{ field: 'country' as const, operator: regionPresets[edit.region].operator, values: [...regionPresets[edit.region].values] }] }]
  const rest = rules.filter((rule) => !isProxy(rule) && !isRegion(rule))
  return [...proxy, ...region, ...rest].map((rule, index) => ({ ...rule, priority: index + 1 }))
}

/** WAF module switch: add the expanded self-developed set, or remove its rules. */
export function toggleWAFSet(rules: SecurityPolicyRule[], setName: string, added: SecurityPolicyRule[] | null): SecurityPolicyRule[] {
  const rest = rules.filter((rule) => !fromCatalogSet(rule, setName))
  return [...rest, ...(added ?? [])].map((rule, index) => ({ ...rule, priority: index + 1 }))
}

/**
 * fix-crstier：网站页“托管 WAF 防护档位”写入本站规则库的 managed_waf 规则（每库至多一条，服务端校验）。
 * 规则页显示为这个名字，两边改的是同一条规则。
 */
export const managedWAFRuleName = '托管 WAF（由网站页设置）'

/** CRS catalog set whose expansion carries the catalog's managed WAF engine defaults (securitypolicy.CatalogWAFRules). */
export const crsCatalogDefaultsKey = 'waf_set:crs_sqli'

/** The CRS profile of the library's enabled managed_waf rule; '' without one. */
export function managedWAFProfile(rules: SecurityPolicyRule[] | undefined): string {
  return (rules ?? []).find((rule) => rule.enabled && rule.action === 'managed_waf')?.action_config.managed_waf?.profile ?? ''
}

/**
 * WAF rules after choosing a managed WAF tier: null removes the managed_waf rule (关闭); a profile updates the
 * existing rule (engine settings kept, exclusions the new profile does not export dropped) or appends one built
 * from `defaults` (the catalog's engine settings). Priorities are renumbered.
 */
export function setManagedWAFTier(rules: SecurityPolicyRule[], tier: { profile: string; exports: number[] } | null,
  defaults?: SecurityPolicyManagedWAF): SecurityPolicyRule[] {
  const current = rules.find((rule) => rule.action === 'managed_waf')
  const rest = rules.filter((rule) => rule.action !== 'managed_waf')
  const renumber = (list: SecurityPolicyRule[]) => list.map((rule, index) => ({ ...rule, priority: index + 1 }))
  if (!tier) return renumber(rest)
  const base = current?.action_config.managed_waf ?? defaults
  if (!base) throw new Error('managed WAF defaults missing')
  const exclusions = (base.exclusions ?? []).filter((id) => tier.exports.includes(id))
  const managed: SecurityPolicyManagedWAF = { ...base, profile: tier.profile, exclusions: exclusions.length ? exclusions : undefined }
  if (current) return renumber(rules.map((rule) => rule === current ? { ...rule, enabled: true, action_config: { managed_waf: managed } } : rule))
  return renumber([...rest, { name: managedWAFRuleName, priority: 1, enabled: true, action: 'managed_waf', flow: 'continue',
    conditions: [], action_config: { managed_waf: managed } }])
}

export function fieldsOf(policy: SecurityPolicy): SecurityPolicyFields {
  return { kind: policy.kind, name: policy.name, description: policy.description, enabled: policy.enabled,
    default_action: policy.default_action, rules: policy.rules, cc_settings: policy.cc_settings, waf_settings: policy.waf_settings }
}

export interface SiteLibraryWrite {
  accessToken: string
  siteId: string
  /** The site's bound library (updated) or undefined (a new one is created for the site and published). */
  policy: SecurityPolicy | undefined
  fields: SecurityPolicyFields
  status: SecurityActivationStatus | undefined
  /** Administrators name the site's tenant scope and owner on create (tenants: the server fills them). */
  target?: { scopeId: string; ownerId: string }
}

/** Publish the saved library to the site (the rules page's site-context save does the same). */
export async function publishToSite(accessToken: string, siteId: string, saved: { id: string; version: number },
  status: SecurityActivationStatus | undefined) {
  return securityPoliciesApi.publishActivation(accessToken, {
    site_id: siteId, policy_id: saved.id, policy_version: saved.version,
    expected_binding_revision: status?.binding?.binding_revision ?? 0,
    expected_active_policy_version: status?.binding?.active_policy_version ?? 0,
    target_node_ids: [], canary_size: 0, expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  }, newSecurityActivationWriteMetadata('publish'))
}

/**
 * CU-SITE-04: the outcome of saving the site's library. A refused publish keeps
 * the saved library and the error: the activation worker only re-publishes a
 * library already bound to the site (securityactivation/rebind.go), so a
 * refused first publish is not retried by itself unless the refusal says so
 * (rule_pack_unavailable auto_resume).
 */
export interface SiteLibraryOutcome { saved: SecurityPolicy; published: boolean; publishError?: unknown }

/** Save the site's library, then publish it. A refused publish is reported with its error. */
export async function saveSiteLibrary(write: SiteLibraryWrite): Promise<SiteLibraryOutcome> {
  const key = `site-protection-${write.siteId}-${crypto.randomUUID()}`
  const saved = write.policy
    ? await securityPoliciesApi.update(write.accessToken, write.policy.id, write.policy.version, write.fields, key)
    : await securityPoliciesApi.create(write.accessToken, { ...write.fields,
      ...(write.target ? { target_scope_id: write.target.scopeId, owner_id: write.target.ownerId } : {}) }, key)
  try {
    await publishToSite(write.accessToken, write.siteId, saved, write.status)
    return { saved, published: true }
  } catch (publishError) {
    return { saved, published: false, publishError }
  }
}

/** CU-SITE-04: whether the server keeps a refused publish and starts it by itself later. */
export function publishAutoResumes(error: unknown): boolean {
  return error instanceof ApiError && error.rulePacks?.auto_resume === true
}

/** 关闭 a site's library: withdraw it from the site (sec-rebind detach, as the rules page's 解除). */
export function detachSiteLibrary(accessToken: string, siteId: string, status: SecurityActivationStatus) {
  const binding = status.binding!
  return securityPoliciesApi.publishActivation(accessToken, {
    site_id: siteId, policy_id: binding.policy_id, policy_version: binding.active_policy_version,
    expected_binding_revision: binding.binding_revision, expected_active_policy_version: binding.active_policy_version,
    target_node_ids: [], canary_size: 0, expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(), detach: true,
  }, newSecurityActivationWriteMetadata('publish'))
}
