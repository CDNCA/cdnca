import type { SecurityPolicy } from '../../api/securityPolicies'

export type WAFModuleState = 'protect' | 'log' | 'off' | 'unknown'

// The ten built-in modules and their
// catalog rule sets: self-developed waf_set:<suffix> (expanded into
// "<set name> · <rule name>" policy rules, securitypolicy.ExpandWAFRuleSets)
// and OWASP CRS waf_set:crs_<suffix> (one managed_waf rule running a CRS
// profile pack that covers all ten).
export const wafModuleCatalogSuffix = {
  sqli: 'sqli', xss: 'xss', upload: 'file_upload', include: 'file_include', command: 'cmd_injection',
  java: 'java_code_injection', javaDeserialize: 'java_deserialization', php: 'php_code_injection',
  phpDeserialize: 'php_deserialization', ssti: 'ssti',
} as const

export type WAFModuleKey = keyof typeof wafModuleCatalogSuffix

export interface WAFModuleStatus {
  key: WAFModuleKey
  state: WAFModuleState
  self: WAFModuleState
  crs: WAFModuleState
}

export interface WAFModuleStates {
  modules: WAFModuleStatus[]
  /** null without CRS; omitted on the policy means log only (FX12). */
  inspectionLimitAction: 'log' | 'block' | null
  reason: 'noPolicy' | 'policyDisabled' | 'protectedPolicy' | null
}

const rank: Record<WAFModuleState, number> = { off: 0, unknown: 1, log: 2, protect: 3 }

function strongest(states: WAFModuleState[]): WAFModuleState {
  return states.reduce<WAFModuleState>((best, state) => rank[state] > rank[best] ? state : best, 'off')
}

function crsProfileState(profile: string): WAFModuleState {
  return profile.endsWith('-log') ? 'log' : 'protect'
}

function actionState(action: string): WAFModuleState {
  return action === 'block' ? 'protect' : action === 'log' ? 'log' : 'off'
}

/**
 * wafModuleStates derives 防护 / 仅记录 / 关闭 per module from the site's
 * active WAF policy: the strongest enabled rule of the module across both
 * engines (block > log). catalogNames maps waf_set keys to catalog set
 * names (null when the catalog cannot be read: self-developed rules are then
 * unknown).
 */
export function wafModuleStates(policy: SecurityPolicy | undefined, catalogNames: Record<string, string> | null): WAFModuleStates {
  const keys = Object.keys(wafModuleCatalogSuffix) as WAFModuleKey[]
  const all = (state: WAFModuleState) => keys.map((key) => ({ key, state, self: state, crs: state }))
  if (!policy) return { modules: all('off'), inspectionLimitAction: null, reason: 'noPolicy' }
  if ((policy as SecurityPolicy & { protected?: boolean }).protected) {
    return { modules: all('unknown'), inspectionLimitAction: null, reason: 'protectedPolicy' }
  }
  if (!policy.enabled) return { modules: all('off'), inspectionLimitAction: null, reason: 'policyDisabled' }
  const rules = (policy.rules ?? []).filter((rule) => rule.enabled)
  const managed = rules.find((rule) => rule.action === 'managed_waf')?.action_config.managed_waf
  const modules = keys.map((key): WAFModuleStatus => {
    const suffix = wafModuleCatalogSuffix[key]
    const setName = catalogNames?.[`waf_set:${suffix}`]
    let self: WAFModuleState = 'off'
    if (catalogNames === null) self = 'unknown'
    else if (setName) {
      self = strongest(rules.filter((rule) => rule.action !== 'managed_waf' && rule.name.startsWith(`${setName} · `))
        .map((rule) => actionState(rule.action)))
    }
    // Every CRS profile pack (system/crs-<level>) runs all ten CRS sets; the
    // *-log profiles only record (PA-12).
    const crs: WAFModuleState = managed ? crsProfileState(managed.profile) : 'off'
    return { key, self, crs, state: strongest([self, crs]) }
  })
  return { modules, inspectionLimitAction: managed ? managed.inspection_limit_action ?? 'log' : null, reason: null }
}
