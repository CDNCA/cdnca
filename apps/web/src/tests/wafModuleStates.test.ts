import type { SecurityPolicy, SecurityPolicyRule } from '../api/securityPolicies'
import { wafModuleStates } from '../pages/site-edit/wafModuleStates'

const now = '2026-10-17T00:00:00Z'
const catalogNames = { 'waf_set:sqli': 'SQL注入', 'waf_set:xss': 'XSS', 'waf_set:cmd_injection': '命令注入' }

function rule(name: string, action: SecurityPolicyRule['action'], enabled = true): SecurityPolicyRule {
  return { name, priority: 1, enabled, action, flow: action === 'block' ? 'stop' : 'continue',
    conditions: [{ field: 'args', operator: 'regex', values: ['x'] }], action_config: {} }
}

function policy(rules: SecurityPolicyRule[], enabled = true): SecurityPolicy {
  return { id: 'p1', scope_id: 's1', version: 3, created_at: now, updated_at: now, kind: 'waf', name: 'site waf',
    description: '', enabled, default_action: 'allow', rules }
}

const managed = (profile: string, inspection?: 'log' | 'block'): SecurityPolicyRule => ({
  name: '托管规则集 (OWASP CRS)', priority: 9, enabled: true, action: 'managed_waf', flow: 'continue', conditions: [],
  action_config: { managed_waf: { request_body_limit: 1, request_body_no_files_limit: 1, request_body_limit_action: 'reject',
    arguments_limit: 1, json_depth_limit: 1, pcre_match_limit: 1, inspection_limit_action: inspection, profile } },
})

describe('WAF module states (启用/仅记录/关闭)', () => {
  it('derives each module from the self-developed rules and the CRS profile of the active policy', () => {
    const result = wafModuleStates(policy([
      rule('SQL注入 · UNION/SELECT 联合查询', 'log'),
      rule('SQL注入 · 语义检测', 'log'),
      rule('XSS · script/iframe/svg 标签', 'block'),
      rule('命令注入 · 分隔符拼接系统命令', 'block', false),
      rule('SQL注入关键字（自定义）', 'block'),
      managed('system/crs-pl1-log', 'block'),
    ]), catalogNames)
    expect(result.reason).toBeNull()
    const byKey = Object.fromEntries(result.modules.map((module) => [module.key, module]))
    // The record-only profile runs every CRS set, recording.
    expect(byKey.sqli).toMatchObject({ state: 'log', self: 'log', crs: 'log' })
    expect(byKey.xss).toMatchObject({ state: 'protect', self: 'protect', crs: 'log' })
    // A disabled rule does not count; CRS still records.
    expect(byKey.command).toMatchObject({ state: 'log', self: 'off', crs: 'log' })
    expect(result.modules).toHaveLength(10)
    expect(result.inspectionLimitAction).toBe('block')
    const blocking = wafModuleStates(policy([managed('system/crs-pl2')]), catalogNames)
    expect(blocking.modules.every((module) => module.crs === 'protect')).toBe(true)
  })

  it('a rule named like a module but not "<set> · <rule>" is not the module', () => {
    const result = wafModuleStates(policy([rule('SQL注入关键字', 'block')]), catalogNames)
    expect(result.modules.find((module) => module.key === 'sqli')?.state).toBe('off')
  })

  it('everything is off without an active or enabled policy, and unknown for a protected library', () => {
    expect(wafModuleStates(undefined, catalogNames)).toMatchObject({ reason: 'noPolicy' })
    expect(wafModuleStates(policy([rule('XSS · a', 'block')], false), catalogNames).modules.every((module) => module.state === 'off')).toBe(true)
    expect(wafModuleStates(policy([rule('XSS · a', 'block')], false), catalogNames).reason).toBe('policyDisabled')
    const protectedPolicy = { ...policy([]), protected: true, rules: [] } as SecurityPolicy
    expect(wafModuleStates(protectedPolicy, catalogNames).reason).toBe('protectedPolicy')
  })

  it('omitted inspection_limit_action is log only (FX12 default)', () => {
    expect(wafModuleStates(policy([managed('system/crs-pl1')]), catalogNames).inspectionLimitAction).toBe('log')
    expect(wafModuleStates(policy([rule('XSS · a', 'block')]), catalogNames).inspectionLimitAction).toBeNull()
  })

  it('without the catalog the self-developed engine is reported unknown, CRS still derived', () => {
    const result = wafModuleStates(policy([rule('SQL注入 · a', 'block'), managed('system/crs-pl1-log')]), null)
    const byKey = Object.fromEntries(result.modules.map((module) => [module.key, module]))
    expect(byKey.sqli).toMatchObject({ self: 'unknown', crs: 'log', state: 'log' })
    expect(byKey.xss).toMatchObject({ crs: 'log', state: 'log' })
  })
})
