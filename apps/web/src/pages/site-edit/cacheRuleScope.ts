// 缓存范围 of a cache rule (新增缓存规则).
import type { CachePolicyRule } from '../../api/cachePolicies'

export type CacheRuleScope = 'home' | 'site' | 'dir' | 'suffix' | 'path'
export const ruleSliceBytes = 1 << 20

// ruleScope reads a rule's 缓存范围 (five kinds).
export function ruleScope(rule: Pick<CachePolicyRule, 'path_exact' | 'path_prefix' | 'extensions'>): CacheRuleScope {
  if (rule.path_exact === '/') return 'home'
  if (rule.path_exact) return 'path'
  if (rule.path_prefix && rule.path_prefix !== '/') return 'dir'
  if ((rule.extensions?.length ?? 0) > 0 && !rule.path_prefix) return 'suffix'
  return 'site'
}
