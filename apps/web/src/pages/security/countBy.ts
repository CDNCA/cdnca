import type { TFunction } from 'i18next'

import type { SecurityPolicyCountKey, SecurityPolicyCountKeyName, SecurityPolicyRule } from '../../api/securityPolicies'

/** The server's canonical key order (securitypolicy.countKeyOrder). */
export const countKeyOrder: SecurityPolicyCountKeyName[] = ['client_ip', 'client_cidr', 'host', 'uri', 'uri_path', 'ja4',
  // CC v7 (fix-ja4rule, CC_MATCH_KEYS).
  'user_agent', 'referer', 'header', 'cookie', 'query']
export const defaultCountPrefix = { ipv4_prefix: 24, ipv6_prefix: 64 }
/** Keys that name one header / cookie / query argument. */
export const namedCountKeys: SecurityPolicyCountKeyName[] = ['header', 'cookie', 'query']
/** Keys only CC v7 nodes run. */
export const v7CountKeys: SecurityPolicyCountKeyName[] = ['user_agent', 'referer', 'header', 'cookie', 'query']

export type CountPrefix = { ipv4_prefix?: number; ipv6_prefix?: number }
export type CountNames = Partial<Record<'header' | 'cookie' | 'query', string>>
export type CountByProblem = 'tooMany' | 'ipAndCidr' | 'uriAndPath' | 'statistics' | 'challengeTrigger' | 'target'

/** Form value (selected keys + network prefixes) -> the stored count_by. */
export function countByFromForm(keys: SecurityPolicyCountKeyName[] | undefined, prefix: CountPrefix | undefined,
  names?: CountNames): SecurityPolicyCountKey[] | undefined {
  const selected = countKeyOrder.filter((key) => keys?.includes(key))
  if (selected.length === 0 || (selected.length === 1 && selected[0] === 'client_ip')) return undefined
  return selected.map((key) => {
    if (key === 'client_cidr') {
      return { key, ipv4_prefix: prefix?.ipv4_prefix || defaultCountPrefix.ipv4_prefix, ipv6_prefix: prefix?.ipv6_prefix || defaultCountPrefix.ipv6_prefix }
    }
    if (key === 'header' || key === 'cookie' || key === 'query') {
      const name = names?.[key]?.trim() ?? ''
      // Header names are case insensitive and stored lower case (the server too).
      return { key, name: key === 'header' ? name.toLowerCase() : name }
    }
    return { key }
  })
}

/** Stored count_by -> form value. */
export function countByToForm(countBy: SecurityPolicyCountKey[] | undefined): { count_keys: SecurityPolicyCountKeyName[]; count_prefix: CountPrefix; count_names: CountNames } {
  const cidr = countBy?.find((key) => key.key === 'client_cidr')
  const names: CountNames = {}
  for (const key of countBy ?? []) {
    if ((key.key === 'header' || key.key === 'cookie' || key.key === 'query') && key.name) names[key.key] = key.name
  }
  return {
    count_keys: countBy?.map((key) => key.key) ?? [],
    count_prefix: { ipv4_prefix: cidr?.ipv4_prefix ?? defaultCountPrefix.ipv4_prefix, ipv6_prefix: cidr?.ipv6_prefix ?? defaultCountPrefix.ipv6_prefix },
    count_names: names,
  }
}

/** The combinations the server refuses (securitypolicy.normalizeCountBy). */
export function countByProblem(rule: Pick<SecurityPolicyRule, 'action' | 'action_config' | 'conditions' | 'count_by' | 'action_target'>,
  keys: SecurityPolicyCountKeyName[] | undefined = rule.count_by?.map((key) => key.key)): CountByProblem | undefined {
  const selected = new Set(keys ?? [])
  if (selected.size > 2) return 'tooMany'
  if (selected.has('client_ip') && selected.has('client_cidr')) return 'ipAndCidr'
  if (selected.has('uri') && selected.has('uri_path')) return 'uriAndPath'
  const counted = selected.size > 0 && !(selected.size === 1 && selected.has('client_ip'))
  if (rule.action_target === 'count_key' &&
    (!counted || rule.action !== 'rate_limit' || rule.action_config.rate_limit?.response_action !== 'temporary_ban')) return 'target'
  if (!counted) return undefined
  if (rule.conditions.some((condition) => condition.field === 'distinct_user_agents' || condition.field === 'status_404_count')) return 'statistics'
  if (rule.action === 'challenge' && !rule.action_config.challenge?.trigger_window_seconds) return 'challengeTrigger'
  return undefined
}

/** "同一 /24 网段 + 同一 URI，10 秒超过 30 次 → 封禁 60 秒". */
export function countByPreview(t: TFunction<'securityPolicies'>, rule: Pick<SecurityPolicyRule, 'action' | 'action_config' | 'count_by' | 'action_target'>): string | undefined {
  const keys = rule.count_by?.length ? rule.count_by : [{ key: 'client_ip' as const }]
  const phrases = keys.map((key) => t(`countBy.phrases.${key.key}`, { v4: key.ipv4_prefix, v6: key.ipv6_prefix, name: key.name ?? '' }))
  let window: number | undefined, requests: number | undefined, action: string
  const limit = rule.action_config.rate_limit
  if (rule.action === 'rate_limit' && limit) {
    window = limit.window_seconds
    requests = limit.max_requests
    const response = limit.response_action ?? 'reject_429'
    action = response === 'temporary_ban'
      ? t(rule.action_target === 'count_key' ? 'countBy.actions.temporary_ban_bucket' : 'countBy.actions.temporary_ban', { seconds: limit.ban_seconds })
      : response === 'log' ? t('countBy.actions.log') : t('countBy.actions.reject_429')
  } else if (rule.action === 'challenge') {
    window = rule.action_config.challenge?.trigger_window_seconds
    requests = rule.action_config.challenge?.trigger_max_requests
    const type = rule.action_config.challenge?.type
    action = type ? t(`countBy.actions.challengeTypes.${type}`, { defaultValue: t('countBy.actions.challenge') }) : t('countBy.actions.challenge')
  } else {
    return undefined
  }
  if (!window || !requests) return undefined
  return t('countBy.preview', { keys: phrases.join(t('countBy.previewJoin')), window, requests, action })
}

/**
 * FX26: priorities after moving the rule at `from` to `to`, as [form index,
 * new priority] in the new order. Priorities stay strictly increasing (the
 * node orders equal priorities by rule ID, not by what the operator sees):
 * the existing distinct values are reused, or 10, 20, 30… when some repeat.
 */
export function reorderedPriorities(priorities: number[], from: number, to: number): Array<[number, number]> {
  const order = priorities.map((_, index) => index)
  const [moved] = order.splice(from, 1)
  order.splice(to, 0, moved)
  const sorted = [...priorities].sort((left, right) => left - right)
  const distinct = sorted.every((value, index) => index === 0 || value > sorted[index - 1])
  return order.map((index, position) => [index, distinct ? sorted[position] : (position + 1) * 10])
}
