// 新增转向 dialog draft: one list of redirects and 内部重写.
import type { HttpPolicyMatchKind, RedirectRule, RewriteRule, RuleCondition } from '../../api/httpPolicies'

export type RedirectType = 301 | 302 | 307 | 308 | 'rewrite'

export interface URLRedirectDraft {
  type: RedirectType
  match_kind: HttpPolicyMatchKind
  match_path: string
  target: string
  preserve_query: boolean
  conditions: RuleCondition[]
}

export function draftFromRedirect(rule: RedirectRule): URLRedirectDraft {
  return { type: rule.status, match_kind: rule.match_kind, match_path: rule.match_path, target: rule.target_url,
    preserve_query: rule.preserve_query, conditions: rule.conditions ?? [] }
}

export function draftFromRewrite(rule: RewriteRule): URLRedirectDraft {
  return { type: 'rewrite', match_kind: rule.match_kind, match_path: rule.match_path, target: rule.target_path,
    preserve_query: rule.preserve_query, conditions: rule.conditions ?? [] }
}

// matchKindOf: the competitor's 匹配路径 is a regex; a plain path stays exact.
export function matchKindOf(path: string, current: HttpPolicyMatchKind): HttpPolicyMatchKind {
  if (current === 'prefix') return 'prefix'
  return /[()[\]*+?|^$\\{}]/.test(path) ? 'regex' : 'exact'
}

export function regexPath(path: string, kind: HttpPolicyMatchKind): string {
  if (kind !== 'regex' || path.startsWith('^/')) return path
  return path.startsWith('/') ? `^${path}` : `^/${path.replace(/^\^/, '')}`
}
