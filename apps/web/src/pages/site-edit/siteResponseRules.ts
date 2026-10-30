import type { SiteResponseRule } from '../../api/siteAccess'

// Response rule helpers of SiteResponseRulesEditor.

/** "404, 500-504" <-> [{404,404},{500,504}]; an unparsable part is kept out (the server refuses bad ranges). */
export function parseStatuses(text: string): { from: number; to: number }[] {
  return text.split(/[,\s]+/).filter(Boolean).flatMap((part) => {
    const match = /^(\d{3})(?:-(\d{3}))?$/.exec(part)
    if (!match) return []
    const from = Number(match[1])
    return [{ from, to: match[2] ? Number(match[2]) : from }]
  })
}

export function formatStatuses(statuses: SiteResponseRule['statuses']): string {
  return (statuses ?? []).map((range) => range.from === range.to ? `${range.from}` : `${range.from}-${range.to}`).join(', ')
}

export function newResponseRule(rules: SiteResponseRule[]): SiteResponseRule {
  let index = rules.length + 1
  while (rules.some((rule) => rule.id === `rule-${index}`)) index++
  return { id: `rule-${index}`, action: 'headers', header_actions: [{ kind: 'set', name: '', value: '' }] }
}

/** The rule as the API takes it: fields of other actions dropped, empty lists omitted. */
export function cleanRule(rule: SiteResponseRule): SiteResponseRule {
  const result: SiteResponseRule = { id: rule.id.trim(), action: rule.action }
  if (rule.statuses?.length) result.statuses = rule.statuses
  if (rule.headers?.length) {
    result.headers = rule.headers.map((condition) => condition.op === 'exists' || condition.op === 'absent'
      ? { name: condition.name.trim(), op: condition.op }
      : { name: condition.name.trim(), op: condition.op, value: condition.value ?? '' })
  }
  if (rule.action === 'headers') {
    result.header_actions = (rule.header_actions ?? []).map((action) => action.kind === 'delete'
      ? { kind: action.kind, name: action.name.trim() }
      : { kind: action.kind, name: action.name.trim(), value: action.value ?? '' })
  }
  if (rule.action === 'error_page' || rule.action === 'block') result.status = rule.status ?? 403
  return result
}
