// 公开审核规则清单（/developers/review-rules）。规则表来自 generated/review-rules.json：由
// market-service 测试 TestReviewRulesDoc 从审核引擎（services/market-service/internal/review
// Analyzers + NewEngine）导出，代码与文件不一致时该测试失败；更新方法：
//   CDNCA_UPDATE_REVIEW_RULES=1 GOWORK=off go -C services/market-service test ./internal/review -run TestReviewRulesDoc
// 这里只补中英文说明与分组标题；reviewRules.test.tsx 要求每条规则都有说明、没有多余说明。
import type { L } from '../i18n'
import data from '../generated/review-rules.json'
import { REVIEW_BUILTIN_SUFFIX, REVIEW_RULE_TEXT } from '../../../../packages/cdnca-ui/src/reviewRules'

export interface ReviewRule {
  id: string
  analyzer: string
  pass: string
  phase: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  action: 'none' | 'quarantine' | 'reject'
  mode: 'evaluation' | 'enforcement'
  fixed: boolean
  summary: string
}

export const REVIEW_RULES = data.rules as ReviewRule[]
export const PRIVILEGED_KINDS: string[] = data.privileged_kinds
export const ENGINE_VERSION: string = data.engine_version

const s = (zh: string, en: string): L => ({ zh, en })

/** 分析器（规则 ID 前缀）的标题，按页面顺序。 */
export const ANALYZERS: { id: string; title: L }[] = [
  { id: 'metadata', title: s('manifest 与版本（metadata）', 'Manifest and version (metadata)') },
  { id: 'entrypoint', title: s('入口与数据包（entrypoint）', 'Entrypoint and data packages (entrypoint)') },
  { id: 'permissions', title: s('权限（permissions）', 'Permissions (permissions)') },
  { id: 'rulepack', title: s('规则包（rulepack）', 'Rule packs (rulepack)') },
  { id: 'theme', title: s('主题（theme）', 'Themes (theme)') },
  { id: 'ui_page', title: s('带页面的插件（ui_page）', 'Page plugins (ui_page)') },
  { id: 'package', title: s('平台包（package）', 'Platform packages (package)') },
  { id: 'secrets', title: s('密钥泄露（secrets）', 'Leaked secrets (secrets)') },
  { id: 'dependencies', title: s('依赖（dependencies）', 'Dependencies (dependencies)') },
  { id: 'malware', title: s('病毒扫描（malware）', 'Malware scan (malware)') },
  { id: 'diff', title: s('版本差异（diff）', 'Version diff (diff)') },
]

/** 规则说明与内置规则后缀见 @cdnca/ui reviewRules（卖家站、运营后台预检报告共用同一份）。 */
export const BUILTIN_SUFFIX = REVIEW_BUILTIN_SUFFIX
export const RULE_TEXT = REVIEW_RULE_TEXT

/** 规则的中英说明。 */
export function ruleText(rule: ReviewRule): L {
  const suffix = rule.id.slice(rule.analyzer.length + 1)
  return RULE_TEXT[rule.id] ?? BUILTIN_SUFFIX[suffix]
}

/** 人工审核条件（services/market-service/internal/plugin/review.go consumeOne）。 */
export const HUMAN_REVIEW: { reason: string; text: L }[] = [
  { reason: 'first_version', text: s('插件首个版本（还没有任何已审核版本）', 'The first version (no reviewed version yet)') },
  { reason: 'permission_change', text: s('权限与上一个已审核版本不同', 'Permissions differ from the last reviewed version') },
  { reason: 'privileged', text: s('高风险类型：', 'Privileged kinds: ') },
  { reason: 'probation', text: s('卖家入驻未满考察期（市场默认 90 天，运营可调）', 'The seller is within probation (market default 90 days, adjustable by the operator)') },
  { reason: 'quarantine', text: s('出现任何生效的隔离项（含扫描器故障）', 'Any enforced quarantine finding (scanner faults included)') },
  { reason: 'scan_failed', text: s('扫描连续 3 次出错', 'Three scan attempts in a row errored') },
]
