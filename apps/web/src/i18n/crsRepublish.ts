import i18n from './index'
import type { ApiError } from '../api/auth'

// The CRS rule text a catalog delivery changed is being
// republished to the scopes whose release embeds it; a release whose JS
// challenge policy has not reached a target node is refused, naming them.
const zhCN = {
  republishing: '正在更新规则（{{count}}）',
  republishingDetail: '授权中心下发的系统规则（如 OWASP CRS、默认启用的规则包）有更新，用到它们的网站正在自动重新发布，括号内为尚未完成的用户数。完成后节点即按新规则拦截，此标签自动消失。',
  challengePolicy: '节点 {{node}} 尚未安装站点 {{domain}} 的 JS 挑战策略（版本 v{{version}}），已拒绝发布。请先对该站点发布 JS 挑战（会把策略下发到节点），再发布配置。',
  challengePolicyOthers: '同样缺少策略的节点：{{nodes}}',
}

type Messages = typeof zhCN

const enUS: Messages = {
  republishing: 'Updating rules ({{count}})',
  republishingDetail: 'System rules delivered by the license center (such as OWASP CRS or default-on rule packs) changed; the websites using them are being republished automatically (the number is the scopes not yet done). Nodes enforce the new rules once done and this tag disappears.',
  challengePolicy: 'Node {{node}} has not installed the JS challenge policy of site {{domain}} (version v{{version}}); the release was refused. Publish the site\'s JS challenge first (it delivers the policy to the node), then publish the configuration.',
  challengePolicyOthers: 'Nodes also missing it: {{nodes}}',
}

function pseudo(messages: Messages): Messages {
  return Object.fromEntries(Object.entries(messages).map(([key, value]) => [key, `［${value}］`])) as Messages
}

export const crsRepublishMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN),
}

for (const [locale, messages] of Object.entries(crsRepublishMessages)) {
  i18n.addResourceBundle(locale, 'crsRepublish', messages, true, true)
}

/** The refusal of a release whose JS challenge policy a node lacks, with the
 * node and site the server named; undefined for any other error. */
export function challengePolicyRefusalText(error: ApiError): string | undefined {
  const refusal = error.code === 'challenge_policy_unavailable' ? error.challenge : undefined
  if (!refusal) return undefined
  const text = i18n.t('crsRepublish:challengePolicy', { node: refusal.node_id, domain: refusal.domain,
    version: refusal.policy_version })
  return refusal.other_node_ids.length
    ? `${text} ${i18n.t('crsRepublish:challengePolicyOthers', { nodes: refusal.other_node_ids.join('、') })}`
    : text
}
