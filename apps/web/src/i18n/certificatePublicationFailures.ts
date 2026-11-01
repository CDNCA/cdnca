import type { TFunction } from 'i18next'
import i18n from './index'

// node-logs3：证书同步（发布到节点）的失败码，来自 services/control-api
// certificatepublish（publication_adapter.go、edgeautopublish.CertificateTargetRejection）
// 与 certificateasset（publication_worker.go、迁移 120 legacy_reissue_required）。
// 码形如 "<code>[.<节点 UUID>]"，带节点时文案里显示节点 ID。
// node_certificate_*：节点回报的 certstore 失败阶段。
const zhCN = {
  target_policy_not_automatic: '网站的发布目标不是自动发布，证书无法自动同步',
  target_policy_invalid: '网站的发布目标配置无效',
  target_snapshot_unresolved: '暂时无法确定网站的发布节点，将自动重试',
  target_no_nodes: '网站的线路组没有可用节点',
  target_node_missing: '发布目标中的{{node}}不存在',
  target_node_inactive: '{{node}}已停用',
  target_node_not_carried: '{{node}}不承载该租户的网站',
  target_node_offline: '{{node}}离线，将自动重试',
  target_node_identity_ineligible: '{{node}}身份暂不可用于发布，将自动重试',
  target_node_capability_missing: '{{node}}版本过低，不支持证书下发，请升级节点',
  target_invalid: '发布目标校验未通过',
  publication_node_not_found: '发布所需节点不存在',
  publication_config_not_releasable: '网站配置当前不可发布',
  publication_input_invalid: '发布请求暂未通过校验，将自动重试',
  publication_unavailable: '发布服务暂时不可用，将自动重试',
  publication_pending: '发布进行中',
  publication_node_busy: '节点正在执行其他发布，等待后自动重试',
  publication_conflict: '与其他发布冲突',
  publication_contract_invalid: '发布结果校验未通过',
  publication_terminal_failed: '节点部署失败，详情见发布记录',
  node_certificate_precheck_failed: '{{node}}的 OpenResty 配置检查未通过证书（nginx -t 失败）',
  node_certificate_activation_failed: '{{node}}的 OpenResty 启动或重载失败，证书未生效',
  node_certificate_health_failed: '{{node}}启用证书后 TLS 握手检查失败，已回退',
  actor_unauthenticated: '发起人身份已失效，请重新绑定证书',
  publisher_unavailable: '发布服务暂时不可用',
  publisher_timeout: '发布超时',
  publisher_cancelled: '发布已取消',
  publisher_panic: '发布服务内部错误',
  publisher_contract_invalid: '发布服务返回无效结果',
  legacy_reissue_required: '旧版本遗留的绑定，请重新绑定证书',
  unknown: '同步失败',
  syncFailed: '同步失败',
  someNode: '部分节点', nodeNamed: '节点 {{id}} ',
  syncFailedReason: '同步失败：{{reason}}',
  syncComplete: '已同步', syncPending: '同步中', syncColumn: '同步状态', syncLabel: '节点同步',
} as const

type Messages = Record<keyof typeof zhCN, string>

const enUS: Messages = {
  target_policy_not_automatic: 'The site publishes to a manual target; the certificate cannot sync automatically',
  target_policy_invalid: 'The site publication target is invalid',
  target_snapshot_unresolved: 'The site publication nodes cannot be resolved yet; it retries automatically',
  target_no_nodes: 'The site line group has no available node',
  target_node_missing: '{{node}} of the publication target does not exist',
  target_node_inactive: '{{node}} is disabled',
  target_node_not_carried: '{{node}} does not serve this tenant\'s sites',
  target_node_offline: '{{node}} is offline; it retries automatically',
  target_node_identity_ineligible: '{{node}} cannot take publications yet; it retries automatically',
  target_node_capability_missing: '{{node}} runs an agent without certificate delivery; upgrade the node',
  target_invalid: 'The publication target failed validation',
  publication_node_not_found: 'A node the publication needs does not exist',
  publication_config_not_releasable: 'The site configuration cannot be published now',
  publication_input_invalid: 'The publication request failed validation; it retries automatically',
  publication_unavailable: 'The publication service is unavailable; it retries automatically',
  publication_pending: 'Publication in progress',
  publication_node_busy: 'A node is running another publication; it retries once that finishes',
  publication_conflict: 'Conflicts with another publication',
  publication_contract_invalid: 'The publication result failed validation',
  publication_terminal_failed: 'Node deployment failed; see the publication records',
  node_certificate_precheck_failed: '{{node}} OpenResty rejected the certificate configuration (nginx -t failed)',
  node_certificate_activation_failed: '{{node}} OpenResty failed to start or reload with the certificate',
  node_certificate_health_failed: '{{node}} TLS handshake check failed after enabling the certificate; it was rolled back',
  actor_unauthenticated: 'The requester\'s session is no longer valid; bind the certificate again',
  publisher_unavailable: 'The publication service is unavailable',
  publisher_timeout: 'Publication timed out',
  publisher_cancelled: 'Publication was cancelled',
  publisher_panic: 'The publication service failed internally',
  publisher_contract_invalid: 'The publication service returned an invalid result',
  legacy_reissue_required: 'A binding left by an old version; bind the certificate again',
  unknown: 'Sync failed',
  syncFailed: 'Sync failed',
  someNode: 'A node', nodeNamed: 'Node {{id}}',
  syncFailedReason: 'Sync failed: {{reason}}',
  syncComplete: 'Synced', syncPending: 'Syncing', syncColumn: 'Sync status', syncLabel: 'Node sync',
}

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => (
    part.startsWith('{{') ? part : [...part].map((char) => /\s/u.test(char) ? char : `${char}~`).join('')
  )).join('')}］`
}

const pseudo = Object.fromEntries(Object.entries(zhCN).map(([key, value]) => [key, pseudoText(value)])) as Messages

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo })) {
  i18n.addResourceBundle(locale, 'certificatePublicationFailures', messages, true, true)
}

const messageKeys = new Set(['unknown', 'syncFailed', 'someNode', 'nodeNamed', 'syncFailedReason', 'syncComplete', 'syncPending', 'syncColumn', 'syncLabel'])
const knownCodes = new Set(Object.keys(zhCN).filter((code) => !messageKeys.has(code)))
const nodeSuffix = /^([a-z][a-z0-9_]*)\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/

// certificatePublicationFailureMessage translates "<code>[.<node ID>]"; an
// unknown code falls back to the generic text (the raw code is never shown).
export function certificatePublicationFailureMessage(code: string, t: TFunction<'certificatePublicationFailures'>): string {
  const match = nodeSuffix.exec(code)
  const base = match ? match[1] : code
  if (!knownCodes.has(base)) return t('unknown')
  return t(base as keyof typeof zhCN, { node: match ? t('nodeNamed', { id: match[2] }) : t('someNode') })
}
