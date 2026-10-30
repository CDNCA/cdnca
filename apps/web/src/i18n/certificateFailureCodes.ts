import type { TFunction } from 'i18next'
import i18n from './index'

// Failure codes certificate orders carry (certificate_orders.failure_code and
// the retry reason from dns_acme_outbox.last_error_code), as produced by
// services/control-api internal/acmeworker (model.go) and acmeruntime.
const zhCN = {
  acme_invalid_input: '证书申请参数无效',
  acme_key_unavailable: '证书密钥暂不可用',
  acme_account_unavailable: '证书签发机构账户暂不可用',
  acme_directory_unavailable: '证书签发机构暂时无法连接',
  acme_rate_limited: '证书签发请求过于频繁，稍后会自动重试',
  acme_order_rejected: '证书签发机构拒绝了该订单',
  acme_order_outcome_uncertain: '证书订单状态暂不确定，正在核对',
  acme_challenge_unavailable: '证书签发机构未提供可用的验证方式',
  acme_http01_node_aggregate_required: '当前版本不支持文件验证（HTTP-01），请改用 DNS 验证',
  acme_http01_node_unsupported: '部分节点版本过低，不支持文件验证（HTTP-01），请升级节点或改用 DNS 验证',
  acme_http01_no_serving_node: '域名不是可用站点或站点线路组没有可用节点，无法进行文件验证（HTTP-01）',
  acme_challenge_publish_failed: '写入验证记录失败（DNS TXT 或节点验证文件）',
  acme_challenge_propagation_failed: '验证 TXT 记录尚未在权威 DNS 全部生效',
  acme_authorization_invalid: '证书签发机构验证域名失败',
  acme_challenge_cleanup_failed: '清理验证记录失败',
  acme_finalize_failed: '证书签发收尾失败',
  acme_certificate_invalid: '签发的证书校验未通过',
  acme_certificate_store_failed: '保存签发的证书失败',
  acme_operation_busy: '同一订单正在处理中',
  acme_operation_conflict: '证书订单状态冲突',
  acme_lease_lost: '处理中断，将自动重试',
  acme_operation_store_failed: '证书订单状态保存失败',
  acme_renewal_claim_failed: '续期任务领取失败',
  acme_cancelled: '证书申请已取消',
  acme_timeout: '证书签发处理超时，将自动重试',
  acme_eab_required: '该签发机构要求 EAB 凭据：请管理员在系统设置 > 网站默认 > 证书中填写，或改用 Let\'s Encrypt',
  acme_runtime_failed: '证书签发服务内部错误',
  acme_issue_result_invalid: '签发结果校验未通过',
  acme_challenge_type_invalid: '验证方式无效',
  acme_dns_provider_invalid: 'DNS API 配置无效',
  acme_dns_provider_unavailable: 'DNS API 暂不可用，请检查 DNS API 配置',
  acme_dns_zone_unavailable: '没有找到该域名所在的 DNS 区域，请确认 DNS API 账号下托管了该域名',
  acme_http_provider_conflict: '文件验证配置冲突',
  acme_operation_snapshot_invalid: '证书订单快照无效',
  acme_order_state_invalid: '证书订单状态无效',
  acme_order_unavailable: '证书订单不存在或不可用',
  acme_outbox_payload_conflict: '证书申请任务内容冲突',
  acme_outbox_payload_invalid: '证书申请任务内容无效',
  dns_propagation_timeout: 'DNS 解析等待超时',
  dns_provider_unavailable: 'DNS 服务商暂时不可用',
  dns_credentials_rejected: 'DNS 服务商凭据被拒绝',
  acme_validation_failed: 'ACME 域名验证失败',
  certificate_issuance_failed: '证书签发失败',
  acme_order_failed: '证书签发机构未完成订单',
  certificate_order_failed: '证书订单处理失败',
  unknown: '证书申请失败',
  retrying: '重试中：{{reason}}',
  expandReason: '展开原因',
  collapseReason: '收起原因',
} as const

type Messages = Record<keyof typeof zhCN, string>

const enUS: Messages = {
  acme_invalid_input: 'The certificate request is invalid',
  acme_key_unavailable: 'The certificate key is unavailable',
  acme_account_unavailable: 'The CA account is unavailable',
  acme_directory_unavailable: 'The certificate authority cannot be reached',
  acme_rate_limited: 'Certificate issuance was rate limited; it retries automatically',
  acme_order_rejected: 'The certificate authority rejected the order',
  acme_order_outcome_uncertain: 'The order outcome is uncertain and is being checked',
  acme_challenge_unavailable: 'The certificate authority offered no usable challenge',
  acme_http01_node_aggregate_required: 'File validation (HTTP-01) is not available in this version; use DNS validation',
  acme_http01_node_unsupported: 'Some nodes run an agent without file validation (HTTP-01); upgrade them or use DNS validation',
  acme_http01_no_serving_node: 'The domain is not an active site or its line group has no serving node, so file validation (HTTP-01) is not possible',
  acme_challenge_publish_failed: 'Writing the validation record failed (DNS TXT or the node validation file)',
  acme_challenge_propagation_failed: 'The validation TXT record is not live on every authoritative DNS server yet',
  acme_authorization_invalid: 'The certificate authority could not validate the domain',
  acme_challenge_cleanup_failed: 'Cleaning up the validation record failed',
  acme_finalize_failed: 'Finalizing the certificate failed',
  acme_certificate_invalid: 'The issued certificate failed validation',
  acme_certificate_store_failed: 'Saving the issued certificate failed',
  acme_operation_busy: 'The order is already being processed',
  acme_operation_conflict: 'The certificate order state conflicts',
  acme_lease_lost: 'Processing was interrupted and retries automatically',
  acme_operation_store_failed: 'Saving the certificate order state failed',
  acme_renewal_claim_failed: 'Claiming the renewal failed',
  acme_cancelled: 'The certificate request was cancelled',
  acme_timeout: 'Issuance timed out and retries automatically',
  acme_eab_required: 'This certificate authority requires EAB credentials: an administrator sets them under System settings > Website defaults > Certificate, or switch to Let\'s Encrypt',
  acme_runtime_failed: 'The issuance service failed internally',
  acme_issue_result_invalid: 'The issuance result failed validation',
  acme_challenge_type_invalid: 'The challenge type is invalid',
  acme_dns_provider_invalid: 'The DNS API configuration is invalid',
  acme_dns_provider_unavailable: 'The DNS API is unavailable; check the DNS API configuration',
  acme_dns_zone_unavailable: 'No DNS zone holds this domain; check that the DNS API account hosts it',
  acme_http_provider_conflict: 'The file validation configuration conflicts',
  acme_operation_snapshot_invalid: 'The certificate order snapshot is invalid',
  acme_order_state_invalid: 'The certificate order state is invalid',
  acme_order_unavailable: 'The certificate order is missing or unavailable',
  acme_outbox_payload_conflict: 'The issuance task content conflicts',
  acme_outbox_payload_invalid: 'The issuance task content is invalid',
  dns_propagation_timeout: 'DNS propagation timed out',
  dns_provider_unavailable: 'The DNS provider is unavailable',
  dns_credentials_rejected: 'The DNS provider rejected the credentials',
  acme_validation_failed: 'ACME domain validation failed',
  certificate_issuance_failed: 'Certificate issuance failed',
  acme_order_failed: 'The certificate authority did not complete the order',
  certificate_order_failed: 'The certificate order failed',
  unknown: 'Certificate request failed',
  retrying: 'Retrying: {{reason}}',
  expandReason: 'Show full reason',
  collapseReason: 'Hide full reason',
}

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => (
    part.startsWith('{{') ? part : [...part].map((char) => /\s/u.test(char) ? char : `${char}~`).join('')
  )).join('')}］`
}

const pseudo = Object.fromEntries(Object.entries(zhCN).map(([key, value]) => [key, pseudoText(value)])) as Messages

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo })) {
  i18n.addResourceBundle(locale, 'certificateFailureCodes', messages, true, true)
}

const messageKeys = new Set(['unknown', 'retrying', 'expandReason', 'collapseReason'])
const knownCodes = new Set(Object.keys(zhCN).filter((code) => !messageKeys.has(code)))

// certificateFailureMessage renders a known code; unknown codes (never the raw
// code, which may carry CA text) fall back to the generic message.
export function certificateFailureMessage(code: string, t: TFunction<'certificateFailureCodes'>): string {
  return knownCodes.has(code) ? t(code as keyof typeof zhCN) : t('unknown')
}

// certificateOrderFailureText is the final failure, or for an order that is
// still in progress the reason of its last retry (retry_error_code).
export function certificateOrderFailureText(
  order: { status: string, failure_code?: string, retry_error_code?: string },
  t: TFunction<'certificateFailureCodes'>,
): string | undefined {
  if (order.failure_code) return certificateFailureMessage(order.failure_code, t)
  if (order.retry_error_code && ['pending', 'validating', 'issuing'].includes(order.status)) {
    return t('retrying', { reason: certificateFailureMessage(order.retry_error_code, t) })
  }
  return undefined
}

// certificateOrderFailureReason is the CA's own explanation (redacted by the
// server, at most 512 characters) of the failure or retry the text above shows.
export function certificateOrderFailureReason(
  order: { status: string, failure_code?: string, failure_reason?: string, retry_error_code?: string, retry_error_reason?: string },
): string | undefined {
  if (order.failure_code) return order.failure_reason || undefined
  if (order.retry_error_code && ['pending', 'validating', 'issuing'].includes(order.status)) return order.retry_error_reason || undefined
  return undefined
}
