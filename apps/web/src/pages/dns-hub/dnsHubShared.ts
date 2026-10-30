import type { TFunction } from 'i18next'

import { ApiError } from '../../api/auth'
import type { DNSHubApiError, DNSHubDomain, DNSHubManaged } from '../../api/dnsHub'
import { providerSpecs, type ProviderChoice } from '../dns/dnsProviderSpecs'

export function domainKey(domain: Pick<DNSHubDomain, 'provider_id' | 'apex'>): string {
  return `${domain.provider_id}/${domain.apex}`
}

export function newIdempotencyKey(prefix: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `${prefix}-${suffix}`
}

// 错误码按 fix-dnshub-api 契约 v1（handler.go serviceError）；未识别的落到通用失败。
const codeKeys: Record<string, string> = {
  network_error: 'errors.network',
  invalid_response: 'errors.invalidResponse',
  validation_error: 'errors.validation',
  invalid_request: 'errors.validation',
  permission_denied: 'errors.permissionDenied',
  dns_hub_not_found: 'errors.notFound',
  idempotency_conflict: 'errors.requestFailed',
  dns_record_changed: 'errors.conflict',
  dns_record_managed: 'errors.managedConfirm',
  dns_record_conflict: 'errors.recordConflict',
  dns_record_unsupported: 'errors.unsupported',
  dns_hub_unavailable: 'errors.providerUnavailable',
}

// DNS 商短码：dns_provider_error 的 error.provider_code、域名清单 list_error、刷新结果 error（去掉 dns_provider_remote_ 前缀）
const providerCodeKeys: Record<string, string> = {
  credentials_rejected: 'errors.credentialsInvalid',
  rate_limited: 'errors.rateLimited',
  unsupported: 'errors.unsupported',
  line_not_in_plan: 'errors.unsupported',
  record_not_found: 'errors.notFound',
  invalid_response: 'errors.invalidResponse',
  invalid_input: 'errors.validation',
}

export function providerCodeKey(code: string | undefined): string {
  return (code && providerCodeKeys[code]) || 'errors.providerUnavailable'
}

export function dnsHubErrorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.code === 'dns_provider_error') return providerCodeKey((error as DNSHubApiError).providerCode)
  const byCode = codeKeys[error.code]
  if (byCode) return byCode
  if (error.status === 409) return 'errors.conflict'
  if (error.status === 404) return 'errors.notFound'
  if (error.status === 429) return 'errors.rateLimited'
  if (error.status === 400 || error.status === 422) return 'errors.validation'
  return 'errors.requestFailed'
}

// 批量逐条结果里的 error（{code, provider_code?}）
export function batchErrorKey(error: { code: string; provider_code?: string } | null | undefined): string {
  if (!error) return 'errors.requestFailed'
  if (error.code === 'dns_provider_error') return providerCodeKey(error.provider_code)
  return codeKeys[error.code] ?? 'errors.requestFailed'
}

export function managedUsage(t: TFunction, managed: DNSHubManaged): string {
  return t(`managed.${managed.kind}`, { site: managed.site_domain || managed.site_id || t('managed.unknownSite') })
}

// TTL 范围按厂商（dnsProviderSpecs：Cloudflare 最低 60、name.com 最低 300）。
export function ttlBounds(providerType: string): { min: number; max: number } {
  const spec = Object.hasOwn(providerSpecs, providerType) ? providerSpecs[providerType as ProviderChoice] : undefined
  return { min: spec?.minTTL ?? 1, max: spec?.maxTTL ?? 86400 }
}
