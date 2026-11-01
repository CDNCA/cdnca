import i18n from './index'
import { ApiError } from '../api/auth'
import { publishRefusalText } from './publishRefusal'

/** omfix-a 5: the control plane has the feature switched off (503 feature_disabled), not a passing outage. */
export function isFeatureDisabled(error: unknown): boolean {
  return error instanceof ApiError && error.code === 'feature_disabled'
}

// MFA step-up display：POST /v1/account/mfa/step-up-proofs 的确定拒绝（mfahttp publicError）。
// 这些是用户输入或账号状态问题，要直接说原因，不能落到「请求失败，请稍后重试」。
const mfaStepUpRefusals = new Set(['mfa_invalid_code', 'mfa_code_replayed', 'mfa_recovery_code_used', 'mfa_not_active'])

/** The step-up refusal text for an MFA code / state error, or null for any other error. */
export function mfaStepUpErrorText(error: unknown): string | null {
  return error instanceof ApiError && mfaStepUpRefusals.has(error.code) ? i18n.t(`errors:${error.code}`) : null
}

export function localizedUnknownApiError(error: unknown, fallback: string): string {
  const stepUp = mfaStepUpErrorText(error)
  if (stepUp) return stepUp
  if (isFeatureDisabled(error)) fallback = i18n.t('errors:feature_disabled')
  // 423 installation_locked (ADR 0014 §5.2) answers every write while the
  // license is locked; say so instead of a generic failure on every page.
  if (error instanceof ApiError && error.code === 'installation_locked') fallback = i18n.t('errors:installation_locked')
  if (error instanceof ApiError && error.code === 'impersonation_sensitive_action_denied') {
    fallback = i18n.t('errors:impersonation_sensitive_action_denied')
  }
  // A structured publish refusal (rule packs / capability) names the nodes
  // instead of a generic failure (ui-errmsg-1024 N17).
  if (error instanceof ApiError) fallback = publishRefusalText(error) ?? fallback
  return error instanceof ApiError && error.requestId
    ? `${fallback}（${i18n.t('errors:requestId', { requestId: error.requestId })}）`
    : fallback
}

export function localizedApiError(error: unknown): string {
  if (!(error instanceof ApiError)) return i18n.t('errors:unknown')

  const key = `errors:${error.code}`
  if (i18n.exists(key)) return i18n.t(key)

  return localizedUnknownApiError(error, i18n.t('errors:request_failed'))
}
