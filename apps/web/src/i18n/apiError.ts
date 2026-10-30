import i18n from './index'
import { ApiError } from '../api/auth'
import { publishRefusalText } from './publishRefusal'

export function localizedUnknownApiError(error: unknown, fallback: string): string {
  // 423 installation_locked (ADR 0014 §5.2) answers every write while the
  // license is locked; say so instead of a generic failure on every page.
  if (error instanceof ApiError && error.code === 'installation_locked') fallback = i18n.t('errors:installation_locked')
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
