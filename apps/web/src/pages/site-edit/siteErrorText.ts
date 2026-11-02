import type { TFunction } from 'i18next'

import { ApiError } from '../../api/auth'
import { localizedUnknownApiError } from '../../i18n/apiError'

/** The localized reason a site write was refused (site edit page and the quick HTTPS switch). */
export function siteEditErrorMessage(error: ApiError, t: TFunction<['sites', 'siteTLS']>): string {
  switch (error.code) {
    case 'site_locked':
    case 'version_conflict':
    case 'permission_denied':
    case 'site_not_found':
    case 'network_error':
    case 'request_failed':
      return t(`edit.errors.${error.code}`)
    case 'validation_error':
      // The server names the refused field (error.details.field).
      if (error.field) {
        return localizedUnknownApiError(error, t(`edit.errors.fields.${error.field}`, {
          defaultValue: t('edit.errors.fieldInvalid', { field: error.field }),
        }))
      }
      return localizedUnknownApiError(error, t('edit.errors.request_failed'))
    default:
      return localizedUnknownApiError(error, t('edit.errors.request_failed'))
  }
}
