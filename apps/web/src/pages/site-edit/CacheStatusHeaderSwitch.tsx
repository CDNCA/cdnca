import { useMutation } from '@tanstack/react-query'
import { App, Switch } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { sitesApi, type SiteDetail } from '../../api/sites'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/cachePolicy'
import './CacheSiteTab.css'
import { useFeedback } from '@cdnca/ui'

const knownErrors = ['version_conflict', 'site_locked', 'permission_denied'] as const

/**
 * 缓存设置 tab「响应头显示缓存状态（X-CDN-Cache）」:
 * saved on its own through the site PATCH (section basic, the saved basic
 * plus cache_status_header), apart from the cache policy revisions. The
 * server defaults it on; the node hides the header while the site is at
 * attack escalation level B or above.
 */
export default function CacheStatusHeaderSwitch({ detail, accessToken, disabled, onSaved }: {
  detail: SiteDetail
  accessToken: string
  disabled: boolean
  onSaved: (saved: SiteDetail) => void
}) {
  const { t } = useTranslation('cachePolicy')
  const feedback = useFeedback()
  const { message } = App.useApp()
  const save = useMutation({
    mutationFn: (enabled: boolean) => sitesApi.patchBasic(accessToken, detail.id, {
      expected_version: detail.version, section: 'basic',
      changes: { ...detail.basic, cache_status_header: enabled },
    }, crypto.randomUUID()),
    onSuccess: (saved) => {
      onSaved(saved)
      message.success(t('statusHeader.saved'))
    },
    onError: (error) => {
      const code = error instanceof ApiError ? error.code : undefined
      const reason = knownErrors.find((known) => known === code)
      feedback.error(t('statusHeader.saveFailed'),
        localizedUnknownApiError(error, t(reason ? `statusHeader.errors.${reason}` : 'statusHeader.errors.request_failed')))
    },
  })
  const checked = save.isPending ? Boolean(save.variables) : detail.basic.cache_status_header ?? true
  return (
    <div className="site-basic-ipv6-row cache-status-header-row">
      <div>
        <strong id="cache-status-header-label">{t('statusHeader.label')}</strong>
        <p id="cache-status-header-help">{t('statusHeader.help')}</p>
      </div>
      <Switch
        aria-label={t('statusHeader.label')}
        aria-describedby="cache-status-header-help"
        checked={checked}
        loading={save.isPending}
        disabled={disabled || save.isPending}
        onChange={(enabled) => save.mutate(enabled)}
      />
    </div>
  )
}
