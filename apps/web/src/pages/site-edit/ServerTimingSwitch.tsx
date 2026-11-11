import { useId } from 'react'
import { useMutation } from '@tanstack/react-query'
import { App, Switch } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { sitesApi, type SiteDetail } from '../../api/sites'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/siteEdgeOptions'
import { SettingGroup } from './SiteEditFields'
import { useFeedback } from '@cdnca/ui'

const knownErrors = ['version_conflict', 'site_locked', 'permission_denied'] as const

/**
 * 高级设置 → 性能与协议「Server-Timing 响应头」:
 * saved on its own through the site PATCH (section basic, the saved basic
 * plus server_timing), like CacheStatusHeaderSwitch. Off by default; the
 * node leaves it out while the site is at attack escalation B or above.
 */
export default function ServerTimingSwitch({ detail, accessToken, disabled, onSaved }: {
  detail: SiteDetail
  accessToken: string
  disabled: boolean
  onSaved: (saved: SiteDetail) => void
}) {
  const { t } = useTranslation('siteEdgeOptions')
  const feedback = useFeedback()
  const { message } = App.useApp()
  const briefId = useId()
  const save = useMutation({
    mutationFn: (enabled: boolean) => sitesApi.patchBasic(accessToken, detail.id, {
      expected_version: detail.version, section: 'basic',
      changes: { ...detail.basic, server_timing: enabled },
    }, crypto.randomUUID()),
    onSuccess: (saved) => {
      onSaved(saved)
      message.success(t('serverTiming.saved'))
    },
    onError: (error) => {
      const code = error instanceof ApiError ? error.code : undefined
      const reason = knownErrors.find((known) => known === code)
      feedback.error(t('serverTiming.saveFailed'),
        localizedUnknownApiError(error, t(reason ? `serverTiming.errors.${reason}` : 'serverTiming.errors.request_failed')))
    },
  })
  const checked = save.isPending ? Boolean(save.variables) : detail.basic.server_timing ?? false
  return (
    <SettingGroup title={t('serverTiming.label')} help={<span id={briefId}>{t('serverTiming.help')}</span>} tip={t('serverTiming.tip')}
      extra={<Switch aria-label={t('serverTiming.label')} aria-describedby={briefId} checked={checked} loading={save.isPending}
        disabled={disabled || save.isPending} onChange={(enabled) => save.mutate(enabled)} />} />
  )
}
