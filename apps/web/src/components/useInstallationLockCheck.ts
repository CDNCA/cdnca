import { useMutation, useQueryClient } from '@tanstack/react-query'
import { App } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { installationLockApi, type InstallationLock } from '../api/installationLock'
import { useSessionStore } from '../auth/session'
import '../i18n/marketSupplier'

export const installationLockQueryKey = ['installation-lock']

// The one "check again" of a locked controller (ADR 0014 §5.2), shared by the
// lock banner and the home page authorization card (LIC-REC-03): it asks the
// controller to fetch the installation state now, renews an expired lease,
// and re-reads the dashboards so both places show the same result.
export function useInstallationLockCheck() {
  const { t } = useTranslation('marketSupplier')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  return useMutation({
    mutationFn: () => installationLockApi.check(token),
    onSuccess: async (next: InstallationLock) => {
      client.setQueryData(installationLockQueryKey, next)
      void message[next.locked ? 'warning' : 'success'](t(next.locked ? 'lock.stillLocked' : 'lock.unlocked'))
      await client.invalidateQueries({ queryKey: ['dashboard'] })
    },
    // C15/AUTH-BAN-FEEDBACK-01: a failed check keeps the lock shown and says so
    // (401 is renewed by the session client and retried there).
    onError: (error) => {
      if (error instanceof ApiError && error.status === 401) return
      const code = error instanceof ApiError ? error.code : 'request_failed'
      const requestID = error instanceof ApiError ? error.requestId : undefined
      void message.error(t('lock.checkFailed', { code }) + (requestID ? ` · ${t('lock.requestId', { id: requestID })}` : ''))
    },
  })
}
