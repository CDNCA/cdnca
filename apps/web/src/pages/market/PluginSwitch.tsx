import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Modal, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, newIdempotencyKey, type MarketPlugin } from '../../api/market'
import {
  newPluginInstallationIdempotencyKey, platformPluginInstallationsApi, type PluginInstallation,
} from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import { grantedModulesQueryKey } from '../../components/useGrantedModules'
import { resumable } from './marketModel'

const managePermission = 'plugin_installations.platform.manage'

interface Attempt { kind: 'disable' | 'resume'; key: string }

const unknownOutcome = (error: unknown) => !(error instanceof ApiError) || error.code === 'plugin_installation_result_unknown' ||
  error.status === 0 || error.status === 408 || error.status >= 500

/**
 * 停用 / 重新启用 of a platform installation record (POST /v1/platform/plugin-installations/{id}/disable|resume, the
 * same calls as 安装记录 详情). Disable says what it does and asks for no reason; resume restores exactly what this
 * controller paused. A platform pause cannot be resumed here. An unknown outcome keeps its Idempotency-Key, so
 * the retry replays it instead of acting twice.
 */
export function InstallationSwitch({ installation, name }: { installation: PluginInstallation; name: string }) {
  const { t } = useTranslation('marketStore')
  const { message } = App.useApp()
  const client = useQueryClient()
  const canManage = useSessionStore((s) => s.principal?.scope_kind === 'platform' &&
    s.principal.permissions.includes(managePermission))
  const [confirming, setConfirming] = useState(false)
  const [unsettled, setUnsettled] = useState<Attempt | null>(null)
  const mutation = useMutation({
    mutationFn: (attempt: Attempt) => {
      const token = useSessionStore.getState().accessToken
      if (!token) throw new ApiError('Permission denied', 403, 'permission_denied')
      const { authorization_id: id, revision, tenant_scope_id: scope } = installation
      return attempt.kind === 'disable'
        ? platformPluginInstallationsApi.disable(token, scope, id, revision, attempt.key)
        : platformPluginInstallationsApi.resume(token, scope, id, revision, attempt.key)
    },
    onSuccess: (_, attempt) => {
      setUnsettled(null)
      setConfirming(false)
      void message.success(t(attempt.kind === 'disable' ? 'toggle.disabled' : 'toggle.resumed'))
      void client.invalidateQueries({ queryKey: ['marketStore', 'library'] })
      void client.invalidateQueries({ queryKey: ['plugin-installations'] })
      void client.invalidateQueries({ queryKey: ['plugin-installation'] })
    },
    onError: (error, attempt) => {
      const unknown = unknownOutcome(error)
      setUnsettled(unknown ? attempt : null)
      if (error instanceof ApiError && error.code === 'plugin_installation_platform_paused') {
        void client.invalidateQueries({ queryKey: ['marketStore', 'library'] })
        return void message.error(t('toggle.platformPaused'))
      }
      void message.error(unknown ? t('toggle.unknown') : t('toggle.failed', { code: error instanceof ApiError ? error.code : 'request_failed' }))
    },
  })
  // The same action after an unknown outcome is a retry: same key. Anything else is a new attempt.
  const run = (kind: Attempt['kind']) => mutation.mutate(
    unsettled && unsettled.kind === kind ? unsettled : { kind, key: newPluginInstallationIdempotencyKey(kind) })

  if (installation.status === 'disabled' && !resumable(installation)) {
    return <Typography.Text type="secondary">{t('toggle.platformPaused')}</Typography.Text>
  }
  if (!canManage) return null
  if (installation.status === 'disabled') {
    return <Button size="small" type="primary" loading={mutation.isPending} onClick={() => run('resume')}>{t('toggle.resume')}</Button>
  }
  if (installation.status !== 'enabled') return null
  return <>
    <Button size="small" danger onClick={() => setConfirming(true)}>{t('toggle.disable')}</Button>
    <Modal open={confirming} title={t('toggle.disableTitle', { name })} okText={t('toggle.confirmDisable')} cancelText={t('actions.cancel')}
      okButtonProps={{ danger: true }} confirmLoading={mutation.isPending}
      onOk={() => run('disable')} onCancel={() => !mutation.isPending && setConfirming(false)} destroyOnHidden>
      <Alert type="warning" showIcon message={t('toggle.disableEffect')} />
    </Modal>
  </>
}

/**
 * 停用 / 重新启用 of an official feature plugin on this controller (POST /v1/admin/market/plugin-library/{id}/
 * disable|enable). Stopping takes its feature code out of the lease's grant here for every tenant; the licence, billing
 * and its configuration stay. The confirmation names the plugins that stop working with it (dependents) without
 * changing their state, and asks for no reason. Same unknown-outcome rule as
 * InstallationSwitch: a retry reuses its Idempotency-Key.
 */
export function FeatureSwitch({ plugin, name, stopped, dependents }: {
  plugin: Pick<MarketPlugin, 'plugin_id' | 'feature_code'>; name: string; stopped: boolean; dependents: readonly string[]
}) {
  const { t } = useTranslation('marketStore')
  const { message } = App.useApp()
  const client = useQueryClient()
  const canManage = useSessionStore((s) => s.principal?.scope_kind === 'platform' &&
    (s.principal.permissions.includes(managePermission) || s.principal.permissions.includes('platform.admin')))
  const [confirming, setConfirming] = useState(false)
  const [unsettled, setUnsettled] = useState<Attempt | null>(null)
  const mutation = useMutation({
    mutationFn: (attempt: Attempt) => {
      const token = useSessionStore.getState().accessToken
      if (!token) throw new ApiError('Permission denied', 403, 'permission_denied')
      return attempt.kind === 'disable'
        ? marketApi.disableLocally(token, plugin.plugin_id, { feature_code: plugin.feature_code ?? '' }, attempt.key)
        : marketApi.enableLocally(token, plugin.plugin_id, attempt.key)
    },
    onSuccess: (_, attempt) => {
      setUnsettled(null)
      setConfirming(false)
      void message.success(t(attempt.kind === 'disable' ? 'toggle.disabled' : 'toggle.resumed'))
      void client.invalidateQueries({ queryKey: ['marketStore', 'library'] })
      void client.invalidateQueries({ queryKey: grantedModulesQueryKey })
    },
    onError: (error, attempt) => {
      const unknown = unknownOutcome(error)
      setUnsettled(unknown ? attempt : null)
      void message.error(unknown ? t('toggle.unknown') : t('toggle.failed', { code: error instanceof ApiError ? error.code : 'request_failed' }))
    },
  })
  const run = (kind: Attempt['kind']) => mutation.mutate(
    unsettled && unsettled.kind === kind ? unsettled
      : { kind, key: newIdempotencyKey(kind === 'disable' ? 'plugin-local-disable' : 'plugin-local-enable') })

  if (!canManage || !plugin.feature_code) return null
  if (stopped) {
    return <Button size="small" type="primary" className="market-store-switch-button" loading={mutation.isPending}
      onClick={() => run('resume')}>{t('toggle.resume')}</Button>
  }
  return <>
    <Button size="small" danger className="market-store-switch-button" onClick={() => setConfirming(true)}>{t('toggle.disable')}</Button>
    <Modal open={confirming} title={t('toggle.disableTitle', { name })} okText={t('toggle.confirmDisable')} cancelText={t('actions.cancel')}
      okButtonProps={{ danger: true }} confirmLoading={mutation.isPending}
      onOk={() => run('disable')} onCancel={() => !mutation.isPending && setConfirming(false)} destroyOnHidden>
      <Alert type="warning" showIcon message={t('toggle.featureDisableEffect')}
        description={dependents.length ? <>
          <div>{t('toggle.dependents')}</div>
          <ul aria-label={t('toggle.dependents')} className="market-store-dependents">{dependents.map((d) => <li key={d}>{d}</li>)}</ul>
          <div>{t('toggle.dependentsHint')}</div>
        </> : undefined} />
    </Modal>
  </>
}
