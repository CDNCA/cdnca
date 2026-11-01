import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Alert, Button, Input, Modal, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../../api/auth'
import { apiKeysApi, type IssuedAPIKey } from '../../api/apiKeys'
import type { PluginInstallation } from '../../api/pluginInstallations'
import '../../i18n/pluginInstallations'
import { FeedbackWhen } from '@cdnca/ui'

// Same safe subset as the account API key page: never platform, identity or API key administration.
function safeScope(permission: string): boolean {
  return permission !== 'platform.admin' && !permission.startsWith('identity.') && !permission.startsWith('api_keys.')
}

/** Scopes a plugin identity key gets: what the tenant approved for the plugin and the signed-in user holds. */
export function pluginIdentityScopes(installation: Pick<PluginInstallation, 'approved_scopes'>, principal: Pick<Principal, 'permissions'>): string[] {
  return installation.approved_scopes.filter((scope) => safeScope(scope) && principal.permissions.includes(scope))
}

function newKey(): string {
  const random = typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '')
    : `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`
  return `plugin-identity-key-${random}`.slice(0, 128)
}

/**
 * 为插件签发 Key（插件身份，ADR 0007 §3.2）：把这把 API Key 绑定到当前安装，交给插件后端调用开放接口。
 * 插件身份的写请求逐次审计为插件、按安装限频；暂停或卸载插件后这把 Key 立即失效。
 * 只对用户端、已启用的安装、有 api_keys.self.manage 的用户显示。
 */
export function PluginIdentityKeyPanel({ token, principal, installation }: {
  token: string; principal: Principal; installation: PluginInstallation
}) {
  const { t } = useTranslation('pluginInstallations')
  const [issued, setIssued] = useState<IssuedAPIKey | null>(null)
  // One key per attempt: a retry after an unknown answer replays the same request.
  const [attemptKey, setAttemptKey] = useState(newKey)
  const scopes = pluginIdentityScopes(installation, principal)
  const mutation = useMutation({
    gcTime: 0,
    mutationFn: () => apiKeysApi.create(token, {
      name: t('identityKey.keyName', { plugin: installation.plugin_id }).slice(0, 128), scopes, ip_allowlist: [],
      plugin_installation_authorization_id: installation.authorization_id,
    }, attemptKey),
    onSuccess: (result) => {
      setIssued(result)
      setAttemptKey(newKey())
    },
    onError: (error) => {
      // A refused request (4xx) is settled; a new click starts a new request.
      if (error instanceof ApiError && error.status >= 400 && error.status < 500 && error.status !== 408) setAttemptKey(newKey())
    },
  })
  if (!principal.permissions.includes('api_keys.self.manage') || installation.status !== 'enabled') return null
  const credential = issued ? `${issued.key.key_id}.${issued.secret}` : ''
  const errorCode = mutation.error instanceof ApiError ? mutation.error.code : undefined
  return <section className="plugin-market-identity-key" aria-label={t('identityKey.title')}>
    <Typography.Title level={5}>{t('identityKey.title')}</Typography.Title>
    <Typography.Paragraph type="secondary">{t('identityKey.help')}</Typography.Paragraph>
    {scopes.length === 0 ? <Alert type="info" showIcon message={t('identityKey.noScopes')} /> : <>
      <Typography.Paragraph>{t('identityKey.scopes', { scopes: scopes.join(', ') })}</Typography.Paragraph>
      <Button type="primary" loading={mutation.isPending} onClick={() => mutation.mutate()}>{t('identityKey.issue')}</Button>
    </>}
    {mutation.isError ? <FeedbackWhen title={t(errorCode === 'plugin_installation_unavailable'
      ? 'identityKey.unavailable' : 'identityKey.failed')} /> : null}
    <Modal open={Boolean(issued)} title={t('identityKey.secretTitle')} closable onCancel={() => setIssued(null)}
      footer={<Button type="primary" onClick={() => setIssued(null)}>{t('identityKey.saved')}</Button>}>
      <Alert type="warning" showIcon message={t('identityKey.secretWarning')} />
      <Input.TextArea readOnly autoSize aria-label={t('identityKey.secretLabel')} value={credential} />
      <Typography.Paragraph type="secondary">{t('identityKey.header')}</Typography.Paragraph>
      <Button onClick={() => void navigator.clipboard?.writeText(credential)}>{t('identityKey.copy')}</Button>
    </Modal>
  </section>
}
