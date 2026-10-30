import { useState } from 'react'
import { Alert, App, Button, Form, Input, Select, Space } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import '../../i18n/systemGlobalSettings'
import { ApiError } from '../../api/auth'
import { pluginProvidersApi, usableMailPlugins } from '../../api/pluginProviders'
import { useGrantedModules } from '../../components/useGrantedModules'
import {
  mailPluginPrefix, mailProviderKind, mailProviderRegions, officialMailProviders, systemMailSettingsApi,
  type OfficialMailProvider, type PlatformSystemMailSettings, type PlatformSystemMailSettingsDocument,
} from '../../api/systemMailSettings'
import { useFeedback } from '@cdnca/ui'

interface Props {
  accessToken: string
  canManage: boolean
  document: PlatformSystemMailSettingsDocument
  draft: PlatformSystemMailSettings
  update: <K extends keyof PlatformSystemMailSettings>(key: K, value: PlatformSystemMailSettings[K]) => void
  secret: string
  onSecretChange: (value: string) => void
  saving: boolean
  disabled: boolean
  onSave: () => void
  /** Form.Item props marking a server-refused field (fix-fielderr-be2). */
  fieldStatus?: (...keys: string[]) => { validateStatus?: 'error'; help?: string }
}

// The system mail sender card: one selector (built-in SMTP / official mail
// service / usable mail plugin), the official provider's fields, and a test
// mail sent with the values on the page before they are saved. An official
// service is offered only while the lease grants its module.mail.<provider>
// (the server refuses it otherwise); a saved one without it stays listed,
// marked unlicensed, so the page never silently shows another sender.
export default function MailProviderSection({ accessToken, canManage, document, draft, update, secret, onSecretChange, saving, disabled, onSave, fieldStatus = () => ({}) }: Props) {
  const { t } = useTranslation('systemGlobalSettings')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const [testTo, setTestTo] = useState('')
  const [testing, setTesting] = useState(false)
  const plugins = useQuery({ queryKey: ['plugin-providers', 'mail'], queryFn: () => pluginProvidersApi.list(accessToken), retry: false })
  const usable = usableMailPlugins(plugins.data ?? [])
  const granted = useGrantedModules(accessToken)
  const licensed = officialMailProviders.filter((provider) => granted.includes(`module.mail.${provider}`))
  const kind = mailProviderKind(draft.mail_provider)
  const official = kind === 'official' ? draft.mail_provider as OfficialMailProvider : null
  const chosenPlugin = kind === 'plugin' ? draft.mail_provider.slice(mailPluginPrefix.length) : ''
  const options = [
    { value: '', label: t('mailProvider.smtp') },
    ...licensed.map((provider) => ({ value: provider, label: t(`mailProvider.${provider}`) })),
    ...(official && !licensed.includes(official)
      ? [{ value: official, label: t('mailProvider.unlicensed', { name: t(`mailProvider.${official}`) }) }] : []),
    ...usable.map((plugin) => ({ value: mailPluginPrefix + plugin.plugin_id, label: t('mailProvider.plugin', { id: plugin.plugin_id }) })),
    ...(chosenPlugin && !usable.some((plugin) => plugin.plugin_id === chosenPlugin)
      ? [{ value: draft.mail_provider, label: t('mailProvider.unavailablePlugin', { id: chosenPlugin }) }] : []),
  ]
  const storedSecretFits = official !== null && document.mail_secret_configured && document.mail_secret_provider === official
  const secretExtra = official === null ? undefined
    : storedSecretFits ? t('mailProvider.secretSet', { fingerprint: document.mail_secret_fingerprint })
      : document.mail_secret_configured ? t('mailProvider.secretOther', { provider: t(`mailProvider.${document.mail_secret_provider}`) })
        : t('mailProvider.secretRequired')
  const field = (key: 'mail_access_key_id' | 'mail_from' | 'mail_from_name', label: string, extra?: string) =>
    <Form.Item label={label} extra={extra} {...fieldStatus(key)}>
      <Input value={draft[key]} disabled={!canManage} aria-label={label} onChange={(event) => update(key, event.target.value)} />
    </Form.Item>

  const test = async () => {
    setTesting(true)
    try {
      const result = await systemMailSettingsApi.test(accessToken, draft, testTo.trim(), official ? secret || undefined : undefined)
      if (result.ok) message.success(t('mailProvider.testSent', { id: result.message_id ? `（${result.message_id}）` : '' }))
      else feedback.error(t('mailProvider.testFailed', { code: result.code ?? '' }))
    } catch (reason) {
      const code = reason instanceof ApiError ? reason.code : 'network_error'
      feedback.error(t(`errors.${code}`, { defaultValue: t('mailProvider.testFailed', { code }) }))
    } finally {
      setTesting(false)
    }
  }

  return <section className="system-settings-config-card" aria-labelledby="system-settings-mail-provider-title">
    <h2 id="system-settings-mail-provider-title">{t('mailProvider.title')}</h2>
    <Form.Item label={t('mailProvider.field')} extra={t('mailProvider.hint')} {...fieldStatus('mail_provider')}>
      <Select value={kind === 'smtp' ? '' : draft.mail_provider} disabled={!canManage} aria-label={t('mailProvider.field')} options={options}
        loading={plugins.isLoading} onChange={(value: string) => update('mail_provider', value)} />
    </Form.Item>
    {official ? <>
      <Form.Item label={t('mailProvider.region')} {...fieldStatus('mail_region')}>
        <Select value={draft.mail_region || mailProviderRegions[official][0]} disabled={!canManage} aria-label={t('mailProvider.region')}
          options={mailProviderRegions[official].map((region) => ({ value: region, label: t(`mailProvider.regions.${region}`) }))}
          onChange={(value: string) => update('mail_region', value)} />
      </Form.Item>
      {official === 'aliyun' ? field('mail_access_key_id', t('mailProvider.accessKeyID')) : null}
      <Form.Item label={official === 'aliyun' ? t('mailProvider.secretAliyun') : t('mailProvider.secretSendGrid')} extra={secretExtra} {...fieldStatus('mail_secret')}>
        <Input.Password value={secret} disabled={!canManage} autoComplete="new-password" placeholder={storedSecretFits ? t('mailProvider.secretKeep') : ''}
          aria-label={official === 'aliyun' ? t('mailProvider.secretAliyun') : t('mailProvider.secretSendGrid')} onChange={(event) => onSecretChange(event.target.value)} />
      </Form.Item>
      {field('mail_from', t('mailProvider.from'), t('mailProvider.fromHint'))}
      {field('mail_from_name', t('mailProvider.fromName'))}
    </> : null}
    {kind === 'plugin' ? <Alert type="info" showIcon style={{ marginBottom: 16 }} message={t('mailProvider.pluginHint')} /> : null}
    <Form.Item label={t('mailProvider.testTo')}>
      <Space.Compact style={{ width: '100%' }}>
        <Input value={testTo} type="email" disabled={!canManage} aria-label={t('mailProvider.testTo')} placeholder="ops@example.com" onChange={(event) => setTestTo(event.target.value)} />
        <Button disabled={!canManage || testTo.trim() === '' || testing} loading={testing} onClick={() => void test()}>{t('mailActions.test')}</Button>
      </Space.Compact>
    </Form.Item>
    <div><Button type="primary" aria-label={t('mailActions.provider')} aria-busy={saving} disabled={!canManage || disabled} loading={saving} onClick={onSave}>{t('mailActions.provider')}</Button></div>
  </section>
}
