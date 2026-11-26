import { useRef, useState, type ReactNode } from 'react'
import type { NotificationRuntimeHealth } from '../../api/notifications'
import { Alert, App, Button, Form, Input, Select, Space, type InputRef } from 'antd'
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
  smtpSettings?: ReactNode
  smtpPasswordPending: boolean
  /** auto: a saved sender is picked up without a restart; explicit: restart needed. */
  notificationMode?: NotificationRuntimeHealth['mode']
  /** Form.Item props marking a server-refused field (fix-fielderr-be2). */
  fieldStatus?: (...keys: string[]) => { validateStatus?: 'error'; help?: string }
}

// The system mail sender card: one selector (built-in SMTP / official mail
// service / usable mail plugin), the official provider's fields, and a test
// mail sent with the values on the page before they are saved. An official
// service is offered only while the lease grants its module.mail.<provider>
// (the server refuses it otherwise); a saved one without it stays listed,
// marked unlicensed, so the page never silently shows another sender.
export default function MailProviderSection({ accessToken, canManage, document, draft, update, secret, onSecretChange, saving, disabled, onSave, smtpSettings, smtpPasswordPending, notificationMode, fieldStatus = () => ({}) }: Props) {
  const { t } = useTranslation('systemGlobalSettings')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const [testTo, setTestTo] = useState('')
  const [testing, setTesting] = useState(false)
  // a malformed recipient is shown once the input is
  // left or the test is clicked; a server refusal of "to" holds for that value.
  const [testToTouched, setTestToTouched] = useState(false)
  const [refusedTo, setRefusedTo] = useState<string | null>(null)
  const testToInput = useRef<InputRef>(null)
  const plugins = useQuery({ queryKey: ['plugin-providers', 'mail'], queryFn: () => pluginProvidersApi.list(accessToken), retry: false })
  const usable = usableMailPlugins(plugins.data ?? [])
  const granted = useGrantedModules(accessToken)
  const licensed = officialMailProviders.filter((provider) => granted.includes(`module.mail.${provider}`))
  const kind = mailProviderKind(draft.mail_provider)
  const testNeedsSavedPassword = kind === 'smtp' && smtpPasswordPending
  // What the SMTP test would report as config_incomplete (smtpMissing in
  // cmd/control-api), judged from the unsaved form and the saved password;
  // the sender is smtp_from, else the SMTP user when it is an address.
  const mailbox = (value: string) => /^[^\s@<>,;]+@[^\s@<>,;]+$/.test(value)
  const sender = draft.smtp_from.trim() !== '' ? draft.smtp_from.trim() : draft.smtp_user.trim()
  const pageMissing = kind !== 'smtp' ? [] : ([
    ['smtp_address', draft.smtp_address.trim() === ''],
    ['smtp_user', draft.smtp_user.trim() === ''],
    ['smtp_password', !smtpPasswordPending && !document.smtp_password_configured && draft.smtp_password_reference === ''],
    ['smtp_from', !mailbox(sender)],
  ] as const).filter(([, missing]) => missing).map(([key]): string => key)
  // A 422 config_incomplete answer may name more (the server also reads its
  // environment); it holds until the form or the saved settings change.
  const [answered, setAnswered] = useState<{ draft: PlatformSystemMailSettings, document: PlatformSystemMailSettingsDocument, missing: string[] } | null>(null)
  const serverMissing = answered && answered.draft === draft && answered.document === document ? answered.missing : []
  const smtpMissing = [...pageMissing, ...serverMissing.filter((key) => !pageMissing.includes(key))]
  const testToMissing = testTo.trim() === ''
  // libs/mail ValidAddress: no spaces or <>,; and at most 254 bytes (the page sends the trimmed value)
  const testToInvalid = !testToMissing && (!mailbox(testTo.trim()) || new TextEncoder().encode(testTo.trim()).length > 254)
  const testToError = testToInvalid && testToTouched || refusedTo !== null && refusedTo === testTo.trim() && !testToMissing
  const focusField = (key: string) => {
    const input = window.document.getElementById(`system-mail-${key}`)
    input?.scrollIntoView?.({ block: 'center' })
    input?.focus({ preventScroll: true })
  }
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
    if (testToInvalid) {
      setTestToTouched(true)
      testToInput.current?.focus()
      return
    }
    setRefusedTo(null)
    setTesting(true)
    try {
      const sent = draft
      const result = await systemMailSettingsApi.test(accessToken, sent, testTo.trim(), official ? secret || undefined : undefined)
      const missing = (result.missing ?? []).map((field) => field.replace(/^value\./, ''))
      setAnswered(result.code === 'config_incomplete' ? { draft: sent, document, missing } : null)
      if (result.ok) message.success(t('mailProvider.testSent', { id: result.message_id ? `（${result.message_id}）` : '' }))
      else if (result.code === 'config_incomplete') feedback.error(t('mailProvider.testIncomplete', {
        fields: missing.map((field) => t(`mailProvider.missingFields.${field}`, { defaultValue: field })).join(t('mailProvider.listSeparator')),
      }))
      else feedback.error(t('mailProvider.testFailed', { code: result.code ?? '' }))
    } catch (reason) {
      const code = reason instanceof ApiError ? reason.code : 'network_error'
      if (reason instanceof ApiError && code === 'system_mail_settings_validation_error' && reason.field === 'to') {
        setRefusedTo(testTo.trim())
        testToInput.current?.focus()
        return
      }
      feedback.error(t(`errors.${code}`, { defaultValue: t('mailProvider.testFailed', { code }) }))
    } finally {
      setTesting(false)
    }
  }

  return <section className="system-settings-config-card" aria-labelledby="system-settings-mail-provider-title">
    <h2 id="system-settings-mail-provider-title">{t('mailProvider.title')}</h2>
    <Form.Item label={t('mailProvider.field')} extra={notificationMode === 'auto' ? t('smsProviders.hintAuto') : notificationMode === 'explicit' ? t('smsProviders.hintRestart') : undefined} {...fieldStatus('mail_provider')}>
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
    {kind === 'smtp' ? smtpSettings : null}
    {/* Every reason the test button is off is spelled out right under it. */}
    <Form.Item label={t('mailProvider.testTo')} {...(testToError ? { validateStatus: 'error' as const, help: <span id="system-mail-test-to-error">{t('mailProvider.testToInvalid')}</span> } : {})} extra={testNeedsSavedPassword || smtpMissing.length > 0 || testToMissing ? <>
      {testNeedsSavedPassword ? <div>{t('mailProvider.savePasswordBeforeTest')}</div> : null}
      {smtpMissing.length > 0 ? <div className="system-settings-mail-test-missing" role="group" aria-label={t('mailProvider.smtpIncomplete')}>
        {t('mailProvider.smtpIncompleteNeed')}
        {smtpMissing.map((key) => <Button key={key} type="link" size="small" style={{ paddingInline: 4 }} onClick={() => focusField(key)}>
          {t(`mailProvider.missingFields.${key}`, { defaultValue: key })}</Button>)}
      </div> : null}
      {testToMissing ? <div>{t('mailProvider.testToRequired')}</div> : null}
    </> : undefined}>
      <Space.Compact className="system-settings-mail-test">
        <Input ref={testToInput} value={testTo} type="email" disabled={!canManage} aria-label={t('mailProvider.testTo')} placeholder="ops@example.com"
          aria-invalid={testToError || undefined} aria-describedby={testToError ? 'system-mail-test-to-error' : undefined}
          onChange={(event) => setTestTo(event.target.value)} onBlur={() => setTestToTouched(true)} />
        <Button disabled={!canManage || testToMissing || testing || testNeedsSavedPassword || smtpMissing.length > 0} loading={testing} onClick={() => void test()}>{t('mailActions.test')}</Button>
      </Space.Compact>
    </Form.Item>
    {kind !== 'smtp' ? <div><Button type="primary" aria-label={t('mailActions.provider')} aria-busy={saving} disabled={!canManage || disabled} loading={saving} onClick={onSave}>{t('mailActions.provider')}</Button></div> : null}
  </section>
}
