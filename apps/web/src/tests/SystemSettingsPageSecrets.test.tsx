import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { pluginProvidersApi } from '../api/pluginProviders'
import { systemMailSettingsApi, type PlatformSystemMailSettingsDocument } from '../api/systemMailSettings'
import { systemUserSettingsApi, type PlatformSystemUserSettingsDocument } from '../api/systemUserSettings'
import { useSessionStore } from '../auth/session'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// every secret on the settings page is a write-only
// plaintext box (Input.Password) that shows only "set" and a fingerprint;
// empty keeps it, the clear button clears it, references stay advanced.

vi.mock('../components/useGrantedModules', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../components/useGrantedModules')>()),
  useGrantedModules: () => [],
}))

const userDocument = {
  schema: 'cdnca.platform-system-user-settings/v1', revision: 3,
  value: {
    session_ttl_seconds: 86400, user_login_domains: '', admin_login_domains: '', email_code_login_enabled: false, sms_code_login_enabled: false,
    registration_enabled: false, registration_success_subject: 's', registration_success_body: 'b', password_reset_subject: 's', password_reset_body: 'b', verification_template_channel: 'email', verification_subject: 's', verification_body: '{{captcha}}', verification_sms_body: '${captcha}', verification_sms_template_id: '', terms_title: 't', terms_body: 'b', username_required: false, email_required: false, email_verification_required: false, phone_required: false, phone_verification_required: false, qq_required: false,
    login_failure_limit_per_hour: 30, login_captcha_threshold_per_hour: 3, session_region_check: false, email_anti_abuse_mode: 'none', sms_anti_abuse_mode: 'none', captcha_provider: 'tencent', captcha_secret_id_reference: '', captcha_secret_key_reference: '', captcha_app_id: '', captcha_app_secret_reference: '', captcha_turnstile_site_key: '', identity_verification_method: 'none', enterprise_verification_enabled: false, identity_policy_saved: false, kyc_provider_name: '', kyc_endpoint: '', kyc_callback_key_id: '', kyc_object_endpoint: '', kyc_object_region: '', kyc_object_bucket: '', kyc_object_prefix: '', kyc_object_kms_key_id: '', wechat_payment_enabled: false, alipay_payment_enabled: false, bank_transfer_enabled: false, default_recharge_method: 'none', recharge_restriction: 'none', default_phone_country_code: '86',
  },
} satisfies PlatformSystemUserSettingsDocument

function signIn() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function setupUser(tab: 'account' | 'payment', document: PlatformSystemUserSettingsDocument = userDocument) {
  signIn()
  vi.spyOn(systemUserSettingsApi, 'get').mockResolvedValue(document)
  // as the server: an omitted secret stays saved
  const put = vi.spyOn(systemUserSettingsApi, 'put').mockImplementation(async (_token, revision, next, _request, _key, secrets) => ({
    ...document, revision: revision + 1, value: next,
    ...Object.fromEntries(Object.entries(secrets ?? {}).filter(([, value]) => value).flatMap(([name]) => [[`${name}_configured`, true], [`${name}_fingerprint`, '0123456789abcdef']])),
  }))
  vi.stubGlobal('fetch', vi.fn(async (path: string) => path.endsWith('/v1/modules')
    ? { ok: true, status: 200, json: async () => ({ status: 'valid', lease_serial: 4, modules: [] }) }
    : { ok: false, status: 404, json: async () => ({ code: 'not_found' }) }))
  renderWithProviders(<SystemGlobalSettingsPage initialTab={tab} />)
  return put
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('CAPTCHA secrets', () => {
  it('saves typed secrets write-only and shows only their fingerprints', async () => {
    const put = setupUser('account')
    const user = userEvent.setup()
    const secretID = await screen.findByLabelText('SecretId')
    expect(secretID).toHaveAttribute('type', 'password')
    expect(screen.queryByRole('textbox', { name: 'SecretId 密钥引用' })).not.toBeInTheDocument()
    await user.type(secretID, 'AKIDplain')
    await user.type(screen.getByLabelText('SecretKey'), 'plain-key')
    await user.type(screen.getByLabelText('AppSecretKey'), 'plain-app')
    await user.click(screen.getAllByRole('button', { name: /保\s*存/ }).at(-1)!)
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [, , value, , , secrets] = put.mock.calls[0]
    expect(secrets).toEqual({ captcha_secret_id: 'AKIDplain', captcha_secret_key: 'plain-key', captcha_app_secret: 'plain-app' })
    expect(JSON.stringify(value)).not.toContain('plain')
    expect(await screen.findAllByText('已设置（指纹 0123456789abcdef），加密保存，不会回显')).toHaveLength(3)
    expect(screen.getByLabelText('SecretId')).toHaveValue('')
  })

  it('keeps a saved secret when left empty and clears it with the clear button', async () => {
    const put = setupUser('account', { ...userDocument, captcha_app_secret_configured: true, captcha_app_secret_fingerprint: 'fedcba9876543210' })
    const user = userEvent.setup()
    expect(await screen.findByText('已设置（指纹 fedcba9876543210），加密保存，不会回显')).toBeInTheDocument()
    expect(screen.getByLabelText('AppSecretKey')).toHaveAttribute('placeholder', '已设置，留空则不修改')
    await user.click(screen.getAllByRole('button', { name: /保\s*存/ }).at(-1)!)
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][5]).toEqual({ captcha_secret_id: undefined, captcha_secret_key: undefined, captcha_app_secret: undefined })
    await user.click(screen.getByRole('button', { name: /清\s*除/ }))
    const confirm = await screen.findByRole('tooltip')
    expect(within(confirm).getByText('清除已保存的 AppSecretKey？')).toBeInTheDocument()
    await user.click(within(confirm).getByRole('button', { name: /确\s*定|OK/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(put.mock.calls[1][5]).toMatchObject({ captcha_app_secret: '' })
  })

  it('still accepts a secret reference under the advanced option', async () => {
    const put = setupUser('account')
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: '高级：使用密钥引用' }))
    await user.type(screen.getByRole('textbox', { name: 'AppSecretKey 密钥引用' }), 'vault://captcha/app-secret')
    await user.click(screen.getAllByRole('button', { name: /保\s*存/ }).at(-1)!)
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][2]).toMatchObject({ captcha_app_secret_reference: 'vault://captcha/app-secret' })
  })
})

describe('KYC provider credentials and identity policy', () => {
  it('sends only the KYC credentials from the payment tab and marks the identity policy saved', async () => {
    const put = setupUser('payment')
    const user = userEvent.setup()
    const apiKey = await screen.findByLabelText('KYC API Key')
    expect(apiKey).toHaveAttribute('type', 'password')
    await user.type(apiKey, 'kyc-api-key-0123456789')
    await user.type(screen.getByLabelText('KYC 回调签名密钥'), 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=')
    await user.click(screen.getByRole('button', { name: '保存认证与支付设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][5]).toEqual({ kyc_api_key: 'kyc-api-key-0123456789', kyc_callback_hmac_key: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=' })
    expect(put.mock.calls[0][2]).toMatchObject({ identity_policy_saved: true })
    expect(JSON.stringify(put.mock.calls[0][2])).not.toContain('kyc-api-key')
  })

  it('saves the KYC service and object store fields; the object store keys are write-only', async () => {
    const put = setupUser('payment')
    const user = userEvent.setup()
    expect(await screen.findByText('未填写的项使用运行环境中对应的 IDENTITY_VERIFICATION_* 配置')).toBeInTheDocument()
    const endpoint = screen.getByRole('textbox', { name: '服务地址' })
    await user.type(endpoint, 'https://kyc.example.com/')
    await user.tab()
    expect(endpoint).toHaveValue('https://kyc.example.com')
    await user.type(screen.getByRole('textbox', { name: '存储桶' }), 'kyc-bucket')
    const secretKey = screen.getByLabelText('Secret Access Key')
    expect(secretKey).toHaveAttribute('type', 'password')
    await user.type(secretKey, 'plain-object-secret')
    await user.click(screen.getByRole('button', { name: '保存认证与支付设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][2]).toMatchObject({ kyc_endpoint: 'https://kyc.example.com', kyc_object_bucket: 'kyc-bucket' })
    expect(put.mock.calls[0][5]).toMatchObject({ kyc_object_secret_access_key: 'plain-object-secret' })
    expect(JSON.stringify(put.mock.calls[0][2])).not.toContain('plain-object-secret')
    expect(await screen.findByText('已设置（指纹 0123456789abcdef），加密保存，不会回显')).toBeInTheDocument()
  })

  it('shows the KYC service as configured when the page holds every required value', async () => {
    const saved = Object.fromEntries(['kyc_api_key', 'kyc_callback_hmac_key', 'kyc_object_access_key_id', 'kyc_object_secret_access_key']
      .flatMap((name) => [[`${name}_configured`, true], [`${name}_fingerprint`, '0123456789abcdef']]))
    setupUser('payment', { ...userDocument, ...saved, value: { ...userDocument.value, kyc_provider_name: 'trusted-kyc', kyc_endpoint: 'https://kyc.example.com',
      kyc_callback_key_id: 'callback-1', kyc_object_endpoint: 'https://s3.example.com', kyc_object_region: 'us-east-1', kyc_object_bucket: 'kyc-bucket',
      kyc_object_kms_key_id: 'kms-1' } })
    expect(await screen.findByText('页面已配置齐全')).toBeInTheDocument()
  })

  it('does not mark the identity policy saved from the account tab', async () => {
    const put = setupUser('account')
    const user = userEvent.setup()
    await screen.findByLabelText('SecretId')
    await user.click(screen.getAllByRole('button', { name: /保\s*存/ }).at(-1)!)
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][2]).toMatchObject({ identity_policy_saved: false })
  })
})

const mailDocument: PlatformSystemMailSettingsDocument = {
  schema: 'cdnca.platform-system-mail-settings/v1', revision: 3,
  value: {
    smtp_address: 'smtp.example.test', smtp_ssl: true, smtp_port: 465, smtp_user: '', smtp_password_reference: '', smtp_from: '', smtp_from_name: '',
    sms_provider: 'https_json', sms_access_key_id: 'account', sms_access_key_reference: '', sms_signature_name: '', sms_template_map: '',
    mail_provider: '', mail_region: '', mail_access_key_id: '', mail_from: '', mail_from_name: '',
  },
}

describe('HTTPS SMS gateway token', () => {
  it('saves the token write-only, keeps it when empty and clears it on request', async () => {
    signIn()
    vi.spyOn(systemMailSettingsApi, 'get').mockResolvedValue(mailDocument)
    vi.spyOn(pluginProvidersApi, 'list').mockResolvedValue([])
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value, _request, _key, secrets) => ({
      ...mailDocument, revision: revision + 1, value,
      ...(secrets?.smsAuthToken ? { sms_auth_token_configured: true, sms_auth_token_fingerprint: '0123456789abcdef' } : {}),
    }))
    renderWithProviders(<SystemGlobalSettingsPage initialTab="mail" />)
    const user = userEvent.setup()
    const token = await screen.findByLabelText('AccessKey Secret')
    expect(token).toHaveAttribute('type', 'password')
    await user.type(token, 'plain-gateway-token')
    await user.click(screen.getByRole('button', { name: '保存短信设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][5]).toMatchObject({ smsAuthToken: 'plain-gateway-token' })
    expect(JSON.stringify(put.mock.calls[0][2])).not.toContain('plain-gateway-token')
    expect(await screen.findByText('已设置（指纹 0123456789abcdef），加密保存，不会回显')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '保存短信设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(put.mock.calls[1][5]?.smsAuthToken).toBeUndefined()
  })
})
