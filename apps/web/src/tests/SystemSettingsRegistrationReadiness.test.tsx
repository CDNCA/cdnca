import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { accountRegistrationApi, type AccountRegistrationConfig } from '../api/accountRegistration'
import { notificationsApi } from '../api/notifications'
import { pluginProvidersApi } from '../api/pluginProviders'
import { systemMailSettingsApi, type PlatformSystemMailSettingsDocument } from '../api/systemMailSettings'
import { systemUserSettingsApi, type PlatformSystemUserSettingsDocument } from '../api/systemUserSettings'
import { useSessionStore } from '../auth/session'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 账号与安全页显示注册验证未就绪的原因与配置入口；要求了邮箱验证而邮件通道发不出时，
// 保存照常成功并给出提示；Turnstile 站点密钥与只写 Secret 在验证码配置一节。

function authenticate() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

const userDocument: PlatformSystemUserSettingsDocument = {
  schema: 'cdnca.platform-system-user-settings/v1', revision: 7, captcha_turnstile_secret_configured: false,
  value: {
    session_ttl_seconds: 86400, user_login_domains: '', admin_login_domains: '', email_code_login_enabled: true, sms_code_login_enabled: false,
    registration_enabled: true, registration_success_subject: '用户注册成功', registration_success_body: '<p>{{username}}</p>', password_reset_subject: '密码已重置',
    password_reset_body: '<p>{{username}}</p>', verification_template_channel: 'email', verification_subject: '用户验证码', verification_body: '<p>{{captcha}}</p>',
    verification_sms_body: '您的验证码为${captcha}，在5分钟内有效。', verification_sms_template_id: '', terms_title: '用户协议', terms_body: '协议内容',
    username_required: false, email_required: true, email_verification_required: true, phone_required: false, phone_verification_required: false, qq_required: false,
    login_failure_limit_per_hour: 30, login_captcha_threshold_per_hour: 3, session_region_check: false, email_anti_abuse_mode: 'none', sms_anti_abuse_mode: 'native',
    captcha_provider: 'tencent', captcha_secret_id_reference: '', captcha_secret_key_reference: '', captcha_app_id: '', captcha_app_secret_reference: '', captcha_turnstile_site_key: '',
    identity_verification_method: 'none', enterprise_verification_enabled: false, identity_policy_saved: false, kyc_provider_name: '', kyc_endpoint: '', kyc_callback_key_id: '', kyc_object_endpoint: '', kyc_object_region: '', kyc_object_bucket: '', kyc_object_prefix: '', kyc_object_kms_key_id: '', kyc_issuer_enabled: false, kyc_issuer_listen_address: '', kyc_issuer_server_certificate: '', kyc_issuer_client_ca: '', kyc_issuer_workload_identities: '', kyc_issuer_kms_endpoint: '',
    wechat_payment_enabled: false, alipay_payment_enabled: false, bank_transfer_enabled: false, default_recharge_method: 'none', recharge_restriction: 'none',
    default_phone_country_code: '86',
  },
}

const mailDocument: PlatformSystemMailSettingsDocument = {
  schema: 'cdnca.platform-system-mail-settings/v1', revision: 3,
  value: {
    smtp_address: 'smtp.example.test', smtp_ssl: true, smtp_port: 465, smtp_user: 'mailer@example.test', smtp_password_reference: '', smtp_from: '', smtp_from_name: '',
    sms_provider: '', sms_access_key_id: '', sms_access_key_reference: '', sms_signature_name: '', sms_template_map: '',
    mail_provider: '', mail_region: '', mail_access_key_id: '', mail_from: '', mail_from_name: '',
  },
}

const notReady: AccountRegistrationConfig = {
  mode: 'builtin', ready: false,
  email: { required: true, available: false }, sms: { required: false, available: false },
  reasons: ['email_sender_unavailable'],
}

describe('registration readiness on the account settings tab', () => {
  it('lists what keeps sign-up verification from being ready, with the administrator session', async () => {
    authenticate()
    vi.spyOn(systemUserSettingsApi, 'get').mockResolvedValue(userDocument)
    const config = vi.spyOn(accountRegistrationApi, 'registrationConfig').mockResolvedValue(notReady)
    renderWithProviders(<SystemGlobalSettingsPage initialTab="account" />)
    const panel = await screen.findByTestId('system-settings-baseline-account')
    const reasons = await within(panel).findByTestId('registration-readiness-reasons')
    expect(reasons).toHaveTextContent('没有可用的邮件发信方')
    expect(within(reasons).getByRole('link', { name: '前往邮件/短信配置' })).toHaveAttribute('href', '/sys/setting?tab=mail')
    expect(config).toHaveBeenCalledWith(undefined, 'memory-only-access-token')
  })

  it('saves a required email verification whose channel cannot send, then warns', async () => {
    authenticate()
    vi.spyOn(systemUserSettingsApi, 'get').mockResolvedValue(userDocument)
    vi.spyOn(accountRegistrationApi, 'registrationConfig').mockResolvedValue(notReady)
    const put = vi.spyOn(systemUserSettingsApi, 'put').mockResolvedValue({ ...userDocument, revision: 8 })
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="account" />)
    const panel = await screen.findByTestId('system-settings-baseline-account')
    await user.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(await screen.findByText(/邮箱验证已开启，但对应通道当前发不出验证码/)).toBeInTheDocument()
  })

  it('saves a required email verification whose channel switch is off, and says it is not in effect yet', async () => {
    // 要求验证开 且 通知渠道开 才生效；渠道关着时用户照常注册，不发码
    authenticate()
    vi.spyOn(systemUserSettingsApi, 'get').mockResolvedValue(userDocument)
    vi.spyOn(accountRegistrationApi, 'registrationConfig').mockResolvedValue({
      mode: 'builtin', ready: true, email: { required: false, available: false }, sms: { required: false, available: false }, reasons: [],
    })
    const put = vi.spyOn(systemUserSettingsApi, 'put').mockResolvedValue({ ...userDocument, revision: 8 })
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="account" />)
    const panel = await screen.findByTestId('system-settings-baseline-account')
    await user.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(await screen.findByText('已保存。邮箱验证要等邮件通知渠道打开后才生效，目前用户照常注册，不需要验证码。')).toBeInTheDocument()
    expect(screen.queryByText(/对应通道当前发不出验证码/)).not.toBeInTheDocument()
  })

  it('sends the Turnstile secret write-only and keeps it when left empty', async () => {
    authenticate()
    vi.spyOn(systemUserSettingsApi, 'get').mockResolvedValue(userDocument)
    vi.spyOn(accountRegistrationApi, 'registrationConfig').mockResolvedValue({ ...notReady, ready: true, reasons: [] })
    const put = vi.spyOn(systemUserSettingsApi, 'put').mockResolvedValue({ ...userDocument, revision: 8, captcha_turnstile_secret_configured: true,
      captcha_turnstile_secret_fingerprint: '0123456789abcdef' })
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="account" />)
    const panel = await screen.findByTestId('system-settings-baseline-account')
    await user.type(within(panel).getByLabelText('Turnstile 站点密钥'), '0x4AAAAAAApage')
    await user.type(within(panel).getByLabelText('Turnstile Secret'), '0x4AAAAAAAturnstile-secret')
    await user.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const call = put.mock.calls[0]!
    expect(call[2].captcha_turnstile_site_key).toBe('0x4AAAAAAApage')
    expect(call[5]).toMatchObject({ captcha_turnstile_secret: '0x4AAAAAAAturnstile-secret' })
    expect(await within(panel).findByText(/已设置（指纹 0123456789abcdef）/)).toBeInTheDocument()
    expect(within(panel).getByLabelText('Turnstile Secret')).toHaveValue('')
  })

  it('offers to turn the email channel on from the mail tab when a sender is set up but the switch is off', async () => {
    authenticate()
    vi.spyOn(systemMailSettingsApi, 'get').mockResolvedValue(mailDocument)
    vi.spyOn(pluginProvidersApi, 'list').mockResolvedValue([])
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({ enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 0, mode: 'auto' })
    vi.spyOn(notificationsApi, 'getChannels').mockResolvedValue({ sms_enabled: false, email_enabled: false, sms_supported: false, email_supported: true, revision: 2, changed: false })
    const put = vi.spyOn(notificationsApi, 'putChannels').mockResolvedValue({ sms_enabled: false, email_enabled: true, sms_supported: false, email_supported: true, revision: 3, changed: true })
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="mail" />)
    const panel = await screen.findByTestId('system-settings-baseline-mail')
    const notice = await within(panel).findByTestId('notification-channel-off-email')
    expect(within(panel).queryByTestId('notification-channel-off-sms')).not.toBeInTheDocument()
    // the switch is only changed by the click
    expect(put).not.toHaveBeenCalled()
    await user.click(within(notice).getByRole('button', { name: '立即开启邮件通知渠道' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('memory-only-access-token', { email_enabled: true, sms_enabled: false }, 2, expect.any(String)))
    await waitFor(() => expect(within(panel).queryByTestId('notification-channel-off-email')).not.toBeInTheDocument())
    // auto notification mode: the SMS note does not ask for a restart
    expect(panel).toHaveTextContent('保存后约 15 秒内自动生效，无需重启。')
    expect(panel).not.toHaveTextContent('保存后需重启发信服务生效')
  })
})
