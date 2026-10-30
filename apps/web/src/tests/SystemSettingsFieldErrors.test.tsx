import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { pluginProvidersApi } from '../api/pluginProviders'
import { systemMailSettingsApi, type PlatformSystemMailSettingsDocument } from '../api/systemMailSettings'
import { systemOtherSettingsApi, type PlatformSystemOtherSettingsDocument } from '../api/systemOtherSettings'
import { systemUserSettingsApi, type PlatformSystemUserSettingsDocument } from '../api/systemUserSettings'
import { useSessionStore } from '../auth/session'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// fix-fielderr-be2：用户/发信/其它设置保存被拒且能定位字段时，原因标在该字段下，不弹窗。

function authenticate() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function refusal(code: string, field: string, reason: string) {
  return Object.assign(new ApiError('API request failed', 400, code, 'req-field'), { field, reason })
}

async function expectUnderField(panel: HTMLElement, label: string, text: string) {
  const item = (await within(panel).findByText(text)).closest('.ant-form-item')
  expect(item?.textContent).toContain(label)
  expect(document.querySelector('.cdnca-feedback')).toBeNull()
}

const userDocument: PlatformSystemUserSettingsDocument = {
  schema: 'cdnca.platform-system-user-settings/v1', revision: 7,
  value: {
    session_ttl_seconds: 86400, user_login_domains: '', admin_login_domains: '', email_code_login_enabled: true, sms_code_login_enabled: false,
    registration_enabled: false, registration_success_subject: '用户注册成功', registration_success_body: '<p>{{username}}</p>', password_reset_subject: '密码已重置',
    password_reset_body: '<p>{{username}}</p>', verification_template_channel: 'email', verification_subject: '用户验证码', verification_body: '<p>{{captcha}}</p>',
    verification_sms_body: '您的验证码为${captcha}，在5分钟内有效。', verification_sms_template_id: '', terms_title: '用户协议', terms_body: '协议内容',
    username_required: false, email_required: false, email_verification_required: false, phone_required: false, phone_verification_required: false, qq_required: false,
    login_failure_limit_per_hour: 30, login_captcha_threshold_per_hour: 3, session_region_check: true, email_anti_abuse_mode: 'none', sms_anti_abuse_mode: 'native',
    captcha_provider: 'tencent', captcha_secret_id_reference: '', captcha_secret_key_reference: '', captcha_app_id: '', captcha_app_secret_reference: '',
    identity_verification_method: 'alipay', enterprise_verification_enabled: false, enterprise_secret_id_reference: '', enterprise_secret_key_reference: '',
    wechat_payment_enabled: false, alipay_payment_enabled: false, bank_transfer_enabled: false, default_recharge_method: 'none', recharge_restriction: 'none',
    default_phone_country_code: '86',
  },
}

const mailDocument: PlatformSystemMailSettingsDocument = {
  schema: 'cdnca.platform-system-mail-settings/v1', revision: 3,
  value: {
    smtp_address: 'smtp.example.test', smtp_ssl: true, smtp_port: 465, smtp_user: '', smtp_password_reference: '',
    sms_provider: '', sms_access_key_id: '', sms_access_key_reference: '', sms_signature_name: '', sms_template_map: '',
    mail_provider: '', mail_region: '', mail_access_key_id: '', mail_from: '', mail_from_name: '',
  },
}

const otherDocument: PlatformSystemOtherSettingsDocument = {
  schema: 'cdnca.platform-system-other-settings/v1', revision: 2,
  value: {
    source_ip_header: 'X-Real-IP', api_key_enabled: true, dns_protection: '', record_repair_mode: 'repair', sync_batch: 1000, sync_scope: 'line_group',
    disable_failed_sync_nodes: false, resource_rank: 100, http_proxy: '', tcp_factor: 1.1, l4_drain_max_seconds: 86400, domain_ownership_policy: 'off',
    certificate_expiry_notice_days: [30, 14, 7], rule_intel_contribution: true,
  },
}

describe('system settings field refusals (fix-fielderr-be2)', () => {
  it('marks a refused account setting under its field', async () => {
    authenticate()
    vi.spyOn(systemUserSettingsApi, 'get').mockResolvedValue(userDocument)
    vi.spyOn(systemUserSettingsApi, 'put').mockRejectedValue(refusal('system_user_settings_validation_error', 'value.login_failure_limit_per_hour', 'out_of_range'))
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="account" />)
    const panel = await screen.findByTestId('system-settings-baseline-account')
    await user.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await expectUnderField(panel, '登录失败限制', '超出允许的范围')
  })

  it('marks a refused SMTP port under its field', async () => {
    authenticate()
    vi.spyOn(systemMailSettingsApi, 'get').mockResolvedValue(mailDocument)
    vi.spyOn(pluginProvidersApi, 'list').mockResolvedValue([])
    vi.spyOn(systemMailSettingsApi, 'put').mockRejectedValue(refusal('system_mail_settings_validation_error', 'value.smtp_port', 'out_of_range'))
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="mail" />)
    const panel = await screen.findByTestId('system-settings-baseline-mail')
    await user.click(within(panel).getByRole('button', { name: '保存SMTP设置' }))
    await expectUnderField(panel, 'SMTP端口', '超出允许的范围')
  })

  it('marks a refused other setting under its field and keeps the dialog for an unlocated refusal', async () => {
    authenticate()
    vi.spyOn(systemOtherSettingsApi, 'get').mockResolvedValue(otherDocument)
    const put = vi.spyOn(systemOtherSettingsApi, 'put').mockRejectedValueOnce(refusal('system_other_settings_validation_error', 'value.sync_batch', 'out_of_range'))
      .mockRejectedValueOnce(new ApiError('API request failed', 400, 'system_other_settings_validation_error', 'req-plain'))
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="other" />)
    const panel = await screen.findByTestId('system-settings-baseline-other')
    await user.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    await expectUnderField(panel, '单次同步站点最大个数', '超出允许的范围')
    await user.click(within(panel).getByRole('button', { name: /保\s*存/ }))
    expect(put).toHaveBeenCalledTimes(2)
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
  })
})
