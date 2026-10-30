import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import { AppRoutes } from '../App'
import { systemCleanupSettingsApi, type PlatformSystemCleanupDocument } from '../api/systemCleanupSettings'
import { systemSettingsApi } from '../api/systemSettings'
import { systemUserSettingsApi, type PlatformSystemUserSettings, type PlatformSystemUserSettingsDocument } from '../api/systemUserSettings'
import { useSessionStore } from '../auth/session'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// ADMIN-CURRENT-08: one tab bar matching the competitor, tab in the URL, drafts kept across tabs,
// scope/save line per tab, retired tabs redirect.

const location = vi.hoisted(() => ({ current: '' }))
function LocationProbe() {
  const value = useLocation()
  useEffect(() => { location.current = `${value.pathname}${value.search}` }, [value])
  return null
}

function authenticate(permissions = ['system_configuration.read', 'system_configuration.manage']) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

const cleanup: PlatformSystemCleanupDocument = {
  schema: 'cdnca.platform-system-cleanup-settings/v1', revision: 2,
  value: {
    cleanup_cache_days: 30, access_logs_days: 7, node_metrics_days: 7, bandwidth_history_days: 90, blacklist_history_days: 7,
    node_traffic_history_days: 45,
    audit_retention_days: { admin: 365, user: 180, auth: 90, site: 180, security: 180, rule: 180, finance: 1095, package: 365, plugin: 180, node: 90, dns: 180, cert: 180, system: 365, other: 180 },
  },
}

const userValue: PlatformSystemUserSettings = {
  session_ttl_seconds: 86400, user_login_domains: '', admin_login_domains: '', email_code_login_enabled: true, sms_code_login_enabled: false,
  registration_enabled: false, registration_success_subject: '用户注册成功', registration_success_body: '<p>{{username}}</p>', password_reset_subject: '密码已重置', password_reset_body: '<p>{{username}}</p>', verification_template_channel: 'email', verification_subject: '用户验证码', verification_body: '<p>{{captcha}}</p>', verification_sms_body: '您的验证码为${captcha}，在5分钟内有效。', verification_sms_template_id: '', terms_title: '用户协议', terms_body: '协议内容', username_required: false, email_required: false, email_verification_required: false, phone_required: false, phone_verification_required: false, qq_required: false,
  login_failure_limit_per_hour: 30, login_captcha_threshold_per_hour: 3, session_region_check: true, email_anti_abuse_mode: 'none', sms_anti_abuse_mode: 'native', captcha_provider: 'tencent', captcha_secret_id_reference: '', captcha_secret_key_reference: '', captcha_app_id: '', captcha_app_secret_reference: '', identity_verification_method: 'alipay', enterprise_verification_enabled: false, enterprise_secret_id_reference: '', enterprise_secret_key_reference: '', wechat_payment_enabled: false, alipay_payment_enabled: false, bank_transfer_enabled: false, default_recharge_method: 'none', recharge_restriction: 'none', default_phone_country_code: '86',
}
const userDocument: PlatformSystemUserSettingsDocument = { schema: 'cdnca.platform-system-user-settings/v1', revision: 7, value: userValue }

function mockUserSettings() {
  vi.spyOn(systemUserSettingsApi, 'get').mockResolvedValue(userDocument)
  return vi.spyOn(systemUserSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({ ...userDocument, revision: revision + 1, value }))
}

describe('system settings navigation (ADMIN-CURRENT-08)', () => {
  it('shows the seven competitor tabs in order, without the moved adaptive WAF tab', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockReturnValue(new Promise(() => {}))
    renderWithProviders(<SystemGlobalSettingsPage />)
    const tabs = await screen.findAllByRole('tab')
    expect(tabs.map((tab) => tab.textContent)).toEqual(['系统配置', '数据清理', '账号与安全', '认证与支付', '发信配置', '通知设置', '其它配置'])
  })

  it('keeps an unsaved cleanup draft across a tab round trip and writes the tab to the URL', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockReturnValue(new Promise(() => {}))
    const get = vi.spyOn(systemCleanupSettingsApi, 'get').mockResolvedValue(cleanup)
    const put = vi.spyOn(systemCleanupSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({ ...cleanup, revision: revision + 1, value }))
    mockUserSettings()
    const user = userEvent.setup()
    renderWithProviders(<><SystemGlobalSettingsPage /><LocationProbe /></>, ['/sys/setting?tab=cleanup'])

    const panel = await screen.findByTestId('system-settings-baseline-cleanup')
    const access = within(panel).getByRole('spinbutton', { name: '网站访问日志 (ES)' })
    await user.clear(access)
    await user.type(access, '15')
    await user.click(screen.getByRole('tab', { name: '账号与安全' }))
    expect(await screen.findByTestId('system-settings-baseline-account')).toBeInTheDocument()
    expect(location.current).toBe('/sys/setting?tab=account')
    await user.click(screen.getByRole('tab', { name: '数据清理' }))

    expect(within(screen.getByTestId('system-settings-baseline-cleanup')).getByRole('spinbutton', { name: '网站访问日志 (ES)' })).toHaveValue('15')
    expect(get).toHaveBeenCalledTimes(1)
    expect(put).not.toHaveBeenCalled()
    await user.click(within(screen.getByTestId('system-settings-baseline-cleanup')).getByRole('button', { name: /保存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][2]).toMatchObject({ access_logs_days: 15 })
    expect(await within(screen.getByTestId('system-settings-baseline-cleanup')).findByText(/修订版本\s*3/)).toBeInTheDocument()
  })

  it('states the scope and save granularity of each tab', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockReturnValue(new Promise(() => {}))
    vi.spyOn(systemCleanupSettingsApi, 'get').mockResolvedValue(cleanup)
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage />)
    expect(await screen.findByTestId('system-settings-scope-system')).toHaveTextContent('约 1 秒自动保存')
    await user.click(screen.getByRole('tab', { name: '数据清理' }))
    const scope = await screen.findByTestId('system-settings-scope-cleanup')
    expect(scope).toHaveTextContent('0 表示永久保留')
  })

  it('has no backup fields on the cleanup tab and links to the single control backup entry', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockReturnValue(new Promise(() => {}))
    vi.spyOn(systemCleanupSettingsApi, 'get').mockResolvedValue(cleanup)
    renderWithProviders(<SystemGlobalSettingsPage />, ['/sys/setting?tab=cleanup'])
    const panel = await screen.findByTestId('system-settings-baseline-cleanup')
    expect(within(panel).queryByText('备份频率')).not.toBeInTheDocument()
    expect(within(panel).queryByText('备份目录')).not.toBeInTheDocument()
    expect(within(panel).getByTestId('system-settings-backup-moved')).toHaveTextContent('主控备份的计划与保留在 维护升级 > 维护操作 > 主控备份与迁移中设置。')
    expect(within(panel).getByRole('link', { name: '维护升级 > 维护操作 > 主控备份与迁移' })).toHaveAttribute('href', '/sys/op?tab=maintenance')
  })

  it('carries the account tab save into the payment tab draft so the shared document is not overwritten', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockReturnValue(new Promise(() => {}))
    const put = mockUserSettings()
    const user = userEvent.setup()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="payment" />)

    // Radio groups share one test id name in this environment, so the payment edit uses a switch.
    const payment = await screen.findByTestId('system-settings-baseline-payment')
    await user.click(within(payment).getByRole('switch', { name: '状态' }))
    await user.click(screen.getByRole('tab', { name: '账号与安全' }))
    const account = await screen.findByTestId('system-settings-baseline-account')
    await user.click(within(account).getByRole('switch', { name: '开放注册' }))
    await user.click(within(account).getByRole('button', { name: /保存/ }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][1]).toBe(7)
    expect(put.mock.calls[0][2]).toMatchObject({ registration_enabled: true, enterprise_verification_enabled: false })

    await user.click(screen.getByRole('tab', { name: '认证与支付' }))
    const paymentAgain = screen.getByTestId('system-settings-baseline-payment')
    expect(within(paymentAgain).getByRole('switch', { name: '状态' })).toBeChecked()
    await user.click(within(paymentAgain).getByRole('button', { name: '保存认证与支付设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(put.mock.calls[1][1]).toBe(8)
    expect(put.mock.calls[1][2]).toMatchObject({ registration_enabled: true, enterprise_verification_enabled: true })
  })

  // SET-002：后台 HTTPS 入口未接通，按 10-25 "未接通不显示" 整段隐藏（含页内导航项），已有引用随保存原样保留。
  it('SET-002: hides the unconnected console HTTPS section and its navigation entry', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockResolvedValue({
      schema: 'cdnca.platform-system-settings/v1', revision: 1,
      value: {
        system_name: 'CDNCA', user_title: '用户', admin_title: '管理员', footer_links: '', footer_text: '', global_js: '', bound_domains: '',
        expiry_close: false, traffic_close: false, allow_upgrade: true, allow_downgrade: false, maintenance: false, maintenance_message: '', auto_upgrade_node: false,
        certificate: 'vault://console/cert', private_key: 'vault://console/key',
      },
    })
    renderWithProviders(<SystemGlobalSettingsPage />)
    const panel = await screen.findByTestId('system-settings-baseline-system')
    expect(within(panel).getByRole('heading', { name: '维护升级' })).toBeInTheDocument()
    expect(within(panel).queryByRole('heading', { name: /HTTPS/ })).not.toBeInTheDocument()
    expect(within(panel).queryByText(/HTTPS/)).not.toBeInTheDocument()
    expect(within(panel).queryByLabelText('证书')).not.toBeInTheDocument()
    expect(within(panel).queryByLabelText('密钥')).not.toBeInTheDocument()
    expect(document.getElementById('system-https')).toBeNull()
  })

  // 社区版：认证与支付页签只保留实名/企业认证，不再有充值与支付服务区块。
  it('has no recharge or payment service section on the payment tab', async () => {
    authenticate()
    vi.spyOn(systemSettingsApi, 'get').mockReturnValue(new Promise(() => {}))
    mockUserSettings()
    renderWithProviders(<SystemGlobalSettingsPage initialTab="payment" />)
    const payment = await screen.findByTestId('system-settings-baseline-payment')
    expect(await within(payment).findByTestId('system-settings-identity-method')).toBeInTheDocument()
    expect(within(payment).queryByTestId('system-settings-payment-grid')).not.toBeInTheDocument()
    expect(within(payment).queryByTestId('system-settings-licensed-payment-methods')).not.toBeInTheDocument()
  })

  it('redirects the retired adaptive WAF tab to the firewall page', async () => {
    authenticate(['system_configuration.read', 'openresty_security.read'])
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/sys/setting?tab=wafAdapt'])
    await waitFor(() => expect(location.current).toBe('/config/waf'))
  })
})
