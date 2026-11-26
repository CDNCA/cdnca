import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { notificationsApi, type NotificationChannelHealth, type NotificationRuntimeHealth } from '../api/notifications'
import { pluginProvidersApi } from '../api/pluginProviders'
import { systemMailSettingsApi, type PlatformSystemMailSettingsDocument } from '../api/systemMailSettings'
import { useSessionStore } from '../auth/session'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// the SMS card shows the fields of the chosen provider only; the
// HTTPS gateway first shows whether its deployment endpoints are configured.

vi.mock('../components/useGrantedModules', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../components/useGrantedModules')>()),
  useGrantedModules: () => [],
}))

const map = '{"node.availability.offline.zh-cn":{"code":"SMS_1","variables":{"node_name":"name"}}}'
const base: PlatformSystemMailSettingsDocument = {
  schema: 'cdnca.platform-system-mail-settings/v1', revision: 3,
  value: {
    smtp_address: 'smtp.example.test', smtp_ssl: true, smtp_port: 465, smtp_user: '', smtp_password_reference: '', smtp_from: '', smtp_from_name: '',
    sms_provider: '', sms_access_key_id: '', sms_access_key_reference: '', sms_signature_name: '', sms_template_map: '',
    mail_provider: '', mail_region: '', mail_access_key_id: '', mail_from: '', mail_from_name: '',
  },
}
const aliyun: PlatformSystemMailSettingsDocument = {
  ...base, sms_secret_configured: true, sms_secret_fingerprint: '0123456789abcdef',
  value: { ...base.value, sms_provider: 'aliyun', sms_access_key_id: 'LTAI-id', sms_signature_name: 'CDNCA', sms_template_map: map },
}

function health(mode: NotificationRuntimeHealth['mode'], sms: NotificationChannelHealth): NotificationRuntimeHealth {
  return { enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1, mode, channels: { sms } }
}

function renderMail(document: PlatformSystemMailSettingsDocument, runtime: NotificationRuntimeHealth | (() => Promise<NotificationRuntimeHealth>)) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'], permissions: ['system_configuration.read', 'system_configuration.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(systemMailSettingsApi, 'get').mockResolvedValue(document)
  vi.spyOn(pluginProvidersApi, 'list').mockResolvedValue([])
  if (typeof runtime === 'function') vi.spyOn(notificationsApi, 'getRuntimeHealth').mockImplementation(runtime)
  else vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue(runtime)
  const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value, _request, _key, secrets) => ({
    ...document, revision: revision + 1, value,
    ...(secrets?.smsAuthToken ? { sms_auth_token_configured: true, sms_auth_token_fingerprint: 'fedcba9876543210' } : {}),
  }))
  renderWithProviders(<SystemGlobalSettingsPage initialTab="mail" />)
  return put
}

const smsCard = async () => within((await screen.findByRole('heading', { name: '手机短信设置' })).closest('section') as HTMLElement)

async function choose(label: string) {
  const user = userEvent.setup()
  await user.click((await smsCard()).getByRole('combobox', { name: '类型' }))
  await user.click(screen.getByText(label, { selector: '.ant-select-item-option-content' }))
  return user
}

afterEach(() => { vi.restoreAllMocks() })

describe('SMS provider fields (SMS-1)', () => {
  it('names the deployment items while the HTTPS gateway endpoints are not configured', async () => {
    const put = renderMail(base, health('auto', { state: 'not_configured' }))
    const user = await choose('自定义 HTTPS 网关')
    const card = await smsCard()
    for (const name of ['AccessKey ID', 'AccessKey Secret', '签名名称', '网关访问令牌', '模板映射']) expect(card.queryByLabelText(name)).toBeNull()
    expect(card.getByRole('status', { name: '未配置' })).toHaveTextContent('未配置')
    // one "网关端点" row; status, short note, then the expandable items, in that order
    const deploy = screen.getByTestId('system-settings-sms-gateway-deploy')
    expect(card.getAllByText('网关端点', { selector: 'label' })).toHaveLength(1)
    expect(deploy.closest('.ant-form-item')).toHaveTextContent('网关端点')
    const [status, note, more] = Array.from(deploy.children)
    expect(deploy.children).toHaveLength(3)
    expect(status).toBe(within(deploy).getByRole('status', { name: '未配置' }))
    expect(note).toHaveTextContent(/^配置网关端点并重启主控后即可保存$/)
    expect(more.tagName).toBe('DETAILS')
    expect(more).not.toHaveAttribute('open')
    await user.click(within(deploy).getByText('查看 control.env 部署项'))
    expect(more).toHaveAttribute('open')
    expect(more).toHaveTextContent('/etc/cdnca-control/control.env')
    expect(more).toHaveTextContent('notification-runtime-wiring')
    for (const name of ['NOTIFICATION_RUNTIME_ENABLED=true', 'NOTIFICATION_SMS_PROVIDER=https_json', 'NOTIFICATION_SMS_ENDPOINT', 'NOTIFICATION_SMS_READY_ENDPOINT',
      'NOTIFICATION_SMS_AUTH_TOKEN', 'ACCOUNT_RECOVERY_SMS_TEMPLATE_ID', 'ACCOUNT_RECOVERY_SMS_TEMPLATE_VERSION']) {
      const key = within(more as HTMLElement).getByText(name, { selector: 'code' })
      expect(key.closest('.system-settings-sms-gateway-env-key')).not.toBeNull()
    }
    expect(within(more as HTMLElement).getAllByRole('button', { name: /复制|Copy/ })).toHaveLength(7)
    expect(more).toHaveTextContent('发送地址')
    expect(more).toHaveTextContent('就绪地址')
    expect(card.getByRole('button', { name: '保存短信设置' })).toBeDisabled()
    expect(card.queryByText(/15 秒/)).toBeNull()
    expect(put).not.toHaveBeenCalled()
  })

  it('treats a ready runtime that sends with the saved aliyun provider as no deployed gateway', async () => {
    renderMail(aliyun, health('explicit', { state: 'ready' }))
    await choose('自定义 HTTPS 网关')
    const card = await smsCard()
    expect(card.getByRole('status', { name: '未配置' })).toBeInTheDocument()
    expect(screen.getByTestId('system-settings-sms-gateway-deploy')).toBeInTheDocument()
    expect(card.queryByLabelText('网关访问令牌')).toBeNull()
  })

  it('shows the available gateway with its token field and saves the token write-only', async () => {
    const put = renderMail(base, health('explicit', { state: 'ready' }))
    const user = await choose('自定义 HTTPS 网关')
    const card = await smsCard()
    expect(card.getByRole('status', { name: '可用' })).toHaveTextContent('可用')
    for (const name of ['AccessKey ID', 'AccessKey Secret', '签名名称', '模板映射']) expect(card.queryByLabelText(name)).toBeNull()
    expect(screen.queryByTestId('system-settings-sms-gateway-deploy')).toBeNull()
    expect(card.getByText('保存后需重启发信服务生效。')).toBeInTheDocument()
    const token = card.getByLabelText('网关访问令牌')
    expect(token).toHaveAttribute('type', 'password')
    await user.click(card.getByRole('button', { name: '保存短信设置' }))
    expect(await card.findByText('请填写网关账号')).toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()
    await user.type(card.getByRole('textbox', { name: '网关账号' }), 'gateway-account')
    await user.type(token, 'plain-gateway-token')
    await user.click(card.getByRole('button', { name: '保存短信设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [, , value, , , secrets] = put.mock.calls[0]
    expect(value).toEqual({ ...base.value, sms_provider: 'https_json', sms_access_key_id: 'gateway-account' })
    expect(secrets).toMatchObject({ smsAuthToken: 'plain-gateway-token', smsAccessKeySecret: undefined })
    expect(JSON.stringify(value)).not.toContain('plain-gateway-token')
    expect(await card.findByText('已设置（指纹 fedcba9876543210），加密保存，不会回显')).toBeInTheDocument()
    expect(token).toHaveValue('')
  })

  it.each([['aliyun', '阿里云短信'], ['submail', 'SUBMAIL（赛邮）']] as const)('keeps the %s fields and template map', async (provider, label) => {
    const put = renderMail(base, health('auto', { state: 'not_configured' }))
    const user = await choose(label)
    const card = await smsCard()
    expect(card.getByText('保存后约 15 秒内自动生效，无需重启。')).toBeInTheDocument()
    expect(card.queryByLabelText('网关访问令牌')).toBeNull()
    expect(card.queryByLabelText('网关账号')).toBeNull()
    await user.type(card.getByRole('textbox', { name: 'AccessKey ID' }), 'key-id')
    await user.type(card.getByLabelText('AccessKey Secret'), 'plain-secret')
    await user.type(card.getByRole('textbox', { name: '签名名称' }), 'CDNCA')
    await user.click(card.getByRole('textbox', { name: '模板映射' }))
    await user.paste(map)
    await user.click(card.getByRole('button', { name: '保存短信设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [, , value, , , secrets] = put.mock.calls[0]
    expect(value).toEqual({ ...base.value, sms_provider: provider, sms_access_key_id: 'key-id', sms_signature_name: 'CDNCA', sms_template_map: map })
    expect(secrets).toMatchObject({ smsAccessKeySecret: 'plain-secret', smsAuthToken: undefined })
  })

  it('shows what the runtime configuration resolves to and keeps the saved fields when switching to it', async () => {
    const put = renderMail(aliyun, health('auto', { state: 'degraded', reason: 'config_incomplete' }))
    const card = await smsCard()
    expect(card.getByRole('textbox', { name: 'AccessKey ID' })).toHaveValue('LTAI-id')
    const user = await choose('使用运行环境配置')
    const status = card.getByRole('status', { name: '不可用（发信配置不完整）' })
    expect(status).toHaveTextContent('不可用（发信配置不完整）')
    expect(status.closest('.ant-form-item')).toHaveTextContent('当前生效')
    for (const name of ['AccessKey ID', 'AccessKey Secret', '签名名称', '模板映射', '网关访问令牌', '网关账号']) expect(card.queryByLabelText(name)).toBeNull()
    expect(card.queryByText(/15 秒/)).toBeNull()
    await user.click(card.getByRole('button', { name: '保存短信设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [, , value, , , secrets] = put.mock.calls[0]
    // only the choice changes; the template map exists for aliyun/submail only
    expect(value).toEqual({ ...aliyun.value, sms_provider: '', sms_template_map: '' })
    expect(secrets).toMatchObject({ smsAccessKeySecret: undefined, smsAuthToken: undefined })
  })
  // SMS-1 补充: an unreadable runtime health is neither "deployed" nor "not
  // deployed"; the gateway is not saved until its endpoints are confirmed.
  describe('runtime health unknown', () => {
    const gateway: PlatformSystemMailSettingsDocument = {
      ...base, sms_auth_token_configured: true, sms_auth_token_fingerprint: '00112233aabbccdd',
      value: { ...base.value, sms_provider: 'https_json', sms_access_key_id: 'gateway-account', sms_signature_name: 'CDNCA' },
    }

    it('shows a failed read in place, keeps the saved gateway fields read-only and retries without losing the draft', async () => {
      let readable = false
      const put = renderMail(gateway, async () => {
        if (!readable) throw new ApiError('unavailable', 503, 'notification_runtime_unavailable')
        return health('auto', { state: 'not_configured' })
      })
      const user = userEvent.setup()
      const card = await smsCard()
      const failure = await card.findByRole('alert')
      expect(failure).toHaveTextContent('读取短信运行状态失败')
      expect(failure).toHaveTextContent('确认网关端点已部署后才能保存网关设置')
      expect(card.queryByRole('status', { name: '未配置' })).toBeNull()
      expect(screen.queryByTestId('system-settings-sms-gateway-deploy')).toBeNull()
      expect(card.getByRole('textbox', { name: '网关账号' })).toHaveValue('gateway-account')
      expect(card.getByRole('textbox', { name: '网关账号' })).toBeDisabled()
      expect(card.getByRole('textbox', { name: '短信签名' })).toBeDisabled()
      expect(card.getByLabelText('网关访问令牌')).toBeDisabled()
      expect(card.getByRole('button', { name: '清除' })).toBeDisabled()
      expect(card.getByRole('button', { name: '保存短信设置' })).toBeDisabled()

      // a draft elsewhere on the tab survives the retry
      const address = screen.getByRole('textbox', { name: 'SMTP地址' })
      await user.clear(address)
      await user.type(address, 'smtp.draft.test')
      const calls = vi.mocked(notificationsApi.getRuntimeHealth).mock.calls.length
      readable = true
      await user.click(within(failure).getByRole('button', { name: '重试' }))
      await waitFor(() => expect(vi.mocked(notificationsApi.getRuntimeHealth).mock.calls.length).toBe(calls + 1))
      expect(await card.findByRole('status', { name: '未配置' })).toBeInTheDocument()
      expect(card.queryByRole('alert')).toBeNull()
      expect(screen.getByTestId('system-settings-sms-gateway-deploy')).toBeInTheDocument()
      expect(card.getByRole('button', { name: '保存短信设置' })).toBeDisabled()
      expect(address).toHaveValue('smtp.draft.test')
      expect(put).not.toHaveBeenCalled()
    })

    it('shows the reading state while the runtime health is pending', async () => {
      renderMail(gateway, () => new Promise(() => undefined))
      const card = await smsCard()
      expect(card.getByRole('status', { name: '正在读取短信运行状态…' })).toBeInTheDocument()
      expect(card.getByRole('button', { name: '保存短信设置' })).toBeDisabled()
      expect(card.getByRole('textbox', { name: '网关账号' })).toBeDisabled()
    })

    it('opens the saved gateway fields once the endpoints are confirmed deployed', async () => {
      const put = renderMail(gateway, health('explicit', { state: 'ready' }))
      const user = userEvent.setup()
      const card = await smsCard()
      expect(await card.findByRole('status', { name: '可用' })).toBeInTheDocument()
      expect(card.queryByRole('alert')).toBeNull()
      const account = card.getByRole('textbox', { name: '网关账号' })
      expect(account).toBeEnabled()
      expect(card.getByLabelText('网关访问令牌')).toBeEnabled()
      await user.type(card.getByRole('textbox', { name: '短信签名' }), '-2')
      await user.click(card.getByRole('button', { name: '保存短信设置' }))
      await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
      expect(put.mock.calls[0][2]).toEqual({ ...gateway.value, sms_signature_name: 'CDNCA-2' })
    })

    it('keeps the SMTP section saveable while the runtime health cannot be read', async () => {
      const put = renderMail(gateway, async () => { throw new ApiError('unavailable', 503, 'notification_runtime_unavailable') })
      const user = userEvent.setup()
      const card = await smsCard()
      expect(await card.findByRole('alert')).toHaveTextContent('读取短信运行状态失败')
      const address = screen.getByRole('textbox', { name: 'SMTP地址' })
      await user.clear(address)
      await user.type(address, 'smtp.other.test')
      const saveSMTP = screen.getByRole('button', { name: '保存SMTP设置' })
      expect(saveSMTP).toBeEnabled()
      await user.click(saveSMTP)
      await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
      expect(put.mock.calls[0][2]).toEqual({ ...gateway.value, smtp_address: 'smtp.other.test' })
    })
  })
})
