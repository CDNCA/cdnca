import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { pluginProvidersApi, type PluginProvider } from '../api/pluginProviders'
import { systemMailSettingsApi, type PlatformSystemMailSettingsDocument } from '../api/systemMailSettings'
import { useSessionStore } from '../auth/session'
import SystemGlobalSettingsPage from '../pages/SystemGlobalSettingsPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// Official mail services are offered by their licence module (module.mail.*).
let grantedModules: string[] = ['module.mail.aliyun', 'module.mail.sendgrid']
vi.mock('../components/useGrantedModules', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../components/useGrantedModules')>()),
  useGrantedModules: () => grantedModules,
}))

const initial: PlatformSystemMailSettingsDocument = {
  schema: 'cdnca.platform-system-mail-settings/v1', revision: 3,
  value: {
    smtp_address: 'smtp.example.test', smtp_ssl: true, smtp_port: 465, smtp_user: '', smtp_password_reference: '',
    sms_provider: '', sms_access_key_id: '', sms_access_key_reference: '', sms_signature_name: '', sms_template_map: '',
    mail_provider: '', mail_region: '', mail_access_key_id: '', mail_from: '', mail_from_name: '',
  },
}

const mailPlugin = { plugin_id: 'com.example.mail', version: '1.0.0', base_url: 'https://mail.example.com', kinds: ['mail'],
  status: 'active', contract_status: 'passed', enabled: true, usable: true, updated_at: '2026-10-22T00:00:00Z' } as PluginProvider
let plugins: PluginProvider[] = []

function renderMail(document = initial) {
  const actor = principal({
    scope_kind: 'platform', tenant_id: null, roles: ['platform_owner'],
    permissions: ['system_configuration.read', 'system_configuration.manage'],
  })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(systemMailSettingsApi, 'get').mockResolvedValue(document)
  vi.spyOn(pluginProvidersApi, 'list').mockResolvedValue(plugins)
  renderWithProviders(<SystemGlobalSettingsPage initialTab="mail" />)
}

describe('SystemGlobalSettingsPage mail section saves', () => {
  it('allows repairing a legacy provider without silently replacing it or submitting unsupported values', async () => {
    const legacy = { ...initial, value: { ...initial.value, sms_provider: 'tencent' } }
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({ ...initial, revision: revision + 1, value }))
    renderMail(legacy)
    const user = userEvent.setup()
    const provider = await screen.findByRole('combobox', { name: '类型' })
    expect(screen.getByText('tencent（当前不支持）')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存SMTP设置' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '保存短信设置' })).toBeDisabled()
    await user.click(provider)
    await user.click(screen.getByText('自定义 HTTPS 网关', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByRole('button', { name: '保存SMTP设置' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '保存短信设置' }))
    await screen.findByText('修订版本 4')
    expect(put.mock.calls[0][2].sms_provider).toBe('https_json')
    expect(screen.getByRole('button', { name: '保存SMTP设置' })).toBeEnabled()
    expect(screen.getByText('自定义 HTTPS 网关', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
  })

  it.each(['smtp', 'sms'] as const)('saves %s without discarding the other section draft', async (section) => {
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({
      ...initial, revision: revision + 1, value,
    }))
    renderMail()
    const user = userEvent.setup()
    const smtp = await screen.findByRole('textbox', { name: 'SMTP地址' })
    const sms = screen.getByRole('textbox', { name: '签名名称' })
    await user.clear(smtp)
    await user.type(smtp, 'smtp.changed.test')
    await user.type(sms, '短信草稿')
    await user.click(screen.getByRole('button', { name: section === 'smtp' ? '保存SMTP设置' : '保存短信设置' }))

    await screen.findByText('修订版本 4')
    expect(put).toHaveBeenCalledTimes(1)
    expect(put.mock.calls[0][2]).toEqual({ ...initial.value,
      ...(section === 'smtp' ? { smtp_address: 'smtp.changed.test' } : { sms_signature_name: '短信草稿' }),
    })
    expect(smtp).toHaveValue('smtp.changed.test')
    expect(sms).toHaveValue('短信草稿')

    await user.click(screen.getByRole('button', { name: section === 'smtp' ? '保存短信设置' : '保存SMTP设置' }))
    await screen.findByText('修订版本 5')
    expect(put.mock.calls[1][1]).toBe(4)
    expect(put.mock.calls[1][2]).toEqual({ ...initial.value, smtp_address: 'smtp.changed.test', sms_signature_name: '短信草稿' })
  })

  it('preserves edits made during a save and prevents overlapping section writes', async () => {
    let resolve!: (value: PlatformSystemMailSettingsDocument) => void
    const pending = new Promise<PlatformSystemMailSettingsDocument>((done) => { resolve = done })
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockReturnValueOnce(pending)
      .mockImplementation(async (_token, revision, value) => ({ ...initial, revision: revision + 1, value }))
    renderMail()
    const user = userEvent.setup()
    const smtp = await screen.findByRole('textbox', { name: 'SMTP地址' })
    await user.clear(smtp)
    await user.type(smtp, 'smtp.first.test')
    await user.click(screen.getByRole('button', { name: '保存SMTP设置' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(screen.getByRole('button', { name: '保存短信设置' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '刷新' })).toBeDisabled()
    await user.clear(smtp)
    await user.type(smtp, 'smtp.newer.test')
    await user.type(screen.getByRole('textbox', { name: '签名名称' }), '较新短信草稿')
    await act(async () => resolve({ ...initial, revision: 4, value: put.mock.calls[0][2] }))
    expect(smtp).toHaveValue('smtp.newer.test')
    expect(screen.getByRole('textbox', { name: '签名名称' })).toHaveValue('较新短信草稿')
    await user.click(screen.getByRole('button', { name: '保存SMTP设置' }))
    await screen.findByText('修订版本 5')
    expect(put.mock.calls[1][2].smtp_address).toBe('smtp.newer.test')
    expect(put.mock.calls[1][2].sms_signature_name).toBe('')
  })

  it('retries an unknown result with the original request and retains unsaved drafts', async () => {
    const put = vi.spyOn(systemMailSettingsApi, 'put')
      .mockRejectedValueOnce(new ApiError('unavailable', 503, 'system_mail_settings_unavailable'))
      .mockImplementationOnce(async (_token, revision, value) => ({ ...initial, revision: revision + 1, value }))
    renderMail()
    const user = userEvent.setup()
    const smtp = await screen.findByRole('textbox', { name: 'SMTP地址' })
    await user.clear(smtp)
    await user.type(smtp, 'smtp.retry.test')
    await user.type(screen.getByRole('textbox', { name: '签名名称' }), '待保存短信')
    await user.click(screen.getByRole('button', { name: '保存SMTP设置' }))
    await user.click(await screen.findByRole('button', { name: '使用同一请求重试' }))
    await screen.findByText('修订版本 4')
    expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
    expect(screen.getByRole('textbox', { name: '签名名称' })).toHaveValue('待保存短信')
  })

  it('keeps save controls named and reuses the latest revision across three alternating saves', async () => {
    let resolve!: (value: PlatformSystemMailSettingsDocument) => void
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(() => new Promise((done) => { resolve = done }))
    renderMail()
    const user = userEvent.setup()
    const smtp = await screen.findByRole('textbox', { name: 'SMTP地址' })
    const sms = screen.getByRole('textbox', { name: '签名名称' })
    await user.clear(smtp)
    await user.type(smtp, 'smtp.first.test')
    await user.click(screen.getByRole('button', { name: '保存SMTP设置' }))
    expect(screen.getByRole('button', { name: '保存SMTP设置' })).toHaveAttribute('aria-busy', 'true')
    await user.clear(smtp)
    await user.type(smtp, 'smtp.latest.test')
    await user.type(sms, '保留短信草稿')
    await act(async () => resolve({ ...initial, revision: 4, value: put.mock.calls[0][2] }))

    await user.click(screen.getByRole('button', { name: '保存短信设置' }))
    expect(put.mock.calls[1][1]).toBe(4)
    expect(put.mock.calls[1][2]).toEqual({ ...initial.value, smtp_address: 'smtp.first.test', sms_signature_name: '保留短信草稿' })
    expect(screen.getByRole('button', { name: '保存短信设置' })).toHaveAttribute('aria-busy', 'true')
    await act(async () => resolve({ ...initial, revision: 5, value: put.mock.calls[1][2] }))

    await user.click(screen.getByRole('button', { name: '保存SMTP设置' }))
    expect(put).toHaveBeenCalledTimes(3)
    expect(put.mock.calls[2][1]).toBe(5)
    expect(put.mock.calls[2][2]).toEqual({ ...initial.value, smtp_address: 'smtp.latest.test', sms_signature_name: '保留短信草稿' })
    expect(new Set(put.mock.calls.map((call) => call[4])).size).toBe(3)
    await act(async () => resolve({ ...initial, revision: 6, value: put.mock.calls[2][2] }))
    await screen.findByText('修订版本 6')
    for (const name of ['保存SMTP设置', '保存短信设置']) {
      expect(screen.getByRole('button', { name })).toBeEnabled()
      expect(screen.getByRole('button', { name })).toHaveAttribute('aria-busy', 'false')
    }
  })

  it('saves an aliyun credential write-only and shows only its fingerprint', async () => {
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({
      ...initial, revision: revision + 1, value, sms_secret_configured: true, sms_secret_fingerprint: '0123456789abcdef',
    }))
    renderMail()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('combobox', { name: '类型' }))
    await user.click(screen.getByText('阿里云短信', { selector: '.ant-select-item-option-content' }))
    await user.type(screen.getByRole('textbox', { name: 'AccessKey ID' }), 'LTAI-id')
    await user.type(screen.getByLabelText('AccessKey Secret'), 'plain-secret')
    await user.type(screen.getByRole('textbox', { name: '签名名称' }), 'CDNCA')
    const map = '{"node.availability.offline.zh-cn":{"code":"SMS_1","variables":{"node_name":"name"}}}'
    await user.click(screen.getByRole('textbox', { name: '模板映射' }))
    await user.paste(map)
    await user.click(screen.getByRole('button', { name: '保存短信设置' }))
    await screen.findByText('修订版本 4')
    const [, , value, , , secret] = put.mock.calls[0]
    expect(secret).toEqual({ smsAccessKeySecret: 'plain-secret', mailSecret: undefined })
    expect(JSON.stringify(value)).not.toContain('plain-secret')
    expect(value).toMatchObject({ sms_provider: 'aliyun', sms_access_key_id: 'LTAI-id', sms_access_key_reference: '', sms_template_map: map })
    expect(screen.getByText('已设置（指纹 0123456789abcdef），留空保存即保留原密钥')).toBeInTheDocument()
    expect(screen.getByLabelText('AccessKey Secret')).toHaveValue('')
  })

  it('switches the mail sender in one save, keeps SMTP, and sends the secret write-only', async () => {
    plugins = []
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({
      ...initial, revision: revision + 1, value, mail_secret_configured: true, mail_secret_provider: 'sendgrid', mail_secret_fingerprint: 'fedcba9876543210',
    }))
    renderMail()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('combobox', { name: '发信方式' }))
    await user.click(screen.getByText('SendGrid', { selector: '.ant-select-item-option-content' }))
    // SendGrid has no AccessKey ID: only the SMS card's field remains.
    expect(screen.getAllByRole('textbox', { name: 'AccessKey ID' })).toHaveLength(1)
    await user.type(screen.getByLabelText('API Key'), 'SG.secret')
    await user.type(screen.getByRole('textbox', { name: '发信地址' }), 'noreply@example.com')
    // An SMTP draft is not saved by the sender button.
    const smtp = screen.getByRole('textbox', { name: 'SMTP地址' })
    await user.clear(smtp)
    await user.type(smtp, 'smtp.draft.test')
    await user.click(screen.getByRole('button', { name: '保存发信服务商' }))
    await screen.findByText('修订版本 4')
    const [, , value, , , secrets] = put.mock.calls[0]
    expect(value).toEqual({ ...initial.value, mail_provider: 'sendgrid', mail_from: 'noreply@example.com' })
    expect(JSON.stringify(value)).not.toContain('SG.secret')
    expect(secrets).toEqual({ smsAccessKeySecret: undefined, mailSecret: 'SG.secret' })
    expect(screen.getByText('已设置（指纹 fedcba9876543210），留空保存即保留原密钥')).toBeInTheDocument()
    expect(screen.getByLabelText('API Key')).toHaveValue('')
    expect(smtp).toHaveValue('smtp.draft.test')
  })

  it('lists only usable mail plugins and tests the unsaved sender', async () => {
    plugins = [mailPlugin, { ...mailPlugin, plugin_id: 'com.example.off', usable: false }, { ...mailPlugin, plugin_id: 'com.example.dns', kinds: ['dns'] }]
    const test = vi.spyOn(systemMailSettingsApi, 'test').mockResolvedValue({ ok: false, provider: 'plugin:com.example.mail', code: 'plugin_unavailable' })
    renderMail()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('combobox', { name: '发信方式' }))
    expect(await screen.findByText('插件：com.example.mail', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
    expect(screen.queryByText('插件：com.example.off', { selector: '.ant-select-item-option-content' })).toBeNull()
    expect(screen.queryByText('插件：com.example.dns', { selector: '.ant-select-item-option-content' })).toBeNull()
    await user.click(screen.getByText('插件：com.example.mail', { selector: '.ant-select-item-option-content' }))
    await user.type(screen.getByRole('textbox', { name: '测试收件地址' }), 'ops@example.com')
    await user.click(screen.getByRole('button', { name: '发送测试邮件' }))
    await waitFor(() => expect(test).toHaveBeenCalledTimes(1))
    expect(test.mock.calls[0][1]).toMatchObject({ mail_provider: 'plugin:com.example.mail' })
    expect(test.mock.calls[0][2]).toBe('ops@example.com')
    expect(test.mock.calls[0][3]).toBeUndefined()
    expect(await screen.findByText('测试邮件发送失败：plugin_unavailable')).toBeInTheDocument()
  })

  it('asks for a new secret when the saved one belongs to another provider', async () => {
    plugins = []
    renderMail({ ...initial, value: { ...initial.value, mail_provider: 'aliyun', mail_access_key_id: 'LTAI', mail_from: 'a@example.com' },
      mail_secret_configured: true, mail_secret_provider: 'aliyun', mail_secret_fingerprint: '0011223344556677' })
    const user = userEvent.setup()
    expect(await screen.findByText('已设置（指纹 0011223344556677），留空保存即保留原密钥')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '发信方式' }))
    await user.click(screen.getByText('SendGrid', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByText('已保存的密钥属于 阿里云邮件推送，切换到该服务商需重新填写')).toBeInTheDocument()
  })

  it('offers only licensed official mail services and marks a saved unlicensed one', async () => {
    plugins = []
    grantedModules = ['module.mail.aliyun']
    try {
      renderMail({ ...initial, value: { ...initial.value, mail_provider: 'sendgrid', mail_from: 'a@example.com' },
        mail_secret_configured: true, mail_secret_provider: 'sendgrid', mail_secret_fingerprint: '0011223344556677' })
      const user = userEvent.setup()
      expect(await screen.findByText('SendGrid（授权未包含，无法发信）', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
      await user.click(screen.getByRole('combobox', { name: '发信方式' }))
      expect(screen.getByText('阿里云邮件推送', { selector: '.ant-select-item-option-content' })).toBeInTheDocument()
      expect(screen.queryByText('SendGrid', { selector: '.ant-select-item-option-content' })).toBeNull()
      await user.click(screen.getByText('内置 SMTP（默认）', { selector: '.ant-select-item-option-content' }))
      await user.click(screen.getByRole('combobox', { name: '发信方式' }))
      // once switched away, the unlicensed service is no longer offered
      expect(screen.queryByText('SendGrid（授权未包含，无法发信）', { selector: '.ant-select-item-option-content' })).toBeNull()
    } finally {
      grantedModules = ['module.mail.aliyun', 'module.mail.sendgrid']
    }
  })
})
