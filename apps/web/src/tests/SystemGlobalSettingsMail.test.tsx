import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { notificationsApi } from '../api/notifications'
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

// SUBMAIL shows its signature field (the inherit choice shows none).
const initial: PlatformSystemMailSettingsDocument = {
  schema: 'cdnca.platform-system-mail-settings/v1', revision: 3,
  value: {
    smtp_address: 'smtp.example.test', smtp_ssl: true, smtp_port: 465, smtp_user: '', smtp_password_reference: '', smtp_from: '', smtp_from_name: '',
    sms_provider: 'submail', sms_access_key_id: '', sms_access_key_reference: '', sms_signature_name: '', sms_template_map: '',
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
  it('shows only the SMTP save action while the built-in SMTP sender is selected', async () => {
    plugins = []
    renderMail()
    const user = userEvent.setup()

    await screen.findByRole('textbox', { name: 'SMTP地址' })
    expect(screen.getByRole('button', { name: '保存SMTP设置' })).toBeVisible()
    expect(screen.queryByRole('button', { name: '保存发信服务商' })).toBeNull()

    await user.click(screen.getByRole('combobox', { name: '发信方式' }))
    await user.click(screen.getByText('SendGrid', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByRole('button', { name: '保存发信服务商' })).toBeVisible()
  })

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
    await user.click(screen.getByText('阿里云短信', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByRole('button', { name: '保存SMTP设置' })).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: 'AccessKey ID' }), 'key-id')
    await user.click(screen.getByRole('button', { name: '保存短信设置' }))
    await screen.findAllByText('发信配置已保存')
    expect(put.mock.calls[0][2].sms_provider).toBe('aliyun')
    expect(screen.getByRole('button', { name: '保存SMTP设置' })).toBeEnabled()
    expect(screen.getByText('阿里云短信', { selector: '.ant-select-selection-item' })).toBeInTheDocument()
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

    await screen.findAllByText('发信配置已保存')
    expect(put).toHaveBeenCalledTimes(1)
    expect(put.mock.calls[0][2]).toEqual({ ...initial.value,
      ...(section === 'smtp' ? { smtp_address: 'smtp.changed.test' } : { sms_signature_name: '短信草稿' }),
    })
    expect(smtp).toHaveValue('smtp.changed.test')
    expect(sms).toHaveValue('短信草稿')

    await user.click(screen.getByRole('button', { name: section === 'smtp' ? '保存短信设置' : '保存SMTP设置' }))
    await screen.findAllByText('发信配置已保存')
    expect(put.mock.calls[1][1]).toBe(4)
    expect(put.mock.calls[1][2]).toEqual({ ...initial.value, smtp_address: 'smtp.changed.test', sms_signature_name: '短信草稿' })
  })

  it('keeps an unsaved SMTP password across an unrelated save and tests only after it is saved', async () => {
    const complete = { ...initial, value: { ...initial.value, smtp_user: 'mailer@example.test' } }
    const put = vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({ ...complete, revision: revision + 1, value,
      smtp_password_configured: true, smtp_password_fingerprint: '0123456789abcdef' }))
    const sendTest = vi.spyOn(systemMailSettingsApi, 'test').mockResolvedValue({ ok: true, provider: 'smtp' })
    renderMail(complete)
    const user = userEvent.setup()
    const password = await screen.findByLabelText('SMTP密码')
    const testButton = screen.getByRole('button', { name: '发送测试邮件' })
    await user.type(password, 'draft-secret')
    await user.type(screen.getByRole('textbox', { name: '测试收件地址' }), 'ops@example.com')
    expect(testButton).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '保存短信设置' }))
    await screen.findAllByText('发信配置已保存')
    expect(password).toHaveValue('draft-secret')
    expect(testButton).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '保存SMTP设置' }))
    await waitFor(() => expect(testButton).toBeEnabled())
    expect(put.mock.calls[1][5]?.smtpPassword).toBe('draft-secret')
    expect(password).toHaveValue('')
    await user.click(testButton)
    expect(sendTest).toHaveBeenCalledWith(expect.any(String), complete.value, 'ops@example.com', undefined)
  })

  // Issue 15: an incomplete SMTP page is shown next to the test button, not after a request.
  it('disables the SMTP test while fields are missing, lists them, and focuses one on click', async () => {
    plugins = []
    const empty = { ...initial, value: { ...initial.value, smtp_address: '' } }
    const sendTest = vi.spyOn(systemMailSettingsApi, 'test').mockResolvedValue({ ok: true, provider: 'smtp' })
    vi.spyOn(systemMailSettingsApi, 'put').mockImplementation(async (_token, revision, value) => ({ ...empty, revision: revision + 1, value,
      smtp_password_configured: true, smtp_password_fingerprint: '0123456789abcdef' }))
    renderMail(empty)
    const user = userEvent.setup()
    await user.type(await screen.findByRole('textbox', { name: '测试收件地址' }), 'ops@example.com')
    const testButton = screen.getByRole('button', { name: '发送测试邮件' })
    const missing = screen.getByRole('group', { name: 'SMTP配置不完整' })
    expect(testButton).toBeDisabled()
    expect(Array.from(missing.querySelectorAll('button')).map((item) => item.textContent)).toEqual(['SMTP地址', 'SMTP用户', 'SMTP密码', '发件地址'])

    await user.click(within(missing).getByRole('button', { name: 'SMTP用户' }))
    expect(screen.getByRole('textbox', { name: 'SMTP用户' })).toHaveFocus()
    await user.click(within(missing).getByRole('button', { name: 'SMTP地址' }))
    expect(screen.getByRole('textbox', { name: 'SMTP地址' })).toHaveFocus()

    await user.type(screen.getByRole('textbox', { name: 'SMTP地址' }), 'smtp.example.test')
    // a user that is an address also serves as the sender
    await user.type(screen.getByRole('textbox', { name: 'SMTP用户' }), 'mailer@example.test')
    expect(Array.from(missing.querySelectorAll('button')).map((item) => item.textContent)).toEqual(['SMTP密码'])
    await user.type(screen.getByLabelText('SMTP密码'), 'secret')
    await user.click(screen.getByRole('button', { name: '保存SMTP设置' }))
    await waitFor(() => expect(testButton).toBeEnabled())
    expect(screen.queryByRole('group', { name: 'SMTP配置不完整' })).toBeNull()
    await user.click(testButton)
    expect(sendTest).toHaveBeenCalledTimes(1)
  })

  // a saved, complete page whose fields are cleared without saving.
  const saved = { ...initial, value: { ...initial.value, smtp_user: 'mailer', smtp_from: 'noreply@example.test' },
    smtp_password_configured: true, smtp_password_fingerprint: '0123456789abcdef' }
  const listed = (name: string) => Array.from(screen.getByRole('group', { name }).querySelectorAll('button')).map((item) => item.textContent)

  it('lists the cleared SMTP fields of the unsaved form next to the test button', async () => {
    plugins = []
    const sendTest = vi.spyOn(systemMailSettingsApi, 'test').mockResolvedValue({ ok: true, provider: 'smtp' })
    renderMail(saved)
    const user = userEvent.setup()
    const testTo = await screen.findByRole('textbox', { name: '测试收件地址' })
    const testButton = screen.getByRole('button', { name: '发送测试邮件' })
    await user.type(testTo, 'ops@example.com')
    expect(testButton).toBeEnabled()
    expect(screen.queryByRole('group', { name: 'SMTP配置不完整' })).toBeNull()

    for (const name of ['SMTP地址', 'SMTP用户', '发件地址']) await user.clear(screen.getByRole('textbox', { name }))
    await user.clear(testTo)
    expect(testButton).toBeDisabled()
    // the saved password (fingerprint shown) counts as filled
    expect(listed('SMTP配置不完整')).toEqual(['SMTP地址', 'SMTP用户', '发件地址'])
    expect(screen.getByText('请填写测试收件地址')).toBeInTheDocument()

    await user.click(within(screen.getByRole('group', { name: 'SMTP配置不完整' })).getByRole('button', { name: 'SMTP地址' }))
    expect(screen.getByRole('textbox', { name: 'SMTP地址' })).toHaveFocus()

    await user.type(screen.getByRole('textbox', { name: 'SMTP地址' }), 'smtp.example.test')
    await user.type(screen.getByRole('textbox', { name: 'SMTP用户' }), 'mailer')
    await user.type(screen.getByRole('textbox', { name: '发件地址' }), 'noreply@example.test')
    // only the recipient is left: no SMTP note, only the recipient one
    expect(screen.queryByRole('group', { name: 'SMTP配置不完整' })).toBeNull()
    expect(screen.getByText('请填写测试收件地址')).toBeInTheDocument()
    expect(testButton).toBeDisabled()

    await user.type(testTo, 'ops@example.com')
    expect(screen.queryByText('请填写测试收件地址')).toBeNull()
    expect(testButton).toBeEnabled()
    await user.click(testButton)
    expect(sendTest).toHaveBeenCalledWith(expect.any(String), saved.value, 'ops@example.com', undefined)
  })

  it('shows the missing fields of a 422 config_incomplete answer', async () => {
    plugins = []
    const complete = { ...initial, value: { ...initial.value, smtp_user: 'mailer@example.test' }, smtp_password_configured: true, smtp_password_fingerprint: '0123456789abcdef' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).endsWith('/v1/admin/system-mail-settings/tests')
      ? new Response(JSON.stringify({ error: { code: 'system_mail_settings_config_incomplete', message: '发信配置不完整', request_id: 'r-1',
        details: { provider: 'smtp', missing: ['smtp_password'] } } }), { status: 422, headers: { 'Content-Type': 'application/json' } })
      : new Response('{}', { status: 404 }))
    renderMail(complete)
    const user = userEvent.setup()
    await user.type(await screen.findByRole('textbox', { name: '测试收件地址' }), 'ops@example.com')
    await user.click(screen.getByRole('button', { name: '发送测试邮件' }))
    expect(await screen.findByText('发信配置还缺：SMTP密码')).toBeInTheDocument()
    // the server's answer stays next to the button until the form changes
    expect(listed('SMTP配置不完整')).toEqual(['SMTP密码'])
    expect(screen.getByRole('button', { name: '发送测试邮件' })).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: '发件人名称' }), 'CDNCA')
    expect(screen.queryByRole('group', { name: 'SMTP配置不完整' })).toBeNull()
    expect(screen.getByRole('button', { name: '发送测试邮件' })).toBeEnabled()
  })

  // the recipient is checked on its own before a test is sent.
  describe('test recipient', () => {
    const mailFetch = (status: number, error: Record<string, unknown>) => vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).endsWith('/v1/admin/system-mail-settings/tests')
        ? new Response(JSON.stringify({ error: { message: 'x', request_id: 'r-to', ...error } }), { status, headers: { 'Content-Type': 'application/json' } })
        : new Response('{}', { status: 404 }))
    const recipient = async () => {
      renderMail(saved)
      const input = await screen.findByRole('textbox', { name: '测试收件地址' })
      return { user: userEvent.setup(), input, button: screen.getByRole('button', { name: '发送测试邮件' }) }
    }
    const expectFieldError = (input: HTMLElement) => {
      expect(input).toHaveAttribute('aria-invalid', 'true')
      const note = window.document.getElementById(input.getAttribute('aria-describedby') ?? '')
      expect(note).toHaveTextContent('请填写有效的邮箱地址，例如 ops@example.com')
    }

    it('keeps the empty recipient required: button off, required note, no field error', async () => {
      const sendTest = vi.spyOn(systemMailSettingsApi, 'test')
      const { input, button } = await recipient()
      expect(button).toBeDisabled()
      expect(screen.getByText('请填写测试收件地址')).toBeInTheDocument()
      expect(input).not.toHaveAttribute('aria-invalid')
      expect(sendTest).not.toHaveBeenCalled()
    })

    it('marks a value without @ beside the input, sends nothing and focuses it on click', async () => {
      const sendTest = vi.spyOn(systemMailSettingsApi, 'test')
      const { user, input, button } = await recipient()
      await user.type(input, 'ops.example.com')
      // no note while typing
      expect(input).not.toHaveAttribute('aria-invalid')
      expect(button).toBeEnabled()
      await user.click(button)
      expect(sendTest).not.toHaveBeenCalled()
      expect(input).toHaveFocus()
      expectFieldError(input)
      await user.clear(input)
      await user.type(input, 'ops@example.com')
      expect(input).not.toHaveAttribute('aria-invalid')
      expect(input).not.toHaveAttribute('aria-describedby')
    })

    it('shows the format note when the input is left', async () => {
      const { user, input } = await recipient()
      await user.type(input, 'ops@')
      await user.tab()
      expectFieldError(input)
    })

    it('trims surrounding spaces and sends a valid address', async () => {
      const sendTest = vi.spyOn(systemMailSettingsApi, 'test').mockResolvedValue({ ok: true, provider: 'smtp', message_id: 'm-1' })
      const { user, input, button } = await recipient()
      await user.type(input, '  ops@example.com ')
      await user.tab()
      expect(input).not.toHaveAttribute('aria-invalid')
      await user.click(button)
      await waitFor(() => expect(sendTest).toHaveBeenCalledTimes(1))
      expect(sendTest.mock.calls[0][2]).toBe('ops@example.com')
      expect(await screen.findByText('测试邮件已发送（m-1）')).toBeInTheDocument()
    })

    it('puts a server refusal of "to" on the input instead of the generic message', async () => {
      const fetch = mailFetch(400, { code: 'system_mail_settings_validation_error', details: { field: 'to', reason: 'invalid_format' } })
      const { user, input, button } = await recipient()
      await user.type(input, 'ops@example')
      await user.click(button)
      await waitFor(() => expect(fetch.mock.calls.filter(([url]) => String(url).endsWith('/v1/admin/system-mail-settings/tests'))).toHaveLength(1))
      await waitFor(() => expect(input).toHaveFocus())
      expectFieldError(input)
      expect(screen.queryByText('发信配置存在无效或不安全的字段')).toBeNull()
      await user.type(input, '.com')
      expect(input).not.toHaveAttribute('aria-invalid')
    })

    it('keeps the original message when the mail service fails', async () => {
      mailFetch(502, { code: 'system_mail_settings_test_failed', details: { provider: 'smtp', reason: 'provider_unavailable' } })
      const { user, input, button } = await recipient()
      await user.type(input, 'ops@example.com')
      await user.click(button)
      expect(await screen.findByText('测试邮件发送失败：provider_unavailable')).toBeInTheDocument()
      expect(input).not.toHaveAttribute('aria-invalid')
    })
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
    await screen.findAllByText('发信配置已保存')
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
    await screen.findAllByText('发信配置已保存')
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
    await screen.findAllByText('发信配置已保存')
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
    await screen.findAllByText('发信配置已保存')
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
    await screen.findAllByText('发信配置已保存')
    const [, , value, , , secrets] = put.mock.calls[0]
    expect(value).toEqual({ ...initial.value, mail_provider: 'sendgrid', mail_from: 'noreply@example.com' })
    expect(JSON.stringify(value)).not.toContain('SG.secret')
    expect(secrets).toEqual({ smsAccessKeySecret: undefined, mailSecret: 'SG.secret' })
    expect(screen.getByText('已设置（指纹 fedcba9876543210），留空保存即保留原密钥')).toBeInTheDocument()
    expect(screen.getByLabelText('API Key')).toHaveValue('')
    expect(smtp).toHaveValue('smtp.draft.test')
  })

  it.each([
    ['auto', '保存后约 15 秒内自动生效，无需重启。', '需重启发信服务'],
    ['explicit', '保存后需重启发信服务生效。', '自动生效'],
  ] as const)('tells how a saved mail sender takes effect in the %s notification mode', async (mode, shown, absent) => {
    plugins = []
    vi.spyOn(notificationsApi, 'getRuntimeHealth').mockResolvedValue({ enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1, mode })
    renderMail()
    const field = (await screen.findByRole('combobox', { name: '发信方式' })).closest('.ant-form-item') as HTMLElement
    await waitFor(() => expect(field).toHaveTextContent(shown))
    expect(field).not.toHaveTextContent(absent)
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
