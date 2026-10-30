import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { acmeCACredentialsApi } from '../../api/acmeCACredentials'
import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import '../../i18n/systemSettings'
import { renderWithProviders } from '../../test/render'
import AcmeCACredentialsCard from './AcmeCACredentialsCard'

const t = i18n.getFixedT('zh-CN', 'systemSettings')

function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  useSessionStore.setState({ accessToken: 'token', sessionEpoch: 1, status: 'authenticated' })
})
afterEach(() => vi.restoreAllMocks())

describe('ACME EAB credentials', () => {
  it('lists both CAs, never accepts an echoed key, and writes KID + HMAC with the revision', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ items: [
        { ca: 'zerossl', directory_url: 'https://acme.zerossl.com/v2/DV90', configured: true, eab_key_id: 'kid-1', eab_hmac_sha256_prefix: '0123abcd', revision: 2 },
        { ca: 'google_trust', directory_url: 'https://dv.acme-v02.api.pki.goog/directory', configured: false, revision: 0 },
      ] }))
      .mockResolvedValueOnce(response({ ca: 'google_trust', directory_url: 'https://dv.acme-v02.api.pki.goog/directory', configured: true, eab_key_id: 'gts-kid', eab_hmac_sha256_prefix: 'deadbeef', revision: 1 }))
      .mockResolvedValue(response({ items: [] }))
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AcmeCACredentialsCard t={t} editable />)
    expect(await screen.findByText('已配置（KID kid-1，密钥指纹 0123abcd）')).toBeInTheDocument()
    expect(screen.getByText('未配置')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Google Trust Services EAB KID'), { target: { value: 'gts-kid' } })
    fireEvent.change(screen.getByLabelText('Google Trust Services EAB HMAC 密钥'), { target: { value: 'zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG4' } })
    fireEvent.click(screen.getAllByRole('button', { name: '保存凭据' })[1]!)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    const [url, init] = fetchMock.mock.calls[1]!
    expect(String(url)).toContain('/v1/admin/acme-ca-credentials/google_trust')
    expect(JSON.parse(String(init.body))).toEqual({ expected_revision: 0, eab_key_id: 'gts-kid', eab_hmac_key: 'zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG4' })
  })

  // ZeroSSL 可按账户邮箱自动获取 EAB；错误码给出可读原因。
  it('obtains ZeroSSL EAB by account email and explains a refusal', async () => {
    const zerossl = { ca: 'zerossl', directory_url: 'https://acme.zerossl.com/v2/DV90', configured: false, revision: 0 }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ items: [zerossl, { ca: 'google_trust', directory_url: 'https://dv.acme-v02.api.pki.goog/directory', configured: false, revision: 0 }] }))
      .mockResolvedValueOnce(response({ error: { code: 'acme_ca_credential_eab_fetch_failed', message: 'upstream detail' } }, 502))
      .mockResolvedValueOnce(response({ ...zerossl, configured: true, eab_key_id: 'kid-mail', eab_hmac_sha256_prefix: '00112233', revision: 1 }))
      .mockResolvedValue(response({ items: [] }))
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AcmeCACredentialsCard t={t} editable />)
    const emailInput = await screen.findByLabelText('ZeroSSL 账户邮箱')
    // 只有 ZeroSSL 有按邮箱获取。
    expect(screen.queryByLabelText('Google Trust Services 账户邮箱')).not.toBeInTheDocument()
    const fetchButton = screen.getByRole('button', { name: '按邮箱获取' })
    expect(fetchButton).toBeDisabled()
    fireEvent.change(emailInput, { target: { value: 'ops@example.com' } })
    expect(fetchButton).toBeEnabled()
    fireEvent.click(fetchButton)
    expect(await screen.findByText('ZeroSSL 没有为该邮箱签发 EAB，请检查邮箱或手动粘贴凭据')).toBeInTheDocument()
    expect(screen.queryByText('upstream detail')).not.toBeInTheDocument()
    const [url, init] = fetchMock.mock.calls[1]!
    expect(String(url)).toContain('/v1/admin/acme-ca-credentials/zerossl/eab-from-email')
    expect(init.method).toBe('POST')
    expect(JSON.parse(String(init.body))).toEqual({ expected_revision: 0, email: 'ops@example.com' })
    fireEvent.click(fetchButton)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4))
    expect(emailInput).toHaveValue('')
  })

  it('refuses a response that carries the HMAC key', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [
      { ca: 'zerossl', directory_url: 'https://acme.zerossl.com/v2/DV90', configured: true, eab_key_id: 'k', eab_hmac_key: 'secret', revision: 1 },
    ] })))
    await expect(acmeCACredentialsApi.list('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
