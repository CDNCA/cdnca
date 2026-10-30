import { useState } from 'react'
import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import {
  certificatesApi,
  type CertificateAsset,
  type CertificateAssetBinding,
  type CertificateAssetVersion,
} from '../../api/certificates'
import type { SiteBasicConfig } from '../../api/sites'
import i18n from '../../i18n'
import { renderWithProviders } from '../../test/render'
import HttpsSiteTab, { type HttpsWorkflowState } from './HttpsSiteTab'

const scopeID = '22222222-2222-4222-8222-222222222222'
const siteID = '33333333-3333-4333-8333-333333333333'
const assetID = '44444444-4444-4444-8444-444444444444'
const versionID = '55555555-5555-4555-8555-555555555555'

const asset: CertificateAsset = {
  id: assetID,
  display_id: '1',
  tenant: { id: '12121212-1212-4212-8212-121212121212', display_id: '1', name: '测试租户' },
  owner: null, owner_status: 'legacy_unknown',
  tenant_scope_id: scopeID,
  name: '边缘证书',
  source: 'uploaded',
  revision: 4,
  created_by: '66666666-6666-4666-8666-666666666666',
  updated_by: '66666666-6666-4666-8666-666666666666',
  created_at: '2026-09-15T00:00:00Z',
  updated_at: '2026-09-15T00:00:00Z',
}

const version: CertificateAssetVersion = {
  id: versionID,
  asset_id: assetID,
  tenant_scope_id: scopeID,
  version: 2,
  status: 'active',
  fingerprint_sha256: 'ab'.repeat(32),
  certificate_pem: 'PUBLIC',
  sans: ['www.example.com'],
  subject: 'CN=www.example.com',
  serial_number: '123',
  public_key_algorithm: 'RSA',
  public_key_bits: 2048,
  signature_algorithm: 'SHA256-RSA',
  not_before: '2026-09-15T00:00:00Z',
  not_after: '2027-09-15T00:00:00Z',
  renewal_due: false,
  imported_by: asset.created_by,
  imported_at: asset.created_at,
}

const binding: CertificateAssetBinding = {
  tenant_scope_id: scopeID,
  site_id: siteID,
  asset_id: assetID,
  version_id: versionID,
  revision: 3,
  default: true,
  bound: true,
  changed_by: asset.updated_by,
  changed_at: asset.updated_at,
}

const disabledConfig: SiteBasicConfig = {
  package_id: null,
  package_name: null,
  group_id: null,
  group_name: null,
  domains: ['www.example.com'],
  http_enabled: true,
  http_listen_ports: ['80'],
  https_listen_ports: ['443'],
  ipv6_enabled: false,
  tls_protocols: ['TLSv1.2', 'TLSv1.3'],
  origins: ['192.0.2.10:80'],
  cname: 'edge.example.com',
  https_enabled: false,
  enabled: true,
  status: 'active',
  sync_status: 'synced',
  is_default: false,
}

interface HarnessProps {
  initial?: SiteBasicConfig
  permissions?: string[]
  readOnly?: boolean
  onWorkflowStateChange?: (state: HttpsWorkflowState) => void
}

function Harness({
  initial = { ...disabledConfig, https_enabled: true },
  permissions = ['certificates.read', 'certificates.manage'],
  readOnly = false,
  onWorkflowStateChange,
  savedHttpsEnabled,
}: HarnessProps & { savedHttpsEnabled?: boolean }) {
  const [value, setValue] = useState(initial)
  return (
    <HttpsSiteTab
      siteId={siteID}
      siteScopeId={scopeID}
      accessToken="certificate-token"
      scopeKind="tenant"
      principalScopeId={scopeID}
      permissions={permissions}
      sessionEpoch={1}
      value={value}
      errors={{}}
      readOnly={readOnly}
     
      onChange={setValue}
      onWorkflowStateChange={onWorkflowStateChange}
      savedHttpsEnabled={savedHttpsEnabled}
    />
  )
}

function siteBindingNotFound(): ApiError {
  return new ApiError('API request failed', 404, 'certificate_site_binding_not_found')
}

const otherAssetID = '77777777-7777-4777-8777-777777777777'
const otherVersionID = '88888888-8888-4888-8888-888888888888'
const otherAsset: CertificateAsset = { ...asset, id: otherAssetID, display_id: '2', name: '备用证书' }
const otherVersion: CertificateAssetVersion = {
  ...version, id: otherVersionID, asset_id: otherAssetID, fingerprint_sha256: 'cd'.repeat(32), sans: ['api.example.com'],
}

function mockCertificateRead(currentBinding: CertificateAssetBinding | null = null, withOther = false) {
  vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue(
    withOther ? { items: [asset, otherAsset], total: 2 } : { items: [asset], total: 1 },
  )
  vi.spyOn(certificatesApi, 'getAsset').mockImplementation(async (_token, id) =>
    id === otherAssetID ? { asset: otherAsset, versions: [otherVersion] } : { asset, versions: [version] })
  vi.spyOn(certificatesApi, 'getSiteBinding').mockImplementation(async () => {
    if (!currentBinding) throw siteBindingNotFound()
    return { binding: currentBinding, version }
  })
}

function clearCertificate(container: HTMLElement) {
  const clear = container.querySelector<HTMLElement>('.ant-select-clear')
  expect(clear).not.toBeNull()
  fireEvent.mouseDown(clear!)
  fireEvent.click(clear!)
}

async function selectCertificate(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('combobox', { name: '证书' }))
  await user.click(await screen.findByText('边缘证书 · www.example.com'))
}

describe('HttpsSiteTab', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await i18n.changeLanguage('zh-CN')
  })

  it('matches the observed disabled state and enables HTTPS through the controlled site draft', async () => {
    mockCertificateRead(binding)
    const user = userEvent.setup()
    renderWithProviders(<Harness initial={disabledConfig} />)

    expect(screen.getByText('HTTPS证书')).toBeInTheDocument()
    expect(screen.getByText('关闭后，HTTPS 入口将不可用；开启后可配置证书和监听端口。')).toBeInTheDocument()
    expect(screen.getByText('HTTPS 未开启，证书、协议和相关增强功能暂不生效。')).toBeInTheDocument()
    // be-gap-2: the certificate loads while HTTPS is off, so it can be bound first.
    expect(await screen.findByText('边缘证书 · www.example.com')).toBeInTheDocument()

    await user.click(screen.getByRole('switch', { name: 'HTTPS访问' }))
    expect(await screen.findByRole('textbox', { name: 'HTTPS监听端口' })).toHaveValue('443')
  })

  it('keeps HTTPS and forced HTTPS off without a bound certificate and offers binding first (be-gap-2)', async () => {
    mockCertificateRead()
    const user = userEvent.setup()
    renderWithProviders(<Harness initial={disabledConfig} />)

    const access = screen.getByRole('switch', { name: 'HTTPS访问' })
    expect(await screen.findByText('还没有绑定证书：请先在下方选择证书（选中即绑定），再开启 HTTPS 和强制跳转。')).toBeInTheDocument()
    await waitFor(() => expect(access).toBeDisabled())
    expect(access).not.toBeChecked()
    // The certificate select is there while HTTPS is off; choosing binds at once (fix-certinstant).
    const bind = vi.spyOn(certificatesApi, 'bindAsset').mockResolvedValue(binding)
    await selectCertificate(user)
    await waitFor(() => expect(bind).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole('button', { name: '应用证书' })).toBeNull()
  })

  it('still turns HTTPS off without a certificate and locks forced HTTPS until one is bound (be-gap-2)', async () => {
    mockCertificateRead()
    const user = userEvent.setup()
    renderWithProviders(<Harness initial={{ ...disabledConfig, https_enabled: true }} />)

    const force = screen.getByRole('switch', { name: '强制HTTPS' })
    await waitFor(() => expect(force).toBeDisabled())
    const access = screen.getByRole('switch', { name: 'HTTPS访问' })
    expect(access).toBeEnabled()
    await user.click(access)
    expect(access).not.toBeChecked()
  })

  it('summarizes HTTPS and warns next to the switch when a live HTTPS is turned off (site-parity4)', async () => {
    mockCertificateRead()
    const user = userEvent.setup()
    renderWithProviders(<Harness initial={{ ...disabledConfig, https_enabled: true }} savedHttpsEnabled />)
    const summary = screen.getByRole('region', { name: '本页摘要' })
    expect(summary).toHaveTextContent('已开启 · 443')
    expect(summary).toHaveTextContent('HTTP/2')
    expect(screen.queryByText(/HTTPS 入口立即停用/u)).toBeNull()
    await user.click(screen.getByRole('switch', { name: 'HTTPS访问' }))
    expect(screen.getByText(/HTTPS 入口立即停用/u)).toBeInTheDocument()
    expect(summary).toHaveTextContent('已关闭')
  })

  it('uses the site detail flag when certificates cannot be read (be-gap-2)', () => {
    const list = vi.spyOn(certificatesApi, 'listAssets')
    renderWithProviders(
      <HttpsSiteTab
        siteId={siteID} siteScopeId={scopeID} accessToken="certificate-token" scopeKind="tenant"
        principalScopeId={scopeID} permissions={[]} sessionEpoch={1}
        value={disabledConfig} errors={{}} readOnly={false}
        onChange={() => undefined} certificateBound={false}
      />,
    )
    expect(list).not.toHaveBeenCalled()
    expect(screen.getByRole('switch', { name: 'HTTPS访问' })).toBeDisabled()
  })

  it('turns forced HTTPS on and picks its redirect port in the site draft (FX07)', async () => {
    mockCertificateRead(binding)
    const changes: SiteBasicConfig[] = []
    function Recorder() {
      const [value, setValue] = useState<SiteBasicConfig>({
        ...disabledConfig, https_enabled: true, https_listen_ports: ['443', '8443'],
      })
      return (
        <HttpsSiteTab
          siteId={siteID} siteScopeId={scopeID} accessToken="certificate-token" scopeKind="tenant"
          principalScopeId={scopeID} permissions={['certificates.read']} sessionEpoch={1}
          value={value} errors={{}} readOnly={false}
          onChange={(next) => { changes.push(next); setValue(next) }}
        />
      )
    }
    const user = userEvent.setup()
    renderWithProviders(<Recorder />)

    const port = screen.getByRole('combobox', { name: '跳转端口' })
    expect(port).toBeDisabled()
    await user.click(screen.getByRole('switch', { name: '强制HTTPS' }))
    expect(changes.at(-1)?.force_https).toBe(true)
    await waitFor(() => expect(port).toBeEnabled())
    await user.click(port)
    await user.click(await screen.findByTitle('8443'))
    expect(changes.at(-1)).toMatchObject({ force_https: true, https_redirect_port: 8443 })
  })

  it('turns HTTP/2 and HTTP/3 off and sets prefer server ciphers per site (fp-site5a)', async () => {
    mockCertificateRead()
    const changes: SiteBasicConfig[] = []
    function Recorder() {
      const [value, setValue] = useState<SiteBasicConfig>({
        ...disabledConfig, https_enabled: true, https_listen_ports: ['443'],
      })
      return (
        <HttpsSiteTab
          siteId={siteID} siteScopeId={scopeID} accessToken="certificate-token" scopeKind="tenant"
          principalScopeId={scopeID} permissions={['certificates.read']} sessionEpoch={1}
          value={value} errors={{}} readOnly={false}
          onChange={(next) => { changes.push(next); setValue(next) }}
        />
      )
    }
    const user = userEvent.setup()
    renderWithProviders(<Recorder />)

    // omitted fields show the server defaults: on, on, by preset
    const http2 = screen.getByRole('switch', { name: 'HTTP/2' })
    const http3 = screen.getByRole('switch', { name: 'HTTP/3' })
    expect(http2).toBeChecked()
    expect(http3).toBeChecked()
    expect(screen.getByText('按套件预设（当前关闭）')).toBeInTheDocument()
    await user.click(http2)
    expect(changes.at(-1)?.http2_enabled).toBe(false)
    await user.click(http3)
    expect(changes.at(-1)).toMatchObject({ http2_enabled: false, http3_enabled: false })
    await user.click(screen.getByRole('combobox', { name: '优先使用服务端套件' }))
    await user.click(await screen.findByTitle('开启'))
    expect(changes.at(-1)?.tls_prefer_server_ciphers).toBe(true)
    await user.click(screen.getByRole('combobox', { name: '优先使用服务端套件' }))
    await user.click(await screen.findByTitle('按套件预设（当前关闭）'))
    expect(changes.at(-1)?.tls_prefer_server_ciphers).toBeNull()
  })

  it('reads the current binding once by site instead of scanning every asset binding', async () => {
    const assetBindings = vi.spyOn(certificatesApi, 'listAssetBindings')
    mockCertificateRead(binding)
    renderWithProviders(<Harness />)

    expect(await screen.findByText('边缘证书 · www.example.com')).toBeInTheDocument()
    expect(certificatesApi.getSiteBinding).toHaveBeenCalledTimes(1)
    expect(certificatesApi.getSiteBinding).toHaveBeenCalledWith(
      'certificate-token',
      siteID,
      undefined,
    )
    expect(assetBindings).not.toHaveBeenCalled()
  })

  it('treats only the stable site-binding 404 as an unbound site', async () => {
    mockCertificateRead()
    vi.mocked(certificatesApi.getSiteBinding).mockRejectedValue(
      new ApiError('API request failed', 404, 'certificate_asset_not_found'),
    )
    renderWithProviders(<Harness />)

    expect(await screen.findByText('证书资产加载失败，请稍后重试。')).toBeInTheDocument()
  })

  // fix-certinstant: choosing a certificate binds it at once; there is no apply button.
  it('binds as soon as a certificate is chosen, with binding revision zero', async () => {
    mockCertificateRead()
    let current: CertificateAssetBinding | null = null
    vi.mocked(certificatesApi.getSiteBinding).mockImplementation(async () => {
      if (!current) throw siteBindingNotFound()
      return { binding: current, version }
    })
    const bind = vi.spyOn(certificatesApi, 'bindAsset').mockImplementation(async () => {
      current = binding
      return binding
    })
    const workflow: HttpsWorkflowState[] = []
    const user = userEvent.setup()
    renderWithProviders(<Harness onWorkflowStateChange={(state) => workflow.push(state)} />)

    await selectCertificate(user)

    await waitFor(() => expect(bind).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole('button', { name: '应用证书' })).toBeNull()
    expect(bind.mock.calls[0][0]).toBe('certificate-token')
    expect(bind.mock.calls[0][1]).toBe(assetID)
    expect(bind.mock.calls[0][2]).toEqual({
      site_id: siteID,
      version_id: versionID,
      expected_revision: 0,
      default: true,
    })
    expect(bind.mock.calls[0][3]).toMatch(/^[0-9a-f-]{36}$/)
    expect(bind.mock.calls[0][4]).toMatch(/^[0-9a-f-]{36}$/)
    expect(await screen.findByText('操作成功')).toBeInTheDocument()
    expect(await screen.findByText('当前绑定 #3')).toBeInTheDocument()
    await waitFor(() => expect(workflow.at(-1)).toEqual({ dirty: false, uncertain: false, pending: false }))
  })

  it('disables the select and shows progress while binding', async () => {
    mockCertificateRead()
    let finish: (value: CertificateAssetBinding) => void = () => undefined
    vi.spyOn(certificatesApi, 'bindAsset').mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const workflow: HttpsWorkflowState[] = []
    const user = userEvent.setup()
    renderWithProviders(<Harness onWorkflowStateChange={(state) => workflow.push(state)} />)

    await selectCertificate(user)
    expect(await screen.findByText('正在绑定证书…')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '证书' })).toBeDisabled()
    // the page holds its own saves while the binding is in flight
    expect(workflow.at(-1)?.pending).toBe(true)
    finish(binding)
    expect(await screen.findByText('操作成功')).toBeInTheDocument()
  })

  it('unbinds at once when the choice is cleared on a site with HTTPS off', async () => {
    let current: CertificateAssetBinding | null = binding
    mockCertificateRead(binding)
    vi.mocked(certificatesApi.getSiteBinding).mockImplementation(async () => {
      if (!current) throw siteBindingNotFound()
      return { binding: current, version }
    })
    const unbind = vi.spyOn(certificatesApi, 'unbindAsset').mockImplementation(async () => {
      current = null
      return { ...binding, revision: 4, bound: false }
    })
    const view = renderWithProviders(<Harness initial={disabledConfig} />)

    await screen.findByText('边缘证书 · www.example.com')
    clearCertificate(view.container)

    await waitFor(() => expect(unbind).toHaveBeenCalledTimes(1))
    expect(unbind.mock.calls[0].slice(0, 4)).toEqual([
      'certificate-token',
      assetID,
      siteID,
      { expected_revision: 3 },
    ])
    expect(screen.queryByText('解绑证书？')).toBeNull()
    expect(await screen.findByText('操作成功')).toBeInTheDocument()
  })

  it('asks before unbinding while HTTPS is on, and keeps the binding when cancelled', async () => {
    mockCertificateRead(binding)
    const unbind = vi.spyOn(certificatesApi, 'unbindAsset').mockResolvedValue({ ...binding, revision: 4, bound: false })
    const user = userEvent.setup()
    const view = renderWithProviders(<Harness initial={{ ...disabledConfig, https_enabled: true, force_https: true }} />)

    await screen.findByText('边缘证书 · www.example.com')
    clearCertificate(view.container)
    expect((await screen.findAllByText('解绑证书？'))[0]).toBeInTheDocument()
    expect(screen.getByText(/强制 HTTPS 与 HSTS 随之失效/u)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '取消' }))
    expect(unbind).not.toHaveBeenCalled()
    expect(screen.getByText('边缘证书 · www.example.com')).toBeInTheDocument()

    clearCertificate(view.container)
    await user.click(await screen.findByRole('button', { name: '解绑' }))
    await waitFor(() => expect(unbind).toHaveBeenCalledTimes(1))
  })

  it('goes back to the server binding when a bind is refused', async () => {
    mockCertificateRead(binding, true)
    vi.spyOn(certificatesApi, 'bindAsset').mockRejectedValue(new ApiError('refused', 422, 'validation_error'))
    const user = userEvent.setup()
    renderWithProviders(<Harness />)

    await screen.findByText('边缘证书 · www.example.com')
    await user.click(screen.getByRole('combobox', { name: '证书' }))
    await user.click(await screen.findByText('备用证书 · api.example.com'))

    expect(await screen.findByText('证书操作失败，请稍后重试。')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('combobox', { name: '证书' })).toBeEnabled())
    const selected = document.querySelector('.site-https-certificate-control .ant-select-selection-item')
    expect(selected).toHaveTextContent('边缘证书 · www.example.com')
  })

  it('retries an unknown binding outcome with the same frozen request identities', async () => {
    mockCertificateRead()
    const bind = vi.spyOn(certificatesApi, 'bindAsset')
      .mockRejectedValueOnce(new ApiError('private transport detail', 0, 'network_error'))
      .mockResolvedValueOnce(binding)
    const user = userEvent.setup()
    renderWithProviders(<Harness />)

    await selectCertificate(user)
    expect(await screen.findByText('证书操作结果未知，使用同一请求重试或刷新核对。')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private transport detail')
    expect(screen.getByRole('combobox', { name: '证书' })).toBeDisabled()
    const firstCall = bind.mock.calls[0]

    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(bind).toHaveBeenCalledTimes(2))
    expect(bind.mock.calls[1]).toEqual(firstCall)
    expect(await screen.findByText('操作成功')).toBeInTheDocument()
  })

  it('sends only the last choice when the certificate is switched quickly', async () => {
    mockCertificateRead(null, true)
    let current: CertificateAssetBinding | null = null
    let holdRead: Promise<void> | null = null
    let releaseRead: () => void = () => undefined
    vi.mocked(certificatesApi.getSiteBinding).mockImplementation(async () => {
      if (holdRead) await holdRead
      if (!current) throw siteBindingNotFound()
      return { binding: current, version: current.version_id === otherVersionID ? otherVersion : version }
    })
    const bind = vi.spyOn(certificatesApi, 'bindAsset').mockImplementation(async (_token, assetId, body) => {
      current = { ...binding, asset_id: assetId, version_id: body.version_id, revision: (current?.revision ?? 2) + 1 }
      // the re-read after this write waits until the test lets it go
      holdRead = new Promise((resolve) => { releaseRead = () => { holdRead = null; resolve() } })
      return current
    })
    const unbind = vi.spyOn(certificatesApi, 'unbindAsset')
    const user = userEvent.setup()
    renderWithProviders(<Harness initial={disabledConfig} />)

    await selectCertificate(user)
    await waitFor(() => expect(bind).toHaveBeenCalledTimes(1))
    // While the first write is re-read: other, back to the first, other again.
    const select = screen.getByRole('combobox', { name: '证书' })
    await waitFor(() => expect(select).toBeEnabled())
    for (const label of ['备用证书 · api.example.com', '边缘证书 · www.example.com', '备用证书 · api.example.com']) {
      await user.click(select)
      const options = await screen.findAllByText(label, { selector: '.ant-select-item-option-content' })
      await user.click(options.at(-1)!)
    }
    expect(bind).toHaveBeenCalledTimes(1)
    act(() => releaseRead())

    await waitFor(() => expect(bind).toHaveBeenCalledTimes(2))
    expect(unbind).not.toHaveBeenCalled()
    expect(bind.mock.calls[1][1]).toBe(otherAssetID)
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(bind).toHaveBeenCalledTimes(2)
    expect(bind.mock.calls[1][2]).toMatchObject({ version_id: otherVersionID, expected_revision: 3 })
  })

  it('keeps certificate operations read-only without certificate permissions', () => {
    const list = vi.spyOn(certificatesApi, 'listAssets')
    renderWithProviders(<Harness permissions={[]} />)

    expect(screen.getByText('当前账号无权读取证书资产，仍可保存 HTTPS 开关、端口和 TLS 协议。')).toBeInTheDocument()
    expect(list).not.toHaveBeenCalled()
    expect(screen.queryByRole('combobox', { name: '证书' })).not.toBeInTheDocument()
  })

  it('shows the certificate but does not bind without the manage permission', async () => {
    mockCertificateRead()
    const bind = vi.spyOn(certificatesApi, 'bindAsset')
    renderWithProviders(<Harness permissions={['certificates.read']} />)

    await waitFor(() => expect(screen.getByRole('combobox', { name: '证书' })).toBeDisabled())
    expect(bind).not.toHaveBeenCalled()
  })
})
