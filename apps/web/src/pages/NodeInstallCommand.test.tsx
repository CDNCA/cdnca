import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { nodesApi } from '../api/nodes'
import { ApiError } from '../api/auth'
import { renderWithProviders } from '../test/render'
import i18n from '../i18n'
import './NodeListPage.locale'
import NodeInstallCommand, { buildNodeInstallCommand } from './NodeInstallCommand'

const upgradeTrust = { __CDNCA_NODE_UPGRADE_TRUST_SHA256__: 'cd'.repeat(32) }
const credential = (suffix = 'A') => ({
  key_id: '0123456789abcdef0123456789abcdef', issued_at: '2026-10-14T08:00:00Z',
  credential: `nrk1.${'0123456789abcdef'.repeat(2)}.${suffix.repeat(43)}`,
})

function setup() {
  Object.assign(window, upgradeTrust)
  const user = userEvent.setup()
  const clipboard = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue()
  const getAccessToken = vi.fn((): string | null => 'fixture-access')
  const create = vi.spyOn(nodesApi, 'create')
  const issue = vi.spyOn(nodesApi, 'issueEnrollmentToken')
  const get = vi.spyOn(nodesApi, 'getRegistrationCredential').mockResolvedValue(credential())
  const reset = vi.spyOn(nodesApi, 'resetRegistrationCredential').mockResolvedValue(credential('B'))
  const view = renderWithProviders(<NodeInstallCommand getAccessToken={getAccessToken} errorText={(error) => error.code || 'failure'} />)
  return { user, clipboard, getAccessToken, create, issue, get, reset, view }
}

const commandBox = () => screen.findByRole('textbox', { name: '节点安装命令' }) as Promise<HTMLTextAreaElement>

describe('reusable node installation command', () => {
  it('shows the same registration command for every node and copying creates nothing', async () => {
    const { user, create, issue, get, clipboard } = setup()
    expect((await commandBox()).value).toContain(`printf '%s\\n' '${credential().credential}' | bash "$f"`)
    await user.click(await screen.findByRole('button', { name: '复制安装命令' }))
    await user.click(screen.getByRole('button', { name: '已复制，再次复制' }))
    expect(clipboard).toHaveBeenCalledTimes(2)
    expect(clipboard.mock.calls[0][0]).toBe(clipboard.mock.calls[1][0])
    expect(get).toHaveBeenCalledOnce()
    expect(create).not.toHaveBeenCalled()
    expect(issue).not.toHaveBeenCalled()
    expect(screen.getByText(i18n.t('nodes:install.reserveDescription'))).toBeInTheDocument()
  })

  it('resets the credential only after confirmation and shows the new command', async () => {
    const { user, reset } = setup()
    await commandBox()
    await user.click(screen.getByRole('button', { name: '重置注册凭据' }))
    expect(await screen.findByText(i18n.t('nodes:install.resetConfirm'))).toBeInTheDocument()
    expect(reset).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '确认重置' }))
    await waitFor(() => expect(reset).toHaveBeenCalledWith('fixture-access'))
    await waitFor(async () => expect((await commandBox()).value).toContain('B'.repeat(43)))
    expect((await commandBox()).value).not.toContain('A'.repeat(43))
  })

  it('keeps the command for manual copy if clipboard permission fails', async () => {
    const { user, clipboard } = setup()
    clipboard.mockRejectedValueOnce(new Error('clipboard denied'))
    await commandBox()
    await user.click(await screen.findByRole('button', { name: '复制安装命令' }))
    expect(await screen.findByText('自动复制失败，请手动复制上方命令。')).toBeInTheDocument()
    expect((await commandBox()).value).toContain(credential().credential)
  })

  it('shows the permission error and disables copy and reset after a 403', async () => {
    const { get, clipboard } = setup()
    get.mockReset().mockRejectedValue(new ApiError('denied', 403, 'permission_denied'))
    renderWithProviders(<NodeInstallCommand getAccessToken={() => 'other-access'} errorText={(error) => error.code} />)
    expect(await screen.findByText('permission_denied')).toBeInTheDocument()
    const copies = screen.getAllByRole('button', { name: '复制安装命令' })
    expect(copies[copies.length - 1]).toBeDisabled()
    expect(clipboard).not.toHaveBeenCalled()
  })

  it('does not show a late credential after the session ends', async () => {
    Object.assign(window, upgradeTrust)
    let finish!: (value: ReturnType<typeof credential>) => void
    vi.spyOn(nodesApi, 'getRegistrationCredential').mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const getAccessToken = vi.fn((): string | null => 'fixture-access')
    renderWithProviders(<NodeInstallCommand getAccessToken={getAccessToken} errorText={(error) => error.code} />)
    getAccessToken.mockReturnValue(null)
    await act(async () => finish(credential()))
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  })

  it('refuses a malformed credential response', async () => {
    const { get } = setup()
    get.mockReset().mockResolvedValue({ ...credential(), credential: "nrk1.x'; id" })
    renderWithProviders(<NodeInstallCommand getAccessToken={() => 'other-access'} errorText={(error) => error.code} />)
    expect(await screen.findByText(i18n.t('nodes:install.unavailable'))).toBeInTheDocument()
  })

  it('builds an HTTPS-only command that downloads, checks and then runs the console installer with the registration key on stdin', () => {
    expect(buildNodeInstallCommand(credential().credential, 'https://control.example:8443', upgradeTrust)).toBe(
      `(f=$(mktemp) || exit 1; trap 'rc=$?; rm -f "$f"; exit $rc' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; { curl --proto '=https' --proto-redir '=https' -fsSL -o "$f" 'https://control.example:8443/downloads/install-node.sh'; } || { rc=$?; echo '[cdnca-edge] error: 无法下载安装脚本' >&2; exit $rc; }; { [ "$(head -c 2 "$f")" = '#!' ] && [ "$(tail -n 1 "$f")" = 'main "$@"' ]; } || { echo '[cdnca-edge] error: 下载的安装脚本为空或不完整' >&2; exit 1; }; printf '%s\\n' '${credential().credential}' | bash "$f" --control-plane 'https://control.example:8443' --registration-key-stdin)`)
  })

  // a Chinese console UI passes --lang zh explicitly (stock Ubuntu LANG=C.UTF-8 would pick English).
  it('appends --lang zh for a Chinese and --lang en for an English console UI', () => {
    const plain = buildNodeInstallCommand(credential().credential, 'https://control.example', upgradeTrust)
    const zh = buildNodeInstallCommand(credential().credential, 'https://control.example', upgradeTrust, 'zh-CN')
    expect(zh).toBe(plain.replace('--registration-key-stdin)', '--registration-key-stdin --lang zh)'))
    expect(buildNodeInstallCommand(credential().credential, 'https://control.example', upgradeTrust, 'zh-TW')).toBe(zh)
    expect(buildNodeInstallCommand(credential().credential, 'https://control.example', upgradeTrust, 'en-US'))
      .toBe(zh.replace('--registration-key-stdin --lang zh)', '--registration-key-stdin --lang en)').replace('无法下载安装脚本', 'cannot download the installer').replace('下载的安装脚本为空或不完整', 'the downloaded installer is empty or incomplete'))
  })

  it.each(['https://evil.example/$(id)', 'https://name:password@control.example', 'http://control.example', 'https://control.example?x=1'])('rejects unsafe command origin %s', (origin) => {
    expect(() => buildNodeInstallCommand(credential().credential, origin, upgradeTrust)).toThrow()
  })

  it.each(['fixture-one-time-secret', `nrk1.${'0'.repeat(32)}.${'A'.repeat(42)}'`, `nrk1.${'G'.repeat(32)}.${'A'.repeat(43)}`])('rejects an invalid registration credential %s', (value) => {
    expect(() => buildNodeInstallCommand(value, 'https://control.example', upgradeTrust)).toThrow()
  })

  // a console on the installer-generated self-signed root publishes its digest.
  it('pins the published management root for a self-signed console and passes it to the installer', () => {
    const digest = 'ef'.repeat(32)
    const pinned = buildNodeInstallCommand(credential().credential, 'https://198.51.100.126', { ...upgradeTrust, __CDNCA_CONTROL_CA_SHA256__: digest })
    expect(pinned).toContain(`curl --proto '=https' --proto-redir '=https' -k -fsSL --max-filesize 65536 -o "$a" 'https://198.51.100.126/downloads/gateway-ca.pem'`)
    expect(pinned).toContain(`[ "$(sha256sum "$a" | cut -d ' ' -f 1)" = '${digest}' ]`)
    expect(pinned).toContain(`--cacert "$a" -fsSL -o "$f" 'https://198.51.100.126/downloads/install-node.sh'`)
    expect(pinned).toContain(`--registration-key-stdin --control-plane-ca-file "$a" --control-plane-ca-sha256 '${digest}')`)
    expect(pinned).not.toContain('--cacert "$a" -k')
    // A publicly trusted console (empty digest) keeps the plain command.
    expect(buildNodeInstallCommand(credential().credential, 'https://control.example', { ...upgradeTrust, __CDNCA_CONTROL_CA_SHA256__: '' }))
      .toBe(buildNodeInstallCommand(credential().credential, 'https://control.example', upgradeTrust))
    const english = buildNodeInstallCommand(credential().credential, 'https://198.51.100.126', { ...upgradeTrust, __CDNCA_CONTROL_CA_SHA256__: digest }, 'en-US')
    expect(english).toContain('cannot download the management root CA or its fingerprint does not match')
    expect(english).not.toMatch(/[\u4e00-\u9fff]/)
    expect(english).toMatch(/--control-plane-ca-sha256 '[0-9a-f]{64}' --lang en\)$/)
  })

  it.each(['AB'.repeat(32), 'ab'.repeat(31), `${'ab'.repeat(32)}'; id`])('refuses a malformed management root digest (%s)', (digest) => {
    expect(() => buildNodeInstallCommand(credential().credential, 'https://control.example', { ...upgradeTrust, __CDNCA_CONTROL_CA_SHA256__: digest })).toThrow()
  })

  it.each([undefined, '', 'AB'.repeat(32), 'ab'.repeat(31), `${'ab'.repeat(32)}'; id`])('refuses to build a command without published upgrade trust (%s)', (digest) => {
    expect(() => buildNodeInstallCommand(credential().credential, 'https://control.example', { __CDNCA_NODE_UPGRADE_TRUST_SHA256__: digest })).toThrow()
  })
})
