import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiError, type Principal } from '../api/auth'
import {
  errorPageSlotKeys,
  errorPagesApi,
  type ErrorPageAsset,
  type ErrorPageSlotBinding,
  type ErrorPageSlotDocument,
  type ErrorPageScopeOverride,
} from '../api/errorPages'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import ErrorPagesPage from '../pages/ErrorPagesPage'
import { authResponse, nodeManagementSettingsFixture } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const platformScopeID = '22222222-2222-4222-8222-222222222222'
const assetID = '11111111-1111-4111-8111-111111111111'
const nodeID = '99999999-9999-4999-8999-999999999999'
const now = '2026-09-15T00:00:00Z'

const asset: ErrorPageAsset = {
  id: assetID,
  scope_id: platformScopeID,
  name: '',
  mime_type: 'text/html',
  size_bytes: 31,
  sha256: 'a'.repeat(64),
  status: 'ready',
  scan_status: 'passed',
  revision: 2,
  created_by: '44444444-4444-4444-8444-444444444444',
  created_at: now,
  updated_at: now,
}

const node: NodeInventoryItem = {
  id: nodeID,
  display_id: '41',
  name: '节点A',
  description: '',
  region: '华东',
  ipv4: '192.0.2.41',
  management_settings: nodeManagementSettingsFixture(),
  admin_state: 'active',
  revision: 3,
  created_at: now,
  updated_at: now,
  presence: {
    status: 'online',
    projection_freshness: 'fresh',
    lease_signal: 'present',
    last_heartbeat_at: now,
  },
}

const override: ErrorPageScopeOverride = {
  display_id: '17',
  target: { kind: 'node', node_display_id: '41', node_name: '节点A', node_ip: '192.0.2.41' },
  items: [{ key: 'http_400' }],
  revision: 3,
  updated_at: now,
}

const emptySlotPage = {
  items: errorPageSlotKeys.map((key): ErrorPageSlotBinding => ({ key, revision: 0 })),
}

function actor(overrides: Partial<Principal> = {}): Principal {
  return {
    user_id: '66666666-6666-4666-8666-666666666666',
    scope_id: platformScopeID,
    scope_kind: 'platform',
    tenant_id: null,
    username: 'admin',
    display_name: 'Admin',
    roles: ['platform_admin'],
    permissions: ['error_pages.read', 'error_pages.manage', 'nodes.read'],
    ...overrides,
  }
}

function authenticate(current = actor(), token = 'error-token') {
  useSessionStore.getState().setSession({ ...authResponse(current), access_token: token }, current, 'new')
}

async function openRegional(user = userEvent.setup()) {
  await user.click(screen.getByRole('tab', { name: '区域及节点配置' }))
  return user
}

async function openCreateDialog(user = userEvent.setup()) {
  await openRegional(user)
  await user.click(screen.getByRole('button', { name: '新增设置' }))
  return screen.findByRole('dialog', { name: '新增设置' })
}

async function selectOption(combobox: HTMLElement, option: string) {
  fireEvent.mouseDown(combobox)
  await userEvent.setup().click(await screen.findByText(option, { selector: '.ant-select-item-option-content' }))
}

describe('ErrorPagesPage', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh-CN')
    vi.restoreAllMocks()
    authenticate()
    vi.spyOn(errorPagesApi, 'listScopeOverrides').mockResolvedValue({ items: [], total: 0 })
    vi.spyOn(errorPagesApi, 'listSlots').mockResolvedValue(emptySlotPage)
    vi.spyOn(errorPagesApi, 'getSlot').mockImplementation(async (_token, key): Promise<ErrorPageSlotDocument> => ({
      binding: { key, revision: 0 }, content: `<html>builtin ${key}</html>`, source: 'builtin', delivery: 'theme',
    }))
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] })
    vi.spyOn(errorPagesApi, 'initiateAsset').mockResolvedValue({ value: asset, replayed: false })
    vi.spyOn(errorPagesApi, 'uploadAssetContent').mockResolvedValue({ value: asset, replayed: false })
    vi.spyOn(errorPagesApi, 'finalizeAsset').mockResolvedValue({ value: asset, replayed: false })
    vi.spyOn(errorPagesApi, 'bindSlot').mockResolvedValue({ value: { key: 'blacklist', asset_id: assetID, revision: 1 }, replayed: false })
    vi.spyOn(errorPagesApi, 'createScopeOverride').mockResolvedValue({ value: override, replayed: false })
    vi.spyOn(errorPagesApi, 'updateScopeOverride').mockResolvedValue({ value: override, replayed: false })
    vi.spyOn(errorPagesApi, 'deleteScopeOverride').mockResolvedValue({ value: { ...override, deleted: true }, replayed: false })
  })

  it('denies access without error_pages.read and makes no scoped request', async () => {
    authenticate(actor({ permissions: [] }))
    renderWithProviders(<ErrorPagesPage />)

    expect(await screen.findByText('无权查看错误页面')).toBeInTheDocument()
    expect(errorPagesApi.listScopeOverrides).not.toHaveBeenCalled()
  })

  it('matches the observed global first view and keeps the regional workflow available', async () => {
    renderWithProviders(<ErrorPagesPage />)

    expect(await screen.findByRole('tab', { name: '全局配置' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: '区域及节点配置' })).toBeInTheDocument()
    expect(screen.getAllByRole('radio')).toHaveLength(12)
    expect(screen.getByRole('radio', { name: '拉黑页面' })).toBeChecked()
    // errpage-content: the page in effect, not an empty "not configured" editor.
    await waitFor(() => expect(screen.getByLabelText('页面内容')).toHaveValue('<html>builtin blacklist</html>'))
    expect(screen.getByTestId('error-page-global-status')).toHaveTextContent('系统默认（未修改）')
    expect(screen.queryByText('尚未配置')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '恢复系统默认' })).not.toBeInTheDocument()
    expect(errorPagesApi.listSlots).toHaveBeenCalledWith('error-token')
    expect(errorPagesApi.listScopeOverrides).not.toHaveBeenCalled()
  })

  it('loads and saves a real global slot through the asset and binding contracts', async () => {
    vi.mocked(errorPagesApi.getSlot).mockResolvedValue({
      binding: { key: 'blacklist', asset_id: assetID, revision: 2 },
      content: '<html>old</html>', source: 'override', delivery: 'theme',
    })
    vi.mocked(errorPagesApi.bindSlot).mockResolvedValue({
      value: { key: 'blacklist', asset_id: assetID, revision: 3, publication: { revision: 7, queued_scopes: 2 } }, replayed: false,
    })
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)

    const content = await screen.findByRole('textbox', { name: '页面内容' })
    await waitFor(() => expect(content).toBeEnabled())
    await user.clear(content)
    await user.type(content, '<html>new global</html>')
    await user.click(screen.getByRole('button', { name: '保存' }))

    await waitFor(() => expect(errorPagesApi.initiateAsset).toHaveBeenCalledWith(
      'error-token', platformScopeID, 'text/html', 23, expect.stringMatching(/^[0-9a-f]{64}$/),
      expect.stringMatching(/^error-page-blacklist-initiate-/),
    ))
    expect(errorPagesApi.bindSlot).toHaveBeenCalledWith(
      'error-token', 'blacklist', assetID, 2, expect.stringMatching(/^error-page-blacklist-bind-/),
    )
    expect(await screen.findByText('已保存，正在发布：错误页发布修订 7，已为 2 个租户排队重新发布。')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '查看发布记录' })).toHaveAttribute('href', '/site/publications')
  })

  // A3-10: template markers are refused before any upload (the server rejects them anyway).
  it('refuses template markers before uploading a global page', async () => {
    vi.mocked(errorPagesApi.getSlot).mockResolvedValue({
      binding: { key: 'blacklist', asset_id: assetID, revision: 2 },
      content: '<html>old</html>', source: 'override', delivery: 'theme',
    })
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const content = await screen.findByRole('textbox', { name: '页面内容' })
    await waitFor(() => expect(content).toBeEnabled())
    for (const [body, marker, line, column] of [['<h1>{{ip}}</h1>', '{{', 1, 5], ['<p>${host}</p>', '${', 1, 4], ['<p>ok</p>\n  <% x %>', '<%', 2, 3]] as const) {
      fireEvent.change(content, { target: { value: body } })
      await user.click(screen.getByRole('button', { name: '保存' }))
      // 字段校验：就地指出位置，编辑器标记为无效
      const alert = await screen.findByText(`第 ${line} 行第 ${column} 列含模板标记「${marker}」，节点不做变量替换，请删除后再保存`)
      expect(alert).toHaveAttribute('role', 'alert')
      expect(content).toHaveAttribute('aria-invalid', 'true')
      expect(content).toHaveAttribute('aria-describedby', alert.id)
      // 保存被拒后焦点回到内容框
      await waitFor(() => expect(content).toHaveFocus())
    }
    // 空内容同样就地标在内容框上并聚焦，不弹「知道了」
    fireEvent.change(content, { target: { value: '' } })
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText('请输入页面内容后再保存')).toHaveAttribute('role', 'alert')
    expect(content).toHaveAttribute('aria-invalid', 'true')
    await waitFor(() => expect(content).toHaveFocus())
    expect(document.querySelector('.cdnca-feedback')).toBeNull()
    fireEvent.change(content, { target: { value: '<p>clean</p>' } })
    // 改动内容即清掉字段错误（投放说明的提示框不属于校验错误，照常显示）
    expect(screen.queryByText(/含模板标记/)).not.toBeInTheDocument()
    expect(content).not.toHaveAttribute('aria-invalid')
    expect(content).not.toHaveAttribute('aria-describedby')
    expect(errorPagesApi.initiateAsset).not.toHaveBeenCalled()
  })

  // 切换错误类型与外层页签都保留草稿，回读不覆盖
  it('keeps the draft of each error type across type and tab switches', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const content = await screen.findByRole('textbox', { name: '页面内容' })
    await waitFor(() => expect(content).toHaveValue('<html>builtin blacklist</html>'))
    fireEvent.change(content, { target: { value: '<html>my draft</html>' } })
    expect(screen.getByRole('radio', { name: /^拉黑页面\s*未保存$/ })).toBeChecked()

    fireEvent.click(screen.getByRole('radio', { name: '400错误' }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: '页面内容' })).toHaveValue('<html>builtin http_400</html>'))
    fireEvent.click(screen.getByRole('radio', { name: /^拉黑页面\s*未保存$/ }))
    await waitFor(() => expect(screen.getByRole('textbox', { name: '页面内容' })).toHaveValue('<html>my draft</html>'))
    expect(errorPagesApi.getSlot).toHaveBeenCalledWith('error-token', 'http_400')

    await openRegional(user)
    await user.click(screen.getByRole('tab', { name: '全局配置' }))
    expect(screen.getByRole('textbox', { name: '页面内容' })).toHaveValue('<html>my draft</html>')
    expect(screen.getByRole('radio', { name: /^拉黑页面\s*未保存$/ })).toBeChecked()

    // 有草稿时不写「系统默认（未修改）」
    expect(screen.getByTestId('error-page-global-status')).not.toHaveTextContent('系统默认（未修改）')

    // 改回服务端内容即视为未改动，来源标签按已保存来源恢复
    fireEvent.change(screen.getByRole('textbox', { name: '页面内容' }), { target: { value: '<html>builtin blacklist</html>' } })
    expect(screen.getByRole('radio', { name: '拉黑页面' })).toBeChecked()
    expect(screen.getByTestId('error-page-global-status')).toHaveTextContent('系统默认（未修改）')
  })

  // 
  it('renders each panel inside its tabpanel with a single empty state and no row selection', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const globalTab = await screen.findByRole('tab', { name: '全局配置' })
    const globalPanel = document.getElementById(globalTab.getAttribute('aria-controls')!)!
    expect(globalPanel).toHaveAttribute('role', 'tabpanel')
    expect(within(globalPanel).getByRole('textbox', { name: '页面内容' })).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('可用变量')

    await openRegional(user)
    const regionalTab = screen.getByRole('tab', { name: '区域及节点配置' })
    const regionalPanel = document.getElementById(regionalTab.getAttribute('aria-controls')!)!
    expect(regionalPanel).toHaveAttribute('role', 'tabpanel')
    expect(await within(regionalPanel).findByText('暂无区域或节点覆盖')).toBeInTheDocument()
    expect(within(regionalPanel).getByRole('table')).toBeInTheDocument()
    expect(within(regionalPanel).getByRole('button', { name: '新增设置' })).toBeInTheDocument()
    expect(within(regionalPanel).queryByRole('checkbox')).not.toBeInTheDocument()
    expect(regionalPanel).not.toHaveTextContent('覆盖配置 0 项')
    expect(regionalPanel).not.toHaveTextContent('暂无数据')
  })

  it('restores the system default by unbinding the override with its revision', async () => {
    vi.mocked(errorPagesApi.getSlot).mockResolvedValue({
      binding: { key: 'blacklist', asset_id: assetID, revision: 4 }, content: '<html>mine</html>', source: 'override', delivery: 'none',
    })
    const unbind = vi.spyOn(errorPagesApi, 'unbindSlot').mockResolvedValue({ value: { key: 'blacklist', revision: 5 }, replayed: false })
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)

    expect(await screen.findByText('未保存时，节点对被拉黑的 IP 返回 403 纯文本 “Forbidden”；保存后返回这里的页面。')).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: '恢复系统默认' }))
    await user.click(await screen.findByRole('button', { name: '确定' }))
    await waitFor(() => expect(unbind).toHaveBeenCalledWith('error-token', 'blacklist', 4, expect.stringMatching(/^error-page-blacklist-unbind-/)))
  })

  // errpage-4: what the node answers for its own pages while unsaved, the
  // site lock page that nodes never serve, and the expiry_close condition.
  it('words the node fallback, the site lock page and the package expiry condition', async () => {
    renderWithProviders(<ErrorPagesPage />)

    expect(await screen.findByText('未保存时，节点对被拉黑的 IP 返回 403 纯文本 “Forbidden”；保存后返回这里的页面。')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '站点锁定' }))
    expect(await screen.findByText('站点锁定不影响访问，此页暂不会被节点返回。保存只会存储内容。')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '套餐到期' }))
    expect(await screen.findByText(/仅在系统设置开启“套餐到期关闭网站”时生效/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '连接数超限' }))
    expect(await screen.findByText(/返回 nginx 默认的 503 页面/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '400错误' }))
    expect(await screen.findByText(/节点当前使用这份内容/)).toBeInTheDocument()
  })

  it('previews the draft in a script-free sandboxed iframe', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)

    await waitFor(() => expect(screen.getByLabelText('页面内容')).toHaveValue('<html>builtin blacklist</html>'))
    await user.click(screen.getByRole('button', { name: '预览' }))
    const frame = await screen.findByTitle('错误页预览')
    expect(frame).toHaveAttribute('sandbox', '')
    expect(frame).toHaveAttribute('srcdoc', '<html>builtin blacklist</html>')
  })

  it('loads the real override collection and renders a retryable localized error', async () => {
    vi.mocked(errorPagesApi.listScopeOverrides)
      .mockRejectedValueOnce(new ApiError('private database detail', 503, 'service_unavailable'))
      .mockResolvedValueOnce({ items: [], total: 0 })
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)

    await openRegional(user)
    expect(await screen.findByText('错误页服务暂不可用，请稍后重试')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private database detail')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无区域或节点覆盖')).toBeInTheDocument()
    expect(errorPagesApi.listScopeOverrides).toHaveBeenCalledTimes(2)
  })

  it('uses a single-choice item adder, hides duplicates, supports removal, and saves the edited value', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const dialog = await openCreateDialog(user)

    await selectOption(within(dialog).getByRole('combobox', { name: '节点选择' }), '41 节点A')
    const itemSelect = within(dialog).getByRole('combobox', { name: '配置项' })
    await selectOption(itemSelect, '400错误')

    expect(within(dialog).getByText('请选择配置项')).toBeInTheDocument()
    expect(within(dialog).getByRole('textbox', { name: '400错误' })).toBeInTheDocument()
    const resetItemSelect = within(dialog).getByRole('combobox', { name: '配置项' })
    fireEvent.mouseDown(resetItemSelect)
    const listbox = await screen.findByRole('listbox')
    expect(within(listbox).queryByRole('option', { name: '400错误' })).not.toBeInTheDocument()
    fireEvent.keyDown(resetItemSelect, { key: 'Escape' })

    await user.click(within(dialog).getByRole('button', { name: '删除400错误配置项' }))
    expect(within(dialog).queryByRole('textbox', { name: '400错误' })).not.toBeInTheDocument()

    await selectOption(within(dialog).getByRole('combobox', { name: '配置项' }), '400错误')
    await user.type(within(dialog).getByRole('textbox', { name: '400错误' }), '<html><body>400</body></html>')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(errorPagesApi.initiateAsset).toHaveBeenCalledWith(
      'error-token', platformScopeID, 'text/html', 29, expect.stringMatching(/^[0-9a-f]{64}$/),
      expect.stringMatching(/^error-page-http_400-initiate-/),
    ))
    expect(errorPagesApi.uploadAssetContent).toHaveBeenCalledWith(
      'error-token', assetID, expect.any(Blob), 'text/html', expect.stringMatching(/^error-page-http_400-upload-/),
    )
    expect(errorPagesApi.finalizeAsset).toHaveBeenCalledWith(
      'error-token', assetID, expect.stringMatching(/^error-page-http_400-finalize-/),
    )
    expect(errorPagesApi.createScopeOverride).toHaveBeenCalledWith(
      'error-token',
      { kind: 'node', node_display_id: '41', region: '' },
      [{ key: 'http_400', asset_id: assetID }],
      expect.stringMatching(/^error-page-override-create-/),
    )
  })

  it('refuses template markers in a regional override before uploading', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const dialog = await openCreateDialog(user)
    await selectOption(within(dialog).getByRole('combobox', { name: '节点选择' }), '41 节点A')
    await selectOption(within(dialog).getByRole('combobox', { name: '配置项' }), '400错误')
    fireEvent.change(within(dialog).getByRole('textbox', { name: '400错误' }), { target: { value: '<h1>{{ip}}</h1>' } })
    await user.click(within(dialog).getByRole('button', { name: '确定' }))
    expect(await within(dialog).findByText('第 1 行第 5 列含模板标记「{{」，节点不做变量替换，请删除后再保存')).toHaveAttribute('role', 'alert')
    expect(within(dialog).getByRole('textbox', { name: '400错误' })).toHaveAttribute('aria-invalid', 'true')
    expect(errorPagesApi.initiateAsset).not.toHaveBeenCalled()
  })

  it('does not list nodes or regions without nodes.read and names the missing permission', async () => {
    authenticate(actor({ permissions: ['error_pages.read', 'error_pages.manage'] }))
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const dialog = await openCreateDialog(user)

    expect(within(dialog).getByText(/nodes\.read/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('radio', { name: '区域' }))
    expect(within(dialog).getByText(/nodes\.read/)).toBeInTheDocument()
    expect(nodesApi.list).not.toHaveBeenCalled()
  })

  it('loads an existing override, uploads changed content, and preserves its revision on update', async () => {
    vi.mocked(errorPagesApi.listScopeOverrides).mockResolvedValue({ items: [override], total: 1 })
    vi.spyOn(errorPagesApi, 'getScopeOverride').mockResolvedValue({
      ...override,
      items: [{ key: 'http_400', content: '<html>old</html>' }],
    })
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)

    await openRegional(user)
    await user.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑设置' })
    const content = await within(dialog).findByRole('textbox', { name: '400错误' })
    await user.clear(content)
    await user.type(content, '<html>new</html>')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(errorPagesApi.updateScopeOverride).toHaveBeenCalledWith(
      'error-token', '17', [{ key: 'http_400', asset_id: assetID }], 3,
      expect.stringMatching(/^error-page-override-update-/),
    ))
  })

  it('retries an outcome-unknown create with the exact frozen write identities', async () => {
    vi.mocked(errorPagesApi.createScopeOverride)
      .mockRejectedValueOnce(new ApiError('private transport detail', 0, 'network_error'))
      .mockResolvedValueOnce({ value: override, replayed: true })
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const dialog = await openCreateDialog(user)

    await selectOption(within(dialog).getByRole('combobox', { name: '节点选择' }), '41 节点A')
    await selectOption(within(dialog).getByRole('combobox', { name: '配置项' }), '400错误')
    await user.type(within(dialog).getByRole('textbox', { name: '400错误' }), '<html>retry</html>')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    expect(await within(dialog).findByText('操作结果尚未确认')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private transport detail')
    const firstCreate = vi.mocked(errorPagesApi.createScopeOverride).mock.calls[0]
    const firstInitiate = vi.mocked(errorPagesApi.initiateAsset).mock.calls[0]
    await user.click(within(dialog).getByRole('button', { name: '按原操作重试' }))

    await waitFor(() => expect(errorPagesApi.createScopeOverride).toHaveBeenCalledTimes(2))
    expect(vi.mocked(errorPagesApi.createScopeOverride).mock.calls[1]).toEqual(firstCreate)
    expect(vi.mocked(errorPagesApi.initiateAsset).mock.calls[1]).toEqual(firstInitiate)
  })

  // 保存进行中不能关；结果未确认时关闭先确认，确认后关闭并刷新列表。
  it('locks closing only while saving and lets an outcome-unknown editor close after a warning, then refreshes', async () => {
    let rejectCreate!: (reason: unknown) => void
    vi.mocked(errorPagesApi.createScopeOverride).mockReturnValueOnce(new Promise((_, reject) => { rejectCreate = reject }))
    const user = userEvent.setup()
    renderWithProviders(<ErrorPagesPage />)
    const dialog = await openCreateDialog(user)
    await selectOption(within(dialog).getByRole('combobox', { name: '节点选择' }), '41 节点A')
    await selectOption(within(dialog).getByRole('combobox', { name: '配置项' }), '400错误')
    await user.type(within(dialog).getByRole('textbox', { name: '400错误' }), '<html>x</html>')
    await user.click(within(dialog).getByRole('button', { name: '确定' }))

    await waitFor(() => expect(errorPagesApi.createScopeOverride).toHaveBeenCalledOnce())
    expect(within(dialog).getByRole('button', { name: '取消' })).toBeDisabled()
    rejectCreate(new ApiError('lost', 0, 'network_error'))
    expect(await within(dialog).findByText('操作结果尚未确认')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '按原操作重试' })).toBeEnabled()
    const cancel = within(dialog).getByRole('button', { name: '取消' })
    expect(cancel).toBeEnabled()

    const reads = vi.mocked(errorPagesApi.listScopeOverrides).mock.calls.length
    await user.click(cancel)
    const confirm = (await screen.findByText('结果尚未确认，关闭后请刷新列表核对是否已生效')).closest<HTMLElement>('.ant-modal-confirm')!
    expect(dialog).toBeInTheDocument()
    await user.click(within(confirm).getByRole('button', { name: '关闭' }))
    await waitFor(() => expect(within(dialog).queryByRole('textbox', { name: '400错误' })).not.toBeInTheDocument())
    await waitFor(() => expect(vi.mocked(errorPagesApi.listScopeOverrides).mock.calls.length).toBeGreaterThan(reads))
  })

  it('removes an override with CAS and hides all writes from a read-only operator', async () => {
    vi.mocked(errorPagesApi.listScopeOverrides).mockResolvedValue({ items: [override], total: 1 })
    const user = userEvent.setup()
    const view = renderWithProviders(<ErrorPagesPage />)
    await openRegional(user)

    await user.click(await screen.findByRole('button', { name: '删除' }))
    await user.click(await screen.findByRole('button', { name: '确定' }))
    await waitFor(() => expect(errorPagesApi.deleteScopeOverride).toHaveBeenCalledWith(
      'error-token', '17', 3, expect.stringMatching(/^error-page-override-delete-/),
    ))

    view.unmount()
    authenticate(actor({ permissions: ['error_pages.read'] }))
    renderWithProviders(<ErrorPagesPage />)
    await openRegional()
    expect(await screen.findByText('节点 41 · 节点A')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增设置' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
  })
})
