import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntApp, ConfigProvider } from 'antd'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, vi } from 'vitest'

import { ApiError } from '../api/auth'
import {
  certificatesApi,
  type CertificateAsset,
	  type CertificateAssetBinding,
  type CertificateAssetDetail,
  type CertificateOrder,
} from '../api/certificates'
import { dnsApi, type DNSProvider } from '../api/dns'
import { sitesApi } from '../api/sites'
import { usersApi, type ManagedUser } from '../api/users'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import CertificateListPage from '../pages/CertificateListPage'
import { samePEMCertificateChain } from '../pages/certificatePEM'
import certificateStyles from '../pages/CertificateListPage.css?raw'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import * as certificateFiles from '../pages/certificateFiles'

// CERT-02 迟到读取：可按用例替换 readPEMFile，其余用例走真实实现。
const readPEMFileOverride = vi.hoisted(() => ({ current: null as null | typeof certificateFiles.readPEMFile }))
vi.mock('../pages/certificateFiles', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../pages/certificateFiles')>()
  return { ...actual, readPEMFile: (...args: Parameters<typeof actual.readPEMFile>) => (readPEMFileOverride.current ?? actual.readPEMFile)(...args) }
})

// antd 在 jsdom 下所有弹窗共用 aria-labelledby="test-id"，常驻的反馈弹窗（useFeedback/OutcomeUnknown）
// 挂在前面时会抢走其他弹窗的可访问名；按可见标题找当前可见的弹窗/抽屉。
const dialogsNamed = (name: string | RegExp) => screen.queryAllByRole('dialog').filter((node) => {
  const title = node.querySelector('.ant-modal-title, .ant-modal-confirm-title, .ant-drawer-title')?.textContent?.trim() ?? ''
  return typeof name === 'string' ? title === name : name.test(title)
})
const queryDialog = (name: string | RegExp) => {
  const found = dialogsNamed(name)
  if (found.length > 1) throw new Error(`multiple dialogs named ${String(name)}`)
  return found[0] ?? null
}
const getDialog = (name: string | RegExp) => {
  const found = queryDialog(name)
  if (!found) throw new Error(`no dialog named ${String(name)}`)
  return found
}
const findDialog = (name: string | RegExp, options?: { timeout?: number }) => waitFor(() => getDialog(name), options)
	import { changeLocale } from '../i18n'

// 到期日相对当前时间：落在 30 天“即将到期”窗口内，不随日期推移而过期。
const expiringNotAfter = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

const activeOrder: CertificateOrder = {
  id: '33333333-3333-4333-8333-333333333333',
  scope_id: '22222222-2222-4222-8222-222222222222',
  domains: ['example.com', 'www.example.com'],
  challenge_type: 'http-01',
  status: 'active',
  auto_renew: true,
  not_after: expiringNotAfter,
  version: 5,
  created_at: '2026-07-22T12:00:00Z',
  updated_at: '2026-07-22T12:00:00Z',
}

const failedOrder: CertificateOrder = {
  ...activeOrder,
  id: '44444444-4444-4444-8444-444444444444',
  domains: ['failed.example.net'],
  challenge_type: 'dns-01',
  status: 'failed',
  auto_renew: false,
  not_after: undefined,
  failure_code: 'dns_propagation_timeout',
}

const provider: DNSProvider = {
  id: '55555555-5555-4555-8555-555555555555',
  scope_id: '22222222-2222-4222-8222-222222222222',
  name: 'Cloudflare primary',
  provider_type: 'cloudflare',
  credentials_configured: true,
  status: 'verified',
  version: 2,
  created_at: '2026-07-22T12:00:00Z',
  updated_at: '2026-07-22T12:00:00Z',
}

const asset: CertificateAsset = {
  id: '66666666-6666-4666-8666-666666666666',
  display_id: '1',
  tenant: { id: '12121212-1212-4212-8212-121212121212', display_id: '9', name: '租户一' },
  owner: { id: '17171717-1717-4717-8717-171717171717', display_id: '17', username: 'target-admin', display_name: '目标管理员' },
  owner_status: 'recorded',
  tenant_scope_id: '22222222-2222-4222-8222-222222222222',
  name: '边缘站点证书', source: 'uploaded', revision: 3,
  created_by: '11111111-1111-4111-8111-111111111111',
  updated_by: '11111111-1111-4111-8111-111111111111',
  created_at: '2026-07-22T12:00:00Z', updated_at: '2026-07-22T12:00:00Z',
}

const assetDetail: CertificateAssetDetail = {
  asset,
  versions: [{
    id: '77777777-7777-4777-8777-777777777777', asset_id: asset.id,
    tenant_scope_id: asset.tenant_scope_id, version: 1, status: 'active',
    fingerprint_sha256: 'ab'.repeat(32), certificate_pem: 'PUBLIC-PEM', sans: ['example.com'],
    subject: 'CN=example.com', serial_number: '123', public_key_algorithm: 'RSA', public_key_bits: 2048,
    signature_algorithm: 'SHA256-RSA', not_before: '2026-07-22T12:00:00Z', not_after: expiringNotAfter,
    renewal_due: false, imported_by: '11111111-1111-4111-8111-111111111111', imported_at: '2026-07-22T12:00:00Z',
  }],
}

const managedTarget: ManagedUser = {
  id: '17171717-1717-4717-8717-171717171717',
  display_id: '17',
  scope_id: asset.tenant_scope_id,
  tenant_id: asset.tenant.id,
  username: 'target-admin',
  display_name: '目标管理员',
  email: 'target@example.com',
  phone: null,
  status: 'active',
  role: 'tenant_owner',
  group_id: null,
  group_name: null,
  revision: 1,
  created_at: '2026-07-22T12:00:00Z',
  updated_at: '2026-07-22T12:00:00Z',
}

const pendingVersion = {
	...assetDetail.versions[0],
	id: '88888888-8888-4888-8888-888888888888',
	version: 2,
	status: 'pending_activation' as const,
}

const binding: CertificateAssetBinding = {
	tenant_scope_id: asset.tenant_scope_id,
	site_id: '99999999-9999-4999-8999-999999999999',
	asset_id: asset.id,
	version_id: assetDetail.versions[0].id,
	revision: 1,
	default: true,
	bound: true,
	changed_by: asset.updated_by,
	changed_at: asset.updated_at,
}

// CERT-04：上传走统一“添加证书”弹窗的“自己上传”类型
async function openUpload(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: '添加证书' }))
  await user.click(within(await findDialog('添加证书')).getByRole('button', { name: /自己上传/ }))
}

// 删除/下载/禁用等单张操作在行内“更多”菜单里。
async function rowAction(user: ReturnType<typeof userEvent.setup>, item: string | RegExp, scope: HTMLElement = document.body) {
  await user.click((await within(scope).findAllByRole('button', { name: /的更多操作$/ }))[0])
  await user.click(await screen.findByRole('menuitem', { name: item }))
}

async function openOrderHistory(user: ReturnType<typeof userEvent.setup>, more: string | RegExp = '更多操作', item: string | RegExp = '申请记录') {
  // The toolbar 更多操作 comes first; rows have their own.
  await user.click((await screen.findAllByRole('button', { name: more }))[0])
  await user.click(await screen.findByRole('menuitem', { name: item }))
}

function authenticate(permissions = ['certificates.read', 'certificates.manage', 'dns.read']) {
  const user = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function tenantSession(
  token: string,
  permissions = ['certificates.read', 'certificates.manage', 'dns.read'],
  update: 'new' | 'refresh' = 'new',
  scopeID = '22222222-2222-4222-8222-222222222222',
  userID = '11111111-1111-4111-8111-111111111111',
) {
  const actor = principal({
    user_id: userID,
    scope_id: scopeID,
    tenant_id: scopeID,
    scope_kind: 'tenant',
    permissions,
  })
  useSessionStore.getState().setSession(
    { ...authResponse(actor), access_token: token },
    actor,
    update,
  )
  return { actor, epoch: useSessionStore.getState().sessionEpoch }
}

function platformSession(
  token = 'platform-certificate-token',
  permissions = ['certificates.read', 'certificates.manage', 'identity.users.manage', 'dns.read', 'dns.manage'],
) {
  const actor = principal({
    scope_kind: 'platform',
    tenant_id: null,
    roles: ['platform_admin'],
    permissions,
  })
  useSessionStore.getState().setSession({ ...authResponse(actor), access_token: token }, actor)
  return actor
}

function certificateHeadingStyle(heading: HTMLElement) {
  const sheet = document.createElement('style')
  sheet.textContent = certificateStyles
  document.head.append(sheet)
  const rule = [...sheet.sheet!.cssRules]
    .filter((item): item is CSSStyleRule => 'selectorText' in item)
    .find((item) => heading.matches(item.selectorText) && item.style.getPropertyValue('position') === 'absolute')
  sheet.remove()
  return rule
}

function ownerTuple(actor: ReturnType<typeof principal>, epoch: number) {
  return [actor.scope_kind, actor.scope_id, actor.tenant_id, actor.user_id, epoch] as const
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function renderCertificatesWithQueryClient(queryClient: QueryClient) {
  return render(
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/site/cert']}><CertificateListPage /></MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>,
  )
}

function allCertificateApiSpies() {
  return [
    vi.spyOn(certificatesApi, 'list'),
    vi.spyOn(certificatesApi, 'create'),
    vi.spyOn(certificatesApi, 'listAssets'),
    vi.spyOn(certificatesApi, 'getAsset'),
    vi.spyOn(certificatesApi, 'uploadAsset'),
    vi.spyOn(certificatesApi, 'activateAssetVersion'),
    vi.spyOn(certificatesApi, 'listAssetBindings'),
    vi.spyOn(certificatesApi, 'bindAsset'),
    vi.spyOn(certificatesApi, 'unbindAsset'),
    vi.spyOn(certificatesApi, 'deleteAsset'),
    vi.spyOn(dnsApi, 'list'),
  ]
}

async function chooseCertificatePageSize(user: ReturnType<typeof userEvent.setup>, value: string) {
  const selector = document.querySelector<HTMLElement>('.identity-pagination .ant-select-selector')
  if (!selector) throw new Error('certificate page-size selector not found')
  await user.click(selector)
  const option = await waitFor(() => {
    const candidate = [...document.querySelectorAll<HTMLElement>('.ant-select-item-option')]
      .find((item) => item.textContent?.trim().startsWith(value))
    if (!candidate) throw new Error(`certificate page-size option not found: ${value}`)
    return candidate
  })
  await user.click(option)
}

// 高级筛选展开状态记在 localStorage，各用例从收起开始。
beforeEach(() => { localStorage.removeItem('cdnca.advancedFilters.certificate-list') })

describe('CertificateListPage', () => {
  // CERT-05：同步状态等高级筛选全部由服务端执行（列表、总数一致），前端不再逐条拉发布回执推断。
  it('sends every advanced filter to the server and reads no publication receipts', async () => {
    authenticate(['certificates.read', 'sites.read'])
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 26, counts: { all: 26, normal: 0, expiring: 26, expired: 0, auto_renew: 0, manual_renew: 26 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const statuses = vi.spyOn(certificatesApi, 'getPublicationStatus')
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText('边缘站点证书')
    await user.click(screen.getByRole('button', { name: '高级筛选' }))
    const filter = screen.getByRole('group', { name: '高级筛选' })
    const choose = async (field: string, option: string) => {
      await user.click(within(within(filter).getByText(field).parentElement!).getByRole('combobox'))
      await user.click(await screen.findByText(option))
    }
    await user.type(within(filter).getByPlaceholderText('一行一个域名，精确搜索'), 'a.example.com')
    await user.type(within(filter).getByPlaceholderText('输入ID、邮箱、用户名、手机号搜索'), 'user@example.com')
    await choose('同步状态', '当前绑定发布失败')
    await choose('到期时间', '90天内到期')
    // CERT-05/06：此项筛的是自动续签（auto_renew），不是证书启用/禁用
    await choose('自动续签', '关闭')
    await choose('签发状态', '签发失败')
    await choose('证书类型', '自动申请')
    expect(within(filter).queryByText('发布状态未知')).not.toBeInTheDocument()
    await user.click(within(filter).getByRole('button', { name: '应用' }))
    await waitFor(() => expect(certificatesApi.listAssets).toHaveBeenLastCalledWith(expect.any(String), undefined, expect.objectContaining({
      page: 1,
      filters: expect.objectContaining({ domains: ['a.example.com'], user: 'user@example.com', sync: 'failed', expiry: 'within90', auto_renew: false, issue: 'failed', source: 'acme' }),
    })))
    // 已启用 7 项显示在按钮徽标与可关闭标签；去掉一项即重查，清空高级条件去掉全部。
    expect(screen.getByRole('button', { name: '高级筛选 · 7' })).toBeInTheDocument()
    const tags = screen.getByRole('list', { name: '已启用的高级条件' })
    expect(within(tags).getByText('签发状态：签发失败')).toBeInTheDocument()
    await user.click(within(tags).getByRole('button', { name: '移除条件 签发状态' }))
    await waitFor(() => expect(vi.mocked(certificatesApi.listAssets).mock.lastCall?.[2]?.filters?.issue).toBeUndefined())
    expect(vi.mocked(certificatesApi.listAssets).mock.lastCall?.[2]?.filters).toEqual(expect.objectContaining({ source: 'acme', user: 'user@example.com' }))
    await user.click(within(filter).getByRole('button', { name: '清空高级条件' }))
    await waitFor(() => expect(vi.mocked(certificatesApi.listAssets).mock.lastCall?.[2]?.filters?.source).toBeUndefined())
    expect(screen.getByRole('button', { name: '高级筛选' })).toBeInTheDocument()
    expect(screen.getByText('共 26 条')).toBeInTheDocument()
    expect(statuses).not.toHaveBeenCalled()
  })

  it('reads platform certificates across tenants without a mandatory user selection', async () => {
    platformSession()
    const listUsers = vi.spyOn(usersApi, 'list').mockRejectedValue(new ApiError('denied', 403, 'permission_denied'))
    const listAssets = vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
    expect(listAssets).toHaveBeenCalledWith('platform-certificate-token', undefined, { page: 1, limit: 10, search: '', status: undefined })
    expect(listUsers).not.toHaveBeenCalled()
    expect(screen.queryByRole('combobox', { name: '目标用户' })).not.toBeInTheDocument()
  })

  it('accepts a tenant identity distinct from its access scope', async () => {
    const actor = principal({ tenant_id: '12121212-1212-4212-8212-121212121212', permissions: ['certificates.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
  })

  it('renders real owners and tenants for duplicate tenant-local certificate IDs without guessing legacy ownership', async () => {
    platformSession()
    const other: CertificateAsset = { ...asset, id: '88888888-8888-4888-8888-888888888888', tenant_scope_id: '99999999-9999-4999-8999-999999999999', tenant: { id: '34343434-3434-4343-8343-343434343434', display_id: '10', name: '租户二' }, owner: null, owner_status: 'legacy_unknown', name: '历史证书' }
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset, other], total: 2, counts: { all: 2, normal: 0, expiring: 2, expired: 0, auto_renew: 0, manual_renew: 2 } })
    vi.spyOn(certificatesApi, 'getAsset').mockImplementation(async (_token, id) => ({ asset: id === asset.id ? asset : other, versions: [] }))
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const first = (await screen.findByText('边缘站点证书')).closest('tr')!
    const second = screen.getByText('历史证书').closest('tr')!
    expect(first).toHaveTextContent('target-admin')
    expect(first).toHaveTextContent('租户一（租户 9）')
    // 无法确定所属用户时显示"未指定用户"，悬浮说明原因。
    expect(second).toHaveTextContent('未指定用户')
    expect(second).not.toHaveTextContent('历史归属未记录')
    expect(within(second).getByText('未指定用户').closest('[title]')).toHaveAttribute('title', '无法确定该证书所属的用户（下单人不是该租户成员，且租户没有唯一的所属用户）')
    expect(second).toHaveTextContent('租户二（租户 10）')
    expect(within(first).getByText('1')).toBeInTheDocument()
    expect(within(second).getByText('1')).toBeInTheDocument()
    expect(first).not.toHaveTextContent(asset.created_by)
    expect(second).not.toHaveTextContent('target-admin')
  })

  it('requires an explicit upload owner and freezes scope, owner and body for uncertain retries', async () => {
    platformSession()
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget], page: 1, limit: 100, total: 1 })
    const receipt = { ...assetDetail, asset: { ...asset, name: 'owned certificate' } }
    const upload = vi.spyOn(certificatesApi, 'uploadAsset').mockRejectedValueOnce(new ApiError('disconnected', 0, 'network_error')).mockResolvedValueOnce(receipt)
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openUpload(user)
    const dialog = getDialog('添加证书')
    await user.type(within(dialog).getByLabelText('名称'), 'owned certificate')
    await user.type(within(dialog).getByLabelText('证书 PEM'), 'PUBLIC-PEM')
    await user.type(within(dialog).getByLabelText('私钥 PEM'), 'PRIVATE-PEM')
    await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
    expect(await within(dialog).findByText('请选择证书归属用户')).toBeInTheDocument()
    expect(upload).not.toHaveBeenCalled()
    const selector = within(dialog).getByRole('combobox', { name: '归属用户' })
    await user.click(selector)
    await user.click(await screen.findByText('target-admin（ID: 17）'))
    await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
    await within(dialog).findByText('操作结果待确认')
    expect(selector).toBeDisabled()
    const frozen = upload.mock.calls[0]!
    expect(frozen[1]).toEqual({ name: 'owned certificate', certificate_pem: 'PUBLIC-PEM', private_key_pem: 'PRIVATE-PEM', owner_user_id: managedTarget.id })
    expect(frozen[4]).toBe(managedTarget.scope_id)
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(upload).toHaveBeenCalledTimes(2))
    expect(upload.mock.calls[1]).toEqual(frozen)
    await waitFor(() => expect(queryDialog('添加证书')).not.toBeInTheDocument())
  })

  it('does not read the user directory without identity.users.manage and names the missing permission', async () => {
    platformSession(undefined, ['certificates.read', 'certificates.manage', 'dns.read', 'dns.manage'])
    const directory = vi.spyOn(usersApi, 'list')
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText('边缘站点证书')
    await openUpload(user)
    const dialog = getDialog('添加证书')
    expect(await within(dialog).findByText(/identity\.users\.manage/)).toBeInTheDocument()
    expect(directory).not.toHaveBeenCalled()
  })

  it('keeps list access independent of a forbidden owner directory and retries the directory in the dialog', async () => {
    platformSession()
    const directory = vi.spyOn(usersApi, 'list').mockRejectedValueOnce(new ApiError('denied', 403, 'permission_denied'))
      .mockResolvedValue({ items: [managedTarget], page: 1, limit: 100, total: 1 })
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText('边缘站点证书')
    await openUpload(user)
    const dialog = getDialog('添加证书')
    // 用户目录读取失败改为 FeedbackWhen 弹窗，重试按钮在弹窗里。
    const failure = await findDialog('无权读取用户目录，请联系管理员')
    expect(screen.getByText('边缘站点证书')).toBeInTheDocument()
    await user.click(within(failure).getByRole('button', { name: '重试' }))
    await waitFor(() => expect(directory).toHaveBeenCalledTimes(2))
    await user.click(within(dialog).getByRole('combobox', { name: '归属用户' }))
    expect(await screen.findByText('target-admin（ID: 17）')).toBeInTheDocument()
  })

  it.each(['owner', 'tenant'] as const)('rejects an upload receipt with the wrong %s and retries the original ownership', async (field) => {
    platformSession()
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget], page: 1, limit: 100, total: 1 })
    const expected = { ...assetDetail, asset: { ...asset, name: 'owned certificate' } }
    const wrong = { ...expected, asset: { ...expected.asset, ...(field === 'owner'
      ? { owner: { ...asset.owner!, id: 'foreign-owner' } }
      : { tenant: { ...asset.tenant, id: 'foreign-tenant' } }) } }
    const upload = vi.spyOn(certificatesApi, 'uploadAsset').mockResolvedValueOnce(wrong).mockResolvedValueOnce(expected)
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openUpload(user)
    const dialog = getDialog('添加证书')
    await user.click(within(dialog).getByRole('combobox', { name: '归属用户' }))
    await user.click(await screen.findByText('target-admin（ID: 17）'))
    await user.type(within(dialog).getByLabelText('名称'), 'owned certificate')
    await user.type(within(dialog).getByLabelText('证书 PEM'), 'PUBLIC-PEM')
    await user.type(within(dialog).getByLabelText('私钥 PEM'), 'PRIVATE-PEM')
    await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
    await within(dialog).findByText('操作结果待确认')
    const frozen = upload.mock.calls[0]!
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(upload).toHaveBeenCalledTimes(2))
    expect(upload.mock.calls[1]).toEqual(frozen)
  })

  it('targets platform details and mutations by each asset scope and rejects foreign-scope receipts', async () => {
    platformSession()
    const other: CertificateAsset = { ...asset, id: '98989898-9898-4898-8898-989898989898', tenant_scope_id: '99999999-9999-4999-8999-999999999999', name: '另一租户证书' }
    const detail = { asset: other, versions: assetDetail.versions.map((version) => ({ ...version, asset_id: other.id, tenant_scope_id: other.tenant_scope_id })) }
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset, other], total: 2, counts: { all: 2, normal: 0, expiring: 2, expired: 0, auto_renew: 0, manual_renew: 2 } })
    const get = vi.spyOn(certificatesApi, 'getAsset').mockImplementation(async (_token, id) => id === other.id ? detail : assetDetail)
    const remove = vi.spyOn(certificatesApi, 'deleteAsset').mockResolvedValueOnce({ ...other, tenant_scope_id: asset.tenant_scope_id, deleted_at: asset.updated_at })
      .mockResolvedValueOnce({ ...other, deleted_at: asset.updated_at })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const row = (await screen.findByText('另一租户证书')).closest('tr')!
    await waitFor(() => expect(get).toHaveBeenCalledWith('platform-certificate-token', other.id, other.tenant_scope_id))
    await rowAction(user, '删除', row)
    const dialog = getDialog('删除证书')
    await user.click(within(dialog).getByRole('button', { name: '确认删除' }))
    await within(dialog).findByText('操作结果待确认')
    const frozen = remove.mock.calls[0]!
    expect(frozen[1]).toBe(other.id)
    expect(frozen[5]).toBe(other.tenant_scope_id)
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(2))
    expect(remove.mock.calls[1]).toEqual(frozen)
  })

  it('searches owner display IDs by their formal field and excludes inactive members', async () => {
    platformSession()
    const directory = vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget, { ...managedTarget, id: 'disabled-user', username: 'disabled-member', status: 'disabled' }], page: 1, limit: 100, total: 2 })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openUpload(user)
    const selector = within(getDialog('添加证书')).getByRole('combobox', { name: '归属用户' })
    await user.type(selector, '17')
    await waitFor(() => expect(directory).toHaveBeenCalledWith('platform-certificate-token', { page: 1, limit: 100, display_id: '17' }))
    expect(screen.queryByText('disabled-member（ID: 17）')).not.toBeInTheDocument()
  })

  it('keeps ACME target scope explicit without inventing upload ownership and freezes its retry', async () => {
    platformSession()
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget], page: 1, limit: 100, total: 1 })
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    const providers = vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider, { ...provider, id: 'foreign-provider', scope_id: 'foreign-scope', name: '其他租户的 DNS' }] })
    const create = vi.spyOn(certificatesApi, 'create').mockRejectedValueOnce(new ApiError('lost receipt', 0, 'network_error'))
      .mockResolvedValueOnce({ ...activeOrder, domains: ['example.com'], status: 'pending', challenge_type: 'dns-01', dns_provider_id: provider.id })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openOrderHistory(user)
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = getDialog('申请证书')
    expect(providers).not.toHaveBeenCalled()
    expect(within(dialog).queryByRole('combobox', { name: '归属用户' })).not.toBeInTheDocument()
    const target = within(dialog).getByRole('combobox', { name: '目标用户' })
    await user.click(target)
    await user.click(await screen.findByText('target-admin（ID: 17）'))
    await user.type(within(dialog).getByLabelText('域名'), 'example.com')
    // 唯一可用的 DNS 服务商自动选中
    expect(await within(dialog).findByTitle('Cloudflare primary')).toBeInTheDocument()
    expect(screen.queryByText('其他租户的 DNS')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    await within(dialog).findByText('申请结果待确认')
    expect(target).toBeDisabled()
    const frozen = create.mock.calls[0]!
    expect(frozen[1].target_scope_id).toBe(managedTarget.scope_id)
    expect(frozen[1]).not.toHaveProperty('owner_user_id')
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(frozen)
  })
  // CERT-04（审测卡 8）：管理员漏选目标用户是必填错误，不是权限不足；不调用下单接口。
  it('reports a missing target user as required, not as a permission problem', async () => {
    platformSession()
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget], page: 1, limit: 100, total: 1 })
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(certificatesApi, 'create')
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openOrderHistory(user)
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = getDialog('申请证书')
    await user.type(within(dialog).getByLabelText('域名'), 'example.com')
    await user.click(within(dialog).getByLabelText('验证方式'))
    await user.click(await screen.findByText('HTTP-01（文件验证）'))
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    expect(await within(dialog).findByText('请选择目标用户')).toBeInTheDocument()
    expect(within(dialog).queryByText('当前账号缺少证书权限')).not.toBeInTheDocument()
    expect(within(dialog).getByLabelText('域名')).toHaveValue('example.com')
    expect(create).not.toHaveBeenCalled()
  })
  beforeEach(() => {
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
	vi.spyOn(certificatesApi, 'listAssetBindings').mockResolvedValue({ items: [] })
  })

  // FX05①: without a DNS API the form points to HTTP-01 (file validation on
  // the nodes) or to the DNS API tab instead of an empty list.
  it('guides to HTTP-01 or the DNS API tab when no DNS API is configured', async () => {
    authenticate()
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<CertificateListPage />, ['/site/cert?domains=www.example.com'])
    const dialog = await findDialog('申请证书')
    expect(await within(dialog).findByText('还没有可用的 DNS API。非通配符域名可改用 HTTP-01 文件验证；需要 DNS 验证时请先在“DNS API”页添加服务商账号。')).toBeInTheDocument()
  })

  // FX05①: HTTP-01 is selectable and is submitted without a DNS provider.
  it('submits an HTTP-01 request without a DNS provider', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(certificatesApi, 'create').mockResolvedValue({
      ...activeOrder, domains: ['www.example.com'], challenge_type: 'http-01', status: 'pending',
    } as CertificateOrder)
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openOrderHistory(user)
    await screen.findByText('暂无证书申请')
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = getDialog('申请证书')
    await user.type(within(dialog).getByLabelText('域名'), 'www.example.com')
    await user.click(within(dialog).getByLabelText('验证方式'))
    await user.click(await screen.findByText('HTTP-01（文件验证）'))
    expect(within(dialog).queryByLabelText('DNS 服务商')).not.toBeInTheDocument()
    expect(within(dialog).getByText('域名需已解析到本平台（CNAME 到站点线路组），所有节点都写入验证文件后才会请求签发机构验证。')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0][1]).toEqual({ domains: ['www.example.com'], challenge_type: 'http-01', auto_renew: true })
  })

  // A refused domains[1] marks the 域名 textarea, without the editor alert.
  it('marks a server-refused order domain on the domains field', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'create').mockRejectedValueOnce(Object.assign(
      new ApiError('API request failed', 400, 'validation_error', 'req-cert'), { field: 'domains[1]', reason: 'invalid_format' }))
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openOrderHistory(user)
    await screen.findByText('暂无证书申请')
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = getDialog('申请证书')
    await user.type(within(dialog).getByLabelText('域名'), 'www.example.com')
    await user.click(within(dialog).getByLabelText('验证方式'))
    await user.click(await screen.findByText('HTTP-01（文件验证）'))
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    expect(await within(dialog).findByText('格式不正确')).toBeInTheDocument()
    expect(dialog.querySelector('.identity-alert.ant-alert-error')).toBeNull()
  })

  it('opens the existing request form with domains passed from the site list', async () => {
    authenticate()
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    renderWithProviders(<CertificateListPage />, ['/site/cert?domains=www.example.com%0Aapi.example.com'])

    const dialog = await findDialog('申请证书')
    expect(within(dialog).getByLabelText('域名')).toHaveValue('www.example.com\napi.example.com')
    expect(within(dialog).getByRole('switch', { name: '自动续期' })).toBeChecked()
  })

  it('provides tenant asset detail, upload, and delete while viewers remain read-only', async () => {
    authenticate()
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const upload = vi.spyOn(certificatesApi, 'uploadAsset').mockResolvedValue({
      ...assetDetail, asset: { ...assetDetail.asset, name: '新证书' },
    })
    const remove = vi.spyOn(certificatesApi, 'deleteAsset').mockResolvedValue({ ...asset, deleted_at: '2026-08-01T00:00:00Z' })
    const user = userEvent.setup()
    const ownerView = renderWithProviders(<CertificateListPage />, ['/site/cert'])

    expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
    expect(screen.getByText('手动上传')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看详情' }))
    const detailDialog = await findDialog('证书详情')
    expect(await within(detailDialog).findByText('example.com')).toBeInTheDocument()
    expect(screen.queryByText('PRIVATE-PEM')).not.toBeInTheDocument()
    await user.click(within(detailDialog).getByRole('button', { name: '关闭' }))

    await openUpload(user)
    const uploadDialog = getDialog('添加证书')
    await user.type(within(uploadDialog).getByLabelText('名称'), '新证书')
    await user.type(within(uploadDialog).getByLabelText('证书 PEM'), 'PUBLIC-PEM')
    await user.type(within(uploadDialog).getByLabelText('私钥 PEM'), 'PRIVATE-PEM')
    await user.click(within(uploadDialog).getByRole('button', { name: '保存证书' }))
    await waitFor(() => expect(upload).toHaveBeenCalledTimes(1))
    expect(upload.mock.calls[0][1]).toEqual({ name: '新证书', certificate_pem: 'PUBLIC-PEM', private_key_pem: 'PRIVATE-PEM' })

    await rowAction(user, '删除')
    const deleteDialog = getDialog('删除证书')
    await user.click(within(deleteDialog).getByRole('button', { name: '确认删除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1))
    expect(remove.mock.calls[0].slice(1)).toEqual([
      asset.id,
      { expected_revision: asset.revision },
      expect.stringMatching(/^certificate-order-create-/),
      expect.stringMatching(/^certificate-asset-/),
      undefined,
    ])

    ownerView.unmount()
    authenticate(['certificates.read'])
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '添加证书' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '吊销' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
  })

	it('activates versions and binds and unbinds sites through real asset responses', async () => {
		authenticate()
		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({ ...assetDetail, versions: [assetDetail.versions[0], pendingVersion] })
		vi.mocked(certificatesApi.listAssetBindings).mockResolvedValue({ items: [binding] })
		const activate = vi.spyOn(certificatesApi, 'activateAssetVersion').mockResolvedValue({ ...pendingVersion, status: 'active' })
		const bind = vi.spyOn(certificatesApi, 'bindAsset').mockResolvedValue({ ...binding, default: false })
		const unbind = vi.spyOn(certificatesApi, 'unbindAsset').mockResolvedValue({ ...binding, revision: 2, bound: false })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])

		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: '查看详情' }))
		let detailDialog = await findDialog('证书详情')
			await user.click(within(detailDialog).getByRole('button', { name: '激活版本' }))
			await waitFor(() => expect(activate).toHaveBeenCalledTimes(1))
			expect(activate.mock.calls[0].slice(1, 4)).toEqual([asset.id, pendingVersion.id, { expected_revision: asset.revision }])
			await waitFor(() => expect(queryDialog('证书详情')).not.toBeInTheDocument())

			await user.click(screen.getByRole('button', { name: '查看详情' }))
			detailDialog = await findDialog('证书详情')
			const bindButton = within(detailDialog).getByRole('button', { name: '绑定网站' })
			expect(bindButton).toBeEnabled()
			await user.click(bindButton)
		const bindDialog = await findDialog('绑定网站')
		await user.type(within(bindDialog).getByLabelText('网站'), binding.site_id)
		await user.click(within(bindDialog).getByRole('button', { name: '确认绑定' }))
			await waitFor(() => expect(bind).toHaveBeenCalledTimes(1))
			expect(bind.mock.calls[0][2]).toEqual({
				site_id: binding.site_id, version_id: assetDetail.versions[0].id, expected_revision: 1, default: false,
			})
			await waitFor(() => expect(queryDialog('绑定网站')).not.toBeInTheDocument())
			await waitFor(() => expect(queryDialog('证书详情')).not.toBeInTheDocument())

			await user.click(screen.getByRole('button', { name: '查看详情' }))
		detailDialog = await findDialog('证书详情')
		await user.click(within(detailDialog).getByRole('button', { name: '解绑' }))
		await waitFor(() => expect(unbind).toHaveBeenCalledTimes(1))
		expect(unbind.mock.calls[0].slice(1, 4)).toEqual([asset.id, binding.site_id, { expected_revision: 1 }])
	})

	it('allows binding only active versions', async () => {
		authenticate()
		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({
			...assetDetail,
			versions: [{ ...assetDetail.versions[0], status: 'default' }],
		})
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])

		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: '查看详情' }))
		const detailDialog = await findDialog('证书详情')
		expect(within(detailDialog).getByRole('button', { name: '绑定网站' })).toBeDisabled()
	})

	it('enforces UTF-8 byte limits and clears private key fields after an unknown upload', async () => {
		authenticate()
		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
		const upload = vi.spyOn(certificatesApi, 'uploadAsset')
			.mockRejectedValue(new ApiError('private upstream failure', 500, 'internal_error'))
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])

		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
		await openUpload(user)
		let uploadDialog = getDialog('添加证书')
		const name = within(uploadDialog).getByLabelText('名称')
		await user.type(name, '证'.repeat(43))
		await user.type(within(uploadDialog).getByLabelText('证书 PEM'), 'PUBLIC-PEM')
		await user.type(within(uploadDialog).getByLabelText('私钥 PEM'), 'PRIVATE-PEM')
		await user.click(within(uploadDialog).getByRole('button', { name: '保存证书' }))
		expect(await within(uploadDialog).findByText('名称长度或格式无效')).toBeInTheDocument()
		expect(upload).not.toHaveBeenCalled()

		await user.clear(name)
		await user.type(name, '有效证书')
		await user.click(within(uploadDialog).getByRole('button', { name: '保存证书' }))
		await waitFor(() => expect(upload).toHaveBeenCalledTimes(1))
		expect(await within(uploadDialog).findByText('操作结果待确认')).toBeInTheDocument()
		await user.click(within(uploadDialog).getByRole('button', { name: '关闭并刷新' }))
		await waitFor(() => expect(queryDialog('添加证书')).not.toBeInTheDocument())

		await openUpload(user)
		uploadDialog = getDialog('添加证书')
		expect(within(uploadDialog).getByLabelText('私钥 PEM')).toHaveValue('')
		await user.click(within(uploadDialog).getByRole('button', { name: '取消' }))
	})

  it('renders status, expiry, failure code, and client-side domain search for read-only users', async () => {
    authenticate(['certificates.read'])
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [activeOrder, failedOrder] })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    expect(await screen.findByRole('heading', { name: '证书管理' })).toBeInTheDocument()
    await openOrderHistory(user)
    expect(await screen.findByText('example.com, www.example.com')).toBeInTheDocument()
    expect(screen.getByText('已生效')).toBeInTheDocument()
		expect(screen.getByText('DNS 解析等待超时')).toBeInTheDocument()
		expect(screen.queryByText(/dns_propagation_timeout/)).not.toBeInTheDocument()
    // 日期、时间分两行显示，按单元格完整文本断言。
    expect(screen.getAllByRole('cell').some((cell) => cell.textContent === formatDateTime(expiringNotAfter, 'zh-CN').replace(' ', ''))).toBe(true)
    expect(screen.queryByRole('button', { name: '申请证书' })).not.toBeInTheDocument()

    // 搜索停下 400ms 后生效（不再每键即查）。
    await user.type(screen.getByRole('searchbox', { name: '搜索域名' }), 'failed')
    expect(screen.getByText('failed.example.net')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('example.com, www.example.com')).not.toBeInTheDocument())
  })

	it('matches the default settings and DNS API page structure', async () => {
    authenticate()
    const providers = vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    await user.click(screen.getByRole('tab', { name: 'DNS API' }))
    expect(await screen.findByText('Cloudflare')).toBeInTheDocument()
    for (const header of ['ID', '名称', '类型', '备注', '操作']) {
      expect(screen.getByRole('columnheader', { name: header })).toBeInTheDocument()
    }
    // CERT-07b：接口没有归属用户，不显示整列占位的"用户"列
    expect(screen.queryByRole('columnheader', { name: '用户' })).not.toBeInTheDocument()
    expect(screen.getAllByText('共 1 条')).toHaveLength(2)
    expect(providers).toHaveBeenCalledTimes(1)
    expect(screen.queryByText(/token|secret/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增 DNS API' })).not.toBeInTheDocument()

		await user.click(screen.getByRole('tab', { name: '默认设置' }))
		// 证书列表的高级筛选面板（收起、hidden）也有「用户」字段，这里只看默认设置里可见的那个。
		await waitFor(() => expect(screen.getAllByLabelText('用户').filter((node) => !node.closest('[hidden]'))).toHaveLength(1))
		expect(screen.getAllByLabelText('证书类型').length).toBeGreaterThan(0)
		expect(screen.getAllByLabelText('DNS API').length).toBeGreaterThan(0)
	})

  // 备注列显示服务商的备注，不再固定横线；停用的仍标“已禁用”。
  it('shows the DNS provider remark in the remark column', async () => {
    authenticate()
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [
      { ...provider, name: 'Main zone', remark: '主站解析' },
      { ...provider, id: 'dns-2', name: 'No remark' },
      { ...provider, id: 'dns-3', name: 'Disabled one', remark: '旧账号', status: 'disabled' },
    ] })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await user.click(screen.getByRole('tab', { name: 'DNS API' }))
    const row = (name: string) => screen.getByText(name).closest('tr') as HTMLElement
    await screen.findByText('Main zone')
    expect(within(row('Main zone')).getByText('主站解析')).toBeInTheDocument()
    expect(within(row('No remark')).getByText('—')).toBeInTheDocument()
    expect(within(row('Disabled one')).getByText(/旧账号/)).toBeInTheDocument()
    expect(within(row('Disabled one')).getByText(/已禁用/)).toBeInTheDocument()
  })

	it('loads and persists certificate defaults through the selected user without exposing tenant scope input', async () => {
		authenticate()
		const defaults = vi.spyOn(certificatesApi, 'getDefaults').mockResolvedValue({
			scope_id: asset.tenant_scope_id, user_id: '11111111-1111-4111-8111-111111111111',
			certificate_type: 'acme', dns_provider_id: provider.id, revision: 2,
			updated_at: '2026-09-30T02:00:00Z',
		})
		const updated = vi.spyOn(certificatesApi, 'updateDefaults').mockResolvedValue({
			scope_id: asset.tenant_scope_id, user_id: '11111111-1111-4111-8111-111111111111',
			certificate_type: 'uploaded', revision: 3, updated_at: '2026-09-30T02:01:00Z',
		})
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])

		await user.click(screen.getByRole('tab', { name: '默认设置' }))
		await waitFor(() => expect(defaults).toHaveBeenCalledWith('memory-only-access-token', undefined, '11111111-1111-4111-8111-111111111111'))
		expect(screen.queryByLabelText('租户作用域')).not.toBeInTheDocument()
		await user.click(screen.getByRole('combobox', { name: '证书类型' }))
		await user.click(await screen.findByText('上传证书'))
		await user.click(screen.getByRole('button', { name: '保存默认设置' }))
		await waitFor(() => expect(updated).toHaveBeenCalledTimes(1))
		expect(updated.mock.calls[0][1]).toMatchObject({
			target_user_id: '11111111-1111-4111-8111-111111111111',
			certificate_type: 'uploaded', expected_revision: 2,
		})
		expect(updated.mock.calls[0][1]).not.toHaveProperty('dns_provider_id')
	})

	// 默认设置被拒能定位字段时标在对应选择框下，不弹窗；改选后清除
	it('marks a refused certificate default under its field without a dialog', async () => {
		authenticate()
		vi.spyOn(certificatesApi, 'getDefaults').mockResolvedValue({
			scope_id: asset.tenant_scope_id, user_id: '11111111-1111-4111-8111-111111111111',
			certificate_type: 'acme', dns_provider_id: provider.id, revision: 2, updated_at: '2026-09-30T02:00:00Z',
		})
		vi.spyOn(certificatesApi, 'updateDefaults').mockRejectedValueOnce(Object.assign(
			new ApiError('API request failed', 400, 'validation_error', 'req-defaults'), { field: 'dns_provider_id', reason: 'invalid' }))
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(screen.getByRole('tab', { name: '默认设置' }))
		await screen.findByRole('combobox', { name: '证书类型' })
		await user.click(screen.getByRole('button', { name: '保存默认设置' }))
		const help = await screen.findByText('填写的内容不符合要求')
		expect(help.closest('.certificate-default-field')).toContainElement(screen.getByRole('combobox', { name: 'DNS API' }))
		expect(screen.getByRole('combobox', { name: 'DNS API' }).closest('.ant-select')).toHaveClass('ant-select-status-error')
		expect(document.querySelector('.cdnca-feedback')).toBeNull()
		await user.click(screen.getByRole('combobox', { name: '证书类型' }))
		await user.click(await screen.findByText('上传证书'))
		expect(screen.queryByText('填写的内容不符合要求')).not.toBeInTheDocument()
	})

	// fp-site CERT-01：服务端规范化后的 PEM（LF、末尾换行、去块外文字）算同一证书，换了证书仍拒绝
	it('compares uploaded certificate chains by their DER content, not the exact PEM text', () => {
		const block = (body: string) => `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`
		const canonical = block('MIIBAAAA\nBBBBCCCC') + block('MIICDDDD')
		const crlf = canonical.replace(/\n/gu, '\r\n').trimEnd()
		expect(samePEMCertificateChain(canonical, crlf)).toBe(true)
		expect(samePEMCertificateChain(canonical, `subject=example\n${canonical}  `)).toBe(true)
		expect(samePEMCertificateChain(canonical, block('MIIBAAAA\nBBBBCCCC'))).toBe(false)
		expect(samePEMCertificateChain(canonical, block('MIIBAAAA\nBBBBCCCX') + block('MIICDDDD'))).toBe(false)
		expect(samePEMCertificateChain('', '')).toBe(false)
	})

	it('accepts an upload whose receipt is the server-normalized PEM of a CRLF input', async () => {
		authenticate()
		const input = '-----BEGIN CERTIFICATE-----\r\nMIIBAAAA\r\n-----END CERTIFICATE-----'
		const upload = vi.spyOn(certificatesApi, 'uploadAsset').mockResolvedValue({
			asset: { ...asset, name: 'crlf upload' },
			versions: [{ ...assetDetail.versions[0], certificate_pem: '-----BEGIN CERTIFICATE-----\nMIIBAAAA\n-----END CERTIFICATE-----\n' }],
		})
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await screen.findByText('暂无证书资产')
		await openUpload(user)
		const dialog = getDialog('添加证书')
		await user.type(within(dialog).getByLabelText('名称'), 'crlf upload')
		fireEvent.change(within(dialog).getByLabelText('证书 PEM'), { target: { value: input } })
		await user.type(within(dialog).getByLabelText('私钥 PEM'), 'PRIVATE-PEM')
		await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
		await waitFor(() => expect(upload).toHaveBeenCalledTimes(1))
		await waitFor(() => expect(queryDialog('添加证书')).not.toBeInTheDocument())
		expect(screen.queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
	})

	// fp-site CERT-03：已保存的默认 DNS 账号带入新申请；用户改选优先
	it('fills a new request with the saved default DNS provider', async () => {
		authenticate()
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(certificatesApi, 'getDefaults').mockResolvedValue({
			scope_id: asset.tenant_scope_id, user_id: '11111111-1111-4111-8111-111111111111',
			certificate_type: 'acme', dns_provider_id: provider.id, revision: 2, updated_at: '2026-09-30T02:00:00Z',
		})
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
		const create = vi.spyOn(certificatesApi, 'create').mockResolvedValue({ ...activeOrder, status: 'pending' } as CertificateOrder)
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openOrderHistory(user)
		await screen.findByText('暂无证书申请')
		await user.click(screen.getByRole('button', { name: '申请证书' }))
		const dialog = getDialog('申请证书')
		await user.type(within(dialog).getByLabelText('域名'), 'www.example.com')
		await waitFor(() => expect(within(dialog).getByText(provider.name)).toBeInTheDocument())
		await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
		await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
		expect(create.mock.calls[0][1]).toMatchObject({ challenge_type: 'dns-01', dns_provider_id: provider.id })
	})

	// fp-site CERT-08：保存默认设置结果未知时冻结输入，只能用原请求重试
	it('locks certificate defaults after an unknown save and retries with the same key', async () => {
		authenticate()
		vi.spyOn(certificatesApi, 'getDefaults').mockResolvedValue({
			scope_id: asset.tenant_scope_id, user_id: '11111111-1111-4111-8111-111111111111',
			certificate_type: 'acme', dns_provider_id: provider.id, revision: 2, updated_at: '2026-09-30T02:00:00Z',
		})
		const updated = vi.spyOn(certificatesApi, 'updateDefaults')
			.mockRejectedValueOnce(new ApiError('down', 503, 'service_unavailable'))
			.mockResolvedValueOnce({
				scope_id: asset.tenant_scope_id, user_id: '11111111-1111-4111-8111-111111111111',
				certificate_type: 'uploaded', revision: 3, updated_at: '2026-09-30T02:01:00Z',
			})
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(screen.getByRole('tab', { name: '默认设置' }))
		await user.click(await screen.findByRole('combobox', { name: '证书类型' }))
		await user.click(await screen.findByText('上传证书'))
		await user.click(screen.getByRole('button', { name: '保存默认设置' }))
		await waitFor(() => expect(updated).toHaveBeenCalledTimes(1))
		const retry = await screen.findByRole('button', { name: '使用同一请求重试' })
		expect(screen.getByRole('combobox', { name: '证书类型' })).toBeDisabled()
		expect(screen.getByRole('button', { name: '保存默认设置' })).toBeDisabled()
		await user.click(retry)
		await waitFor(() => expect(updated).toHaveBeenCalledTimes(2))
		expect(updated.mock.calls[1][2]).toBe(updated.mock.calls[0][2])
		expect(updated.mock.calls[1][1]).toEqual(updated.mock.calls[0][1])
	})

	it('keeps the certificate list toolbar, page statistics, and nine-column contract', async () => {
		authenticate()
		// Pill counts come from the server over every page; a pill filters on the server.
		const listAssets = vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset], total: 1,
			counts: { all: 25, normal: 20, expiring: 3, expired: 2, auto_renew: 7, manual_renew: 18 } })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		const user = userEvent.setup()

		expect(await screen.findByText('添加证书')).toBeInTheDocument()
		expect(screen.getByRole('button', { name: '重新申请' })).toBeDisabled()
		expect(screen.getByRole('button', { name: '更多操作' })).toBeEnabled()
		expect(screen.getByRole('button', { name: '高级筛选' })).toBeEnabled()
		expect(screen.getByRole('button', { name: '重置' })).toBeEnabled()
		expect(screen.getByRole('button', { name: '导出' })).toBeDisabled()
		expect(screen.getByRole('searchbox', { name: '输入域名,模糊搜索' })).toHaveAttribute('placeholder', '输入域名,模糊搜索')
		expect(screen.getByRole('button', { name: '查询' })).toBeEnabled()
		for (const header of ['ID', '证书信息', '类型', '创建时间', '到期时间', '自动续签', '状态', '操作']) {
			expect(screen.getByRole('columnheader', { name: header })).toBeInTheDocument()
		}
		expect(await screen.findByText('example.com')).toBeInTheDocument()
		expect(screen.getByRole('button', { name: '导出' })).toBeEnabled()
		expect(screen.queryByRole('columnheader', { name: '名称' })).not.toBeInTheDocument()
		// Tenant view: no 用户 column, no inner 证书资产 / 自动申请 tabs.
		expect(screen.queryByRole('columnheader', { name: '用户' })).not.toBeInTheDocument()
		expect(screen.queryByRole('tab', { name: '自动申请' })).not.toBeInTheDocument()
		expect(screen.getByLabelText('证书状态统计')).toHaveTextContent('全部25正常20即将到期3已过期2自动续签7未开启续签18')
		expect(screen.queryByText('统计当前页')).not.toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: /自动续签\s*7/ }))
		await waitFor(() => expect(listAssets).toHaveBeenLastCalledWith(expect.any(String), undefined, { page: 1, limit: 10, search: '', status: 'auto_renew' }))
		await user.click(screen.getByRole('button', { name: /全部\s*25/ }))
		await waitFor(() => expect(listAssets).toHaveBeenLastCalledWith(expect.any(String), undefined, { page: 1, limit: 10, search: '', status: undefined }))

		const NativeURL = URL
		const createObjectURL = vi.fn().mockReturnValue('blob:certificate-export')
		const revokeObjectURL = vi.fn()
		class TestURL extends NativeURL {
			static createObjectURL = createObjectURL
			static revokeObjectURL = revokeObjectURL
		}
		vi.stubGlobal('URL', TestURL)
		const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
		await user.click(screen.getByRole('button', { name: '导出' }))
		const blob = createObjectURL.mock.calls[0]?.[0] as Blob
		const csv = await new Promise<string>((resolve, reject) => {
			const reader = new FileReader()
			reader.onload = () => resolve(String(reader.result))
			reader.onerror = () => reject(reader.error)
			reader.readAsText(blob)
		})
		expect(csv).toContain('"域名","类型"')
		expect(csv).toContain('"example.com","手动上传"')
		expect(click).toHaveBeenCalledTimes(1)
		expect(revokeObjectURL).toHaveBeenCalledWith('blob:certificate-export')
		vi.unstubAllGlobals()
	})

	it('opens one certificate\'s 申请记录 from its row and filters by the renewal pills (B4)', async () => {
		authenticate()
		// The server filters by renewal status; manual_renew has no asset here.
		const counts = { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 1, manual_renew: 0 }
		vi.mocked(certificatesApi.listAssets).mockImplementation(async (_token, _target, query) => (
			query?.status === 'manual_renew' ? { items: [], total: 0, counts } : { items: [asset], total: 1, counts }))
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [
			{ ...activeOrder, domains: ['example.com'], issued_asset_id: asset.id },
			failedOrder,
		] })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])

		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: /自动续签\s*1/ }))
		expect(screen.getByText('边缘站点证书')).toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: /未开启续签\s*0/ }))
		expect(await screen.findByText('没有匹配的证书资产')).toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: /全部\s*1/ }))

		await rowAction(user, '申请记录')
		expect(screen.getByText('证书 example.com 的申请记录')).toBeInTheDocument()
		expect(await screen.findByText('example.com')).toBeInTheDocument()
		expect(screen.queryByText('failed.example.net')).not.toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: '返回证书列表' }))
		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
	})

	it('keeps certificate filter and bulk-action dropdowns interactive', async () => {
		authenticate()
		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])

		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: '高级筛选' }))
		expect(screen.getByRole('group', { name: '高级筛选' })).toBeVisible()
		await user.click(screen.getByRole('button', { name: '应用' }))
		await user.click(screen.getByRole('button', { name: /即将到期\s*1/ }))
		expect(screen.getByRole('button', { name: /即将到期\s*1/ })).toHaveClass('is-active')

		// 表头“更多操作”只放批量动作；未勾选时批量项禁用，不再有“管理”等单张入口。
		await user.click(screen.getByRole('button', { name: '更多操作' }))
		expect(screen.queryByRole('menuitem', { name: '管理' })).not.toBeInTheDocument()
		expect(screen.getByRole('menuitem', { name: '删除' })).toHaveAttribute('aria-disabled', 'true')
		expect(screen.getByRole('menuitem', { name: '开启续签' })).toBeInTheDocument()
	})

	// 行内“吊销”“删除”是 link 按钮（删除为 danger），不再是没有样式的原生按钮；行内“更多”里不再重复这两项。
	// 操作列 管理 · 重新申请 · 更多▼；更多里 下载证书/禁用|启用/…/删除（危险色）。
	// 更多里不再重复“重新申请”，“吊销”下线（只改本地状态、与禁用重叠）。
	it('renders the row actions in the reference shape with single-certificate actions under 更多', async () => {
		authenticate()
		vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset], total: 1 })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		const row = (await screen.findByText('边缘站点证书')).closest('tr') as HTMLElement
		const actions = row.querySelector('.certificate-row-actions') as HTMLElement
		await waitFor(() => expect(within(actions).getAllByRole('button').map((button) => button.textContent?.trim())).toEqual(['管理', '重新申请', '更多']))
		for (const name of ['吊销', '删除', '申请记录', '更多操作']) expect(within(actions).queryByRole('button', { name })).not.toBeInTheDocument()
		await user.click(within(actions).getByRole('button', { name: '边缘站点证书 的更多操作' }))
		const items = (await screen.findAllByRole('menuitem')).map((item) => item.textContent?.trim())
		expect(items).toEqual(['下载证书', '禁用', '申请记录', '绑定网站', '删除'])
		expect(items).not.toContain('重新申请')
		expect(items).not.toContain('吊销')
		expect(items).not.toContain('启用')
		expect(screen.getByRole('menuitem', { name: '删除' })).toHaveClass('ant-dropdown-menu-item-danger')
	})

	it('filters certificate assets by the remark field', async () => {
		authenticate()
		const assetWithRemark = { ...asset, remark: 'production certificate' }
		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [assetWithRemark], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({ ...assetDetail, asset: assetWithRemark })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])

		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
		await user.click(screen.getByRole('button', { name: '高级筛选' }))
		const remark = screen.getByPlaceholderText('请输入证书备注，模糊搜索')
		await user.type(remark, 'production')
		await user.click(screen.getByRole('button', { name: '应用' }))
		// CERT-05：备注交给服务端筛选（列表、总数同一条件）
		await waitFor(() => expect(certificatesApi.listAssets).toHaveBeenLastCalledWith(expect.any(String), undefined,
			expect.objectContaining({ page: 1, filters: expect.objectContaining({ remark: 'production' }) })))
		expect(screen.getByText('边缘站点证书')).toBeInTheDocument()

		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
		await user.clear(remark)
		await user.type(remark, 'staging')
		await user.click(screen.getByRole('button', { name: '应用' }))
		expect(await screen.findByText('没有匹配的证书资产')).toBeInTheDocument()
	})

	// CERT-02：上传可选本地证书/私钥文件填入文本框，非 PEM 文件就地报错；备注随上传提交。
	it('fills the PEM fields from local files and sends the remark', async () => {
		authenticate(['certificates.read', 'certificates.manage'])
		const upload = vi.spyOn(certificatesApi, 'uploadAsset').mockResolvedValue({ ...assetDetail, asset: { ...asset, name: 'file upload' } })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openUpload(user)
		const dialog = getDialog('添加证书')
		await user.type(within(dialog).getByLabelText('名称'), 'file upload')
		await user.type(within(dialog).getByLabelText('备注'), 'cdn edge')
		const certificate = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
		await user.upload(within(dialog).getByLabelText('上传私钥文件'), new File(['not a key'], 'key.pem'))
		expect(await within(dialog).findByText('文件不是 PEM 格式，或不含对应的证书/私钥')).toBeInTheDocument()
		await user.upload(within(dialog).getByLabelText('上传证书文件'), new File([certificate], 'cert.pem'))
		await waitFor(() => expect(within(dialog).getByLabelText('证书 PEM')).toHaveValue(certificate))
		await user.upload(within(dialog).getByLabelText('上传私钥文件'), new File(['-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n'], 'key.pem'))
		await waitFor(() => expect(within(dialog).queryByText('文件不是 PEM 格式，或不含对应的证书/私钥')).not.toBeInTheDocument())
		await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
		await waitFor(() => expect(upload).toHaveBeenCalledTimes(1))
		expect(upload.mock.calls[0][1]).toMatchObject({ name: 'file upload', remark: 'cdn edge', certificate_pem: certificate })
	})

	// CERT-02（审测卡 6）：读取未完成就取消/重开或手改字段，迟到的读取结果不得覆盖新草稿。
	it('drops a late file read that no longer belongs to the current draft', async () => {
		authenticate(['certificates.read', 'certificates.manage'])
		const pending: Array<(value: { text: string }) => void> = []
		readPEMFileOverride.current = () => new Promise((resolve) => { pending.push(resolve) })
		try {
			const user = userEvent.setup()
			renderWithProviders(<CertificateListPage />, ['/site/cert'])
			await openUpload(user)
			let dialog = getDialog('添加证书')
			await user.upload(within(dialog).getByLabelText('上传证书文件'), new File(['a'], 'a.pem'))
			await user.click(within(dialog).getByRole('button', { name: '取消' }))
			await openUpload(user)
			dialog = getDialog('添加证书')
			await user.type(within(dialog).getByLabelText('证书 PEM'), 'SYNTHETIC_DRAFT_B')
			await act(async () => { pending[0]({ text: 'SYNTHETIC_FILE_READ_A' }) })
			expect(within(dialog).getByLabelText('证书 PEM')).toHaveValue('SYNTHETIC_DRAFT_B')

			// 同一弹窗内：读取期间手改字段，旧读取也不落地。
			await user.upload(within(dialog).getByLabelText('上传证书文件'), new File(['c'], 'c.pem'))
			await user.type(within(dialog).getByLabelText('证书 PEM'), '_EDITED')
			await act(async () => { pending[1]({ text: 'SYNTHETIC_FILE_READ_C' }) })
			expect(within(dialog).getByLabelText('证书 PEM')).toHaveValue('SYNTHETIC_DRAFT_B_EDITED')

			// 后选的文件先回、先选的后回：只保留后选的。
			await user.upload(within(dialog).getByLabelText('上传私钥文件'), new File(['d'], 'd.key'))
			await user.upload(within(dialog).getByLabelText('上传私钥文件'), new File(['e'], 'e.key'))
			await act(async () => { pending[3]({ text: 'SYNTHETIC_KEY_E' }) })
			await act(async () => { pending[2]({ text: 'SYNTHETIC_KEY_D' }) })
			expect(within(dialog).getByLabelText('私钥 PEM')).toHaveValue('SYNTHETIC_KEY_E')
		} finally {
			readPEMFileOverride.current = null
		}
	})

	// CERT-02：有 sites.read 时绑定网站用本人网站选择器，并标出证书不覆盖的网站。
	it('binds a site picked by domain instead of a typed site ID', async () => {
		authenticate(['certificates.read', 'certificates.manage', 'sites.read'])
		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
		const covered = assetDetail.versions[0].sans[0]
		const sites = vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [
			{ id: binding.site_id, display_id: '7', domain: covered },
			{ id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', display_id: '8', domain: 'other.invalid' },
		], total: 2, page: 1, limit: 50 } as unknown as Awaited<ReturnType<typeof sitesApi.list>>)
		const bind = vi.spyOn(certificatesApi, 'bindAsset').mockResolvedValue({ ...binding, default: false })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(await screen.findByRole('button', { name: '查看详情' }))
		const detailDialog = await findDialog('证书详情')
		await user.click(within(detailDialog).getByRole('button', { name: '绑定网站' }))
		const bindDialog = await findDialog('绑定网站')
		await user.click(within(bindDialog).getByRole('combobox', { name: '网站' }))
		expect(await screen.findByText('other.invalid（ID 8，证书不含此域名）')).toBeInTheDocument()
		await user.click(screen.getByText(`${covered}（ID 7）`))
		await user.click(within(bindDialog).getByRole('button', { name: '确认绑定' }))
		await waitFor(() => expect(bind).toHaveBeenCalledTimes(1))
		expect(bind.mock.calls[0][2]).toMatchObject({ site_id: binding.site_id })
		expect(sites).toHaveBeenCalledWith(expect.any(String), expect.not.objectContaining({ owner: expect.anything() }))
	})

	// CERT-04：申请带名称/备注/签发机构；只列平台已配置的 CA，只有一个时不显示选择。
	it('requests with a name, remark and a configured CA only', async () => {
		authenticate(['certificates.read', 'certificates.manage', 'dns.read'])
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		const issuers = vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt', 'zerossl'], default: 'lets_encrypt' })
		const create = vi.spyOn(certificatesApi, 'create').mockResolvedValue({ ...activeOrder, domains: ['example.com'], status: 'pending', challenge_type: 'http-01', dns_provider_id: undefined, auto_renew: true, issuer: 'zerossl' })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openOrderHistory(user)
		await user.click(screen.getByRole('button', { name: '申请证书' }))
		const dialog = getDialog('申请证书')
		await waitFor(() => expect(issuers).toHaveBeenCalled())
		await user.click(await within(dialog).findByRole('button', { name: /ZeroSSL/ }))
		expect(within(dialog).queryByRole('button', { name: /Google Trust Services/ })).not.toBeInTheDocument()
		// 申请记录里的“申请证书”只申请，不出现“自己上传”
		expect(within(dialog).queryByRole('button', { name: /自己上传/ })).not.toBeInTheDocument()
		await user.type(within(dialog).getByLabelText('证书名称'), 'shop')
		await user.type(within(dialog).getByLabelText('备注'), 'main site')
		await user.type(within(dialog).getByLabelText('域名'), 'example.com')
		await user.click(within(dialog).getByRole('combobox', { name: '验证方式' }))
		await user.click((await screen.findAllByText(/HTTP-01/)).at(-1)!)
		await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
		await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
		expect(create.mock.calls[0][1]).toMatchObject({ name: 'shop', remark: 'main site', issuer: 'zerossl', challenge_type: 'http-01' })
	})

	// 添加证书固定显示 ZeroSSL 卡；未配置 EAB 时置灰说明，平台管理员可直达默认设置配置。
	it('shows ZeroSSL disabled with a reason until the platform configures EAB', async () => {
		platformSession('platform-certificate-token', ['certificates.read', 'certificates.manage', 'dns.read', 'system_configuration.manage'])
		vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [] } as never)
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt'], default: 'lets_encrypt' })
		const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [
			{ ca: 'zerossl', directory_url: 'https://acme.zerossl.com/v2/DV90', configured: false, revision: 0 },
		] }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
		vi.stubGlobal('fetch', fetchMock)
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(await screen.findByRole('button', { name: '添加证书' }))
		const dialog = await findDialog('添加证书')
		const zerossl = await within(dialog).findByRole('button', { name: /ZeroSSL/ })
		const cards = within(within(dialog).getByRole('region', { name: '证书类型' })).getAllByRole('button').map((button) => button.querySelector('strong')?.textContent)
		expect(cards.filter(Boolean)).toEqual(['自己上传', 'ZeroSSL', "Let's Encrypt"])
		expect(zerossl).toBeDisabled()
		expect(zerossl).toHaveAccessibleDescription('平台尚未配置 EAB，暂不可用。')
		expect(within(dialog).getByRole('button', { name: /Let's Encrypt/ })).toHaveAttribute('aria-pressed', 'true')
		await user.click(within(dialog).getByRole('button', { name: '去配置' }))
		// 跳到“默认设置”，平台管理员看到 EAB 凭据卡（含按邮箱获取）。
		expect(await screen.findByRole('heading', { name: 'ACME 签发机构凭据' })).toBeInTheDocument()
		expect(await screen.findByLabelText('ZeroSSL 账户邮箱')).toBeInTheDocument()
		vi.unstubAllGlobals()
	})

	it('hides the EAB settings from tenants and shows ZeroSSL without a configure link', async () => {
		tenantSession('tenant-token')
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt'], default: 'lets_encrypt' })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(await screen.findByRole('button', { name: '添加证书' }))
		const dialog = await findDialog('添加证书')
		expect(await within(dialog).findByRole('button', { name: /ZeroSSL/ })).toBeDisabled()
		expect(within(dialog).queryByRole('button', { name: '去配置' })).not.toBeInTheDocument()
	})

	it('hides the CA choice when the platform offers only Let\'s Encrypt', async () => {
		authenticate(['certificates.read', 'certificates.manage', 'dns.read'])
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		const issuers = vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt'], default: 'lets_encrypt' })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openOrderHistory(user)
		await user.click(screen.getByRole('button', { name: '申请证书' }))
		const dialog = getDialog('申请证书')
		await waitFor(() => expect(issuers).toHaveBeenCalled())
		expect(within(dialog).queryByRole('region', { name: '证书类型' })).not.toBeInTheDocument()
	})

	// CERT-04：统一“添加证书”——单个=自己上传/已配置 CA，空格分隔域名；未配置的 CA 不显示
	it('adds a certificate from one dialog with upload or a configured CA and space-separated domains', async () => {
		authenticate(['certificates.read', 'certificates.manage', 'dns.read'])
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt', 'zerossl'], default: 'lets_encrypt' })
		const create = vi.spyOn(certificatesApi, 'create').mockResolvedValue({ ...activeOrder, domains: ['example.com', 'www.example.com'], status: 'pending', challenge_type: 'http-01', dns_provider_id: undefined, auto_renew: true, issuer: 'zerossl' })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(await screen.findByRole('button', { name: '添加证书' }))
		const dialog = await findDialog('添加证书')
		expect(within(dialog).getByRole('tab', { name: '单个' })).toHaveAttribute('aria-selected', 'true')
		expect(within(dialog).getByRole('tab', { name: '批量申请' })).toBeInTheDocument()
		const zerossl = await within(dialog).findByRole('button', { name: /ZeroSSL/ })
		// 平台默认 Let's Encrypt 预选；未配置的 Google Trust 不显示
		expect(within(dialog).getByRole('button', { name: /Let's Encrypt/ })).toHaveAttribute('aria-pressed', 'true')
		expect(within(dialog).queryByRole('button', { name: /Google Trust/ })).not.toBeInTheDocument()
		// 切到自己上传再切回，名称保留
		await user.type(within(dialog).getByLabelText('证书名称'), 'shop')
		await user.click(within(dialog).getByRole('button', { name: /自己上传/ }))
		expect(within(dialog).getByLabelText('证书 PEM')).toBeInTheDocument()
		expect(within(dialog).getByLabelText('名称')).toHaveValue('shop')
		await user.click(zerossl)
		expect(within(dialog).queryByLabelText('证书 PEM')).not.toBeInTheDocument()
		expect(within(dialog).getByLabelText('证书名称')).toHaveValue('shop')
		await user.type(within(dialog).getByLabelText('域名'), 'www.example.com example.com')
		await user.click(within(dialog).getByRole('combobox', { name: '验证方式' }))
		await user.click((await screen.findAllByText(/HTTP-01/)).at(-1)!)
		await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
		await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
		expect(create.mock.calls[0][1]).toMatchObject({ name: 'shop', issuer: 'zerossl', domains: ['example.com', 'www.example.com'] })
	})

	it('preselects 自己上传 when the saved default certificate type is uploaded', async () => {
		authenticate(['certificates.read', 'certificates.manage', 'dns.read'])
		vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt'], default: 'lets_encrypt' })
		vi.spyOn(certificatesApi, 'getDefaults').mockResolvedValue({
			scope_id: asset.tenant_scope_id, user_id: '11111111-1111-4111-8111-111111111111',
			certificate_type: 'uploaded', revision: 1, updated_at: '2026-09-30T02:00:00Z',
		})
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(await screen.findByRole('button', { name: '添加证书' }))
		const dialog = await findDialog('添加证书')
		await waitFor(() => expect(within(dialog).getByRole('button', { name: /自己上传/ })).toHaveAttribute('aria-pressed', 'true'))
		expect(within(dialog).getByLabelText('证书 PEM')).toBeInTheDocument()
	})

	// 批量申请：每行一个独立订单、独立幂等键；明确失败换新键重试，结果未知用原键重试
	it('creates one order per batch line with its own key and retries only the lines that did not succeed', async () => {
		authenticate(['certificates.read', 'certificates.manage', 'dns.read'])
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
		vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt', 'zerossl'], default: 'zerossl' })
		const order = (domains: string[]) => ({ ...activeOrder, domains, status: 'pending', challenge_type: 'dns-01', dns_provider_id: provider.id, auto_renew: true, issuer: 'zerossl' } as CertificateOrder)
		const create = vi.spyOn(certificatesApi, 'create')
			.mockResolvedValueOnce(order(['a.example.com']))
			.mockRejectedValueOnce(new ApiError('lost', 0, 'network_error'))
			.mockRejectedValueOnce(new ApiError('bad', 422, 'certificate_order_invalid'))
			.mockResolvedValueOnce(order(['b.example.com', 'www.b.example.com']))
			.mockResolvedValueOnce(order(['*.c.example.com']))
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(await screen.findByRole('button', { name: '添加证书' }))
		const dialog = await findDialog('添加证书')
		await user.click(within(dialog).getByRole('tab', { name: '批量申请' }))
		expect(within(dialog).queryByRole('button', { name: /自己上传/ })).not.toBeInTheDocument()
		expect(within(dialog).getByRole('button', { name: /ZeroSSL/ })).toHaveAttribute('aria-pressed', 'true')
		await user.type(within(dialog).getByLabelText('批量域名'), 'a.example.com{enter}www.b.example.com b.example.com{enter}{enter}*.c.example.com')
		// 唯一可用的 DNS 服务商自动选中
		expect(await within(dialog).findByTitle(provider.name)).toBeInTheDocument()
		await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
		await waitFor(() => expect(create).toHaveBeenCalledTimes(3))
		expect(create.mock.calls.map((call) => call[1].domains)).toEqual([['a.example.com'], ['b.example.com', 'www.b.example.com'], ['*.c.example.com']])
		expect(create.mock.calls[0][1]).toMatchObject({ challenge_type: 'dns-01', dns_provider_id: provider.id, issuer: 'zerossl', auto_renew: true })
		expect(new Set(create.mock.calls.map((call) => call[2])).size).toBe(3)
		expect(await within(dialog).findByText('已受理 1 行，未成功 2 行。')).toBeInTheDocument()
		expect(within(dialog).getByText('结果待确认')).toBeInTheDocument()
		expect(within(dialog).getByText('失败')).toBeInTheDocument()
		await user.click(within(dialog).getByRole('button', { name: '重试未成功的行' }))
		await waitFor(() => expect(create).toHaveBeenCalledTimes(5))
		// 结果未知的行（第 2 行）用原键；明确失败的行（第 4 行）换新键
		expect(create.mock.calls[3][2]).toBe(create.mock.calls[1][2])
		expect(create.mock.calls[4][2]).not.toBe(create.mock.calls[2][2])
		expect(await within(dialog).findByText('已受理 3 行，未成功 0 行。')).toBeInTheDocument()
		expect(within(dialog).queryByRole('button', { name: '重试未成功的行' })).not.toBeInTheDocument()
	})

	it('rejects invalid batch lines and wildcard lines without a DNS API before creating anything', async () => {
		authenticate(['certificates.read', 'certificates.manage', 'dns.read'])
		vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
		vi.spyOn(certificatesApi, 'listIssuers').mockResolvedValue({ items: ['lets_encrypt'], default: 'lets_encrypt' })
		const create = vi.spyOn(certificatesApi, 'create')
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await user.click(await screen.findByRole('button', { name: '添加证书' }))
		const dialog = await findDialog('添加证书')
		await user.click(within(dialog).getByRole('tab', { name: '批量申请' }))
		await user.type(within(dialog).getByLabelText('批量域名'), 'ok.example.com{enter}bad_domain{enter}*.w.example.com')
		await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
		expect(await within(dialog).findByText('第 2 行域名格式无效、重复或超过 100 个')).toBeInTheDocument()
		expect(within(dialog).getByText('第 3 行含通配符域名，必须选择 DNS API')).toBeInTheDocument()
		expect(create).not.toHaveBeenCalled()
	})

	it('supports DNS API provider create, edit, verify, and delete for dns.manage users', async () => {
    authenticate(['certificates.read', 'certificates.manage', 'dns.read', 'dns.manage'])
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    const list = vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    const created = { ...provider, id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: 'Cloudflare created', status: 'unverified' as const }
    let createInput: unknown
    const create = vi.spyOn(dnsApi, 'create').mockImplementation(async (_token, input) => {
      createInput = { ...input, credentials: { ...input.credentials } }
      return created
    })
    let updateInput: unknown
    const update = vi.spyOn(dnsApi, 'update').mockImplementation(async (_token, id, providerType, input) => {
      updateInput = { id, providerType, input: { ...input, ...(input.credentials ? { credentials: { ...input.credentials } } : {}) } }
      return { ...created, id: provider.id, name: 'Cloudflare updated', version: 3 }
    })
    const verify = vi.spyOn(dnsApi, 'verify').mockResolvedValue({ ...created, id: provider.id, name: 'Cloudflare updated', status: 'verified', version: 3 })
    const remove = vi.spyOn(dnsApi, 'remove').mockResolvedValue(undefined)
    const user = userEvent.setup()

    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await user.click(screen.getByRole('tab', { name: 'DNS API' }))
    expect(await screen.findByText('Cloudflare primary')).toBeInTheDocument()
    expect(screen.getAllByText('共 1 条')).toHaveLength(2)

    await user.click(screen.getByRole('button', { name: '新增 DNS API' }))
    const createDialog = getDialog('新增DNS API')
    await user.type(within(createDialog).getByLabelText('名称'), 'Cloudflare created')
    await user.type(within(createDialog).getByLabelText('API Token'), 'create-token')
    await user.click(within(createDialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(createInput).toEqual({
      name: 'Cloudflare created', remark: '', provider_type: 'cloudflare', credentials: { api_token: 'create-token' },
    })
    expect(create.mock.calls[0]?.[2]).toMatch(/^certificate-dns-provider-create-/)

    await user.click(screen.getByRole('button', { name: '编辑Cloudflare primary' }))
    const editDialog = getDialog('编辑 DNS 服务商')
    await user.clear(within(editDialog).getByLabelText('名称'))
    await user.type(within(editDialog).getByLabelText('名称'), 'Cloudflare updated')
    await user.click(within(editDialog).getByRole('switch', { name: '替换凭据' }))
    await user.type(within(editDialog).getByLabelText('API Token'), 'updated-token')
    await user.click(within(editDialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    expect(updateInput).toEqual({
      id: provider.id,
      providerType: 'cloudflare',
      input: { expected_version: provider.version, name: 'Cloudflare updated', remark: '', status: 'unverified', credentials: { api_token: 'updated-token' } },
    })
    await waitFor(() => expect(queryDialog('编辑 DNS 服务商')).not.toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: '验证Cloudflare primary' }))
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1))
    expect(verify.mock.calls[0]?.slice(1)).toEqual([
      provider.id, 'cloudflare', provider.version, expect.stringMatching(/^certificate-dns-provider-verify-/),
    ])

    await user.click(screen.getByRole('button', { name: '删除Cloudflare primary' }))
    const confirmText = await screen.findByText('确定删除这个 DNS 服务商吗？')
    const confirm = confirmText.closest('.ant-popconfirm') ?? confirmText.parentElement
    if (!confirm) throw new Error('DNS provider delete confirmation not found')
    await user.click(within(confirm as HTMLElement).getByRole('button', { name: '删除' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1))
    expect(remove.mock.calls[0]?.slice(1)).toEqual([
      provider.id, provider.version, expect.stringMatching(/^certificate-dns-provider-delete-/),
    ])
    expect(list).toHaveBeenCalled()
  })

  it('creates a Name.com DNS provider with username + API token and warns that carrier lines are unavailable', async () => {
    authenticate(['certificates.read', 'certificates.manage', 'dns.read', 'dns.manage'])
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
    let createInput: unknown
    const create = vi.spyOn(dnsApi, 'create').mockImplementation(async (_token, input) => {
      createInput = { ...input, credentials: { ...input.credentials } }
      return { ...provider, name: 'Name.com', provider_type: 'namecom', status: 'unverified' as const }
    })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await user.click(screen.getByRole('tab', { name: 'DNS API' }))
    await user.click(screen.getByRole('button', { name: '新增 DNS API' }))
    const dialog = getDialog('新增DNS API')
    // The default provider Cloudflare writes the default line only (NET-03).
    expect(within(dialog).getByText(/不支持按运营商分线路/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('combobox', { name: 'DNS 服务商' }))
    await user.click(await screen.findByText('Name.com', { selector: '.ant-select-item-option-content' }))
    expect(await within(dialog).findByText(/该服务商不支持按运营商分线路/)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('名称'), 'Name.com')
    await user.type(within(dialog).getByLabelText('用户名'), 'fixture:user')
    await user.type(within(dialog).getByLabelText('API Token'), 'fixture-token')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText('请输入有效的凭据字段')).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
    await user.clear(within(dialog).getByLabelText('用户名'))
    await user.type(within(dialog).getByLabelText('用户名'), 'fixture-user')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(createInput).toEqual({
      name: 'Name.com', remark: '', provider_type: 'namecom', credentials: { username: 'fixture-user', api_token: 'fixture-token' },
    })
  })

  it('keeps DNS credentials in the same-request retry path and clears them after closing an unknown result', async () => {
    authenticate(['certificates.read', 'certificates.manage', 'dns.read', 'dns.manage'])
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
    const create = vi.spyOn(dnsApi, 'create')
      .mockRejectedValueOnce(new ApiError('private provider failure', 500, 'provider_verification_unavailable'))
      .mockResolvedValueOnce({ ...provider, name: 'Retry provider' })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await user.click(screen.getByRole('tab', { name: 'DNS API' }))
    await user.click(screen.getByRole('button', { name: '新增 DNS API' }))
    const dialog = getDialog('新增DNS API')
    await user.type(within(dialog).getByLabelText('名称'), 'Retry provider')
    await user.type(within(dialog).getByLabelText('API Token'), 'retry-secret')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    expect(await within(dialog).findByText('操作结果待确认')).toBeInTheDocument()
    const first = create.mock.calls[0]!
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(create.mock.calls[1]).toEqual(first)
    expect(queryDialog('新增DNS API')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private provider failure')
  })

	it('shows backend failure codes and the retry reason of in-progress orders (FX10)', async () => {
		authenticate(['certificates.read'])
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({
			items: [{ ...failedOrder, failure_code: 'acme_http01_node_aggregate_required' },
				{ ...failedOrder, id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', status: 'validating', failure_code: undefined,
					retry_error_code: 'acme_timeout' }],
		})
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openOrderHistory(user)
		expect(await screen.findByText('当前版本不支持文件验证（HTTP-01），请改用 DNS 验证')).toBeInTheDocument()
		expect(screen.getByText('重试中：证书签发处理超时，将自动重试')).toBeInTheDocument()
		expect(screen.queryByText(/acme_/)).not.toBeInTheDocument()
	})

	// 分类文案后显示 CA 给出的具体原因（已在服务端脱敏、≤512 字符），可展开。
	it('shows the CA reason after the failure category and expands it', async () => {
		authenticate(['certificates.read'])
		const reason = 'www.example.test: Invalid response from [url]: 404'
		const long = 'DNS problem: NXDOMAIN looking up A for api.example.test - check that a DNS record exists for this domain; '.repeat(2).trim()
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({
			items: [{ ...failedOrder, failure_code: 'acme_authorization_invalid', failure_reason: reason },
				{ ...failedOrder, id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', status: 'validating', failure_code: undefined,
					retry_error_code: 'acme_timeout', retry_error_reason: 'Service busy' },
				{ ...failedOrder, id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', failure_code: 'acme_order_rejected', failure_reason: long }],
		})
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openOrderHistory(user)
		const category = await screen.findByText('证书签发机构验证域名失败')
		const detail = screen.getByText(reason)
		expect(detail).toHaveAttribute('title', reason)
		expect(category.closest('.certificate-failure')).toContainElement(detail)
		expect(screen.getByText('Service busy')).toBeInTheDocument()
		// 只有长原因有展开按钮。
		expect(screen.getAllByRole('button', { name: '展开原因' })).toHaveLength(1)
		await user.click(screen.getByRole('button', { name: '展开原因' }))
		expect(screen.getByRole('button', { name: '收起原因' })).toHaveAttribute('aria-expanded', 'true')
	})

	it('gives the failure reason the widest column, two lines and the full text on hover', async () => {
		authenticate(['certificates.read'])
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({
			items: [{ ...failedOrder, challenge_type: 'http-01', failure_code: 'acme_http01_no_serving_node' }],
		})
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openOrderHistory(user)
		const full = '域名不是可用站点或站点线路组没有可用节点，无法进行文件验证（HTTP-01）'
		const cell = await screen.findByText(full)
		expect(cell).toHaveClass('certificate-failure-cell')
		expect(cell).toHaveAttribute('title', full)
		// 固定表格布局，列宽按 colgroup 生效；失败原因列是最宽的一列。
		const table = within(screen.getByTestId('certificate-table-scroll')).getByRole('table')
		expect(table.style.tableLayout).toBe('fixed')
		const widths = [...table.querySelectorAll('colgroup col')].map((col) => Number.parseInt((col as HTMLElement).style.width, 10))
		const headers = within(table).getAllByRole('columnheader').map((th) => th.textContent)
		expect(widths[headers.indexOf('失败原因')]).toBe(Math.max(...widths))
	})

	it('localizes known and unknown failure codes in the generated pseudo locale', async () => {
		await changeLocale('qps-ploc')
		authenticate(['certificates.read'])
		vi.spyOn(certificatesApi, 'list').mockResolvedValue({
			items: [failedOrder, { ...failedOrder, id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', failure_code: 'private_ca_english' }],
		})
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		await openOrderHistory(user, /更~多~操~作~/, /申~请~记~录~/)
		expect(await screen.findByText(/D~N~S~ 解~析~等~待~超~时~/)).toBeInTheDocument()
		expect(screen.getByText(/证~书~申~请~失~败/)).toBeInTheDocument()
		expect(screen.queryByText(/private_ca_english|dns_propagation_timeout/)).not.toBeInTheDocument()
	})

	it('shows detail and delete failures and retries unknown deletes exactly', async () => {
		authenticate()
		vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		const detail = vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
		const remove = vi.spyOn(certificatesApi, 'deleteAsset')
			.mockRejectedValueOnce(new ApiError('private upstream failure', 500, 'certificate_asset_internal_error'))
			.mockResolvedValue({ ...asset, deleted_at: '2026-08-01T00:00:00Z' })
		const user = userEvent.setup()
		renderWithProviders(<CertificateListPage />, ['/site/cert'])
		expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
		await waitFor(() => expect(detail).toHaveBeenCalledTimes(1))
		detail.mockRejectedValueOnce(new ApiError('private forbidden detail', 403, 'certificate_asset_permission_denied'))

		await user.click(screen.getByRole('button', { name: '查看详情' }))
		expect(await screen.findByText('当前账号缺少证书资产权限')).toBeInTheDocument()
		expect(screen.queryByText('private forbidden detail')).not.toBeInTheDocument()
		detail.mockResolvedValue(assetDetail)

		await rowAction(user, '删除')
		const deleteDialog = await findDialog('删除证书')
		await user.click(within(deleteDialog).getByRole('button', { name: '确认删除' }))
		expect(await within(deleteDialog).findByText('操作结果待确认')).toBeInTheDocument()
		await user.click(within(deleteDialog).getByRole('button', { name: '使用同一请求重试' }))
		await waitFor(() => expect(remove).toHaveBeenCalledTimes(2))
		expect(remove.mock.calls[1]).toEqual(remove.mock.calls[0])
		expect(screen.queryByText('private upstream failure')).not.toBeInTheDocument()
		expect(detail).toHaveBeenCalledTimes(2)
	})

  it('maps list failures locally, including permission denial, without exposing server messages', async () => {
    authenticate(['certificates.read'])
    vi.spyOn(certificatesApi, 'list').mockRejectedValueOnce(new ApiError('private role row', 403, 'permission_denied'))
    const user = userEvent.setup()
    const view = renderWithProviders(<CertificateListPage />, ['/site/cert'])

    await openOrderHistory(user)

    expect(await screen.findByText('无权查看证书管理')).toBeInTheDocument()
    expect(screen.queryByText('private role row')).not.toBeInTheDocument()

    view.unmount()
    authenticate(['certificates.read'])
    vi.spyOn(certificatesApi, 'list').mockRejectedValue(new ApiError('private database detail', 500, 'internal_error'))
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openOrderHistory(user)
    expect(await screen.findByText('证书申请加载失败')).toBeInTheDocument()
    expect(screen.queryByText('private database detail')).not.toBeInTheDocument()
  })

  it('requires DNS-01 and a provider for wildcard domains and reports 202 as pending issuance', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    // 两个服务商：不自动选中，必须选择
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider, { ...provider, id: '56565656-5656-4565-8565-565656565656', name: 'Aliyun backup' }] })
    const create = vi.spyOn(certificatesApi, 'create').mockResolvedValue({
      ...activeOrder,
      domains: ['*.example.com', 'www.example.com'],
      challenge_type: 'dns-01',
      dns_provider_id: provider.id,
      status: 'pending',
    })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    await openOrderHistory(user)
    expect(await screen.findByText('暂无证书申请')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText('域名'), '*.Example.com.\nwww.example.com')
    expect(within(dialog).getByRole('switch', { name: '自动续期' })).toBeChecked()
    expect(within(dialog).getByText('DNS-01')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    expect(await within(dialog).findByText('DNS-01 验证必须选择 DNS 服务商')).toBeInTheDocument()

    await user.click(within(dialog).getByLabelText('DNS 服务商'))
    await user.click(await screen.findByText('Cloudflare primary'))
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    expect(create.mock.calls[0][1]).toEqual({
      domains: ['*.example.com', 'www.example.com'],
      challenge_type: 'dns-01',
      dns_provider_id: provider.id,
      auto_renew: true,
    })
    expect(await screen.findByText('证书申请已提交')).toBeInTheDocument()
    expect(screen.getByText('系统已受理申请并进入待签发流程，请在列表中查看后续状态。')).toBeInTheDocument()
    expect(screen.queryByText('证书签发成功')).not.toBeInTheDocument()
  })

  // 10-26 用户实机：500 不再判"结果未知"锁表单。先按幂等键回放取真实结果；
  // 回放也失败就提示原因，表单不锁，再点提交复用同一幂等键。
  it('replays a 500 by its idempotency key and shows the real result', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    const create = vi.spyOn(certificatesApi, 'create')
      .mockRejectedValueOnce(new ApiError('private upstream failure', 500, 'internal_error'))
      .mockResolvedValue({ ...activeOrder, domains: ['example.com'], challenge_type: 'dns-01', dns_provider_id: provider.id, status: 'pending' })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    await openOrderHistory(user)
    await screen.findByText('暂无证书申请')
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText('域名'), 'example.com')
    // 唯一可用的 DNS 服务商自动选中
    expect(await within(dialog).findByTitle('Cloudflare primary')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))

    expect(await screen.findByText('证书申请已提交')).toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(2)
    expect(create.mock.calls[1]).toEqual(create.mock.calls[0])
    expect(screen.queryByText('申请结果待确认')).not.toBeInTheDocument()
  })

  it('shows a failure that the replay cannot resolve without locking the form', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    const create = vi.spyOn(certificatesApi, 'create')
      .mockRejectedValueOnce(new ApiError('private upstream failure', 500, 'internal_error'))
      .mockRejectedValueOnce(new ApiError('private upstream failure', 500, 'internal_error'))
      .mockResolvedValue({ ...activeOrder, domains: ['example.com'], challenge_type: 'dns-01', dns_provider_id: provider.id, status: 'pending' })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    await openOrderHistory(user)
    await screen.findByText('暂无证书申请')
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText('域名'), 'example.com')
    // 唯一可用的 DNS 服务商自动选中
    expect(await within(dialog).findByTitle('Cloudflare primary')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
    expect(await within(dialog).findByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(within(dialog).queryByText('申请结果待确认')).not.toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: '使用同一请求重试' })).not.toBeInTheDocument()
    expect(within(dialog).getByLabelText('域名')).toBeEnabled()
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    expect(await screen.findByText('证书申请已提交')).toBeInTheDocument()
    expect(create.mock.calls[2]).toEqual(create.mock.calls[0])
  })

  it('reapplies an ACME certificate with the original order after one confirmation', async () => {
    authenticate()
    const sourceOrder: CertificateOrder = {
      ...activeOrder, domains: ['example.com'], challenge_type: 'dns-01', dns_provider_id: provider.id,
      auto_renew: true, issued_asset_id: asset.id, issued_version_id: assetDetail.versions[0]!.id,
    }
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [sourceOrder] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    const acmeAsset: CertificateAsset = { ...asset, source: 'acme' }
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [acmeAsset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 1, manual_renew: 0 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({
      ...assetDetail, asset: acmeAsset, versions: [{ ...assetDetail.versions[0]!, acme_order_id: sourceOrder.id }],
    })
    const create = vi.spyOn(certificatesApi, 'create')
      .mockRejectedValueOnce(new ApiError('private upstream failure', 500, 'internal_error'))
      .mockResolvedValue({ ...sourceOrder, id: '88888888-8888-4888-8888-888888888888', status: 'pending' })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    const row = (await screen.findByText(asset.name)).closest('tr')!
    await waitFor(() => expect(within(row).getByRole('button', { name: '重新申请' })).toBeEnabled())
    await user.click(within(row).getByRole('button', { name: '重新申请' }))
    const dialog = await findDialog('重新申请证书')
    expect(within(dialog).getByText(`重新申请 ${asset.name}（example.com）？将沿用原证书的域名、验证方式、DNS 服务商和自动续期设置。`)).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('域名')).not.toBeInTheDocument()
    expect(queryDialog('申请证书')).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '确认重新申请' }))

    expect(await screen.findByText('已提交重新申请')).toBeInTheDocument()
    expect(create).toHaveBeenCalledTimes(2)
    expect(create.mock.calls[0]![1]).toEqual({
      domains: ['example.com'], challenge_type: 'dns-01', auto_renew: true, dns_provider_id: provider.id,
    })
    expect(create.mock.calls[1]).toEqual(create.mock.calls[0])
    expect(queryDialog('重新申请证书')).not.toBeInTheDocument()
    expect(screen.queryByText('申请结果待确认')).not.toBeInTheDocument()
  })

  // 重新申请点击后要有即时反馈；手动上传证书不能重新申请。
  it('toasts a reapply, shows the row as 申请中 at once, and blocks a second reapply', async () => {
    authenticate()
    const acmeAsset: CertificateAsset = { ...asset, source: 'acme' }
    const sourceOrder: CertificateOrder = {
      ...activeOrder, domains: ['example.com'], challenge_type: 'dns-01', dns_provider_id: provider.id,
      auto_renew: true, issued_asset_id: asset.id,
    }
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [sourceOrder] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [acmeAsset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 1, manual_renew: 0 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({ ...assetDetail, asset: acmeAsset, versions: [{ ...assetDetail.versions[0]!, acme_order_id: sourceOrder.id }] })
    const pending = deferred<CertificateOrder>()
    vi.spyOn(certificatesApi, 'create').mockReturnValue(pending.promise)
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    const row = (await screen.findByText(asset.name)).closest('tr')!
    await waitFor(() => expect(within(row).getByRole('button', { name: '重新申请' })).toBeEnabled())
    await user.click(within(row).getByRole('button', { name: '重新申请' }))
    const dialog = await findDialog('重新申请证书')
    await user.click(within(dialog).getByRole('button', { name: '确认重新申请' }))
    await waitFor(() => expect(within(dialog).getByRole('button', { name: /确认重新申请/ })).toHaveClass('ant-btn-loading'))
    // 列表不重拉也要立刻显示（回执写进申请记录缓存）
    vi.mocked(certificatesApi.list).mockReturnValue(new Promise(() => undefined))
    pending.resolve({ ...sourceOrder, id: '88888888-8888-4888-8888-888888888888', status: 'pending', issued_asset_id: undefined, not_after: undefined })

    expect(await screen.findByText('已提交重新申请')).toBeInTheDocument()
    expect(await within(row).findByText('申请中')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: '重新申请' })).toBeDisabled()
  })

  // 同域名两张证书（手动上传 + ACME 已签发）都一直标“申请中”，
  // 因为有一笔早于当前版本、卡在 validating 的旧订单。
  it('marks 申请中 only for newer unissued orders of ACME certificates and links it to 申请记录', async () => {
    authenticate()
    const acmeAsset: CertificateAsset = { ...asset, id: '99999999-9999-4999-8999-999999999999', display_id: '2', name: 'ACME 证书', source: 'acme' }
    const versionAt = '2026-10-26T16:57:36Z'
    const version = { ...assetDetail.versions[0]!, imported_at: versionAt }
    const staleStuck: CertificateOrder = {
      ...activeOrder, id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', domains: ['example.com'], status: 'validating',
      not_after: undefined, created_at: '2026-10-26T15:42:36Z', updated_at: '2026-10-26T15:42:37Z',
    }
    const issued: CertificateOrder = {
      ...activeOrder, id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', domains: ['example.com'], status: 'issued',
      issued_asset_id: acmeAsset.id, created_at: '2026-10-26T16:55:25Z',
    }
    const orders = { items: [staleStuck, issued] }
    vi.spyOn(certificatesApi, 'list').mockResolvedValue(orders)
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset, acmeAsset], total: 2, counts: { all: 2, normal: 2, expiring: 0, expired: 0, auto_renew: 1, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockImplementation(async (_token, id) => (
      id === acmeAsset.id
        ? { ...assetDetail, asset: acmeAsset, versions: [{ ...version, asset_id: acmeAsset.id, acme_order_id: issued.id }] }
        : { ...assetDetail, versions: [version] }))
    const user = userEvent.setup()
    const view = renderWithProviders(<CertificateListPage />, ['/site/cert'])

    const uploadedRow = (await screen.findByText(asset.name)).closest('tr')!
    const acmeRow = screen.getByText(acmeAsset.name).closest('tr')!
    await waitFor(() => expect(within(acmeRow).getByRole('button', { name: '重新申请' })).toBeEnabled())
    expect(within(uploadedRow).queryByText('申请中')).not.toBeInTheDocument()
    expect(within(acmeRow).queryByText('申请中')).not.toBeInTheDocument()

    // 比当前版本新、未产出证书的申请才算；手动上传证书永远不标。
    const newer: CertificateOrder = { ...staleStuck, id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', created_at: '2026-10-26T18:00:00Z', updated_at: '2026-10-26T18:00:00Z' }
    vi.mocked(certificatesApi.list).mockResolvedValue({ items: [...orders.items, newer] })
    view.unmount()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const acmeRow2 = (await screen.findByText(acmeAsset.name)).closest('tr')!
    const applying = await within(acmeRow2).findByRole('button', { name: '申请中' })
    expect(within(screen.getByText(asset.name).closest('tr')!).queryByText('申请中')).not.toBeInTheDocument()
    await user.click(applying)
    expect(await screen.findByText('证书 example.com 的申请记录')).toBeInTheDocument()
  })

  it('flags orders still validating after an hour in 申请记录', async () => {
    authenticate(['certificates.read'])
    const hourAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    const fresh = new Date().toISOString()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [
      { ...failedOrder, status: 'validating', failure_code: undefined, created_at: hourAgo, updated_at: hourAgo },
      { ...failedOrder, id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', domains: ['fresh.example.net'], status: 'validating', failure_code: undefined, created_at: fresh, updated_at: fresh },
    ] })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await openOrderHistory(user)
    const stuckRow = (await screen.findByText('failed.example.net')).closest('tr')!
    expect(within(stuckRow).getByText('超过 1 小时未完成')).toBeInTheDocument()
    expect(within(screen.getByText('fresh.example.net').closest('tr')!).queryByText('超过 1 小时未完成')).not.toBeInTheDocument()
  })

  it('keeps reapply failures readable in the confirmation', async () => {
    authenticate()
    const acmeAsset: CertificateAsset = { ...asset, source: 'acme' }
    const sourceOrder: CertificateOrder = { ...activeOrder, domains: ['example.com'], issued_asset_id: asset.id }
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [sourceOrder] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [acmeAsset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 1, manual_renew: 0 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({ ...assetDetail, asset: acmeAsset })
    vi.spyOn(certificatesApi, 'create').mockRejectedValue(new ApiError('private', 422, 'domain_blocked'))
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const row = (await screen.findByText(asset.name)).closest('tr')!
    await waitFor(() => expect(within(row).getByRole('button', { name: '重新申请' })).toBeEnabled())
    await user.click(within(row).getByRole('button', { name: '重新申请' }))
    const dialog = await findDialog('重新申请证书')
    await user.click(within(dialog).getByRole('button', { name: '确认重新申请' }))
    expect(await within(dialog).findByText('可直接再次确认重新申请。')).toBeInTheDocument()
    expect(within(dialog).queryByText('private')).not.toBeInTheDocument()
    expect(screen.queryByText('已提交重新申请')).not.toBeInTheDocument()
  })

  it('disables reapply for manually uploaded certificates and explains why on hover', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const create = vi.spyOn(certificatesApi, 'create')
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const row = (await screen.findByText(asset.name)).closest('tr')!
    await screen.findAllByText('example.com')
    const button = within(row).getByRole('button', { name: '重新申请' })
    expect(button).toBeDisabled()
    await user.hover(button.closest('.certificate-blocked-action')!)
    expect(await screen.findByText(/手动上传的证书没有申请参数，不能重新申请/)).toBeInTheDocument()
    expect(queryDialog('申请证书')).not.toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
  })

  // 行内 更多 > 禁用/启用、下载证书；表头 更多操作 批量。
  it('disables and re-enables a certificate from the row 更多 menu, explaining a bound refusal', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    const listAssets = vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset], total: 1 })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const setDisabled = vi.spyOn(certificatesApi, 'setAssetDisabled')
      .mockRejectedValueOnce(new ApiError('private detail', 409, 'certificate_asset_referenced'))
      .mockResolvedValueOnce({ ...asset, disabled: true, revision: 4 })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText(asset.name)
    await rowAction(user, '禁用')
    expect(await screen.findByText('操作失败：证书仍被网站使用，请先解绑后再禁用')).toBeInTheDocument()
    expect(screen.queryByText('private detail')).not.toBeInTheDocument()
    listAssets.mockResolvedValue({ items: [{ ...asset, disabled: true, revision: 4 }], total: 1 })
    await rowAction(user, '禁用')
    expect(await screen.findByText('证书已禁用')).toBeInTheDocument()
    const [, assetID, input, , , scopeID] = setDisabled.mock.calls[1]!
    expect([assetID, input, scopeID]).toEqual([asset.id, { disabled: true, expected_revision: 3 }, undefined])
    const row = (await screen.findByText(asset.name)).closest('tr')!
    expect(await within(row).findByText('已禁用')).toBeInTheDocument()
    // 已禁用：菜单显示“启用”、不显示“禁用”，“绑定网站”不可用。
    await user.click(within(row).getByRole('button', { name: `${asset.name} 的更多操作` }))
    expect(await screen.findByRole('menuitem', { name: '启用' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: '禁用' })).not.toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: '绑定网站' })).toHaveAttribute('aria-disabled', 'true')
  })

  it('downloads the certificate zip from the row 更多 menu and refuses revoked versions with a reason', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset], total: 1 })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const blob = new Blob(['zip'], { type: 'application/zip' })
    const download = vi.spyOn(certificatesApi, 'downloadAsset')
      .mockResolvedValueOnce({ blob, filename: 'example.com.zip' })
      .mockRejectedValueOnce(new ApiError('x', 409, 'certificate_asset_download_unavailable'))
    const createURL = vi.fn(() => 'blob:certificate')
    const revokeURL = vi.fn()
    Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: revokeURL })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText(asset.name)
    await rowAction(user, '下载证书')
    expect(await screen.findByText('证书已下载（含私钥，请妥善保管）')).toBeInTheDocument()
    const [token, assetID, requestID, scopeID] = download.mock.calls[0]!
    expect([token, assetID, scopeID]).toEqual(['memory-only-access-token', asset.id, undefined])
    expect(requestID).toMatch(/^[A-Za-z0-9]/)
    expect(createURL).toHaveBeenCalledWith(blob)
    expect(click).toHaveBeenCalledTimes(1)
    expect(revokeURL).toHaveBeenCalledWith('blob:certificate')
    await rowAction(user, '下载证书')
    expect(await screen.findByText('当前版本已吊销，无法下载')).toBeInTheDocument()
    click.mockRestore()
  })

  it('runs toolbar 更多操作 bulk actions only on applicable selected certificates', async () => {
    authenticate()
    const acmeAsset: CertificateAsset = { ...asset, id: '68686868-6868-4868-8868-686868686868', display_id: '2', name: '自动签发证书', source: 'acme', auto_renew: false }
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset, acmeAsset], total: 2 })
    vi.spyOn(certificatesApi, 'getAsset').mockImplementation(async (_token, id) => id === acmeAsset.id
      ? { asset: acmeAsset, versions: [{ ...assetDetail.versions[0]!, id: '79797979-7979-4979-8979-797979797979', asset_id: acmeAsset.id }] }
      : assetDetail)
    const setAutoRenew = vi.spyOn(certificatesApi, 'setAssetAutoRenew').mockResolvedValue({ ...acmeAsset, auto_renew: true, revision: 4 })
    const setDisabled = vi.spyOn(certificatesApi, 'setAssetDisabled').mockImplementation(async (_token, id) =>
      ({ ...(id === asset.id ? asset : acmeAsset), disabled: true, revision: 4 }))
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText(acmeAsset.name)
    for (const checkbox of screen.getAllByRole('checkbox').slice(1)) await user.click(checkbox)
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '开启续签' }))
    // 手动上传证书不能续签：只对自动签发的那张调用。
    expect(await screen.findByText('已处理 1 张证书')).toBeInTheDocument()
    expect(setAutoRenew.mock.calls.map((call) => call[1])).toEqual([acmeAsset.id])
    await user.click(screen.getByRole('button', { name: '更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '禁用' }))
    expect(await screen.findByText('已处理 2 张证书')).toBeInTheDocument()
    expect(setDisabled.mock.calls.map((call) => call[1]).sort()).toEqual([asset.id, acmeAsset.id].sort())
  })

  // 自动续签列是可直接点击的开关，读证书资产层 auto_renew。
  it('toggles auto-renew from the list with loading and refreshed counts', async () => {
    authenticate()
    const acmeAsset: CertificateAsset = { ...asset, source: 'acme', auto_renew: false }
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    const listAssets = vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [acmeAsset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({ ...assetDetail, asset: acmeAsset })
    const pending = deferred<CertificateAsset>()
    const setAutoRenew = vi.spyOn(certificatesApi, 'setAssetAutoRenew').mockReturnValue(pending.promise)
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const row = (await screen.findByText(asset.name)).closest('tr')!
    const toggle = within(row).getByRole('switch', { name: '自动续签' })
    expect(toggle).not.toBeChecked()
    expect(toggle).toBeEnabled()
    listAssets.mockResolvedValue({ items: [{ ...acmeAsset, auto_renew: true, revision: 4 }], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 1, manual_renew: 0 } })
    await user.click(toggle)
    // 立即显示为开启并 loading，等服务端确认。
    await waitFor(() => expect(toggle).toHaveClass('ant-switch-loading'))
    expect(toggle).toBeChecked()
    expect(setAutoRenew).toHaveBeenCalledTimes(1)
    const [, assetID, input, key, requestID, scopeID] = setAutoRenew.mock.calls[0]!
    expect([assetID, input, scopeID]).toEqual([asset.id, { enabled: true, expected_revision: 3 }, undefined])
    expect(key).toMatch(/^[A-Za-z0-9]/)
    expect(requestID).toMatch(/^[A-Za-z0-9]/)
    pending.resolve({ ...acmeAsset, auto_renew: true, revision: 4 })
    expect(await screen.findByText('已开启自动续签')).toBeInTheDocument()
    await waitFor(() => expect(within(row).getByRole('switch', { name: '自动续签' })).not.toHaveClass('ant-switch-loading'))
    expect(within(row).getByRole('switch', { name: '自动续签' })).toBeChecked()
    await waitFor(() => expect(listAssets.mock.calls.length).toBeGreaterThan(1))
  })

  it('rolls the auto-renew switch back and shows a readable reason on failure', async () => {
    authenticate()
    const acmeAsset: CertificateAsset = { ...asset, source: 'acme', auto_renew: true }
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [acmeAsset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 1, manual_renew: 0 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({ ...assetDetail, asset: acmeAsset })
    vi.spyOn(certificatesApi, 'setAssetAutoRenew').mockRejectedValue(new ApiError('private detail', 409, 'certificate_asset_revision_conflict'))
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const row = (await screen.findByText(asset.name)).closest('tr')!
    const toggle = within(row).getByRole('switch', { name: '自动续签' })
    expect(toggle).toBeChecked()
    await user.click(toggle)
    expect(await screen.findByText(/自动续签修改失败/)).toBeInTheDocument()
    expect(screen.queryByText('private detail')).not.toBeInTheDocument()
    await waitFor(() => expect(within(row).getByRole('switch', { name: '自动续签' })).toBeChecked())
    expect(within(row).getByRole('switch', { name: '自动续签' })).not.toHaveClass('ant-switch-loading')
  })

  it('disables the auto-renew switch for uploaded certificates and read-only users', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const setAutoRenew = vi.spyOn(certificatesApi, 'setAssetAutoRenew')
    const user = userEvent.setup()
    const view = renderWithProviders(<CertificateListPage />, ['/site/cert'])
    let row = (await screen.findByText(asset.name)).closest('tr')!
    const uploaded = within(row).getByRole('switch', { name: '自动续签' })
    expect(uploaded).toBeDisabled()
    await user.hover(uploaded.closest('.certificate-blocked-action')!)
    expect(await screen.findByText('手动上传的证书不能自动续签，到期前请重新上传')).toBeInTheDocument()
    expect(setAutoRenew).not.toHaveBeenCalled()
    view.unmount()

    authenticate(['certificates.read', 'dns.read'])
    const acmeAsset: CertificateAsset = { ...asset, source: 'acme', auto_renew: true }
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [acmeAsset], total: 1, counts: { all: 1, normal: 1, expiring: 0, expired: 0, auto_renew: 1, manual_renew: 0 } })
    vi.mocked(certificatesApi.getAsset).mockResolvedValue({ ...assetDetail, asset: acmeAsset })
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    row = (await screen.findByText(asset.name)).closest('tr')!
    const readOnly = within(row).getByRole('switch', { name: '自动续签' })
    expect(readOnly).toBeChecked()
    expect(readOnly).toBeDisabled()
    await user.hover(readOnly.closest('.certificate-blocked-action')!)
    expect(await screen.findByText('当前账号没有修改证书的权限')).toBeInTheDocument()
  })

  // 申请证书弹窗的目标用户与 DNS 服务商带入。
  it('requests for the site owner without a picker when opened from a site', async () => {
    platformSession(undefined, ['certificates.read', 'certificates.manage', 'identity.users.manage', 'dns.read', 'sites.read'])
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    const detail = vi.spyOn(sitesApi, 'detail').mockResolvedValue({
      id: binding.site_id, scope_id: asset.tenant_scope_id, owner: { id: managedTarget.id, display_id: '17', display_name: 'target-admin' },
    } as never)
    const users = vi.spyOn(usersApi, 'list')
    const create = vi.spyOn(certificatesApi, 'create').mockResolvedValue({ ...activeOrder, domains: ['www.example.com'], challenge_type: 'dns-01', dns_provider_id: provider.id, status: 'pending', scope_id: asset.tenant_scope_id })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, [`/site/cert?domains=www.example.com&site=${binding.site_id}`])

    const dialog = await findDialog('申请证书')
    expect(await within(dialog).findByDisplayValue('target-admin（ID: 17）')).toHaveAttribute('readonly')
    expect(within(dialog).queryByRole('combobox', { name: '目标用户' })).not.toBeInTheDocument()
    expect(detail).toHaveBeenCalledWith(expect.any(String), binding.site_id)
    // 唯一的 DNS 服务商自动选中
    await waitFor(() => expect(within(dialog).getByText('Cloudflare primary')).toBeInTheDocument())
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    expect(create.mock.calls[0]![1]).toMatchObject({ domains: ['www.example.com'], target_scope_id: asset.tenant_scope_id, dns_provider_id: provider.id })
    expect(users).not.toHaveBeenCalled()
  })

  it('makes users choose among several DNS providers and links to DNS API when there is none', async () => {
    authenticate()
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
    const list = vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider, { ...provider, id: '56565656-5656-4565-8565-565656565656', name: 'Aliyun backup' }] })
    const user = userEvent.setup()
    const view = renderWithProviders(<CertificateListPage />, ['/site/cert?domains=www.example.com'])
    let dialog = await findDialog('申请证书')
    await waitFor(() => expect(list).toHaveBeenCalled())
    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(within(dialog).queryByText('Cloudflare primary')).not.toBeInTheDocument()
    expect(within(dialog).getByText('选择已配置的 DNS 服务商')).toBeInTheDocument()
    view.unmount()

    list.mockResolvedValue({ items: [] })
    renderWithProviders(<CertificateListPage />, ['/site/cert?domains=www.example.com'])
    dialog = await findDialog('申请证书')
    await user.click(await within(dialog).findByRole('button', { name: '去配置 DNS API' }))
    await waitFor(() => expect(queryDialog('申请证书')).not.toBeInTheDocument())
    expect(screen.getByRole('tab', { name: 'DNS API' })).toHaveAttribute('aria-selected', 'true')
  })

  describe('receipt integrity', () => {
    it.each([
      ['name', 'mismatched receipt name', 'RECEIPT-CERTIFICATE-PEM'],
      ['certificate PEM', 'receipt upload', 'MISMATCHED-CERTIFICATE-PEM'],
    ])('keeps a mismatched upload %s receipt unknown and retries the exact frozen certificate attempt', async (_field, receiptName, receiptPEM) => {
      authenticate()
      const matchingReceipt: CertificateAssetDetail = {
        asset: { ...asset, name: 'receipt upload' },
        versions: [{ ...assetDetail.versions[0], certificate_pem: 'RECEIPT-CERTIFICATE-PEM' }],
      }
      const upload = vi.spyOn(certificatesApi, 'uploadAsset')
        .mockResolvedValueOnce({
          asset: { ...matchingReceipt.asset, name: receiptName },
          versions: [{ ...matchingReceipt.versions[0], certificate_pem: receiptPEM }],
        })
        .mockResolvedValueOnce(matchingReceipt)
      const user = userEvent.setup()
      renderWithProviders(<CertificateListPage />, ['/site/cert'])

      await screen.findByText('暂无证书资产')
      await openUpload(user)
      const dialog = getDialog('添加证书')
      await user.type(within(dialog).getByLabelText('名称'), 'receipt upload')
      await user.type(within(dialog).getByLabelText('证书 PEM'), 'RECEIPT-CERTIFICATE-PEM')
      await user.type(within(dialog).getByLabelText('私钥 PEM'), 'RECEIPT-PRIVATE-KEY')
      await user.click(within(dialog).getByRole('button', { name: '保存证书' }))

      expect(await within(dialog).findByText('操作结果待确认')).toBeInTheDocument()
      expect(within(dialog).getByLabelText('名称')).toBeDisabled()
      expect(screen.queryByText('证书申请已提交')).not.toBeInTheDocument()
      expect(getDialog('添加证书')).toBeInTheDocument()
      const frozenCall = upload.mock.calls[0]!
      await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
      await waitFor(() => expect(upload).toHaveBeenCalledTimes(2))
      expect(upload.mock.calls[1]).toEqual(frozenCall)
      await waitFor(() => expect(queryDialog('添加证书')).not.toBeInTheDocument())
      expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    })

    it.each([
      ['domains', { domains: ['mismatched-receipt.example.com'] }],
      ['challenge', { challenge_type: 'http-01' as const }],
      ['DNS provider', { dns_provider_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }],
      ['auto renew', { auto_renew: false }],
    ])('keeps a create-order receipt with mismatched %s unknown and retries the exact normalized request', async (_field, patch) => {
      authenticate()
      vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
      vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
      const matchingReceipt: CertificateOrder = {
        ...activeOrder,
        domains: ['*.example.com', 'www.example.com'],
        challenge_type: 'dns-01',
        dns_provider_id: provider.id,
        auto_renew: true,
        status: 'pending',
      }
      const create = vi.spyOn(certificatesApi, 'create')
        .mockResolvedValueOnce({ ...matchingReceipt, ...patch } as CertificateOrder)
        .mockResolvedValueOnce(matchingReceipt)
      const user = userEvent.setup()
      renderWithProviders(<CertificateListPage />, ['/site/cert'])

      await openOrderHistory(user)
      await screen.findByText('暂无证书申请')
      await user.click(screen.getByRole('button', { name: '申请证书' }))
      const dialog = getDialog('申请证书')
      await user.type(within(dialog).getByLabelText('域名'), '*.Example.com.\nwww.Example.com')
      // 唯一可用的 DNS 服务商自动选中
      expect(await within(dialog).findByTitle('Cloudflare primary')).toBeInTheDocument()
      await user.click(within(dialog).getByRole('button', { name: '提交申请' }))

      expect(await within(dialog).findByText('申请结果待确认')).toBeInTheDocument()
      expect(within(dialog).getByLabelText('域名')).toBeDisabled()
      expect(screen.queryByText('证书申请已提交')).not.toBeInTheDocument()
      expect(getDialog('申请证书')).toBeInTheDocument()
      const frozenCall = create.mock.calls[0]!
      expect(frozenCall[1]).toEqual({
        domains: ['*.example.com', 'www.example.com'],
        challenge_type: 'dns-01', dns_provider_id: provider.id, auto_renew: true,
      })
      await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
      await waitFor(() => expect(create).toHaveBeenCalledTimes(2))
      expect(create.mock.calls[1]).toEqual(frozenCall)
      expect(await screen.findByText('证书申请已提交')).toBeInTheDocument()
      expect(queryDialog('申请证书')).not.toBeInTheDocument()
    })

    it.each([
      ['activate wrong status'],
      ['delete missing deleted_at'],
      ['bind bound false'],
      ['bind default mismatch'],
      ['unbind bound true'],
    ] as const)('keeps %s unknown and retries the exact command receipt', async (scenario) => {
      authenticate()
      vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
      vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({
        ...assetDetail,
        versions: [assetDetail.versions[0], pendingVersion],
      })
      vi.mocked(certificatesApi.listAssetBindings).mockResolvedValue({
        items: scenario === 'unbind bound true' ? [binding] : [],
      })
      const user = userEvent.setup()
      let calls = (): unknown[][] => []
      let workflowDialog!: HTMLElement

      if (scenario === 'activate wrong status') {
        const command = vi.spyOn(certificatesApi, 'activateAssetVersion')
          .mockResolvedValueOnce(pendingVersion)
          .mockResolvedValueOnce({ ...pendingVersion, status: 'active' })
        calls = () => command.mock.calls as unknown[][]
      } else if (scenario === 'delete missing deleted_at') {
        const command = vi.spyOn(certificatesApi, 'deleteAsset')
          .mockResolvedValueOnce(asset)
          .mockResolvedValueOnce({ ...asset, deleted_at: '2026-08-01T00:00:00Z' })
        calls = () => command.mock.calls as unknown[][]
      } else if (scenario === 'bind bound false' || scenario === 'bind default mismatch') {
        const matchingBinding = { ...binding, default: false, bound: true }
        const command = vi.spyOn(certificatesApi, 'bindAsset')
          .mockResolvedValueOnce(scenario === 'bind bound false'
            ? { ...matchingBinding, bound: false }
            : { ...matchingBinding, default: true })
          .mockResolvedValueOnce(matchingBinding)
        calls = () => command.mock.calls as unknown[][]
      } else {
        const command = vi.spyOn(certificatesApi, 'unbindAsset')
          .mockResolvedValueOnce({ ...binding, revision: 2, bound: true })
          .mockResolvedValueOnce({ ...binding, revision: 2, bound: false })
        calls = () => command.mock.calls as unknown[][]
      }

      renderWithProviders(<CertificateListPage />, ['/site/cert'])
      await screen.findByText('边缘站点证书')

      if (scenario === 'activate wrong status') {
        await user.click(screen.getByRole('button', { name: '查看详情' }))
        workflowDialog = await findDialog('证书详情')
        await user.click(within(workflowDialog).getByRole('button', { name: '激活版本' }))
      } else if (scenario === 'delete missing deleted_at') {
        await rowAction(user, '删除')
        workflowDialog = await findDialog('删除证书')
        await user.click(within(workflowDialog).getByRole('button', { name: '确认删除' }))
      } else if (scenario === 'bind bound false' || scenario === 'bind default mismatch') {
        await user.click(screen.getByRole('button', { name: '查看详情' }))
        const detailDialog = await findDialog('证书详情')
        await user.click(within(detailDialog).getByRole('button', { name: '绑定网站' }))
        workflowDialog = await findDialog('绑定网站')
        await user.type(within(workflowDialog).getByLabelText('网站'), binding.site_id)
        await user.click(within(workflowDialog).getByRole('button', { name: '确认绑定' }))
      } else {
        await user.click(screen.getByRole('button', { name: '查看详情' }))
        workflowDialog = await findDialog('证书详情')
        await user.click(within(workflowDialog).getByRole('button', { name: '解绑' }))
      }

      expect(await within(workflowDialog).findByText('操作结果待确认')).toBeInTheDocument()
      expect(screen.queryByText('证书申请已提交')).not.toBeInTheDocument()
      expect(calls()).toHaveLength(1)
      const frozenCall = calls()[0]
      // 证书详情 shows OutcomeUnknown: while its outcome dialog is open the retry
      // button is there, not in the details dialog (f3f426931).
      const outcome = document.querySelector<HTMLElement>('.cdnca-feedback')
      await user.click(within(outcome && within(outcome).queryByRole('button', { name: '使用同一请求重试' }) ? outcome : workflowDialog)
        .getByRole('button', { name: '使用同一请求重试' }))
      await waitFor(() => expect(calls()).toHaveLength(2))
      expect(calls()[1]).toEqual(frozenCall)
      await waitFor(() => expect(document.body).not.toHaveTextContent('操作结果待确认'))
    })
  })

  it.each([
    ['unauthenticated', null],
    ['incomplete tenant owner', principal({ tenant_id: null, permissions: ['certificates.read', 'certificates.manage', 'dns.read'] })],
    ['tenant missing certificates.read', principal({ permissions: ['certificates.manage', 'dns.read'] })],
  ])('denies %s locally before every certificate or DNS request', async (_name, actor) => {
    if (actor) useSessionStore.getState().setSession(authResponse(actor), actor)
    else useSessionStore.getState().clearSession()
    const apiSpies = allCertificateApiSpies()

    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    await waitFor(() => {
      if (actor) expect(screen.getByText('无权查看证书管理')).toBeInTheDocument()
      else expect(screen.queryByRole('heading', { name: '证书管理' })).not.toBeInTheDocument()
    })
    expect(screen.queryByTestId('certificate-table-scroll')).not.toBeInTheDocument()
    for (const spy of apiSpies) expect(spy).not.toHaveBeenCalled()
  })

  it.each(['loading', 'empty', 'failed', 'cleared'] as const)(
    'keeps the list usable and its heading accessible while upload owner selection is %s', async (state) => {
      platformSession()
      const users = deferred<Awaited<ReturnType<typeof usersApi.list>>>()
      vi.spyOn(usersApi, 'list').mockReturnValue(users.promise)
      vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
      vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
      const user = userEvent.setup()
      renderWithProviders(<CertificateListPage />, ['/site/cert'])
      await screen.findByText('边缘站点证书')
      const heading = screen.getByRole('heading', { name: '证书管理', level: 1 })
      expect(heading.closest('.certificate-page')).toHaveAttribute('aria-labelledby', heading.id)
      expect(heading).not.toHaveAttribute('aria-hidden')
      expect(heading).not.toHaveAttribute('hidden')
      const rule = certificateHeadingStyle(heading)
      expect(rule).toBeDefined()
      expect(rule!.style.getPropertyValue('width')).toBe('1px')
      expect(rule!.style.getPropertyValue('height')).toBe('1px')
      expect(rule!.style.getPropertyValue('overflow')).toBe('hidden')
      expect(rule!.style.getPropertyValue('clip-path')).toBe('inset(50%)')
      expect(rule!.style.getPropertyValue('display')).not.toBe('none')
      const unrelated = document.createElement('section')
      unrelated.append(heading.cloneNode(true))
      expect(unrelated.firstElementChild!.matches(rule!.selectorText)).toBe(false)
      expect(screen.getByRole('button', { name: '添加证书' }).matches(rule!.selectorText)).toBe(false)

      await openUpload(user)
      const dialog = getDialog('添加证书')
      if (state !== 'loading') {
        await act(async () => {
          if (state === 'failed') users.reject(new ApiError('private failure', 503, 'request_failed'))
          else users.resolve({ items: state === 'cleared' ? [managedTarget] : [], page: 1, limit: 100, total: state === 'cleared' ? 1 : 0 })
        })
        if (state === 'failed') await findDialog('用户列表加载失败')
      }
      const selector = within(dialog).getByRole('combobox', { name: '归属用户' })
      if (state === 'loading') expect(selector.closest('.ant-select')).toHaveClass('ant-select-loading')
      else await waitFor(() => expect(selector.closest('.ant-select')).not.toHaveClass('ant-select-loading'))
      if (state === 'cleared') {
        await user.click(selector)
        await user.click(await screen.findByText('target-admin（ID: 17）'))
        await user.click(dialog.querySelector('.ant-select-clear') as HTMLElement)
        expect(selector).toHaveValue('')
      }
      expect(screen.getByText('边缘站点证书')).toBeInTheDocument()
    },
  )

  it('keeps platform list global and requires explicit targets only inside scoped settings', async () => {
    platformSession()
    const listUsers = vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget], page: 1, limit: 100, total: 1 })
    const listAssets = vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    const getAsset = vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const defaults = vi.spyOn(certificatesApi, 'getDefaults').mockResolvedValue({
      scope_id: managedTarget.scope_id, user_id: managedTarget.id, certificate_type: 'uploaded', revision: 1,
    })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText('边缘站点证书')
    expect(listUsers).not.toHaveBeenCalled()
    expect(listAssets).toHaveBeenCalledWith('platform-certificate-token', undefined, { page: 1, limit: 10, search: '', status: undefined })
    await waitFor(() => expect(getAsset).toHaveBeenCalledWith('platform-certificate-token', asset.id, managedTarget.scope_id))
    expect(screen.queryByRole('combobox', { name: '目标用户' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: '默认设置' }))
    expect(defaults).not.toHaveBeenCalled()
    await user.click(screen.getByRole('combobox', { name: '目标用户' }))
    await user.click(await screen.findByText('target-admin（ID: 17）'))
    await waitFor(() => expect(defaults).toHaveBeenCalledWith('platform-certificate-token', managedTarget.scope_id, managedTarget.id))
    expect(screen.getByRole('tab', { name: '默认设置' })).toHaveAttribute('aria-selected', 'true')
  })

  // CERT-03（审测卡 7）：管理员新增按弹窗里选的目标用户读取默认（不是设置页的用户）；
  // 换目标重新读取、只初始化未改过的字段。
  it('reads the defaults of the target picked inside the add dialog', async () => {
    platformSession()
    const otherTarget: ManagedUser = { ...managedTarget, id: '18181818-1818-4818-8818-181818181818', display_id: '18',
      username: 'second-user', display_name: '第二个用户', scope_id: '23232323-2323-4323-8323-232323232323' }
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget, otherTarget], page: 1, limit: 100, total: 2 })
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)
    const targetProvider = { ...provider, scope_id: managedTarget.scope_id }
    const defaults = vi.spyOn(certificatesApi, 'getDefaults').mockImplementation(async (_token, scopeID, userID) => (
      userID === managedTarget.id
        ? { scope_id: scopeID!, user_id: userID, certificate_type: 'acme' as const, dns_provider_id: targetProvider.id, revision: 1 }
        : { scope_id: scopeID!, user_id: userID!, certificate_type: 'uploaded' as const, revision: 1 }))
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [targetProvider] })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText('边缘站点证书')
    await user.click(screen.getByRole('button', { name: '添加证书' }))
    const dialog = getDialog('添加证书')
    expect(defaults).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('combobox', { name: '目标用户' }))
    await user.click(await screen.findByText('target-admin（ID: 17）'))
    await waitFor(() => expect(defaults).toHaveBeenCalledWith('platform-certificate-token', managedTarget.scope_id, managedTarget.id))
    await waitFor(() => expect(within(dialog).getByText(targetProvider.name)).toBeInTheDocument())
    await user.click(within(dialog).getByRole('combobox', { name: '目标用户' }))
    await user.click(await screen.findByText('second-user（ID: 18）'))
    await waitFor(() => expect(defaults).toHaveBeenCalledWith('platform-certificate-token', otherTarget.scope_id, otherTarget.id))
    expect(within(dialog).queryByText(targetProvider.name)).not.toBeInTheDocument()
  })

  it('treats platform.admin as the permission wildcard for certificate and DNS controls', async () => {
    platformSession('platform-admin-wildcard-token', ['platform.admin'])
    vi.spyOn(usersApi, 'list').mockResolvedValue({ items: [managedTarget], page: 1, limit: 100, total: 1 })
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue(assetDetail)

    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'DNS API' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '添加证书' })).toBeEnabled()
  })

  it('keeps asset tab, search, page 2/20, detail, and token-free owner queries across a token refresh', async () => {
    const session = tenantSession('certificate-read-token-a')
    const owner = ownerTuple(session.actor, session.epoch)
    const assets = Array.from({ length: 25 }, (_, index): CertificateAsset => ({
      ...asset,
      id: `66666666-6666-4666-8${String(index).padStart(3, '0')}-666666666666`,
      name: `stable asset ${String(index + 1).padStart(2, '0')}`,
    }))
	const listAssets = vi.mocked(certificatesApi.listAssets).mockImplementation(async (_token, _target, query) => ({
		items: assets.slice((query!.page - 1) * query!.limit, query!.page * query!.limit),
		total: assets.length,
	}))
    const getAsset = vi.spyOn(certificatesApi, 'getAsset').mockImplementation(async (_token, assetID) => ({
      ...assetDetail,
      asset: assets.find((item) => item.id === assetID)!,
      versions: assetDetail.versions.map((version) => ({ ...version, asset_id: assetID })),
    }))
    vi.mocked(certificatesApi.listAssetBindings).mockResolvedValue({ items: [] })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    expect(await screen.findByText('stable asset 01')).toBeInTheDocument()
		await user.type(screen.getByRole('searchbox', { name: '输入域名,模糊搜索' }), 'stable')
    await chooseCertificatePageSize(user, '20')
    await user.click(await screen.findByTitle('2'))
    expect(await screen.findByText('stable asset 21')).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: '查看详情' })[0]!)
    expect(await findDialog('证书详情')).toBeInTheDocument()
    const readsBeforeRefresh = listAssets.mock.calls.length

    act(() => tenantSession('certificate-read-token-b', undefined, 'refresh'))

    expect(useSessionStore.getState().sessionEpoch).toBe(session.epoch)
    // Still the certificate list, not the 申请记录 view.
    expect(document.querySelector('.certificate-orders-heading')).toBeNull()
		expect(screen.getByRole('searchbox', { name: '输入域名,模糊搜索' })).toHaveValue('stable')
    expect(document.querySelector('.identity-pagination .ant-pagination-item-active')).toHaveAttribute('title', '2')
    expect(document.querySelector('.identity-pagination .ant-select-selection-item')).toHaveTextContent('20')
    expect(getDialog('证书详情')).toBeInTheDocument()
    expect(listAssets).toHaveBeenCalledTimes(readsBeforeRefresh)

    await user.click(screen.getByRole('button', { name: '关闭' }))
    await user.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(listAssets.mock.calls.length).toBeGreaterThan(readsBeforeRefresh))
	expect(listAssets).toHaveBeenLastCalledWith(
	  'certificate-read-token-b', undefined, { page: 2, limit: 20, search: 'stable', status: undefined },
	)
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    expect(queryKeys).toEqual(expect.arrayContaining([
	  ['certificate-assets', ...owner, 2, 20, 'stable', ''],
      ['certificate-asset', ...owner, assets[20]!.id],
      ['certificate-asset-bindings', ...owner, assets[20]!.id],
    ]))
    expect(JSON.stringify(queryKeys)).not.toContain('certificate-read-token-')
    expect(getAsset).toHaveBeenLastCalledWith('certificate-read-token-a', assets[20]!.id, undefined)
  })

  it('keeps upload retries outside cache state and reuses the exact attempt with the latest token', async () => {
    const session = tenantSession('certificate-upload-token-a')
    const owner = ownerTuple(session.actor, session.epoch)
    const upload = vi.spyOn(certificatesApi, 'uploadAsset')
      .mockRejectedValueOnce(new ApiError('private upload topology', 0, 'network_error'))
      .mockResolvedValueOnce({
        ...assetDetail,
        asset: { ...assetDetail.asset, name: 'sensitive upload' },
        versions: [{ ...assetDetail.versions[0], certificate_pem: 'PUBLIC-SENSITIVE-PEM' }],
      })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    await screen.findByText('暂无证书资产')
    await openUpload(user)
    const dialog = getDialog('添加证书')
    await user.type(within(dialog).getByLabelText('名称'), 'sensitive upload')
    await user.type(within(dialog).getByLabelText('证书 PEM'), 'PUBLIC-SENSITIVE-PEM')
    await user.type(within(dialog).getByLabelText('私钥 PEM'), 'PRIVATE-SENSITIVE-KEY')
    await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
    expect(await within(dialog).findByText('操作结果待确认')).toBeInTheDocument()
    const firstAttempt = upload.mock.calls[0]!
    const cacheBeforeRetry = JSON.stringify({
      queries: queryClient.getQueryCache().getAll(),
      mutations: queryClient.getMutationCache().getAll(),
    })

    act(() => tenantSession('certificate-upload-token-b', undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(session.epoch)
    expect(getDialog('添加证书')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(upload).toHaveBeenCalledTimes(2))

    expect(upload.mock.calls.map(([token]) => token)).toEqual([
      'certificate-upload-token-a', 'certificate-upload-token-b',
    ])
    expect(upload.mock.calls[1]?.slice(1)).toEqual(firstAttempt.slice(1))
    await waitFor(() => expect(queryDialog('添加证书')).not.toBeInTheDocument())
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    const mutationKeys = queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey)
    expect(mutationKeys).toContainEqual(['certificate-asset-upload', ...owner])
    const cacheAfterRetry = JSON.stringify({
      queries: queryClient.getQueryCache().getAll(),
      mutations: queryClient.getMutationCache().getAll(),
    })
    for (const secret of [
      'certificate-upload-token-a', 'certificate-upload-token-b',
      'PUBLIC-SENSITIVE-PEM', 'PRIVATE-SENSITIVE-KEY', 'sensitive upload',
    ]) {
      expect(`${cacheBeforeRetry}${cacheAfterRetry}`).not.toContain(secret)
    }
    expect(document.body).not.toHaveTextContent('private upload topology')
  })

  it('uses full owner keys for orders, DNS providers, and order creation without caching request data', async () => {
    const session = tenantSession('certificate-order-token-a')
    const owner = ownerTuple(session.actor, session.epoch)
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [provider] })
    vi.spyOn(certificatesApi, 'create').mockRejectedValue(new ApiError('private create edge', 0, 'network_error'))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    await screen.findByText('暂无证书资产')
    await openOrderHistory(user)
    expect(await screen.findByText('暂无证书申请')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '申请证书' }))
    const dialog = getDialog('申请证书')
    await user.type(within(dialog).getByLabelText('域名'), 'cache-identity.example.com')
    // 唯一可用的 DNS 服务商自动选中
    expect(await within(dialog).findByTitle('Cloudflare primary')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '提交申请' }))
    expect(await within(dialog).findByText('申请结果待确认')).toBeInTheDocument()

    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    const mutationKeys = queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey)
    expect(queryKeys).toEqual(expect.arrayContaining([
	  ['certificate-assets', ...owner, 1, 10, '', ''],
      ['certificate-orders', ...owner],
      ['dns-providers', ...owner, 'certificate-order-editor'],
    ]))
    expect(mutationKeys).toContainEqual(['certificate-order-create', ...owner])
    const caches = JSON.stringify({
      queries: queryClient.getQueryCache().getAll(),
      mutations: queryClient.getMutationCache().getAll(),
    })
    expect(caches).not.toContain('certificate-order-token-a')
    expect(caches).not.toContain('cache-identity.example.com')
    expect(document.body).not.toHaveTextContent('private create edge')
  })

  it('rejects foreign and malformed asset and order list envelopes without rendering or caching them', async () => {
    const session = tenantSession('certificate-envelope-token')
    const foreignAsset = {
      ...asset,
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      tenant_scope_id: '99999999-9999-4999-8999-999999999999',
      name: 'FOREIGN ASSET NAME',
    }
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [foreignAsset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    expect(await screen.findByText('证书资产加载失败')).toBeInTheDocument()
    expect(screen.getByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText('FOREIGN ASSET NAME')).not.toBeInTheDocument()
    expect(JSON.stringify(queryClient.getQueryCache().getAll())).not.toContain(foreignAsset.id)

    vi.spyOn(certificatesApi, 'list').mockResolvedValue({
      items: [{
        ...activeOrder,
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        scope_id: '99999999-9999-4999-8999-999999999999',
        domains: ['foreign-order.example.com'],
      }],
    })
    await openOrderHistory(user)
    expect(await screen.findByText('证书申请加载失败')).toBeInTheDocument()
    expect(screen.queryByText('foreign-order.example.com')).not.toBeInTheDocument()
    expect(JSON.stringify(queryClient.getQueryCache().getAll())).not.toContain('foreign-order.example.com')
    expect(useSessionStore.getState().principal?.scope_id).toBe(session.actor.scope_id)
  })

  it('rejects mismatched detail versions and bindings without leaking foreign identifiers or raw messages', async () => {
    tenantSession('certificate-detail-envelope-token')
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    const foreignVersion = {
      ...assetDetail.versions[0],
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      asset_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      tenant_scope_id: '99999999-9999-4999-8999-999999999999',
      sans: ['foreign-version.example.com'],
    }
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({
      asset,
      versions: [foreignVersion],
    })
    vi.mocked(certificatesApi.listAssetBindings).mockResolvedValue({
      items: [{
        ...binding,
        site_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        asset_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        version_id: foreignVersion.id,
      }],
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看详情' }))

    expect(await screen.findByText('请求失败，请稍后重试')).toBeInTheDocument()
    expect(queryDialog('证书详情')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/foreign-version|aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/)
    expect(JSON.stringify(queryClient.getQueryCache().getAll())).not.toContain(foreignVersion.id)
  })

  it('rejects a foreign DNS provider before it can enter the editor or provider cache', async () => {
    tenantSession('certificate-provider-envelope-token')
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    const foreignProvider = {
      ...provider,
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      scope_id: '99999999-9999-4999-8999-999999999999',
      name: 'FOREIGN DNS PROVIDER',
    }
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [foreignProvider] })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    await openOrderHistory(user)
    await screen.findByText('暂无证书申请')
    await user.click(screen.getByRole('button', { name: '申请证书' }))

    expect(await screen.findByText('DNS 服务商加载失败')).toBeInTheDocument()
    expect(screen.queryByText('FOREIGN DNS PROVIDER')).not.toBeInTheDocument()
    expect(JSON.stringify(queryClient.getQueryCache().getAll())).not.toContain(foreignProvider.id)
  })

  it('resets tab, search, paging, dialogs, private input, and unknown attempts for a new owner', async () => {
    const scopeB = '99999999-9999-4999-8999-999999999999'
    const sessionA = tenantSession('certificate-reset-token-a')
    const ownerA = ownerTuple(sessionA.actor, sessionA.epoch)
    const assetsA = Array.from({ length: 21 }, (_, index): CertificateAsset => ({
      ...asset,
      id: `66666666-6666-4666-8${String(index).padStart(3, '0')}-666666666666`,
      name: `owner A asset ${String(index + 1).padStart(2, '0')}`,
    }))
    const assetB = {
      ...asset,
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      tenant_scope_id: scopeB,
      name: 'owner B clean asset',
    }
	vi.mocked(certificatesApi.listAssets).mockImplementation((token, _target, query) => {
	  if (token === 'certificate-reset-token-a') return Promise.resolve({
		items: assetsA.slice((query!.page - 1) * query!.limit, query!.page * query!.limit), total: assetsA.length,
	  })
	  if (token === 'certificate-reset-token-b') return Promise.resolve({ items: [assetB], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
      throw new Error(`unexpected reset token ${token}`)
    })
    vi.spyOn(certificatesApi, 'uploadAsset')
      .mockRejectedValue(new ApiError('private owner A upload', 0, 'network_error'))
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    await screen.findByText('owner A asset 01')
    await user.type(screen.getByRole('searchbox', { name: '输入域名,模糊搜索' }), 'owner A')
    await chooseCertificatePageSize(user, '20')
    await user.click(await screen.findByTitle('2'))
    await openUpload(user)
    const dialog = getDialog('添加证书')
    await user.type(within(dialog).getByLabelText('名称'), 'private owner A draft')
    await user.type(within(dialog).getByLabelText('证书 PEM'), 'OWNER-A-PUBLIC-PEM')
    await user.type(within(dialog).getByLabelText('私钥 PEM'), 'OWNER-A-PRIVATE-KEY')
    await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
    expect(await within(dialog).findByText('操作结果待确认')).toBeInTheDocument()

    let sessionB!: ReturnType<typeof tenantSession>
    await act(async () => {
      sessionB = tenantSession(
        'certificate-reset-token-b', undefined, 'new', scopeB,
        '88888888-8888-4888-8888-888888888888',
      )
      await Promise.resolve()
    })
    const ownerB = ownerTuple(sessionB.actor, sessionB.epoch)

    expect(await screen.findByText('owner B clean asset')).toBeInTheDocument()
    // Still the certificate list, not the 申请记录 view.
    expect(document.querySelector('.certificate-orders-heading')).toBeNull()
    expect(screen.getByRole('searchbox', { name: '输入域名,模糊搜索' })).toHaveValue('')
    expect(document.querySelector('.identity-pagination .ant-pagination-item-active')).toHaveAttribute('title', '1')
    expect(document.querySelector('.identity-pagination .ant-select-selection-item')).toHaveTextContent('10')
    expect(queryDialog('添加证书')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/private owner A|OWNER-A-/)
    const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
    const mutationKeys = queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey)
    expect(queryKeys.some((key) => key.slice(1, 6).every((value, index) => value === ownerA[index]))).toBe(false)
    expect(mutationKeys.some((key) => key?.slice(1, 6).every((value, index) => value === ownerA[index]))).toBe(false)
	expect(queryKeys).toContainEqual(['certificate-assets', ...ownerB, 1, 10, '', ''])
  })

  it.each(['success', 'error'] as const)(
    'isolates delayed old-owner asset list and detail %s from the new owner UI and cache',
    async (outcome) => {
      const scopeB = '99999999-9999-4999-8999-999999999999'
      const sessionA = tenantSession('certificate-late-read-token-a')
      const ownerA = ownerTuple(sessionA.actor, sessionA.epoch)
      const assetB = {
        ...asset,
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        tenant_scope_id: scopeB,
        name: 'owner B authoritative asset',
      }
	  const lateList = deferred<{ items: CertificateAsset[], total: number }>()
      const lateDetail = deferred<CertificateAssetDetail>()
      let ownerAReads = 0
      vi.mocked(certificatesApi.listAssets).mockImplementation((token) => {
        if (token === 'certificate-late-read-token-a') {
          ownerAReads += 1
		  return ownerAReads === 1 ? Promise.resolve({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } }) : lateList.promise
        }
		if (token === 'certificate-late-read-token-b') return Promise.resolve({ items: [assetB], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
        throw new Error(`unexpected late-read token ${token}`)
      })
      vi.spyOn(certificatesApi, 'getAsset').mockImplementation((token) => {
        if (token === 'certificate-late-read-token-a') return lateDetail.promise
        throw new Error(`unexpected detail token ${token}`)
      })
      vi.mocked(certificatesApi.listAssetBindings).mockResolvedValue({ items: [] })
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const user = userEvent.setup()

      renderCertificatesWithQueryClient(queryClient)
      await screen.findByText('边缘站点证书')
      await user.click(screen.getByRole('button', { name: '查看详情' }))
      await user.click(screen.getByRole('button', { name: '刷新' }))
      await waitFor(() => expect(ownerAReads).toBe(2))

      let sessionB!: ReturnType<typeof tenantSession>
      await act(async () => {
        sessionB = tenantSession(
          'certificate-late-read-token-b', undefined, 'new', scopeB,
          '88888888-8888-4888-8888-888888888888',
        )
        await Promise.resolve()
      })
      const ownerB = ownerTuple(sessionB.actor, sessionB.epoch)
      expect(await screen.findByText('owner B authoritative asset')).toBeInTheDocument()

      await act(async () => {
        if (outcome === 'success') {
          lateList.resolve({ items: [{ ...asset, name: 'owner A late asset' }], total: 1 })
          lateDetail.resolve({
            ...assetDetail,
            asset: { ...asset, name: 'owner A late detail' },
          })
        } else {
          lateList.reject(new ApiError('private owner A late list', 503, 'request_failed'))
          lateDetail.reject(new ApiError('private owner A late detail', 503, 'request_failed'))
        }
        await Promise.allSettled([lateList.promise, lateDetail.promise])
      })

      expect(screen.getByText('owner B authoritative asset')).toBeInTheDocument()
      expect(document.body).not.toHaveTextContent(/owner A late|private owner A/)
      expect(queryDialog('证书详情')).not.toBeInTheDocument()
      const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
      expect(queryKeys.some((key) => key.slice(1, 6).every((value, index) => value === ownerA[index]))).toBe(false)
	  expect(queryKeys).toContainEqual(['certificate-assets', ...ownerB, 1, 10, '', ''])
    },
  )

  it('rechecks live manage permission and uses the latest token when a new upload starts', async () => {
    const session = tenantSession('certificate-live-token-a')
    const upload = vi.spyOn(certificatesApi, 'uploadAsset').mockResolvedValue({
      ...assetDetail,
      asset: { ...assetDetail.asset, name: 'latest allowed upload' },
      versions: [{ ...assetDetail.versions[0], certificate_pem: 'LATEST-PUBLIC' }],
    })
    const user = userEvent.setup()

    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    await screen.findByText('暂无证书资产')
    await openUpload(user)
    let dialog = getDialog('添加证书')
    await user.type(within(dialog).getByLabelText('名称'), 'stale denied upload')
    await user.type(within(dialog).getByLabelText('证书 PEM'), 'STALE-PUBLIC')
    await user.type(within(dialog).getByLabelText('私钥 PEM'), 'STALE-PRIVATE')

    act(() => tenantSession('certificate-live-token-b', ['certificates.read'], 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(session.epoch)
    expect(queryDialog('添加证书')).not.toBeInTheDocument()
    expect(upload).not.toHaveBeenCalled()

    act(() => tenantSession('certificate-live-token-c', undefined, 'refresh'))
    expect(queryDialog('添加证书')).not.toBeInTheDocument()
    await openUpload(user)
    dialog = getDialog('添加证书')
    await user.type(within(dialog).getByLabelText('名称'), 'latest allowed upload')
    await user.type(within(dialog).getByLabelText('证书 PEM'), 'LATEST-PUBLIC')
    await user.type(within(dialog).getByLabelText('私钥 PEM'), 'LATEST-PRIVATE')
    act(() => tenantSession('certificate-live-token-d', undefined, 'refresh'))
    await user.click(within(dialog).getByRole('button', { name: '保存证书' }))
    await waitFor(() => expect(upload).toHaveBeenCalledOnce())
    expect(upload.mock.calls[0]?.slice(0, 2)).toEqual([
      'certificate-live-token-d',
      { name: 'latest allowed upload', certificate_pem: 'LATEST-PUBLIC', private_key_pem: 'LATEST-PRIVATE' },
    ])
    await waitFor(() => expect(queryDialog('添加证书')).not.toBeInTheDocument())
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
  })

  it('settles a same-owner known delete only into original caches while manage permission is revoked', async () => {
    const session = tenantSession('certificate-known-token-a')
    const owner = ownerTuple(session.actor, session.epoch)
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    const pendingDelete = deferred<CertificateAsset>()
    const remove = vi.spyOn(certificatesApi, 'deleteAsset').mockReturnValue(pendingDelete.promise)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const foreignKey = [
      'certificate-assets', 'tenant', '99999999-9999-4999-8999-999999999999',
      '99999999-9999-4999-8999-999999999999', session.actor.user_id, session.epoch + 10,
    ] as const
    queryClient.setQueryData(foreignKey, { owner: 'foreign' })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    await screen.findByText('边缘站点证书')
    await rowAction(user, '删除')
    await user.click(within(getDialog('删除证书'))
      .getByRole('button', { name: '确认删除' }))
    expect(remove).toHaveBeenCalledOnce()
    invalidate.mockClear()

    act(() => tenantSession('certificate-known-token-b', ['certificates.read'], 'refresh'))
    expect(queryDialog('删除证书')).not.toBeInTheDocument()
    await act(async () => pendingDelete.resolve({ ...asset, deleted_at: '2026-08-01T00:00:00Z' }))

    await waitFor(() => expect(invalidate).toHaveBeenCalledWith({ queryKey: ['certificate-assets', ...owner] }))
    expect(queryClient.getQueryData(foreignKey)).toEqual({ owner: 'foreign' })
    expect(queryClient.getQueryState(foreignKey)?.isInvalidated).toBe(false)
    expect(document.body).not.toHaveTextContent(/删除成功|操作结果待确认/)

    act(() => tenantSession('certificate-known-token-c', undefined, 'refresh'))
    expect(queryDialog('删除证书')).not.toBeInTheDocument()
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(remove).toHaveBeenCalledOnce()
    const mutationKeys = queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey)
    expect(mutationKeys).toContainEqual(['certificate-asset-command', ...owner])
  })

  it('hides an unknown same-owner delete during revoke and retries its exact IDs with the latest token after regrant', async () => {
    const session = tenantSession('certificate-unknown-token-a')
    const owner = ownerTuple(session.actor, session.epoch)
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    const pendingDelete = deferred<CertificateAsset>()
    const remove = vi.spyOn(certificatesApi, 'deleteAsset')
      .mockReturnValueOnce(pendingDelete.promise)
      .mockResolvedValueOnce({ ...asset, deleted_at: '2026-08-01T00:00:00Z' })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
    })
    const user = userEvent.setup()

    renderCertificatesWithQueryClient(queryClient)
    await screen.findByText('边缘站点证书')
    await rowAction(user, '删除')
    await user.click(within(getDialog('删除证书'))
      .getByRole('button', { name: '确认删除' }))
    const firstAttempt = remove.mock.calls[0]!

    act(() => tenantSession('certificate-unknown-token-b', ['certificates.read'], 'refresh'))
    await act(async () => {
      pendingDelete.reject(new ApiError('private revoked delete', 0, 'network_error'))
      await pendingDelete.promise.catch(() => undefined)
    })
    expect(screen.queryByText('操作结果待确认')).not.toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private revoked delete')

    act(() => tenantSession('certificate-unknown-token-c', undefined, 'refresh'))
    expect(useSessionStore.getState().sessionEpoch).toBe(session.epoch)
    const dialog = await findDialog('删除证书')
    expect(within(dialog).getByText('操作结果待确认')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(2))
    expect(remove.mock.calls.map(([token]) => token)).toEqual([
      'certificate-unknown-token-a', 'certificate-unknown-token-c',
    ])
    expect(remove.mock.calls[1]?.slice(1)).toEqual(firstAttempt.slice(1))
    expect(firstAttempt.slice(1, 3)).toEqual([asset.id, { expected_revision: asset.revision }])
    expect(queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey))
      .toContainEqual(['certificate-asset-command', ...owner])
  })

  it.each(['success', 'error'] as const)(
    'isolates a delayed old-owner certificate mutation %s from the new owner',
    async (outcome) => {
      const scopeB = '99999999-9999-4999-8999-999999999999'
      const sessionA = tenantSession('certificate-late-write-token-a')
      const ownerA = ownerTuple(sessionA.actor, sessionA.epoch)
      const assetB = {
        ...asset,
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        tenant_scope_id: scopeB,
        name: 'owner B mutation-safe asset',
      }
      vi.mocked(certificatesApi.listAssets).mockImplementation((token) => {
		if (token === 'certificate-late-write-token-a') return Promise.resolve({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
		if (token === 'certificate-late-write-token-b') return Promise.resolve({ items: [assetB], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
        throw new Error(`unexpected late-write token ${token}`)
      })
      const pendingDelete = deferred<CertificateAsset>()
      vi.spyOn(certificatesApi, 'deleteAsset').mockReturnValue(pendingDelete.promise)
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
      })
      const user = userEvent.setup()

      renderCertificatesWithQueryClient(queryClient)
      await screen.findByText('边缘站点证书')
      await rowAction(user, '删除')
      await user.click(within(getDialog('删除证书'))
        .getByRole('button', { name: '确认删除' }))

      let sessionB!: ReturnType<typeof tenantSession>
      await act(async () => {
        sessionB = tenantSession(
          'certificate-late-write-token-b', undefined, 'new', scopeB,
          '88888888-8888-4888-8888-888888888888',
        )
        await Promise.resolve()
      })
      const ownerB = ownerTuple(sessionB.actor, sessionB.epoch)
      expect(await screen.findByText('owner B mutation-safe asset')).toBeInTheDocument()

      await act(async () => {
        if (outcome === 'success') {
          pendingDelete.resolve({ ...asset, deleted_at: '2026-08-01T00:00:00Z' })
        } else {
          pendingDelete.reject(new ApiError('private owner A delayed delete', 503, 'request_failed'))
        }
        await pendingDelete.promise.catch(() => undefined)
      })

      expect(screen.getByText('owner B mutation-safe asset')).toBeInTheDocument()
      expect(document.body).not.toHaveTextContent(/private owner A|操作结果待确认|删除成功/)
      const queryKeys = queryClient.getQueryCache().getAll().map((query) => query.queryKey)
      const mutationKeys = queryClient.getMutationCache().getAll().map((mutation) => mutation.options.mutationKey)
      expect(queryKeys.some((key) => key.slice(1, 6).every((value, index) => value === ownerA[index]))).toBe(false)
      expect(mutationKeys.some((key) => key?.slice(1, 6).every((value, index) => value === ownerA[index]))).toBe(false)
	  expect(queryKeys).toContainEqual(['certificate-assets', ...ownerB, 1, 10, '', ''])
    },
  )

  it('renders natural asset loading, empty, generic error retry, and API 403 states without raw messages', async () => {
    tenantSession('certificate-state-token')
    const pending = deferred<{ items: CertificateAsset[], total: number }>()
    vi.mocked(certificatesApi.listAssets).mockReturnValueOnce(pending.promise)
    const user = userEvent.setup()
    const loadingView = renderWithProviders(<CertificateListPage />, ['/site/cert'])

    expect(screen.getByTestId('certificate-table-scroll')).toHaveAttribute('aria-busy', 'true')
    await act(async () => pending.resolve({ items: [], total: 0 }))
    expect(await screen.findByText('暂无证书资产')).toBeInTheDocument()
    loadingView.unmount()

    tenantSession('certificate-state-token-error')
    vi.mocked(certificatesApi.listAssets)
      .mockRejectedValueOnce(new ApiError('private asset database row', 500, 'internal_error'))
      .mockResolvedValueOnce({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    expect(await screen.findByText('证书资产加载失败')).toBeInTheDocument()
    expect(screen.queryByText('private asset database row')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await screen.findByText('暂无证书资产')).toBeInTheDocument()

    vi.mocked(certificatesApi.listAssets)
      .mockRejectedValue(new ApiError('private IAM policy', 403, 'permission_denied'))
    await act(async () => {
      tenantSession('certificate-state-token-forbidden', undefined, 'new')
      await Promise.resolve()
    })
    await waitFor(() => expect(screen.getByText('无权查看证书管理')).toBeInTheDocument())
    expect(document.body).not.toHaveTextContent(/private asset database row|private IAM policy/)
  })

  it('keeps generic errors localized in en-US and expands empty and forbidden states in qps-ploc', async () => {
    await changeLocale('en-US')
    tenantSession('certificate-locale-token-en')
    vi.mocked(certificatesApi.listAssets)
      .mockRejectedValue(new ApiError('private English upstream detail', 500, 'certificate_asset_internal_error'))
    const englishView = renderWithProviders(<CertificateListPage />, ['/site/cert'])

    expect(await screen.findByText('Failed to load certificate assets')).toBeInTheDocument()
    expect(screen.getByText('The certificate asset service is unavailable')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private English upstream detail')
    englishView.unmount()

    await changeLocale('qps-ploc')
    tenantSession('certificate-locale-token-pseudo')
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    expect(await screen.findByText(/暂~无~证~书~资~产~/)).toBeInTheDocument()

    act(() => tenantSession('certificate-locale-token-pseudo-denied', [], 'refresh'))
    expect(await screen.findByText(/无~权~查~看~证~书~管~理~/)).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent(/certificate-locale-token|permission_denied|internal_error/)
  })

  it('registers the dedicated certificate asset namespace and surfaces ACME renewal metadata', async () => {
    await changeLocale('zh-CN')
    tenantSession('certificate-acme-token')
    vi.mocked(certificatesApi.listAssets).mockResolvedValue({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    vi.spyOn(certificatesApi, 'getAsset').mockResolvedValue({
      ...assetDetail,
      asset: { ...asset, source: 'acme' },
      versions: [{
        ...assetDetail.versions[0],
        acme_order_id: 'order-acme-123',
        renewal_due: true,
        renewal_due_at: '2026-09-01T00:00:00Z',
      }],
    })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    expect(await screen.findByText('边缘站点证书')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '查看详情' }))
    const dialog = await findDialog('证书详情')
    expect(within(dialog).getAllByText('ACME 订单').length).toBeGreaterThan(0)
    expect(within(dialog).getByText('order-acme-123')).toBeInTheDocument()
    expect(within(dialog).getByText('待续期')).toBeInTheDocument()
  })

  it('uses owner-bound server pagination and resets the asset page for search and page-size changes', async () => {
    tenantSession('certificate-pagination-token')
    const firstPage = Array.from({ length: 11 }, (_, index) => ({
      ...asset,
      id: `${String(index + 1).padStart(8, '0')}-0000-4000-8000-000000000000`,
      name: `远程页资产 ${index + 1}`,
    }))
    const secondPage = [{
      ...asset,
      id: '20000000-0000-4000-8000-000000000000',
      name: '第二页资产',
    }]
    const listAssets = vi.mocked(certificatesApi.listAssets).mockImplementation(async (...args) => {
      const query = args[2]
      if (query?.search === 'edge') return { items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } }
      if (query?.page === 2) return { items: secondPage, total: 25 }
      return { items: firstPage, total: 25 }
    })
    const user = userEvent.setup()
    renderWithProviders(<CertificateListPage />, ['/site/cert'])

    expect(await screen.findByText('远程页资产 11')).toBeInTheDocument()
    await waitFor(() => expect(listAssets).toHaveBeenLastCalledWith(
      'certificate-pagination-token', undefined, { page: 1, limit: 10, search: '' },
    ))

    const next = document.querySelector<HTMLButtonElement>('.ant-pagination-next button')
    if (!next) throw new Error('next page button not found')
    await user.click(next)
    expect(await screen.findByText('第二页资产')).toBeInTheDocument()
    await waitFor(() => expect(listAssets).toHaveBeenLastCalledWith(
      'certificate-pagination-token', undefined, { page: 2, limit: 10, search: '' },
    ))

    await chooseCertificatePageSize(user, '20')
    await waitFor(() => expect(listAssets).toHaveBeenLastCalledWith(
      'certificate-pagination-token', undefined, { page: 1, limit: 20, search: '' },
    ))

	await user.type(screen.getByPlaceholderText('输入域名,模糊搜索'), 'edge')
    await waitFor(() => expect(listAssets).toHaveBeenLastCalledWith(
      'certificate-pagination-token', undefined, { page: 1, limit: 20, search: 'edge' },
    ))
  })
})

describe('CertificateListPage E5 visibility', () => {
  function clippedBy(element: Element) {
    const sheet = document.createElement('style')
    sheet.textContent = certificateStyles
    document.head.append(sheet)
    const rules = [...sheet.sheet!.cssRules].filter((item): item is CSSStyleRule => 'selectorText' in item)
    const hits: string[] = []
    for (let node: Element | null = element; node; node = node.parentElement) {
      for (const rule of rules) {
        if (rule.selectorText.includes(':focus')) continue
        if (node.matches(rule.selectorText) && rule.style.getPropertyValue('width') === '1px' && rule.style.getPropertyValue('position') === 'absolute') hits.push(rule.selectorText)
      }
    }
    sheet.remove()
    return hits
  }

  it('keeps the 更多操作 (申请记录 entry) and toolbar 刷新 buttons visible (not clipped to 1px)', async () => {
    useSessionStore.getState().setSession({ ...authResponse(principal({ scope_kind: 'tenant', permissions: ['certificates.read', 'certificates.manage'] })), access_token: 'e5-token' }, principal({ scope_kind: 'tenant', permissions: ['certificates.read', 'certificates.manage'] }))
    vi.spyOn(certificatesApi, 'listAssets').mockResolvedValue({ items: [], total: 0, counts: { all: 0, normal: 0, expiring: 0, expired: 0, auto_renew: 0, manual_renew: 0 } })
    vi.spyOn(certificatesApi, 'list').mockResolvedValue({ items: [] })
    vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [] })
    renderWithProviders(<CertificateListPage />, ['/site/cert'])
    const tab = await screen.findByRole('button', { name: '更多操作' })
    const refresh = screen.getByRole('button', { name: '刷新' })
    expect(clippedBy(tab)).toEqual([])
    expect(clippedBy(refresh)).toEqual([])
  })
})
