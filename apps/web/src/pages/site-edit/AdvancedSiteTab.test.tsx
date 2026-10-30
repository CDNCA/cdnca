import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render as rtlRender, screen, waitFor, within } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../api/auth'
import { errorPagesApi, type ErrorPageAsset, type ErrorPageRule } from '../../api/errorPages'
import { httpPoliciesApi, type HttpPolicy } from '../../api/httpPolicies'

import AdvancedSiteTab from './AdvancedSiteTab'

// The access cards and 302 card read the router; render inside one.
const render = (ui: ReactElement) => rtlRender(ui, { wrapper: MemoryRouter })

vi.mock('../../api/httpPolicies', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api/httpPolicies')>()),
  MAX_HTTP_POLICY_UPLOAD_BYTES: 1073741824,
  emptyHttpPolicyConfig: () => ({ max_upload_bytes: 0, request_headers: [], response_headers: [], rewrites: [], redirect_allowed_hosts: [], redirects: [], cors: null, referer_check: null }),
  configFromHttpPolicy: (value: HttpPolicy) => ({ max_upload_bytes: value.max_upload_bytes, request_headers: value.request_headers, response_headers: value.response_headers, rewrites: value.rewrites, redirect_allowed_hosts: value.redirect_allowed_hosts, redirects: value.redirects, cors: value.cors }),
  httpPoliciesApi: {
    list: vi.fn().mockResolvedValue({ items: [] }),
    preview: vi.fn().mockResolvedValue({ state: 'preview', sha256: 'a'.repeat(64), snapshot: { schema_version: 'cdnca.edge.http-policy/v1', policy_version: 1, sites: [] } }),
    create: vi.fn(), update: vi.fn(), setEnabled: vi.fn(), delete: vi.fn(),
  },
}))
vi.mock('../../api/siteSchedule302', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api/siteSchedule302')>()),
  siteSchedule302Api: { get: vi.fn().mockResolvedValue({ site_id: '11111111-1111-4111-8111-111111111111', version: 1, plain_http: true, updated_at: null,
    settings: { enabled: false, target: 'address', keep_path: true, keep_query: true, signature_ttl_seconds: 60, https_to_http: false,
      extensions: [], path_prefixes: [], min_size_bytes: 0 } }), replace: vi.fn() },
}))
vi.mock('../../api/errorPages', () => ({
  errorPagesApi: { listAssets: vi.fn().mockResolvedValue({ items: [] }), listRules: vi.fn().mockResolvedValue({ items: [] }), initiateAsset: vi.fn(), uploadAssetContent: vi.fn(), finalizeAsset: vi.fn(), deleteAsset: vi.fn(), getAssetContent: vi.fn(), createRule: vi.fn(), updateRule: vi.fn(), setRuleEnabled: vi.fn(), deleteRule: vi.fn() },
}))
const siteTrafficLimitInitial = {
  site_id: '55555555-5555-4555-8555-555555555555', version: 3,
  setting: { enabled: false, daily_bytes: null, monthly_bytes: null, total_bytes: null, time_zone: 'Asia/Shanghai', notice_html: '' },
  total_since: null, exceeded_period: '' as const, exceeded_at: null, evaluated_at: null, updated_at: null,
}
vi.mock('../../api/siteTrafficLimit', () => ({ siteTrafficLimitApi: { get: vi.fn(), put: vi.fn() } }))
const tenantPrincipal = {
  scope_kind: 'tenant', scope_id: '22222222-2222-4222-8222-222222222222', tenant_id: '22222222-2222-4222-8222-222222222222', user_id: '44444444-4444-4444-8444-444444444444', permissions: ['sites.read', 'sites.manage', 'http_policies.read', 'http_policies.manage', 'error_pages.read', 'error_pages.manage'],
}
const session = vi.hoisted(() => ({ principal: null as Record<string, unknown> | null }))
vi.mock('../../auth/session', () => ({
  useSessionStore: { getState: () => ({ accessToken: 'token', sessionEpoch: 1, principal: session.principal }) },
}))

beforeEach(() => {
  session.principal = tenantPrincipal
  vi.restoreAllMocks()
  vi.clearAllMocks()
  vi.mocked(httpPoliciesApi.list).mockReset().mockResolvedValue({ items: [] })
  vi.mocked(httpPoliciesApi.create).mockReset()
  vi.mocked(httpPoliciesApi.update).mockReset()
  vi.mocked(httpPoliciesApi.setEnabled).mockReset()
  vi.mocked(httpPoliciesApi.preview).mockReset().mockResolvedValue({ state: 'preview', sha256: 'a'.repeat(64), snapshot: { schema_version: 'cdnca.edge.http-policy/v1', policy_version: 1, sites: [] } })
  vi.mocked(httpPoliciesApi.delete).mockReset()
  vi.mocked(errorPagesApi.listAssets).mockReset().mockResolvedValue({ items: [] })
  vi.mocked(errorPagesApi.listRules).mockReset().mockResolvedValue({ items: [] })
  vi.mocked(errorPagesApi.initiateAsset).mockReset()
  vi.mocked(errorPagesApi.uploadAssetContent).mockReset()
  vi.mocked(errorPagesApi.finalizeAsset).mockReset()
  vi.mocked(errorPagesApi.deleteAsset).mockReset()
  vi.mocked(errorPagesApi.getAssetContent).mockReset().mockRejectedValue(new ApiError('no content', 404, 'not_found'))
  vi.mocked(errorPagesApi.createRule).mockReset()
  vi.mocked(errorPagesApi.updateRule).mockReset()
  vi.mocked(errorPagesApi.setRuleEnabled).mockReset()
  vi.mocked(errorPagesApi.deleteRule).mockReset()
})

const scopeId = '22222222-2222-4222-8222-222222222222'
const siteId = '55555555-5555-4555-8555-555555555555'
const userId = '44444444-4444-4444-8444-444444444444'

const policy: HttpPolicy = {
  id: 'policy-1', tenant_scope_id: scopeId, site_id: siteId, site_owner_user_id: userId,
  max_upload_bytes: 1, request_headers: [], response_headers: [], rewrites: [], redirect_allowed_hosts: [], redirects: [], cors: null, referer_check: null,
  enabled: true, deleted: false, revision: 7, publication_revision: 1, created_at: '2026-01-01', updated_at: '2026-01-01',
}

const asset: ErrorPageAsset = {
  id: 'asset-1', scope_id: scopeId, name: '维护页.html', mime_type: 'text/html', size_bytes: 7, sha256: 'a'.repeat(64),
  status: 'ready', scan_status: 'passed', revision: 5, created_by: userId, created_at: '2026-01-01', updated_at: '2026-01-01',
}

const rule: ErrorPageRule = {
  id: 'rule-1', target: { kind: 'site', scope_id: scopeId, site_id: siteId },
  fields: { category: 'origin_response', match: { kind: 'exact', from: 404, to: 404 }, asset_id: asset.id, enabled: true },
  priority: 1, revision: 9, deleted: false, created_by: userId, created_at: '2026-01-01', updated_at: '2026-01-01',
}

// the hidden <input type=file> of the error page dialog's Upload
function fileInput(): HTMLInputElement {
  const input = document.querySelector<HTMLInputElement>('.ant-modal input[type=file]')
  if (!input) throw new Error('error page file input not found')
  return input
}

async function chooseAsset(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('combobox', { name: '页面内容' }))
  // be-gap-2: a named asset shows its name, not the MIME type and id.
  await user.click(await screen.findByText(`${asset.name} · 7 B`))
}

function renderTab(permissions: string[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <AdvancedSiteTab
        siteId={siteId} accessToken="token" scopeKind="tenant" scopeId={scopeId} tenantId={scopeId}
        userId={userId} sessionEpoch={1} permissions={permissions} canManage lockedForTenant={false}
      />
    </QueryClientProvider>,
  )
  return client
}

describe('AdvancedSiteTab', () => {
  it('renders natural empty states from real policy and error-page queries', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <AdvancedSiteTab
          siteId="55555555-5555-4555-8555-555555555555"
          accessToken="token"
          scopeKind="tenant"
          scopeId="22222222-2222-4222-8222-222222222222"
          tenantId="22222222-2222-4222-8222-222222222222"
          userId="44444444-4444-4444-8444-444444444444"
          sessionEpoch={1}
          permissions={['sites.read', 'sites.manage', 'http_policies.read', 'error_pages.read']}
          canManage
          lockedForTenant={false}
        />
      </QueryClientProvider>,
    )
    expect(await screen.findByRole('heading', { name: '上传大小限制' })).toBeInTheDocument()
    // the six groups, in order, then 更多设置
    expect(screen.getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent)).toEqual([
      '上传大小限制', '防盗链与跨域', '性能与协议', '自定义页面与转发', 'Header 设置', '更多设置',
    ])
    expect(await screen.findByText('暂无自定义错误页')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '新增页面' })).not.toBeInTheDocument()
  })

  it('does not request when local policy permissions are absent', async () => {
    const { siteTrafficLimitApi } = await import('../../api/siteTrafficLimit')
    vi.mocked(siteTrafficLimitApi.get).mockResolvedValue(siteTrafficLimitInitial)
    const { httpPoliciesApi } = await import('../../api/httpPolicies')
    const { errorPagesApi } = await import('../../api/errorPages')
    const client = new QueryClient()
    render(
      <QueryClientProvider client={client}>
        <AdvancedSiteTab
          siteId="55555555-5555-4555-8555-555555555555" accessToken="token" scopeKind="tenant"
          scopeId="22222222-2222-4222-8222-222222222222" tenantId="22222222-2222-4222-8222-222222222222"
          userId="44444444-4444-4444-8444-444444444444" sessionEpoch={1} permissions={['sites.read']}
          canManage={false} lockedForTenant={false}
        />
      </QueryClientProvider>,
    )
    // sites.read alone shows the website traffic limit (read-only), and never
    // requests HTTP policies or error pages.
    expect(await screen.findByRole('heading', { name: /网站流量上限/ })).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '启用' })).toBeDisabled()
    expect(httpPoliciesApi.list).not.toHaveBeenCalled()
    expect(errorPagesApi.listAssets).not.toHaveBeenCalled()
  })

  it.each(['0', '1073741825'])('rejects max upload input %s before a policy request', async (value) => {
    const { httpPoliciesApi } = await import('../../api/httpPolicies')
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><AdvancedSiteTab siteId="55555555-5555-4555-8555-555555555555" accessToken="token" scopeKind="tenant" scopeId="22222222-2222-4222-8222-222222222222" tenantId="22222222-2222-4222-8222-222222222222" userId="44444444-4444-4444-8444-444444444444" sessionEpoch={1} permissions={['http_policies.read', 'http_policies.manage']} canManage lockedForTenant={false} /></QueryClientProvider>)
    await screen.findByRole('heading', { name: '上传大小限制' })
    // While typing the out-of-range size is marked and not sent; on blur the field
    // clamps to its range, and only the clamped value is saved.
    vi.mocked(httpPoliciesApi.create).mockImplementation(async (_token, _scope, _site, config) => ({ ...policy, ...config }))
    fireEvent.click(screen.getByText('自定义'))
    const input = await screen.findByLabelText('上传大小上限（字节）')
    fireEvent.focus(input)
    fireEvent.change(input, { target: { value } })
    expect(httpPoliciesApi.create).not.toHaveBeenCalled()
    fireEvent.blur(input)
    await waitFor(() => expect(httpPoliciesApi.create).toHaveBeenCalledTimes(1))
    expect(vi.mocked(httpPoliciesApi.create).mock.calls[0]![3].max_upload_bytes).toBe(value === '0' ? 1 : 1073741824)
  })

  it.each([
    ['unsupported MIME', new File(['x'], 'page.svg', { type: 'image/svg+xml' })],
    ['empty file', new File([], 'page.html', { type: 'text/html' })],
    ['oversize file', new File([new Uint8Array(1048577)], 'page.html', { type: 'text/html' })],
  ])('rejects %s locally without initiating an asset request', async (_name, file) => {
    const { errorPagesApi } = await import('../../api/errorPages')
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><AdvancedSiteTab siteId="55555555-5555-4555-8555-555555555555" accessToken="token" scopeKind="tenant" scopeId="22222222-2222-4222-8222-222222222222" tenantId="22222222-2222-4222-8222-222222222222" userId="44444444-4444-4444-8444-444444444444" sessionEpoch={1} permissions={['error_pages.read', 'error_pages.manage']} canManage lockedForTenant={false} /></QueryClientProvider>)
    fireEvent.click(await screen.findByRole('button', { name: '新增页面' }))
    fireEvent.change(fileInput(), { target: { files: [file] } })
    await waitFor(() => expect(screen.getByRole('button', { name: '上传错误页面资源' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: '上传错误页面资源' }))
    await waitFor(() => expect(screen.getByText('请填写有效的策略字段。')).toBeInTheDocument())
    expect(errorPagesApi.initiateAsset).not.toHaveBeenCalled()
  })

  it('shows localized terminal 403 feedback for a state mutation without retrying', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    vi.mocked(httpPoliciesApi.setEnabled).mockRejectedValue(new ApiError('raw server message', 403, 'permission_denied'))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={client}><AdvancedSiteTab siteId="55555555-5555-4555-8555-555555555555" accessToken="token" scopeKind="tenant" scopeId="22222222-2222-4222-8222-222222222222" tenantId="22222222-2222-4222-8222-222222222222" userId="44444444-4444-4444-8444-444444444444" sessionEpoch={1} permissions={['http_policies.read', 'http_policies.manage']} canManage lockedForTenant={false} /></QueryClientProvider>)
    await screen.findByRole('heading', { name: '上传大小限制' })
    fireEvent.click(screen.getByRole('switch', { name: '停用 HTTP 策略' }))
    await waitFor(() => expect(screen.getByText('当前账号无权修改 HTTP 策略')).toBeInTheDocument())
    expect(screen.queryByText('raw server message')).not.toBeInTheDocument()
    expect(httpPoliciesApi.setEnabled).toHaveBeenCalledTimes(1)
  })

  it('abandons and refetches or retries an unknown policy create with the exact frozen body and key', async () => {
    vi.mocked(httpPoliciesApi.create)
      .mockRejectedValueOnce(new ApiError('raw network', 0, 'network_error'))
      .mockRejectedValueOnce(new ApiError('raw unavailable', 503, 'request_failed'))
      .mockResolvedValueOnce(policy)
    const user = userEvent.setup()
    renderTab(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: '上传大小限制' })
    // The typed size creates the policy on blur
    await user.click(screen.getByText('自定义'))
    await user.clear(screen.getByLabelText('上传大小上限（字节）'))
    await user.type(screen.getByLabelText('上传大小上限（字节）'), '1024')
    fireEvent.blur(screen.getByLabelText('上传大小上限（字节）'))
    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(screen.getByLabelText('上传大小上限（字节）')).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '放弃并刷新' }))
    await waitFor(() => expect(httpPoliciesApi.list).toHaveBeenCalledTimes(2))

    await user.clear(screen.getByLabelText('上传大小上限（字节）'))
    await user.type(screen.getByLabelText('上传大小上限（字节）'), '2048')
    fireEvent.blur(screen.getByLabelText('上传大小上限（字节）'))
    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const frozenCall = vi.mocked(httpPoliciesApi.create).mock.calls[1]
    await user.click(screen.getByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(httpPoliciesApi.create).toHaveBeenCalledTimes(3))
    expect(vi.mocked(httpPoliciesApi.create).mock.calls[2]).toEqual(frozenCall)
    expect(document.body.textContent).not.toContain('raw unavailable')
  })

  it('retries policy update and toggle with their original revision, body, and idempotency key', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    vi.mocked(httpPoliciesApi.update)
      .mockRejectedValueOnce(new ApiError('raw timeout', 408, 'request_failed'))
      .mockResolvedValueOnce({ ...policy, max_upload_bytes: 2048, revision: 8 })
    vi.mocked(httpPoliciesApi.setEnabled)
      .mockRejectedValueOnce(new ApiError('raw limited', 429, 'request_failed'))
      .mockResolvedValueOnce({ ...policy, enabled: false, revision: 8 })
    const user = userEvent.setup()
    renderTab(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: '上传大小限制' })

    await user.clear(screen.getByLabelText('上传大小上限（字节）'))
    await user.type(screen.getByLabelText('上传大小上限（字节）'), '2048')
    fireEvent.blur(screen.getByLabelText('上传大小上限（字节）'))
    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const updateCall = vi.mocked(httpPoliciesApi.update).mock.calls[0]
    expect(updateCall[3]).toBe(7)
    await user.click(screen.getByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(httpPoliciesApi.update).toHaveBeenCalledTimes(2))
    expect(vi.mocked(httpPoliciesApi.update).mock.calls[1]).toEqual(updateCall)

    await user.click(screen.getByRole('switch', { name: '停用 HTTP 策略' }))
    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const toggleCall = vi.mocked(httpPoliciesApi.setEnabled).mock.calls[0]
    expect(toggleCall[3]).toBe(8)
    await user.click(screen.getByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(httpPoliciesApi.setEnabled).toHaveBeenCalledTimes(2))
    expect(vi.mocked(httpPoliciesApi.setEnabled).mock.calls[1]).toEqual(toggleCall)
  })

  it('saves internal rewrites and fixed redirects in the exact HTTP policy config', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    vi.mocked(httpPoliciesApi.update).mockImplementation(async (_token, _scope, _id, revision, config) => ({ ...policy, ...config, revision: revision + 1 }))
    const user = userEvent.setup()
    renderTab(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: '上传大小限制' })

    // one URL 转向 list: 内部重写 is our rewrite, 302 our redirect
    for (const [match, target, type] of [['/old/(.*)', '/new/$1', '内部重写'], ['/legacy', 'https://docs.example.test/new', '302 临时']]) {
      await user.click(screen.getByRole('button', { name: '新增转向' }))
      const dialog = within(await screen.findByRole('dialog'))
      const input = dialog.getByRole('textbox', { name: '匹配路径' })
      await user.clear(input)
      await user.type(input, match!)
      await user.type(dialog.getByRole('textbox', { name: '目标 URL' }), target!)
      await user.click(dialog.getByRole('radio', { name: type }))
      await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    }
    // Each dialog 确定 saves; the last save holds both rules.
    await waitFor(() => expect(httpPoliciesApi.update).toHaveBeenCalledTimes(2))
    const body = vi.mocked(httpPoliciesApi.update).mock.calls[1]?.[4]
    expect(body).toMatchObject({
      redirect_allowed_hosts: ['docs.example.test'],
      rewrites: [{ match_kind: 'regex', match_path: '^/old/(.*)', target_path: '/new/$1' }],
      redirects: [{ match_kind: 'exact', match_path: '/legacy', status: 302, target_url: 'https://docs.example.test/new' }],
    })
  })

  it.each([
    [new ApiError('raw forbidden', 403, 'permission_denied'), '当前账号无权修改 HTTP 策略'],
    [new ApiError('raw missing', 404, 'not_found'), 'HTTP 策略不存在或已不可访问'],
    [new ApiError('raw conflict', 409, 'idempotency_conflict'), '幂等键已被其他请求使用，请刷新后重试'],
    [new ApiError('raw stale', 412, 'revision_conflict'), 'HTTP 策略修订已变化，请刷新后重试'],
    [new ApiError('raw invalid', 422, 'validation_error'), /^请填写有效的 HTTP 策略字段（响应头不能包含节点管理的头/],
  ])('renders terminal write status without exact retry: %s', async (error, localized) => {
    vi.mocked(httpPoliciesApi.create).mockRejectedValue(error)
    const user = userEvent.setup()
    renderTab(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: '上传大小限制' })
    await user.click(screen.getByText('自定义'))
    await user.clear(screen.getByLabelText('上传大小上限（字节）'))
    await user.type(screen.getByLabelText('上传大小上限（字节）'), '1')
    fireEvent.blur(screen.getByLabelText('上传大小上限（字节）'))
    expect(await screen.findByText(localized)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '按原请求重试' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain(error.message)
  })

  it.each(['initiate', 'upload', 'finalize'] as const)('resumes an unknown asset %s step with the frozen file and step keys', async (stage) => {
    const unknown = new ApiError(`raw ${stage}`, stage === 'initiate' ? 0 : stage === 'upload' ? 500 : 429, stage === 'initiate' ? 'invalid_response' : 'request_failed')
    const initiated = { value: { ...asset, status: 'initiated' }, replayed: false }
    const uploaded = { value: { ...asset, status: 'staged' }, replayed: false }
    const finalized = { value: asset, replayed: false }
    vi.mocked(errorPagesApi.initiateAsset).mockResolvedValue(initiated)
    vi.mocked(errorPagesApi.uploadAssetContent).mockResolvedValue(uploaded)
    vi.mocked(errorPagesApi.finalizeAsset).mockResolvedValue(finalized)
    const failedApi = stage === 'initiate' ? errorPagesApi.initiateAsset : stage === 'upload' ? errorPagesApi.uploadAssetContent : errorPagesApi.finalizeAsset
    vi.mocked(failedApi).mockRejectedValueOnce(unknown).mockResolvedValueOnce(stage === 'initiate' ? initiated : stage === 'upload' ? uploaded : finalized)
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    const file = new File(['<html/>'], '404.html', { type: 'text/html' })
    Object.defineProperty(file, 'arrayBuffer', { value: () => Promise.resolve(new TextEncoder().encode('<html/>').buffer) })
    await user.upload(fileInput(), file)
    await user.click(screen.getByRole('button', { name: '上传错误页面资源' }))

    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const firstCall = vi.mocked(failedApi).mock.calls[0]
    expect(screen.getByRole('button', { name: '上传错误页面资源' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '按原操作重试' }))
    await waitFor(() => expect(vi.mocked(failedApi)).toHaveBeenCalledTimes(2))
    expect(vi.mocked(failedApi).mock.calls[1]).toEqual(firstCall)
    expect(errorPagesApi.initiateAsset).toHaveBeenCalledTimes(stage === 'initiate' ? 2 : 1)
    // be-gap-2: the uploaded file name is the asset name.
    expect(vi.mocked(errorPagesApi.initiateAsset).mock.calls[0]![6]).toBe('404.html')
    expect(errorPagesApi.uploadAssetContent).toHaveBeenCalledTimes(stage === 'upload' ? 2 : 1)
    expect(errorPagesApi.finalizeAsset).toHaveBeenCalledTimes(stage === 'finalize' ? 2 : 1)
  })

  // 错误页内容直接编辑——按文本新建资源并保存规则；编辑时读回内容。
  it('creates a page from text: asset initiate, upload, finalize, then the rule with it', async () => {
    const finalized = { value: { ...asset, id: 'a2a2a2a2-0000-4000-8000-000000000002' }, replayed: false }
    vi.mocked(errorPagesApi.initiateAsset).mockResolvedValue({ value: { ...asset, id: finalized.value.id, status: 'initiated' }, replayed: false })
    vi.mocked(errorPagesApi.uploadAssetContent).mockResolvedValue({ value: { ...finalized.value, status: 'staged' }, replayed: false })
    vi.mocked(errorPagesApi.finalizeAsset).mockResolvedValue(finalized)
    vi.mocked(errorPagesApi.createRule).mockResolvedValue({ value: rule, replayed: false })
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    await user.click(screen.getByRole('button', { name: '纯文本' }))
    const content = screen.getByRole('textbox', { name: '内容' })
    expect((content as HTMLTextAreaElement).value).toContain('404')
    await user.clear(content)
    await user.type(content, '页面走丢了')
    await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(errorPagesApi.createRule).toHaveBeenCalledTimes(1))
    const [, mime, size, , , name] = vi.mocked(errorPagesApi.initiateAsset).mock.calls[0]!.slice(1)
    expect(mime).toBe('text/plain')
    expect(size).toBe(new TextEncoder().encode('页面走丢了').length)
    // be-gap-2: a page written as text is named after its category and status.
    expect(name).toMatch(/404$/)
    const blob = vi.mocked(errorPagesApi.uploadAssetContent).mock.calls[0]![2]
    expect(blob.size).toBe(new TextEncoder().encode('页面走丢了').length)
    expect(blob.type).toBe('text/plain')
    expect(vi.mocked(errorPagesApi.createRule).mock.calls[0]![1].fields).toMatchObject({ asset_id: finalized.value.id, category: 'origin_response' })
    expect(await screen.findByText('已保存')).toBeInTheDocument()
  })

  // errpage-2（be-gap-2 第 5 项，s4-site 遗留 6）：管理员编辑租户站点时，资源列表/上传、规则列表、规则新建都用站点所属租户 scope。
  it('targets the site tenant scope for a platform admin in all error page calls', async () => {
    const platformScope = '99999999-9999-4999-8999-999999999999'
    session.principal = { scope_kind: 'platform', scope_id: platformScope, tenant_id: null, user_id: userId, permissions: ['platform.admin'] }
    const finalized = { value: { ...asset, id: 'a2a2a2a2-0000-4000-8000-000000000002' }, replayed: false }
    vi.mocked(errorPagesApi.initiateAsset).mockResolvedValue({ value: { ...asset, id: finalized.value.id, status: 'initiated' }, replayed: false })
    vi.mocked(errorPagesApi.uploadAssetContent).mockResolvedValue({ value: { ...finalized.value, status: 'staged' }, replayed: false })
    vi.mocked(errorPagesApi.finalizeAsset).mockResolvedValue(finalized)
    vi.mocked(errorPagesApi.createRule).mockResolvedValue({ value: rule, replayed: false })
    const user = userEvent.setup()
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <AdvancedSiteTab siteId={siteId} siteScopeId={scopeId} accessToken="token" scopeKind="platform" scopeId={platformScope}
          tenantId={null} userId={userId} sessionEpoch={1} permissions={['platform.admin']} canManage lockedForTenant={false} />
      </QueryClientProvider>,
    )
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    expect(vi.mocked(errorPagesApi.listAssets).mock.calls[0]![1]).toBe(scopeId)
    expect(vi.mocked(errorPagesApi.listRules).mock.calls[0]![1]).toBe(scopeId)
    await user.click(screen.getByRole('button', { name: '纯文本' }))
    const content = screen.getByRole('textbox', { name: '内容' })
    await user.clear(content)
    await user.type(content, '页面走丢了')
    await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(errorPagesApi.createRule).toHaveBeenCalledTimes(1))
    expect(vi.mocked(errorPagesApi.initiateAsset).mock.calls[0]![1]).toBe(scopeId)
    expect(vi.mocked(errorPagesApi.createRule).mock.calls[0]![1].target).toEqual({ kind: 'site', scope_id: scopeId, site_id: siteId })
  })

  it('reads a page back for editing and saves a changed text as a new asset on the same rule', async () => {
    vi.mocked(errorPagesApi.listAssets).mockResolvedValue({ items: [asset] })
    vi.mocked(errorPagesApi.listRules).mockResolvedValue({ items: [rule] })
    vi.mocked(errorPagesApi.getAssetContent).mockReset().mockResolvedValue({ asset, content: '<h1>old</h1>' })
    vi.mocked(errorPagesApi.initiateAsset).mockResolvedValue({ value: { ...asset, status: 'initiated' }, replayed: false })
    vi.mocked(errorPagesApi.uploadAssetContent).mockResolvedValue({ value: { ...asset, status: 'staged' }, replayed: false })
    vi.mocked(errorPagesApi.finalizeAsset).mockResolvedValue({ value: asset, replayed: false })
    vi.mocked(errorPagesApi.updateRule).mockResolvedValue({ value: { ...rule, revision: rule.revision + 1 }, replayed: false })
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '编辑规则' }))
    const content = await screen.findByRole('textbox', { name: '内容' })
    await waitFor(() => expect(content).toHaveValue('<h1>old</h1>'))
    expect(errorPagesApi.getAssetContent).toHaveBeenCalledWith(expect.any(String), asset.id)
    // unchanged text keeps the asset: only the rule is saved
    await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(errorPagesApi.updateRule).toHaveBeenCalledTimes(1))
    expect(errorPagesApi.initiateAsset).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: '编辑规则' }))
    const again = await screen.findByRole('textbox', { name: '内容' })
    await waitFor(() => expect(again).toHaveValue('<h1>old</h1>'))
    await user.clear(again)
    await user.type(again, '<h1>new</h1>')
    await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(errorPagesApi.updateRule).toHaveBeenCalledTimes(2))
    expect(errorPagesApi.initiateAsset).toHaveBeenCalledTimes(1)
    expect(vi.mocked(errorPagesApi.updateRule).mock.calls[1]![1]).toBe(rule.id)
  })

  // be-gap-2 (s4 遗留 6, like C28): a platform administrator works on the site's error pages in the
  // site's tenant scope, never the platform scope (the service refuses a site rule there).
  it('reads and writes a site error page in the site scope for a platform administrator', async () => {
    const platformScope = '99999999-9999-4999-8999-999999999999'
    session.principal = { scope_kind: 'platform', scope_id: platformScope, tenant_id: null, user_id: userId, permissions: ['platform.admin'] }
    vi.mocked(errorPagesApi.listAssets).mockResolvedValue({ items: [asset] })
    vi.mocked(errorPagesApi.createRule).mockResolvedValue({ value: { id: 'rule-1' } as never, replayed: false })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={client}>
        <AdvancedSiteTab
          siteId={siteId} siteScopeId={scopeId} accessToken="token" scopeKind="platform" scopeId={platformScope} tenantId={null}
          userId={userId} sessionEpoch={1} permissions={['platform.admin']} canManage lockedForTenant={false}
        />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(errorPagesApi.listAssets).toHaveBeenCalledWith('token', scopeId, 'ready'))
    expect(errorPagesApi.listRules).toHaveBeenCalledWith('token', scopeId, siteId)
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    await chooseAsset(user)
    await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(errorPagesApi.createRule).toHaveBeenCalledTimes(1))
    expect(vi.mocked(errorPagesApi.createRule).mock.calls[0]![1].target).toEqual({ kind: 'site', scope_id: scopeId, site_id: siteId })
  })

  it('does not request site error pages for a platform administrator before the site scope is known', async () => {
    session.principal = { scope_kind: 'platform', scope_id: '99999999-9999-4999-8999-999999999999', tenant_id: null, user_id: userId, permissions: ['platform.admin'] }
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <AdvancedSiteTab
          siteId={siteId} accessToken="token" scopeKind="platform" scopeId="99999999-9999-4999-8999-999999999999" tenantId={null}
          userId={userId} sessionEpoch={1} permissions={['platform.admin']} canManage lockedForTenant={false}
        />
      </QueryClientProvider>,
    )
    await screen.findByRole('heading', { name: '上传大小限制' }).catch(() => undefined)
    expect(errorPagesApi.listAssets).not.toHaveBeenCalled()
    expect(errorPagesApi.listRules).not.toHaveBeenCalled()
  })

  it('shows an asset uploaded before names by type, size and id (be-gap-2)', async () => {
    vi.mocked(errorPagesApi.listAssets).mockResolvedValue({ items: [{ ...asset, name: '' }] })
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    await user.click(screen.getByRole('combobox', { name: '页面内容' }))
    expect(await screen.findByText(`text/html · 7 B · ${asset.id}`)).toBeInTheDocument()
  })

  it('retries asset deletion with the frozen revision and key', async () => {
    vi.mocked(errorPagesApi.listAssets).mockResolvedValue({ items: [asset] })
    vi.mocked(errorPagesApi.deleteAsset)
      .mockRejectedValueOnce(new ApiError('raw delete', 503, 'request_failed'))
      .mockResolvedValueOnce({ value: { ...asset, status: 'delete_pending' }, replayed: true })
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    await chooseAsset(user)
    await user.click(screen.getByRole('button', { name: '删除资源' }))
    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const frozenCall = vi.mocked(errorPagesApi.deleteAsset).mock.calls[0]
    expect(frozenCall[2]).toBe(asset.revision)
    await user.click(screen.getByRole('button', { name: '按原操作重试' }))
    await waitFor(() => expect(errorPagesApi.deleteAsset).toHaveBeenCalledTimes(2))
    expect(vi.mocked(errorPagesApi.deleteAsset).mock.calls[1]).toEqual(frozenCall)
    confirm.mockRestore()
  })

  it.each(['create', 'update', 'toggle', 'delete'] as const)('retries an unknown rule %s with frozen fields, revision, and key', async (operation) => {
    vi.mocked(errorPagesApi.listRules).mockResolvedValue({ items: operation === 'create' ? [] : [rule] })
    vi.mocked(errorPagesApi.createRule).mockResolvedValue({ value: rule, replayed: false })
    vi.mocked(errorPagesApi.updateRule).mockResolvedValue({ value: { ...rule, revision: 10 }, replayed: false })
    vi.mocked(errorPagesApi.setRuleEnabled).mockResolvedValue({ value: { ...rule, fields: { ...rule.fields, enabled: false }, revision: 10 }, replayed: false })
    vi.mocked(errorPagesApi.deleteRule).mockResolvedValue({ value: { ...rule, deleted: true, revision: 10 }, replayed: false })
    const failedApi = operation === 'create' ? errorPagesApi.createRule : operation === 'update' ? errorPagesApi.updateRule : operation === 'toggle' ? errorPagesApi.setRuleEnabled : errorPagesApi.deleteRule
    vi.mocked(failedApi).mockRejectedValueOnce(new ApiError(`raw ${operation}`, 500, 'request_failed'))
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const user = userEvent.setup()
    vi.mocked(errorPagesApi.listAssets).mockResolvedValue({ items: [asset] })
    renderTab(['error_pages.read', 'error_pages.manage'])
    await screen.findByRole('button', { name: '新增页面' })

    if (operation === 'create') {
      await user.click(screen.getByRole('button', { name: '新增页面' }))
      await chooseAsset(user)
      await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    } else if (operation === 'update') {
      await user.click(await screen.findByRole('button', { name: '编辑规则' }))
      await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    } else if (operation === 'toggle') {
      await user.click(await screen.findByRole('switch', { name: '启用 404' }))
    } else {
      await user.click(screen.getByRole('button', { name: '删除规则' }))
    }

    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    const frozenCall = vi.mocked(failedApi).mock.calls[0]
    await user.click(screen.getByRole('button', { name: '按原操作重试' }))
    await waitFor(() => expect(vi.mocked(failedApi)).toHaveBeenCalledTimes(2))
    expect(vi.mocked(failedApi).mock.calls[1]).toEqual(frozenCall)
    confirm.mockRestore()
  })
})

// CU-ADV-01 A：“其他状态码”按选择意图显示单码输入，不从数值反推回常用码。
describe('AdvancedSiteTab error page status choice (CU-ADV-01)', () => {
  const statusGroup = () => document.querySelector<HTMLElement>('.ant-modal .ant-radio-group[aria-label="状态码"]')!
  const choose = (user: ReturnType<typeof userEvent.setup>, label: string) => user.click(within(statusGroup()).getByText(label))
  const checked = () => statusGroup().querySelector('.ant-radio-button-wrapper-checked')?.textContent

  it('404 → 其他 shows the single code input and saves the code typed there', async () => {
    vi.mocked(errorPagesApi.listAssets).mockResolvedValue({ items: [asset] })
    vi.mocked(errorPagesApi.createRule).mockResolvedValue({ value: rule, replayed: false })
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    expect(checked()).toBe('404')
    await choose(user, '其他')
    expect(checked()).toBe('其他')
    const code = screen.getByRole('spinbutton', { name: '状态码' })
    await user.clear(code)
    await user.type(code, '418')
    expect(checked()).toBe('其他')
    await chooseAsset(user)
    await user.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(errorPagesApi.createRule).toHaveBeenCalledTimes(1))
    expect(vi.mocked(errorPagesApi.createRule).mock.calls[0]![1].fields.match).toEqual({ kind: 'exact', from: 418, to: 418 })
  })

  it('范围 → 其他 keeps the single code input; 其他 with a common code stays 其他', async () => {
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '新增页面' }))
    await choose(user, '范围')
    expect(screen.getByRole('spinbutton', { name: '状态码结束' })).toBeInTheDocument()
    await choose(user, '其他')
    expect(checked()).toBe('其他')
    expect(screen.getByRole('spinbutton', { name: '状态码' })).toBeInTheDocument()
    expect(screen.queryByRole('spinbutton', { name: '状态码结束' })).not.toBeInTheDocument()
  })

  it('opens an existing uncommon code as 其他 and a range as 范围', async () => {
    vi.mocked(errorPagesApi.listAssets).mockResolvedValue({ items: [asset] })
    vi.mocked(errorPagesApi.listRules).mockResolvedValue({ items: [{ ...rule, fields: { ...rule.fields, match: { kind: 'exact', from: 451, to: 451 } } }] })
    const user = userEvent.setup()
    renderTab(['error_pages.read', 'error_pages.manage'])
    await user.click(await screen.findByRole('button', { name: '编辑规则' }))
    expect(checked()).toBe('其他')
    expect(screen.getByRole('spinbutton', { name: '状态码' })).toHaveValue('451')
  })
})

describe('SiteTrafficLimitCard', () => {
  beforeEach(async () => {
    const { siteTrafficLimitApi } = await import('../../api/siteTrafficLimit')
    vi.mocked(siteTrafficLimitApi.get).mockResolvedValue(siteTrafficLimitInitial)
  })

  it('saves caps in bytes with the site version and shows an exceeded state', async () => {
    const { siteTrafficLimitApi } = await import('../../api/siteTrafficLimit')
    vi.mocked(siteTrafficLimitApi.get).mockResolvedValueOnce({ site_id: '55555555-5555-4555-8555-555555555555', version: 7,
      setting: { enabled: true, daily_bytes: null, monthly_bytes: 10 * 1024 ** 3, total_bytes: null, time_zone: 'Asia/Shanghai', notice_html: '' },
      total_since: null, exceeded_period: 'monthly', exceeded_at: '2026-10-18T04:00:00Z', evaluated_at: '2026-10-18T04:00:00Z', updated_at: null })
    vi.mocked(siteTrafficLimitApi.put).mockImplementation(async (_token, _site, version, setting) => ({
      site_id: '55555555-5555-4555-8555-555555555555', version: version + 1, setting, total_since: null,
      exceeded_period: '', exceeded_at: null, evaluated_at: null, updated_at: null }))
    const { SiteTrafficLimitCard } = await import('./SiteTrafficLimitCard')
    const user = userEvent.setup()
    render(<QueryClientProvider client={new QueryClient()}><SiteTrafficLimitCard siteId="55555555-5555-4555-8555-555555555555" accessToken="token" canManage /></QueryClientProvider>)
    expect(await screen.findByText('已超出每月上限')).toBeInTheDocument()
    // Typed fields save on blur (the cap, then the notice page against the new version).
    await user.type(screen.getByLabelText('每日上限 (GB)'), '2')
    await user.type(screen.getByLabelText('超限提示页 (HTML)'), '<p>over</p>')
    fireEvent.blur(screen.getByLabelText('超限提示页 (HTML)'))
    await waitFor(() => expect(vi.mocked(siteTrafficLimitApi.put).mock.calls.at(-1)?.[3].notice_html).toBe('<p>over</p>'))
    const [, site, version] = vi.mocked(siteTrafficLimitApi.put).mock.calls[0]
    expect(site).toBe('55555555-5555-4555-8555-555555555555')
    expect(version).toBe(7)
    expect(vi.mocked(siteTrafficLimitApi.put).mock.calls.at(-1)?.[3]).toEqual({ enabled: true, daily_bytes: 2 * 1024 ** 3,
      monthly_bytes: 10 * 1024 ** 3, total_bytes: null, time_zone: 'Asia/Shanghai', notice_html: '<p>over</p>' })
  })

  it('refuses to enable a limit without any cap', async () => {
    const { SiteTrafficLimitCard } = await import('./SiteTrafficLimitCard')
    const user = userEvent.setup()
    render(<QueryClientProvider client={new QueryClient()}><SiteTrafficLimitCard siteId="55555555-5555-4555-8555-555555555555" accessToken="token" canManage /></QueryClientProvider>)
    const { siteTrafficLimitApi } = await import('../../api/siteTrafficLimit')
    await user.click(await screen.findByRole('switch', { name: '启用' }))
    expect(screen.getByText('启用时至少设置一个上限')).toBeInTheDocument()
    expect(siteTrafficLimitApi.put).not.toHaveBeenCalled()
  })
})
