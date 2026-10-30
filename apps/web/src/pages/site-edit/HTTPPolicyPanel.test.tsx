import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/auth'
import { httpPoliciesApi, type HttpPolicy, type HttpPolicyPublicationPreview } from '../../api/httpPolicies'
import '../../i18n/httpPolicies'
import HTTPPolicyPanel from './HTTPPolicyPanel'

const scopeID = '22222222-2222-4222-8222-222222222222'
const siteID = '55555555-5555-4555-8555-555555555555'
const userID = '44444444-4444-4444-8444-444444444444'

const { session } = vi.hoisted(() => ({
  session: {
    accessToken: 'token', sessionEpoch: 1,
    principal: { scope_kind: 'tenant', scope_id: '22222222-2222-4222-8222-222222222222',
      tenant_id: '22222222-2222-4222-8222-222222222222', user_id: '44444444-4444-4444-8444-444444444444',
      permissions: ['http_policies.read', 'http_policies.manage'] },
  },
}))

vi.mock('../../auth/session', () => ({ useSessionStore: { getState: () => session } }))

const policy: HttpPolicy = {
  id: '11111111-1111-4111-8111-111111111111', tenant_scope_id: scopeID, site_id: siteID, site_owner_user_id: userID,
  max_upload_bytes: 1024, request_headers: [], response_headers: [], rewrites: [], redirect_allowed_hosts: [], redirects: [], cors: null, referer_check: null,
  enabled: true, deleted: false, revision: 7, publication_revision: 3,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
}

const preview: HttpPolicyPublicationPreview = {
  state: 'preview', sha256: 'a'.repeat(64),
  snapshot: { schema_version: 'cdnca.edge.http-policy/v1', policy_version: 12, sites: [{ site_id: siteID,
    max_upload_bytes: policy.max_upload_bytes, request_headers: [], response_headers: [], rewrites: [],
    redirect_allowed_hosts: [], redirects: [], cors: null, referer_check: null }] },
}

function renderPanel(permissions: string[], canManage = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={client}><HTTPPolicyPanel
    siteId={siteID} scopeKind="tenant" scopeId={scopeID} tenantId={scopeID} userId={userID}
    sessionEpoch={1} permissions={permissions} canManage={canManage} lockedForTenant={false}
  /></QueryClientProvider>)
  return client
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.spyOn(httpPoliciesApi, 'list').mockResolvedValue({ items: [] })
  vi.spyOn(httpPoliciesApi, 'preview').mockResolvedValue(preview)
  // fix-siteinstant：保存返回保存后的内容（与服务端一致），改动即保存时草稿不被旧值覆盖。
  vi.spyOn(httpPoliciesApi, 'create').mockImplementation(async (_token, _scope, _site, config) => ({ ...policy, ...config }))
  vi.spyOn(httpPoliciesApi, 'update').mockImplementation(async (_token, _scope, _id, revision, config) => ({ ...policy, ...config, revision: revision + 1 }))
  vi.spyOn(httpPoliciesApi, 'setEnabled').mockResolvedValue({ ...policy, revision: 8, enabled: false })
  vi.spyOn(httpPoliciesApi, 'delete').mockResolvedValue({ ...policy, revision: 8, deleted: true })
})

describe('HTTPPolicyPanel', () => {
  it('returns a localized denial with zero API calls and zero write controls without read permission', () => {
    renderPanel([])
    expect(screen.getByText('当前账号无权查看 HTTP 策略')).toBeInTheDocument()
    expect(httpPoliciesApi.list).not.toHaveBeenCalled()
    expect(httpPoliciesApi.preview).not.toHaveBeenCalled()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })

  it('keeps a readable policy strictly non-writable without manage permission', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    renderPanel(['http_policies.read'], false)
    await screen.findByRole('heading', { name: 'HTTP 策略' })
    expect(screen.queryByRole('button', { name: '保存 HTTP 策略' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除 HTTP 策略' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('上传大小上限（字节）')).toBeDisabled()
    expect(httpPoliciesApi.update).not.toHaveBeenCalled()
    expect(httpPoliciesApi.setEnabled).not.toHaveBeenCalled()
    expect(httpPoliciesApi.delete).not.toHaveBeenCalled()
  })

  it('creates the complete header, upload, rewrite, redirect allowlist, and CORS configuration', async () => {
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: 'HTTP 策略' })

    await user.click(screen.getByText('自定义'))
    const upload = screen.getByLabelText('上传大小上限（字节）')
    await user.clear(upload)
    await user.type(upload, '2048')
    // 新增请求头 dialog: 覆盖 with a variable; 删除; 添加 with 允许重复
    const addHeader = async (button: string, name: string, kind: string, value?: string, duplicate = false) => {
      await user.click(screen.getByRole('button', { name: button }))
      const dialog = within(await screen.findByRole('dialog'))
      await user.type(dialog.getByRole('textbox', { name: /名称/ }), name)
      await user.click(dialog.getByRole('radio', { name: new RegExp(`^${kind}`) }))
      if (value !== undefined) {
        await user.click(dialog.getByRole('textbox', { name: /值/ }))
        await user.paste(value)
      }
      if (duplicate) await user.click(dialog.getByRole('switch', { name: '允许重复' }))
      await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    }
    await addHeader('新增请求头', 'X-Request-ID', '覆盖', 'edge-$remote_addr')
    await addHeader('新增请求头', 'X-Legacy', '删除')
    await addHeader('新增响应头', 'X-Frame-Options', '添加', 'DENY', true)
    // 新增转向: 内部重写 and a 302 with an advanced condition
    const addRedirect = async (match: string, target: string, type: string, condition?: [string, string]) => {
      await user.click(screen.getByRole('button', { name: '新增转向' }))
      const dialog = within(await screen.findByRole('dialog'))
      const matchInput = dialog.getByRole('textbox', { name: '匹配路径' })
      await user.clear(matchInput)
      await user.type(matchInput, match)
      await user.type(dialog.getByRole('textbox', { name: '目标 URL' }), target)
      await user.click(dialog.getByRole('radio', { name: type }))
      if (condition) {
        await user.click(dialog.getByRole('button', { name: '高级条件' }))
        await user.click(dialog.getByRole('combobox', { name: '请选择要设置的条件' }))
        await user.click(await screen.findByTitle(condition[0]))
        await user.type(dialog.getByRole('textbox', { name: '示例值: Safari|Chrome' }), condition[1])
        await user.click(dialog.getByRole('button', { name: '添加条件' }))
        expect(dialog.getByText('1 个条件')).toBeInTheDocument()
      }
      await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    }
    await addRedirect('/old', '/new', '内部重写')
    await addRedirect('/go', 'https://example.com/landing', '302 临时', ['User-Agent', 'iPhone|Android'])
    expect(screen.getByText('1 个条件')).toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: '启用跨域策略' }))
    await user.type(screen.getByLabelText('允许的来源'), 'https://app.example.com')
    fireEvent.change(screen.getByLabelText('允许的方法'), { target: { value: 'GET\nPOST' } })
    fireEvent.blur(screen.getByLabelText('允许的方法'))

    // fix-siteinstant：没有保存按钮；第一次改动创建策略，之后的改动按返回的 revision 更新。
    expect(screen.queryByRole('button', { name: '创建 HTTP 策略' })).toBeNull()
    expect(screen.queryByRole('button', { name: '保存 HTTP 策略' })).toBeNull()
    await waitFor(() => expect(vi.mocked(httpPoliciesApi.update).mock.calls.at(-1)?.[4].cors?.allowed_methods).toEqual(['GET', 'POST']))
    expect(httpPoliciesApi.create).toHaveBeenCalledTimes(1)
    const created = vi.mocked(httpPoliciesApi.create).mock.calls[0]!
    expect(created.slice(0, 3)).toEqual(['token', scopeID, siteID])
    expect(created[4]).toEqual(expect.objectContaining({ idempotencyKey: expect.any(String), requestID: expect.any(String), traceID: expect.any(String) }))
    const revisions = vi.mocked(httpPoliciesApi.update).mock.calls.map((item) => item[3])
    expect(revisions).toEqual(revisions.map((_, index) => 7 + index))
    const call = [...vi.mocked(httpPoliciesApi.update).mock.calls.at(-1)!]
    call.splice(2, 2)
    expect(call[2]).toMatchObject({
      max_upload_bytes: 2048,
      request_headers: [{ kind: 'set', name: 'X-Request-ID', values: ['edge-$remote_addr'] }, { kind: 'delete', name: 'X-Legacy', values: [] }],
      response_headers: [{ kind: 'add', name: 'X-Frame-Options', values: ['DENY'], allow_duplicate: true }],
      rewrites: [expect.objectContaining({ match_kind: 'exact', match_path: '/old', target_path: '/new' })],
      redirect_allowed_hosts: ['example.com'],
      redirects: [expect.objectContaining({ match_kind: 'exact', match_path: '/go', status: 302, target_url: 'https://example.com/landing',
        conditions: [{ source: 'user_agent', pattern: 'iPhone|Android' }] })],
      cors: expect.objectContaining({ allowed_origins: ['https://app.example.com'], allowed_methods: ['GET', 'POST'] }),
    })
    expect((call[2] as { rewrites: object[] }).rewrites[0]).not.toHaveProperty('conditions')
  })

  it('refuses an unknown header variable and a duplicate header name in the dialog', async () => {
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: 'HTTP 策略' })
    await user.click(screen.getByRole('button', { name: '新增请求头' }))
    let dialog = within(await screen.findByRole('dialog'))
    await user.type(dialog.getByRole('textbox', { name: /名称/ }), 'X-A')
    await user.click(dialog.getByRole('textbox', { name: /值/ }))
    await user.paste('$nope')
    await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
    expect(await dialog.findByText(/\$ 只能用于列出的变量/)).toBeInTheDocument()
    await user.click(dialog.getByRole('button', { name: '$country' }))
    const value = dialog.getByRole('textbox', { name: /值/ })
    await user.clear(value)
    await user.click(dialog.getByRole('button', { name: '$country' }))
    expect(value).toHaveValue('$country')
    await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByRole('cell', { name: 'X-A' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '新增请求头' }))
    dialog = within(await screen.findByRole('dialog'))
    await user.type(dialog.getByRole('textbox', { name: /名称/ }), 'x-a')
    await user.click(dialog.getByRole('textbox', { name: /值/ }))
    await user.paste('v')
    await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
    expect(await dialog.findByText('请输入有效的请求头名称，且不能与已有名称重复')).toBeInTheDocument()
  })

  // CU-ADV-01 B：节点托管的响应头在弹窗里就地拒绝，弹窗与草稿保留，可原位改名，不发必败请求。
  it('refuses a node-managed response header in place and keeps the dialog draft for correction', async () => {
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: 'HTTP 策略' })
    await user.click(screen.getByRole('button', { name: '新增响应头' }))
    const dialog = within(await screen.findByRole('dialog'))
    const name = dialog.getByRole('textbox', { name: /名称/ })
    await user.type(name, 'Access-Control-Allow-Origin')
    await user.type(dialog.getByRole('textbox', { name: /值/ }), '*')
    await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
    expect(await dialog.findByText(/由节点或跨域设置管理/)).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(name).toHaveValue('Access-Control-Allow-Origin')
    expect(dialog.getByRole('textbox', { name: /值/ })).toHaveValue('*')
    expect(httpPoliciesApi.create).not.toHaveBeenCalled()
    await user.clear(name)
    await user.type(name, 'X-Allow-Origin')
    await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(httpPoliciesApi.create).toHaveBeenCalledTimes(1))
    expect(vi.mocked(httpPoliciesApi.create).mock.calls[0]![3].response_headers).toEqual([{ kind: 'add', name: 'X-Allow-Origin', values: ['*'] }])
  })

  it.each([['request', '新增请求头', 'X-Forwarded-For'], ['response', '新增响应头', 'Strict-Transport-Security'], ['request', '新增请求头', 'X-CDNCA-Node']])(
    'refuses the reserved %s header %s before writing', async (_side, button, header) => {
      const user = userEvent.setup()
      renderPanel(['http_policies.read', 'http_policies.manage'])
      await screen.findByRole('heading', { name: 'HTTP 策略' })
      await user.click(screen.getByRole('button', { name: button }))
      const dialog = within(await screen.findByRole('dialog'))
      await user.type(dialog.getByRole('textbox', { name: /名称/ }), header)
      await user.type(dialog.getByRole('textbox', { name: /值/ }), 'v')
      await user.click(dialog.getByRole('button', { name: /^确\s?定$/ }))
      expect(await dialog.findByText(/由节点或跨域设置管理/)).toBeInTheDocument()
      expect(httpPoliciesApi.create).not.toHaveBeenCalled()
    })

  it('retries an unknown update with the exact frozen config, revision, identity, and metadata', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    vi.mocked(httpPoliciesApi.update)
      .mockRejectedValueOnce(new ApiError('raw upstream body', 503, 'service_unavailable'))
      .mockResolvedValueOnce({ ...policy, revision: 8 })
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    const upload = await screen.findByLabelText('上传大小上限（字节）')
    await user.clear(upload)
    await user.type(upload, '4096')
    fireEvent.blur(upload)
    expect(await screen.findByText('操作结果尚未确认', { selector: '.cdnca-outcome-bar .ant-alert-message' })).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw upstream body')
    const frozen = vi.mocked(httpPoliciesApi.update).mock.calls[0]
    await user.click(screen.getByRole('button', { name: '按原请求重试' }))
    await waitFor(() => expect(httpPoliciesApi.update).toHaveBeenCalledTimes(2))
    expect(vi.mocked(httpPoliciesApi.update).mock.calls[1]).toEqual(frozen)
  })

  it('uses the current revision for disable and delete, and exposes only the current-site preview summary', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    expect(await screen.findByText('策略版本 12，当前站点已包含')).toBeInTheDocument()
    expect(screen.getByText(preview.sha256)).toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: '停用 HTTP 策略' }))
    await waitFor(() => expect(httpPoliciesApi.setEnabled).toHaveBeenCalledTimes(1))
    expect(vi.mocked(httpPoliciesApi.setEnabled).mock.calls[0]?.slice(0, 5)).toEqual(['token', scopeID, policy.id, 7, false])
    await screen.findByRole('switch', { name: '启用 HTTP 策略' })
    await user.click(screen.getByRole('button', { name: '删除 HTTP 策略' }))
    await waitFor(() => expect(httpPoliciesApi.delete).toHaveBeenCalledTimes(1))
    expect(vi.mocked(httpPoliciesApi.delete).mock.calls[0]?.slice(0, 4)).toEqual(['token', scopeID, policy.id, 8])
    confirm.mockRestore()
  })

  // moved from the retired ?tab=access sub-page (tp-b3c): 防盗链 now saves with the policy
  it('saves hotlink protection in the policy and keeps it canonical', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    expect(await screen.findByText('当前关闭，不限制资源引用来源。')).toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: '启用防盗链' }))
    await user.click(screen.getByRole('checkbox', { name: '无 Referer 时检查 Origin' }))
    await user.type(screen.getByLabelText('白名单域名'), '*.Partner.example.com{Enter}cdn.friend.test')
    await user.type(screen.getByLabelText('黑名单域名'), 'bad.partner.example.com')
    await user.type(screen.getByLabelText('只检查扩展名'), '.PNG{Enter}jpg')
    fireEvent.blur(screen.getByLabelText('只检查扩展名'))
    await waitFor(() => expect(vi.mocked(httpPoliciesApi.update).mock.calls.at(-1)?.[4].referer_check?.extensions).toEqual(['jpg', 'png']))
    const config = vi.mocked(httpPoliciesApi.update).mock.calls.at(-1)![4]
    expect(config.referer_check).toEqual({
      allow_empty: true, allow_same_domain: true, allowed_domains: ['*.partner.example.com', 'cdn.friend.test'],
      denied_domains: ['bad.partner.example.com'], check_origin: true, extensions: ['jpg', 'png'],
    })
    expect(config.cors).toBeNull()
    expect(config.max_upload_bytes).toBe(1024)
  })

  it('refuses a hotlink check that restricts nothing without calling the API', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    await user.click(await screen.findByRole('switch', { name: '启用防盗链' }))
    // 开启（默认允许本站域名）是合法的，会保存一次；去掉后什么都不限制，校验失败不再提交。
    await waitFor(() => expect(httpPoliciesApi.update).toHaveBeenCalledTimes(1))
    await user.click(screen.getByRole('checkbox', { name: '允许本站域名' }))
    expect(await screen.findByText(/防盗链设置无效/)).toBeInTheDocument()
    expect(httpPoliciesApi.update).toHaveBeenCalledTimes(1)
  })

  it('rejects wildcard origins with credentials before writing', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [policy] })
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    await user.click(await screen.findByRole('switch', { name: '启用跨域策略' }))
    await user.type(screen.getByLabelText('允许的来源'), '*')
    await user.type(screen.getByLabelText('允许的方法'), 'GET')
    await user.click(screen.getByRole('switch', { name: '允许携带凭据' }))
    expect(await screen.findByText(/^请填写有效的 HTTP 策略字段/)).toBeInTheDocument()
    // 中间合法的状态会保存；“* + 携带凭据”从未提交。
    expect(vi.mocked(httpPoliciesApi.update).mock.calls.some((call) => call[4].cors?.allow_credentials)).toBe(false)
  })

  it('maps terminal stable error codes without rendering the server message or exact retry', async () => {
    vi.mocked(httpPoliciesApi.create).mockRejectedValue(new ApiError('raw entitlement detail', 403, 'entitlement_denied'))
    const user = userEvent.setup()
    renderPanel(['http_policies.read', 'http_policies.manage'])
    await screen.findByRole('heading', { name: 'HTTP 策略' })
    await user.click(screen.getByText('自定义'))
    expect(await screen.findByText('当前套餐或授权不允许此操作')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw entitlement detail')
    expect(screen.queryByRole('button', { name: '按原请求重试' })).not.toBeInTheDocument()
  })
})

// C28 / site-parity3b: an administrator reads and writes the site's tenant HTTP
// policy (target = the site's tenant scope, actor identity unchanged); without
// the site's tenant scope nothing is requested.
describe('HTTPPolicyPanel administrator target (C28)', () => {
  const platformScope = '99999999-9999-4999-8999-999999999999'
  function renderAdmin(siteScopeId?: string) {
    session.principal = { ...session.principal, scope_kind: 'platform', scope_id: platformScope, tenant_id: null as unknown as string, permissions: ['platform.admin'] }
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    render(<QueryClientProvider client={client}><HTTPPolicyPanel
      siteId={siteID} siteScopeId={siteScopeId} scopeKind="platform" scopeId={platformScope} tenantId={null} userId={userID}
      sessionEpoch={1} permissions={['platform.admin']} canManage lockedForTenant={false}
    /></QueryClientProvider>)
  }
  const tenantPrincipal = { ...session.principal }
  afterEach(() => { session.principal = tenantPrincipal })

  it('lists the site tenant scope, not the platform scope, and can save', async () => {
    vi.mocked(httpPoliciesApi.list).mockResolvedValue({ items: [{ ...policy }] })
    renderAdmin(scopeID)
    await screen.findByRole('heading', { name: 'HTTP 策略' })
    expect(httpPoliciesApi.list).toHaveBeenCalledWith('token', scopeID, siteID, undefined)
    expect(httpPoliciesApi.preview).toHaveBeenCalledWith('token', scopeID)
    expect(await screen.findByRole('switch', { name: '启用防盗链' })).toBeEnabled()
    expect(screen.queryByText('当前账号只能查看 HTTP 策略')).not.toBeInTheDocument()
  })

  it('creates the policy in the site tenant scope without an owner filter', async () => {
    const user = userEvent.setup()
    renderAdmin(scopeID)
    await screen.findByRole('heading', { name: 'HTTP 策略' })
    await user.click(await screen.findByText('自定义'))
    await waitFor(() => expect(httpPoliciesApi.create).toHaveBeenCalledTimes(1))
    const call = vi.mocked(httpPoliciesApi.create).mock.calls[0]!
    expect(call.slice(0, 3)).toEqual(['token', scopeID, siteID])
    expect(call[5]).toBeUndefined()
  })

  it('requests nothing when the site tenant scope is unknown', () => {
    renderAdmin(undefined)
    expect(httpPoliciesApi.list).not.toHaveBeenCalled()
    expect(httpPoliciesApi.preview).not.toHaveBeenCalled()
  })
})
