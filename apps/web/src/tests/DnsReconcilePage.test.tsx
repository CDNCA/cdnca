import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App as AntApp, ConfigProvider } from 'antd'
import { StrictMode } from 'react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError, type Principal } from '../api/auth'
import {
  dnsReconcileApi,
  type DNSReconcileTask,
} from '../api/dnsReconcile'
import { dnsApi } from '../api/dns'
import { dnsZonesApi } from '../api/dnsZones'
import { sitesApi } from '../api/sites'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { authResponse, principal } from '../test/fixtures'
import DnsReconcilePage from '../pages/DnsReconcilePage'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const siteID = '22222222-2222-4222-8222-222222222222'
const tenantID = '11111111-1111-4111-8111-111111111111'
const zoneID = '33333333-3333-4333-8333-333333333333'
const taskID = '44444444-4444-4444-8444-444444444444'

function actor(overrides: Partial<Principal> = {}) {
  return principal({
    scope_kind: 'tenant', scope_id: tenantID, tenant_id: tenantID,
    permissions: ['dns.read', 'dns.manage'], ...overrides,
  })
}

function authenticate(next = actor(), token = 'dns-token', update: 'new' | 'refresh' = 'new') {
  useSessionStore.getState().setSession({ ...authResponse(next), access_token: token }, next, update)
  return next
}

const result = {
  tenant_id: tenantID,
  site_id: siteID,
  zone_id: zoneID,
  payload_digest: 'a'.repeat(64),
  plan: {
    tenant_id: tenantID,
    site_id: siteID,
    zone_id: zoneID,
    precondition_revision: 7,
    digest: 'b'.repeat(64),
    operations: [{
      sequence: 1, action: 'update' as const, record_id: 'record-1', name: 'www.example.com',
      type: 'A' as const, value: '192.0.2.10', ttl: 300, previous_value: '192.0.2.9',
      previous_ttl: 300, reason: 'value_mismatch',
    }],
  },
  status: 'ready_to_commit' as const,
  replayed: false,
  started_at: '2026-08-07T00:00:00Z',
  updated_at: '2026-08-07T00:02:00Z',
  ready_at: '2026-08-07T00:02:00Z',
  initial_revision: 7,
  provider_revision: 8,
  operations: [], deferred_deletes: [], compensation_plan: [],
  propagation: [{ number: 1, checked_at: '2026-08-07T00:01:00Z', status: 'healthy', consecutive_healthy: 1 }],
  last_check: undefined,
  error_class: '' as const, error_code: '',
}

const task: DNSReconcileTask = {
  id: taskID, tenant_id: tenantID, site_id: siteID, revision: 4, required_consecutive: 1,
  job: {
    id: taskID, kind: 'dns_reconcile', subject: 'www.example.com', state: 'running', attempt: 1,
    max_attempts: 5, progress: { total: 1, completed: 0, succeeded: 0, failed: 0, cancelled: 0, pending: 1 },
    created_at: '2026-08-07T00:00:00Z', updated_at: '2026-08-07T00:02:00Z',
  },
  request: {
    name: 'www.example.com', expected: [{ type: 'A', values: ['192.0.2.10'] }],
    authoritative_ns: ['ns1.example.net'], ttl: 300, propagation_window_seconds: 900,
    provider: { zone_id: zoneID, revision: 7, records: [] },
  },
  result, created_at: '2026-08-07T00:00:00Z', updated_at: '2026-08-07T00:02:00Z', replayed: false,
}

function renderPage(
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } }),
  strict = false,
  state?: unknown,
) {
  const page = (
    <ConfigProvider button={{ autoInsertSpace: false }}>
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[{ pathname: `/site/${siteID}/dns-reconcile`, state }]}>
            <Routes>
              <Route path="/site/:id/dns-reconcile" element={<DnsReconcilePage />} />
              <Route path="/site/list" element={<BackProbe />} />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>
  )
  return {
    queryClient,
    ...render(strict ? <StrictMode>{page}</StrictMode> : page),
  }
}

// 区域与 DNS 账号读接口：默认返回一个托管 example.com 的区域（版本 7），页面据此自动带出区域与版本。
const providerID = '55555555-5555-4555-8555-555555555555'
const zone = {
  id: zoneID, scope_id: tenantID, provider_id: providerID, name: 'example.com', status: 'draft' as const, version: 7,
  created_at: '2026-08-07T00:00:00Z', updated_at: '2026-08-07T00:00:00Z',
}
function mockZones(items = [zone]) {
  vi.spyOn(dnsApi, 'list').mockResolvedValue({ items: [{
    id: providerID, scope_id: tenantID, name: 'own-cloudflare', provider_type: 'cloudflare', credentials_configured: true,
    status: 'verified', version: 1, created_at: '2026-08-07T00:00:00Z', updated_at: '2026-08-07T00:00:00Z',
  }] } as Awaited<ReturnType<typeof dnsApi.list>>)
  return vi.spyOn(dnsZonesApi, 'listZones').mockResolvedValue({ items })
}

// 带解析检测上下文进入，等区域自动匹配完成后点「检查并生成修复方案」。
async function checkAndPlan(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText('example.com')
  await user.click(screen.getByRole('button', { name: '检查并生成修复方案' }))
}

async function startFix(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: '开始修复' }))
  await user.click(screen.getAllByRole('button', { name: '开始修复' }).at(-1)!)
}

function BackProbe() {
  const state = useLocation().state as { siteSubnav?: string; dnsCheckBack?: { page: number; filter: string } } | null
  return <p>{`back:${state?.siteSubnav}:${state?.dnsCheckBack?.filter}:${state?.dnsCheckBack?.page}`}</p>
}

const checkContext = {
  siteID, siteDisplayID: '12', domain: 'www.example.com', cname: 'abc.cdn.example.net',
  provider: { id: '55555555-5555-4555-8555-555555555555', name: 'own-cloudflare' },
  task: { state: 'failed' as const, code: 'zone_not_hosted', attempts: 3, updatedAt: '2026-10-27T00:00:00Z' },
  resolve: 'failed' as const,
  back: { filter: 'failed' as const, page: 2, limit: 10, search: { domain: '', siteIds: '' } },
}

const contextState = { dnsCheck: checkContext }

describe('DnsReconcilePage', () => {
  beforeEach(async () => { await i18n.changeLanguage('zh-CN') })

  // DC-UX-DETAIL-01（审测卡 12）：从解析检测进入先给只读诊断，不发写/方案请求；
  // 期望值默认带入 CNAME，区域与版本按域名自动匹配；返回保留筛选与页码。
  it('opens a read-only diagnosis with values derived from the site and DNS account', async () => {
    authenticate()
    mockZones()
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
    const applySpy = vi.spyOn(dnsReconcileApi, 'apply')
    const user = userEvent.setup()
    renderPage(undefined, false, contextState)
    expect(await screen.findByText('www.example.com 的当前情况')).toBeInTheDocument()
    expect(screen.getByText('问题在 DNS 账号')).toBeInTheDocument()
    expect(screen.getByText('所选 DNS 账号下没有托管这个域名。')).toBeInTheDocument()
    expect(screen.getByText('abc.cdn.example.net')).toBeInTheDocument()
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    expect(dryRunSpy).not.toHaveBeenCalled()
    expect(applySpy).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: /高级设置/ }))
    expect(screen.getByLabelText('应指向的值')).toHaveValue('abc.cdn.example.net')
    expect(screen.getByLabelText('区域版本')).toHaveValue('7')
    await user.click(screen.getByRole('button', { name: '返回解析检测' }))
    expect(await screen.findByText('back:dnsCheck:failed:2')).toBeInTheDocument()
  })

  it('keeps advanced fields collapsed by default and gives each a visible label and help', async () => {
    authenticate()
    mockZones()
    const user = userEvent.setup()
    renderPage(undefined, false, contextState)
    await screen.findByText('example.com')
    for (const label of ['TTL', '权重', '最长等待生效', '权威 DNS 服务器', 'DNS 区域', '区域版本']) {
      expect(screen.queryByLabelText(label)).not.toBeInTheDocument()
    }
    await user.click(screen.getByRole('button', { name: /高级设置/ }))
    const ttl = screen.getByLabelText('TTL')
    expect(ttl).toHaveValue('300')
    expect(ttl).toHaveAccessibleDescription(/1–604800 秒/)
    expect(screen.getByLabelText('最长等待生效')).toHaveValue('900')
    expect(screen.getByLabelText('权重')).toHaveAccessibleDescription(/0–100/)
  })

  it('asks for a domain first when opened without a check context', async () => {
    authenticate()
    const zonesSpy = mockZones()
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
    const listSpy = vi.spyOn(sitesApi, 'list').mockResolvedValue({ items: [{
      id: siteID, display_id: '12', version: 1, owner: null, domain: 'www.example.com', domains: ['www.example.com', 'img.example.com'],
      listen_ports: ['80'], origins: [], cname: 'abc.cdn.example.net', https_enabled: false, package: null, group_name: null, region: null,
      status: 'active', listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
      lock: { locked: false, reason: null, locked_at: null, operator: null }, created_at: '2026-08-07T00:00:00Z', auto_dns: null,
    }] as unknown as Awaited<ReturnType<typeof sitesApi.list>>['items'], total: 1, page: 1, limit: 20 })
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByRole('heading', { name: '选择要检查的域名' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '检查并生成修复方案' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: '应指向的值' })).not.toBeInTheDocument()
    expect(zonesSpy).not.toHaveBeenCalled()
    expect(listSpy).toHaveBeenCalledWith('dns-token', expect.objectContaining({ site_ids: siteID }))
    await user.click(screen.getByRole('combobox', { name: '域名' }))
    await user.click(await screen.findByText('img.example.com'))
    expect(await screen.findByText('img.example.com 的当前情况')).toBeInTheDocument()
    expect(screen.getByText('这个网站没有配置用于自动添加记录的 DNS 账号。')).toBeInTheDocument()
    expect(dryRunSpy).not.toHaveBeenCalled()
  })

  it('denies invalid tenant identity locally without a request', async () => {
    authenticate(actor({ permissions: [] }))
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
    renderPage()
    expect(await screen.findByText('无权查看域名解析修复')).toBeInTheDocument()
    expect(dryRunSpy).not.toHaveBeenCalled()
  })

  it('shows field-level errors next to invalid advanced settings without a request', async () => {
    authenticate()
    mockZones([])
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
    const user = userEvent.setup()
    renderPage(undefined, false, contextState)
    expect(await screen.findByText('未找到托管这个域名的区域')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /高级设置/ }))
    await user.clear(screen.getByLabelText('TTL'))
    await user.type(screen.getByLabelText('TTL'), '0')
    await user.clear(screen.getByLabelText('权重'))
    await user.type(screen.getByLabelText('权重'), '101')
    await user.click(screen.getByRole('button', { name: '检查并生成修复方案' }))
    expect(await screen.findByText('有 4 项设置需要修改，已在下方标出。')).toBeInTheDocument()
    expect(screen.getByLabelText('TTL')).toHaveAccessibleDescription(/请输入 1–604800 之间的整数/)
    expect(screen.getByLabelText('权重')).toHaveAccessibleDescription(/请输入 0–100 之间的整数/)
    expect(screen.getByLabelText('DNS 区域')).toHaveAccessibleDescription(/请选择托管这个域名的 DNS 区域/)
    expect(screen.getByLabelText('区域版本')).toHaveAttribute('aria-invalid', 'true')
    expect(dryRunSpy).not.toHaveBeenCalled()
  })
  it('presents the plan as records to add, change and delete with before and after values', async () => {
    authenticate()
    mockZones()
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run', plan: { ...result.plan, operations: [
      { sequence: 1, action: 'create', name: 'www.example.com', type: 'CNAME', value: 'abc.cdn.example.net', ttl: 300, reason: 'missing' },
      ...result.plan.operations,
      { sequence: 3, action: 'delete', record_id: 'record-2', name: 'www.example.com', type: 'A', value: '192.0.2.8', ttl: 600, reason: 'conflict' },
    ] } })
    const user = userEvent.setup()
    renderPage(undefined, false, contextState)
    await checkAndPlan(user)
    expect(await screen.findByRole('heading', { name: /新增记录/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /修改记录/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /删除记录/ })).toBeInTheDocument()
    expect(screen.getByText('共 3 项：新增 1，修改 1，删除 1')).toBeInTheDocument()
    expect(screen.getByText('值：192.0.2.9 → 192.0.2.10')).toBeInTheDocument()
    expect(screen.getByText('旧记录会在新记录各地生效、你再次确认之后才删除。')).toBeInTheDocument()
    expect(dryRunSpy.mock.calls[0][2]).toMatchObject({
      name: 'www.example.com', expected: [{ type: 'CNAME', values: ['abc.cdn.example.net'] }], authoritative_ns: [],
      ttl: 300, weight: 0, propagation_window_seconds: 900, provider: { zone_id: zoneID, revision: 7, records: [] },
    })
    // 内部用语只在「技术详情」里。
    expect(document.body).not.toHaveTextContent(/确定性|显式提交|持久化任务|前置修订/)
  })

  it('covers loading, empty, error and retry states', async () => {
    authenticate()
    mockZones()
    let resolvePending!: (value: Awaited<ReturnType<typeof dnsReconcileApi.dryRun>>) => void
    const pending = new Promise<Awaited<ReturnType<typeof dnsReconcileApi.dryRun>>>((resolve) => { resolvePending = resolve })
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
      .mockReturnValueOnce(pending)
      .mockRejectedValueOnce(new ApiError('private detail', 503, 'dns_reconcile_unavailable'))
      .mockResolvedValueOnce({ ...result, status: 'dry_run', plan: { ...result.plan, operations: [] } })
    const user = userEvent.setup()
    renderPage(undefined, false, contextState)
    await checkAndPlan(user)
    expect(await screen.findByLabelText('正在读取当前解析并生成修复方案')).toBeInTheDocument()
    await act(async () => {
      resolvePending({ ...result, status: 'dry_run' })
      await Promise.resolve()
    })
    await waitFor(() => expect(screen.queryByLabelText('正在读取当前解析并生成修复方案')).not.toBeInTheDocument())
    expect(await screen.findByText('共 1 项：修改 1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重新检查' }))
    await waitFor(() => expect(dryRunSpy).toHaveBeenCalledTimes(2))
    expect(await screen.findByText('修复服务暂时不可用，请稍后重试。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(document.body.textContent).not.toContain('private detail')
    expect(await screen.findByText('解析已经正确，不需要修改。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '开始修复' })).not.toBeInTheDocument()
    expect(dryRunSpy).toHaveBeenCalledTimes(3)
  })

  it('completes a dry-run under React StrictMode', async () => {
    authenticate()
    mockZones()
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    const user = userEvent.setup()
    renderPage(undefined, true, contextState)
    await checkAndPlan(user)
    expect(await screen.findByText('共 1 项：修改 1')).toBeInTheDocument()
  })

  it('submits a dry-run, applies, and retries an unknown apply with the same identity', async () => {
    authenticate()
    mockZones()
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    const applySpy = vi.spyOn(dnsReconcileApi, 'apply')
      .mockRejectedValueOnce(new ApiError('private upstream', 503, 'dns_reconcile_result_unknown'))
      .mockResolvedValueOnce(task)
    vi.spyOn(dnsReconcileApi, 'get').mockResolvedValue(task)
    const user = userEvent.setup()
    renderPage(undefined, false, contextState)
    await checkAndPlan(user)
    await startFix(user)
    expect(await screen.findByText('暂时无法确认是否已执行', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '用原请求再试一次' }))
    await waitFor(() => expect(applySpy).toHaveBeenCalledTimes(2))
    expect(applySpy.mock.calls[1]?.[3]).toEqual(applySpy.mock.calls[0]?.[3])
    expect(applySpy.mock.calls[0]?.[3].expectedRevision).toBe(7)
    expect(await screen.findByText('新记录已在各地生效')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认生效并删除旧记录' })).toBeEnabled()
  })

  it('keeps owner/session query keys free of tokens and drops late reads after a new session', async () => {
    const first = authenticate(actor(), 'old-token')
    mockZones()
    const deferredRead = (() => {
      let resolve!: (value: DNSReconcileTask) => void
      const promise = new Promise<DNSReconcileTask>((done) => { resolve = done })
      return { promise, resolve }
    })()
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    const getSpy = vi.spyOn(dnsReconcileApi, 'get').mockReturnValueOnce(deferredRead.promise)
    const user = userEvent.setup()
    const { queryClient } = renderPage(undefined, false, contextState)
    await checkAndPlan(user)
    vi.spyOn(dnsReconcileApi, 'apply').mockResolvedValue(task)
    await startFix(user)
    await waitFor(() => expect(getSpy).toHaveBeenCalled())
    await act(async () => {
      useSessionStore.getState().setSession({ ...authResponse(first), access_token: 'new-token' }, first)
      await Promise.resolve()
    })
    await act(async () => deferredRead.resolve(task))
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toContain('old-token')
    expect(keys).not.toContain('new-token')
    expect(screen.queryByText('新记录已在各地生效')).not.toBeInTheDocument()
  })

  it('lets tenant administrators manage reconciliation while tenant viewers remain read-only', async () => {
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    mockZones()
    const viewer = actor({ roles: ['tenant_viewer'], permissions: ['dns.read'] })
    authenticate(viewer)
    const user = userEvent.setup()
    const { unmount } = renderPage(undefined, false, contextState)
    await checkAndPlan(user)
    expect(await screen.findByText('你只有查看权限，需要有 DNS 管理权限的成员执行修复。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '开始修复' })).not.toBeInTheDocument()
    unmount()

    const administrator = actor({ roles: ['tenant_owner'], permissions: ['dns.read', 'dns.manage'] })
    authenticate(administrator)
    renderPage(undefined, false, contextState)
    await checkAndPlan(user)
    expect(await screen.findByRole('button', { name: '开始修复' })).toBeEnabled()
  })
  it('renders durable operation, resolver, compensation and LKG evidence without exposing private errors', async () => {
    authenticate()
    const diagnosticTask: DNSReconcileTask = {
      ...task,
      job: {
        ...task.job,
        state: 'partial_failed',
        attempt: 3,
        max_attempts: 5,
        last_error_code: 'provider_timeout',
      },
      result: {
        ...result,
        status: 'failed',
        error_class: 'timeout',
        error_code: 'provider_timeout',
        operations: [{
          source_sequence: 1,
          operation: result.plan.operations[0],
          client_request_id: 'dns-client-1',
          provider_request_id: 'provider-request-1',
          provider_record_id: 'provider-record-1',
          provider_revision: 8,
          status: 'transient_failed',
          attempts: 3,
          error_class: 'timeout',
          error_code: 'provider_timeout',
          report_sequence: 2,
        }],
        compensation_plan: [{
          sequence: 2,
          action: 'delete',
          record_id: 'provider-record-1',
          name: 'www.example.com',
          type: 'A',
          value: '192.0.2.10',
          ttl: 300,
          reason: 'compensate_applied_create',
        }],
        last_check: {
          name: 'www.example.com',
          status: 'public_propagating',
          compliant: false,
          checked_at: '2026-08-07T00:02:00Z',
          repair_plan: result.plan,
          observations: [
            {
              role: 'authoritative', resolver: 'ns1.example.net', record_type: 'A', status: 'healthy',
              values: ['192.0.2.10'], cname_chain: [], attempts: 1, minimum_ttl: 300, error_code: '',
            },
            {
              role: 'public_recursive', resolver: 'public-a', record_type: 'A', status: 'wrong_value',
              values: ['192.0.2.9'], cname_chain: [], attempts: 2, minimum_ttl: 120, error_code: '',
            },
          ],
        },
      },
    }
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    vi.spyOn(dnsReconcileApi, 'apply').mockResolvedValue(diagnosticTask)
    vi.spyOn(dnsReconcileApi, 'get').mockResolvedValue(diagnosticTask)
    mockZones()
    const user = userEvent.setup()
    renderPage(undefined, false, contextState)
    await checkAndPlan(user)
    await startFix(user)

    expect(await screen.findByText('修复没有完成：DNS 服务商返回错误')).toBeInTheDocument()
    expect(screen.getByText('已保留最近一次正常的解析状态')).toBeInTheDocument()
    expect(screen.getByText(/公共 DNS · public-a/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '取消修复' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: /技术详情/ }))
    expect(await screen.findByText(taskID)).toBeInTheDocument()
    expect(screen.getByText('第 3 / 5 次尝试')).toBeInTheDocument()
    expect(screen.getByText('provider-request-1')).toBeInTheDocument()
    expect(screen.getByText('provider-record-1')).toBeInTheDocument()
    expect(screen.getAllByText('权威 DNS').length).toBeGreaterThan(0)
    expect(screen.getByText('撤销方案')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private')
  })
})
