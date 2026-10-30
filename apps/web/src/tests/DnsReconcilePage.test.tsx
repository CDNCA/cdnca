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

function fillForm(user: ReturnType<typeof userEvent.setup>) {
  return (async () => {
    await user.type(screen.getByRole('textbox', { name: '域名' }), 'www.example.com')
    await user.type(screen.getByRole('textbox', { name: '预期记录值' }), '192.0.2.10')
    await user.type(screen.getByRole('textbox', { name: '权威 DNS' }), 'ns1.example.net')
    await user.clear(screen.getByRole('textbox', { name: 'DNS 区域 ID' }))
    await user.type(screen.getByRole('textbox', { name: 'DNS 区域 ID' }), zoneID)
    await user.clear(screen.getByRole('textbox', { name: '提供商修订' }))
    await user.type(screen.getByRole('textbox', { name: '提供商修订' }), '7')
  })()
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

describe('DnsReconcilePage', () => {
  beforeEach(async () => { await i18n.changeLanguage('zh-CN') })

  // DC-UX-DETAIL-01（审测卡 12）：从解析检测进入先给只读诊断，不发写/计划请求；高级修复带入域名与 CNAME；
  // 返回保留筛选与页码。
  it('opens a read-only diagnosis of the clicked domain from the resolution check', async () => {
    authenticate()
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
    const applySpy = vi.spyOn(dnsReconcileApi, 'apply')
    const user = userEvent.setup()
    renderPage(undefined, false, { dnsCheck: checkContext })
    expect(await screen.findByText('www.example.com 的解析检测结果')).toBeInTheDocument()
    expect(screen.getByText('问题在 DNS 账号')).toBeInTheDocument()
    expect(screen.getByText('所选 DNS 账号下没有托管这个域名。')).toBeInTheDocument()
    expect(screen.getByText('abc.cdn.example.net')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'DNS 区域 ID' })).not.toBeInTheDocument()
    expect(dryRunSpy).not.toHaveBeenCalled()
    expect(applySpy).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '打开高级修复（生成对账计划）' }))
    expect(screen.getByRole('textbox', { name: '域名' })).toHaveValue('www.example.com')
    expect(screen.getByRole('textbox', { name: '预期记录值' })).toHaveValue('abc.cdn.example.net')
    expect(dryRunSpy).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '返回解析检测' }))
    expect(await screen.findByText('back:dnsCheck:failed:2')).toBeInTheDocument()
  })

  it('denies invalid tenant identity locally without a request', async () => {
    authenticate(actor({ permissions: [] }))
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
    renderPage()
    expect(await screen.findByText('无权查看 DNS 对账')).toBeInTheDocument()
    expect(dryRunSpy).not.toHaveBeenCalled()
  })

  it('covers loading, empty, error and retry states', async () => {
    authenticate()
    let resolvePending!: (value: Awaited<ReturnType<typeof dnsReconcileApi.dryRun>>) => void
    const pending = new Promise<Awaited<ReturnType<typeof dnsReconcileApi.dryRun>>>((resolve) => { resolvePending = resolve })
    const dryRunSpy = vi.spyOn(dnsReconcileApi, 'dryRun')
      .mockReturnValueOnce(pending)
      .mockRejectedValueOnce(new ApiError('private detail', 503, 'dns_reconcile_unavailable'))
      .mockResolvedValueOnce({ ...result, status: 'dry_run' })
    const user = userEvent.setup()
    renderPage()
    await fillForm(user)
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    expect(await screen.findByLabelText('正在生成 DNS 对账计划')).toBeInTheDocument()
    await act(async () => {
      resolvePending({ ...result, status: 'dry_run' })
      await Promise.resolve()
    })
    await waitFor(() => expect(screen.queryByLabelText('正在生成 DNS 对账计划')).not.toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    await waitFor(() => expect(dryRunSpy).toHaveBeenCalledTimes(2))
    expect(await screen.findByText('DNS 对账服务暂不可用，请稍后重试。')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(document.body.textContent).not.toContain('private detail')
    expect(await screen.findByText('发现 1 项变更')).toBeInTheDocument()
    expect(dryRunSpy).toHaveBeenCalledTimes(3)
  })

  it('completes a dry-run under React StrictMode', async () => {
    authenticate()
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    const user = userEvent.setup()
    renderPage(undefined, true)
    await fillForm(user)
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    await waitFor(() => expect(screen.queryByLabelText('正在生成 DNS 对账计划')).not.toBeInTheDocument())
    expect(await screen.findByText('发现 1 项变更')).toBeInTheDocument()
  })

  it('submits a dry-run, applies, and retries an unknown apply with the same identity', async () => {
    authenticate()
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    const applySpy = vi.spyOn(dnsReconcileApi, 'apply')
      .mockRejectedValueOnce(new ApiError('private upstream', 503, 'dns_reconcile_result_unknown'))
      .mockResolvedValueOnce(task)
    vi.spyOn(dnsReconcileApi, 'get').mockResolvedValue(task)
    const user = userEvent.setup()
    renderPage()
    await fillForm(user)
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    expect(await screen.findByText('发现 1 项变更')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '执行对账' }))
    await user.click(screen.getAllByRole('button', { name: '执行对账' }).at(-1)!)
    expect(await screen.findByText('写入结果待确认', { selector: OUTCOME_BAR })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '使用同一请求重试' }))
    await waitFor(() => expect(applySpy).toHaveBeenCalledTimes(2))
    expect(applySpy.mock.calls[1]?.[3]).toEqual(applySpy.mock.calls[0]?.[3])
    expect(await screen.findByText('可提交')).toBeInTheDocument()
  })

  it('keeps owner/session query keys free of tokens and drops late reads after a new session', async () => {
    const first = authenticate(actor(), 'old-token')
    const deferredRead = (() => {
      let resolve!: (value: DNSReconcileTask) => void
      const promise = new Promise<DNSReconcileTask>((done) => { resolve = done })
      return { promise, resolve }
    })()
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    const getSpy = vi.spyOn(dnsReconcileApi, 'get').mockReturnValueOnce(deferredRead.promise)
    const user = userEvent.setup()
    const { queryClient } = renderPage()
    await fillForm(user)
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    expect(await screen.findByText('发现 1 项变更')).toBeInTheDocument()
    vi.spyOn(dnsReconcileApi, 'apply').mockResolvedValue(task)
    await user.click(screen.getByRole('button', { name: '执行对账' }))
    await user.click(screen.getAllByRole('button', { name: '执行对账' }).at(-1)!)
    await waitFor(() => expect(getSpy).toHaveBeenCalled())
    await act(async () => {
      useSessionStore.getState().setSession({ ...authResponse(first), access_token: 'new-token' }, first)
      await Promise.resolve()
    })
    await act(async () => deferredRead.resolve(task))
    const keys = JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.queryKey))
    expect(keys).not.toContain('old-token')
    expect(keys).not.toContain('new-token')
    expect(screen.queryByText('www.example.com')).not.toBeInTheDocument()
  })

  it('lets tenant administrators manage reconciliation while tenant viewers remain read-only', async () => {
    vi.spyOn(dnsReconcileApi, 'dryRun').mockResolvedValue({ ...result, status: 'dry_run' })
    const viewer = actor({ roles: ['tenant_viewer'], permissions: ['dns.read'] })
    authenticate(viewer)
    const user = userEvent.setup()
    const { unmount } = renderPage()
    await fillForm(user)
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    expect(await screen.findByText('发现 1 项变更')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '执行对账' })).not.toBeInTheDocument()
    unmount()

    const administrator = actor({ roles: ['tenant_admin'], permissions: ['dns.read', 'dns.manage'] })
    authenticate(administrator)
    renderPage()
    await fillForm(user)
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    expect(await screen.findByRole('button', { name: '执行对账' })).toBeEnabled()
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
    const user = userEvent.setup()
    renderPage()
    await fillForm(user)
    await user.click(screen.getByRole('button', { name: '生成对账计划' }))
    await user.click(await screen.findByRole('button', { name: '执行对账' }))
    await user.click(screen.getAllByRole('button', { name: '执行对账' }).at(-1)!)

    expect(await screen.findByText(taskID)).toBeInTheDocument()
    expect(screen.getByText('第 3 / 5 次尝试')).toBeInTheDocument()
    expect(screen.getByText('provider-request-1')).toBeInTheDocument()
    expect(screen.getByText('provider-record-1')).toBeInTheDocument()
    expect(screen.getByText('权威 DNS')).toBeInTheDocument()
    expect(screen.getByText('公共递归 DNS')).toBeInTheDocument()
    expect(screen.getByText('补偿计划')).toBeInTheDocument()
    expect(screen.getByText('最近有效状态已保留')).toBeInTheDocument()
    expect(document.body).not.toHaveTextContent('private')
  })
})
